//! Wallet entropy, key derivation, and authenticated seed encryption.

pub mod constants;

use std::sync::LazyLock;

use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce, Tag, aead::AeadMutInPlace};
use alloy::{network::EthereumWallet, signers::local::PrivateKeySigner};
use bdk_wallet::{
    CreateParams, KeychainKind, LoadParams, Wallet,
    descriptor::{ExtendedDescriptor, IntoWalletDescriptor},
    miniscript::descriptor::{DescriptorPublicKey, DescriptorXKey, Wildcard},
};
use bip39::{Language, Mnemonic};
use bitcoin::{
    Network, PrivateKey,
    bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
    psbt::{GetKey, GetKeyError, KeyRequest},
    secp256k1::{All, PublicKey, Secp256k1, SecretKey, Signing},
};
use password::{HashVersion, Password};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use terrors::OneOf;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::constants::{
    AES_NONCE_LEN, AES_TAG_LEN, BIP44_ALPEN_EVM_WALLET_PATH, BIP86_ACCOUNT_PATH,
    DRT_RECLAIM_PURPOSE, PW_SALT_LEN, SEED_LEN,
};

/// Shared secp256k1 context for wallet key derivation, signing, and verification.
pub static SECP256K1: LazyLock<Secp256k1<All>> = LazyLock::new(Secp256k1::new);

/// A deposit-request reclaim keypair, deterministically derived from the seed. Zeroizes its own
/// stored secret-key copy on drop.
#[expect(
    missing_debug_implementations,
    reason = "Struct contains a secret key that should not be debug printed"
)]
pub struct DrtReclaimKeypair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl Zeroize for DrtReclaimKeypair {
    fn zeroize(&mut self) {
        // NOTE: `SecretKey::non_secure_erase` writes `1`s to the memory.
        self.secret_key.non_secure_erase();
    }
}

impl ZeroizeOnDrop for DrtReclaimKeypair {}

impl Drop for DrtReclaimKeypair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A BIP32 extended private key that wipes its private key and chain code on drop.
///
/// [`Xpriv`] is [`Copy`], so this cannot stop copies from being made: rust-bitcoin copies it
/// internally while deriving and signing, and dereferencing [`Self::as_xpriv`] copies it out of
/// the wrapper. It only guarantees that the copy it owns is erased.
#[expect(
    missing_debug_implementations,
    reason = "Struct contains a private key that should not be debug printed"
)]
pub struct ZeroizingXpriv(Xpriv);

impl ZeroizingXpriv {
    /// Borrows the wrapped key. Prefer passing the wrapper itself (it implements [`GetKey`]) over
    /// copying the [`Xpriv`] out, as copies are not erased.
    pub fn as_xpriv(&self) -> &Xpriv {
        &self.0
    }

    /// Derives a child key, wrapped so it is erased on drop too.
    fn derive_priv(&self, path: &impl AsRef<[ChildNumber]>) -> Self {
        Self(
            self.0
                .derive_priv(&SECP256K1, path)
                .expect("valid derivation path"),
        )
    }
}

impl GetKey for ZeroizingXpriv {
    type Error = GetKeyError;

    fn get_key<C: Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        self.0.get_key(key_request, secp)
    }
}

impl Zeroize for ZeroizingXpriv {
    fn zeroize(&mut self) {
        // NOTE: `SecretKey::non_secure_erase` writes `1`s to the memory.
        self.0.private_key.non_secure_erase();
        let chain_code: &mut [u8] = self.0.chain_code.as_mut();
        chain_code.zeroize();
    }
}

impl ZeroizeOnDrop for ZeroizingXpriv {}

impl Drop for ZeroizingXpriv {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[expect(
    missing_debug_implementations,
    reason = "Struct contains sensitive wallet parameters that should not be debug printed"
)]
pub struct BaseWallet(LoadParams, CreateParams);

impl BaseWallet {
    pub fn split(self) -> (LoadParams, CreateParams) {
        (self.0, self.1)
    }
}

#[derive(Clone)]
#[expect(missing_debug_implementations, reason = "do not expose seed entropy")]
// NOTE: This is not a BIP39 seed, instead random bytes of entropy.
pub struct Seed(Zeroizing<[u8; SEED_LEN]>);

impl Seed {
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut bytes = Zeroizing::new([0u8; SEED_LEN]);
        rng.fill_bytes(bytes.as_mut());
        Self(bytes)
    }

    /// Constructs wallet entropy from a fixed-size byte array.
    pub fn from_entropy(bytes: [u8; SEED_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Returns the mnemonic for this wallet's entropy.
    pub fn mnemonic(&self, language: Language) -> Mnemonic {
        Mnemonic::from_entropy_in(language, self.0.as_ref()).expect("valid entropy")
    }

    pub fn descriptor_recovery_key(&self) -> Zeroizing<[u8; 32]> {
        let mut hasher = <Sha256 as Digest>::new(); // this is to appease the analyzer
        hasher.update(b"alpen labs alpen descriptor recovery file 2024");
        hasher.update(self.0.as_slice());
        // Hash straight into the zeroizing buffer rather than returning a temporary array.
        let mut key = Zeroizing::new([0u8; 32]);
        let key_bytes: &mut [u8; 32] = &mut key;
        hasher.finalize_into(key_bytes.into());
        key
    }

    /// Derives the deposit-request reclaim keypair for the given counter.
    ///
    /// This is deterministic in the seed and `counter`, so a deposit's reclaim key can always be
    /// recovered from the mnemonic alone, given the counter value it was created with. `counter`
    /// must never be reused for a live deposit request: it is intended to come from
    /// `DescriptorRecovery::next_reclaim_counter` in the Bitcoin wallet library,
    /// which persists the increment before handing out a value.
    ///
    /// The BIP32 master key is derived directly from the mnemonic's raw entropy, independently of
    /// the BIP39 PBKDF2 seed used by the signet wallet. Changing this would make existing deposit
    /// requests unrecoverable.
    pub fn drt_reclaim_keypair(&self, counter: u32) -> DrtReclaimKeypair {
        let rootpriv = ZeroizingXpriv(
            Xpriv::new_master(Network::Signet, self.0.as_ref()).expect("valid xpriv"),
        );
        let path = DerivationPath::master().extend([
            DRT_RECLAIM_PURPOSE,
            ChildNumber::from_hardened_idx(counter).expect("counter fits in 31 bits"),
        ]);
        let derived = rootpriv.derive_priv(&path);
        let secret_key = derived.0.private_key;
        let public_key = PublicKey::from_secret_key(&SECP256K1, &secret_key);
        DrtReclaimKeypair {
            secret_key,
            public_key,
        }
    }

    pub fn encrypt<R: CryptoRngCore>(
        &self,
        password: &mut Password,
        rng: &mut R,
    ) -> Result<EncryptedSeed, OneOf<(argon2::Error, aes_gcm_siv::Error)>> {
        let mut buf = [0u8; EncryptedSeed::LEN];
        rng.fill_bytes(&mut buf[..PW_SALT_LEN + AES_NONCE_LEN]);

        let seed_encryption_key = password
            .seed_encryption_key(
                &buf[..PW_SALT_LEN].try_into().expect("cannot fail"),
                HashVersion::V0,
            )
            .map_err(OneOf::new)?;

        let (salt_and_nonce, rest) = buf.split_at_mut(PW_SALT_LEN + AES_NONCE_LEN);
        let (seed, _) = rest.split_at_mut(SEED_LEN);
        seed.copy_from_slice(self.0.as_ref());

        let mut cipher = Aes256GcmSiv::new_from_slice(seed_encryption_key.as_ref())
            .expect("should be correct key size");
        let nonce = Nonce::from_slice(&salt_and_nonce[PW_SALT_LEN..]);
        let tag = cipher
            .encrypt_in_place_detached(nonce, &[], seed)
            .map_err(OneOf::new)?;
        buf[(EncryptedSeed::LEN - AES_TAG_LEN)..].copy_from_slice(tag.as_slice());
        Ok(EncryptedSeed(buf))
    }

    /// Returns the BIP32 master key derived from the BIP39 seed (no passphrase) of this entropy.
    fn bip39_master_key(&self, network: Network) -> ZeroizingXpriv {
        let mnemonic = Mnemonic::from_entropy(self.0.as_ref()).expect("valid entropy");
        // We do not use a passphrase.
        let bip39_seed = Zeroizing::new(mnemonic.to_seed(""));
        ZeroizingXpriv(Xpriv::new_master(network, bip39_seed.as_ref()).expect("valid xpriv"))
    }

    /// Returns the BIP32 master key that signs PSBTs built by [`Self::bitcoin_wallet`].
    ///
    /// BDK no longer keeps signing keys, so pass this to [`Psbt::sign`](bitcoin::Psbt::sign).
    /// The key is erased when the returned value is dropped.
    pub fn bitcoin_signer(&self, network: Network) -> ZeroizingXpriv {
        self.bip39_master_key(network)
    }

    /// Returns watch-only wallet parameters; sign with [`Self::bitcoin_signer`].
    pub fn bitcoin_wallet(&self, network: Network) -> BaseWallet {
        let (external_desc, internal_desc) = self.bitcoin_descriptors(network);
        BaseWallet(
            Wallet::load()
                .descriptor(KeychainKind::External, Some(external_desc.clone()))
                .descriptor(KeychainKind::Internal, Some(internal_desc.clone())),
            Wallet::create(external_desc, internal_desc),
        )
    }

    /// Returns the external and internal BIP-86 descriptors, `tr([fp/86h/0h/0h]xpub/{0,1}/*)`.
    ///
    /// These are built from the account xpub rather than by parsing an xprv descriptor string, so
    /// no private key is ever serialized. They equal what BDK derives from
    /// `tr(<rootpriv>/86h/0h/0h/{0,1}/*)`, so wallets created that way still load.
    fn bitcoin_descriptors(&self, network: Network) -> (ExtendedDescriptor, ExtendedDescriptor) {
        let rootpriv = self.bitcoin_signer(network);
        let fingerprint = rootpriv.0.fingerprint(&SECP256K1);
        let account_xpub =
            Xpub::from_priv(&SECP256K1, &rootpriv.derive_priv(&BIP86_ACCOUNT_PATH).0);
        let descriptor = |keychain: u32| {
            let key = DescriptorPublicKey::XPub(DescriptorXKey {
                origin: Some((fingerprint, BIP86_ACCOUNT_PATH.into())),
                xkey: account_xpub,
                derivation_path: [ChildNumber::from_normal_idx(keychain).expect("valid index")]
                    .as_slice()
                    .into(),
                wildcard: Wildcard::Unhardened,
            });
            ExtendedDescriptor::new_tr(key, None)
                .expect("valid descriptor")
                .into_wallet_descriptor(&SECP256K1, network.into())
                .expect("valid descriptor")
                .0
        };
        (descriptor(0), descriptor(1))
    }

    pub fn get_alpen_wallet(&self) -> EthereumWallet {
        let derivation_path = DerivationPath::master().extend(BIP44_ALPEN_EVM_WALLET_PATH);

        // Network choice affects how extended public and private keys are serialized. See
        // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#serialization-format.
        // Given the popularity of MetaMask, we follow their example (they always hardcode mainnet)
        // and hardcode Network::Bitcoin (mainnet) for EVM-based wallet.
        let master_key = self.bip39_master_key(Network::Bitcoin);

        // Derive the child key for the given path
        let derived_key = master_key.derive_priv(&derivation_path);
        let secret_bytes = Zeroizing::new(derived_key.0.private_key.secret_bytes());
        let signer = PrivateKeySigner::from_slice(secret_bytes.as_slice()).expect("valid slice");

        EthereumWallet::from(signer)
    }
}

#[expect(
    missing_debug_implementations,
    reason = "Struct contains encrypted seed data that should not be debug printed"
)]
pub struct EncryptedSeed([u8; Self::LEN]);

impl EncryptedSeed {
    /// Returns the serialized encrypted seed, including salt, nonce, and authentication tag.
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Restores a serialized encrypted seed; authenticity is checked on decryption.
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    pub const LEN: usize = PW_SALT_LEN + AES_NONCE_LEN + SEED_LEN + AES_TAG_LEN;

    pub fn decrypt(
        mut self,
        password: &mut Password,
    ) -> Result<Seed, OneOf<(argon2::Error, aes_gcm_siv::Error)>> {
        let seed_encryption_key = password
            .seed_encryption_key(
                &self.0[..PW_SALT_LEN].try_into().expect("cannot fail"),
                HashVersion::V0,
            )
            .map_err(OneOf::new)?;

        let mut cipher = Aes256GcmSiv::new_from_slice(seed_encryption_key.as_ref())
            .expect("should be correct key size");
        let (salt_and_nonce, rest) = self.0.split_at_mut(PW_SALT_LEN + AES_NONCE_LEN);
        let (encrypted_seed, tag) = rest.split_at_mut(SEED_LEN);
        let tag = Tag::from_slice(tag);
        let nonce = Nonce::from_slice(&salt_and_nonce[PW_SALT_LEN..]);

        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        seed.copy_from_slice(encrypted_seed);

        cipher
            .decrypt_in_place_detached(nonce, &[], seed.as_mut(), tag)
            .map_err(OneOf::new)?;

        Ok(Seed(seed))
    }
}

pub mod password;

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use rand_core::OsRng;
    use sha2::digest::generic_array::GenericArray;

    use super::*;

    #[test]
    // Sanity checks on curve scalar construction, to ensure proper rejection
    // This treats zero as invalid (for ECDSA reasons)
    fn scalar_sanity_checks() {
        // This is the (big-endian) order of the `secp256k1` curve group
        // You can find it in, for example, section 2.4.1 of https://www.secg.org/sec2-v2.pdf
        let mut order: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ];

        // The scalar can't be zero
        assert!(PrivateKeySigner::from_field_bytes(GenericArray::from_slice(&[0u8; 32])).is_err());

        // The scalar can be well within the group order
        assert!(PrivateKeySigner::from_field_bytes(GenericArray::from_slice(&[1u8; 32])).is_ok());

        // The scalar can't equal the group order
        assert!(PrivateKeySigner::from_field_bytes(GenericArray::from_slice(&order)).is_err());

        // The scalar can't exceed the group order
        order[31] = 0x42;
        assert!(PrivateKeySigner::from_field_bytes(GenericArray::from_slice(&order)).is_err());
        assert!(
            PrivateKeySigner::from_field_bytes(GenericArray::from_slice(&[u8::MAX; 32])).is_err()
        );

        // The scalar can be _just_ under the group order
        order[31] = 0x40;
        assert!(PrivateKeySigner::from_field_bytes(GenericArray::from_slice(&order)).is_ok());
    }

    #[test]
    // Test valid seed encryption and decryption
    fn seed_encrypt_decrypt() {
        let mut password = Password::new(String::from("swordfish"));
        let seed = Seed::generate(&mut OsRng);

        let encrypted_seed = seed.encrypt(&mut password, &mut OsRng).unwrap();
        let decrypted_seed = encrypted_seed.decrypt(&mut password).unwrap();

        assert_eq!(seed.0, decrypted_seed.0);
    }

    #[test]
    // Using an evil password fails decryption
    fn evil_password() {
        let mut password = Password::new(String::from("swordfish"));
        let mut evil_password = Password::new(String::from("evil"));
        let seed = Seed::generate(&mut OsRng);

        let encrypted_seed = seed.encrypt(&mut password, &mut OsRng).unwrap();

        assert!(encrypted_seed.decrypt(&mut evil_password).is_err());
    }

    #[test]
    // Using an evil salt fails decryption
    fn evil_salt() {
        let mut password = Password::new(String::from("swordfish"));
        let seed = Seed::generate(&mut OsRng);

        let mut encrypted_seed = seed.encrypt(&mut password, &mut OsRng).unwrap();
        let index = 0;
        encrypted_seed.0[index] = !encrypted_seed.0[index];

        assert!(encrypted_seed.decrypt(&mut password).is_err());
    }

    #[test]
    // Using an evil nonce fails decryption
    fn evil_nonce() {
        let mut password = Password::new(String::from("swordfish"));
        let seed = Seed::generate(&mut OsRng);

        let mut encrypted_seed = seed.encrypt(&mut password, &mut OsRng).unwrap();
        let index = PW_SALT_LEN;
        encrypted_seed.0[index] = !encrypted_seed.0[index];

        assert!(encrypted_seed.decrypt(&mut password).is_err());
    }

    #[test]
    // Using an evil seed fails decryption
    fn evil_seed() {
        let mut password = Password::new(String::from("swordfish"));
        let seed = Seed::generate(&mut OsRng);

        let mut encrypted_seed = seed.encrypt(&mut password, &mut OsRng).unwrap();
        let index = PW_SALT_LEN + AES_NONCE_LEN;
        encrypted_seed.0[index] = !encrypted_seed.0[index];

        assert!(encrypted_seed.decrypt(&mut password).is_err());
    }

    #[test]
    // Using an evil tag fails decryption
    fn evil_tag() {
        let mut password = Password::new(String::from("swordfish"));
        let seed = Seed::generate(&mut OsRng);

        let mut encrypted_seed = seed.encrypt(&mut password, &mut OsRng).unwrap();
        let index = PW_SALT_LEN + AES_NONCE_LEN + SEED_LEN;
        encrypted_seed.0[index] = !encrypted_seed.0[index];

        assert!(encrypted_seed.decrypt(&mut password).is_err());
    }

    #[test]
    // Test L2 wallet address matches the one from BIP39 tool (e.g. https://iancoleman.io/bip39/)
    // using the same menmonic and derivation path.
    fn test_l2_wallet_address() {
        let seed = Seed(
            [
                0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
                0x41, 0x41,
            ]
            .into(),
        );
        let l2wallet = seed.get_alpen_wallet();
        let address = l2wallet.default_signer().address().to_string();
        // BIP39 Mnemonic for `seed` should be:
        // rival ivory defy future meat build young envelope mimic like motion loan
        // The expected address is obtained using the BIP39 tool with the above mnemonic
        // and BIP44 derivation path m/44'/60'/0'/0/0.
        let expected_address = "0x4eEE6B504Bc2c47650bAa7d135DA10F2A469E582".to_string();
        assert_eq!(address, expected_address);
    }
    #[test]
    // BIP-86's official test vector for m/86'/0'/0'/0/0 (mnemonic "abandon abandon abandon
    // abandon abandon abandon abandon abandon abandon abandon abandon about", all-zero entropy).
    // Confirms the signet wallet is now derived via the standard BIP39 path (entropy -> mnemonic
    // -> PBKDF2 seed -> BIP32) instead of raw entropy, so any BIP-86-compliant wallet can recover
    // the same funds. https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors
    fn test_l1_signet_wallet_matches_bip86_test_vector() {
        let seed = Seed([0u8; SEED_LEN].into());
        let (_, create) = seed.bitcoin_wallet(Network::Signet).split();
        let mut wallet = create
            .network(Network::Signet)
            .create_wallet_no_persist()
            .expect("valid descriptor");
        let script_pubkey = wallet
            .reveal_next_address(KeychainKind::External)
            .address
            .script_pubkey();

        let expected_bytes = shrex::decode_alloc(
            "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
        )
        .expect("valid hex");
        assert_eq!(script_pubkey.as_bytes(), expected_bytes.as_slice());
    }

    #[test]
    // The reclaim keypair must be a pure function of (seed, counter): same inputs always
    // reproduce the same key, so a lost descriptor DB doesn't strand funds.
    fn drt_reclaim_keypair_is_deterministic_and_distinct_per_counter() {
        let seed = Seed::generate(&mut OsRng);

        let keypair_0 = seed.drt_reclaim_keypair(0);
        let keypair_0_again = seed.drt_reclaim_keypair(0);
        assert_eq!(keypair_0.secret_key, keypair_0_again.secret_key);
        assert_eq!(keypair_0.public_key, keypair_0_again.public_key);

        let keypair_1 = seed.drt_reclaim_keypair(1);
        assert_ne!(keypair_0.secret_key, keypair_1.secret_key);
        assert_ne!(keypair_0.public_key, keypair_1.public_key);

        let other_seed = Seed::generate(&mut OsRng);
        let keypair_0_other_seed = other_seed.drt_reclaim_keypair(0);
        assert_ne!(keypair_0.secret_key, keypair_0_other_seed.secret_key);
    }

    #[test]
    fn builds_bitcoin_mainnet_wallet() {
        let seed = Seed([0u8; SEED_LEN].into());
        let (_, builder) = seed.bitcoin_wallet(Network::Bitcoin).split();
        let mut wallet = builder
            .network(Network::Bitcoin)
            .create_wallet_no_persist()
            .expect("valid descriptor");
        let address = wallet.reveal_next_address(KeychainKind::External).address;

        assert_eq!(
            address.to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
    }

    #[test]
    // Pins the signer and the watch-only descriptors to BIP-86's official rootpriv and account
    // xpub for the all-zero entropy mnemonic.
    // https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors
    fn bitcoin_signer_and_descriptors_match_bip86_test_vector() {
        let seed = Seed([0u8; SEED_LEN].into());
        let signer = seed.bitcoin_signer(Network::Bitcoin);
        assert_eq!(
            signer.as_xpriv().to_string(),
            "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
        );

        let (external, internal) = seed.bitcoin_descriptors(Network::Bitcoin);
        let account_xpub = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";
        assert_eq!(
            external.to_string(),
            ExtendedDescriptor::from_str(&format!("tr([73c5da0a/86'/0'/0']{account_xpub}/0/*)"))
                .unwrap()
                .to_string()
        );
        assert_eq!(
            internal.to_string(),
            ExtendedDescriptor::from_str(&format!("tr([73c5da0a/86'/0'/0']{account_xpub}/1/*)"))
                .unwrap()
                .to_string()
        );
    }

    #[test]
    // The public descriptors must be identical to what BDK derived from the xprv descriptors used
    // before, or existing wallets would fail to load.
    fn bitcoin_descriptors_match_legacy_xprv_descriptors() {
        let seeds = [
            Seed([0u8; SEED_LEN].into()),
            Seed([0xFF; SEED_LEN].into()),
            Seed::generate(&mut OsRng),
        ];
        for seed in &seeds {
            for network in [
                Network::Bitcoin,
                Network::Testnet,
                Network::Signet,
                Network::Regtest,
            ] {
                let rootpriv = *seed.bitcoin_signer(network).as_xpriv();
                let legacy = |keychain: u32| {
                    format!("tr({rootpriv}/86h/0h/0h/{keychain}/*)")
                        .into_wallet_descriptor(&SECP256K1, network.into())
                        .unwrap()
                        .0
                };
                let (external, internal) = seed.bitcoin_descriptors(network);
                assert_eq!(external, legacy(0));
                assert_eq!(internal, legacy(1));
            }
        }
    }

    #[test]
    fn zeroizing_xpriv_erases_key_material() {
        let seed = Seed([0u8; SEED_LEN].into());
        let mut signer = seed.bitcoin_signer(Network::Bitcoin);
        let original = *signer.as_xpriv();

        signer.zeroize();

        assert_ne!(signer.as_xpriv().private_key, original.private_key);
        assert_eq!(signer.as_xpriv().chain_code.as_bytes(), &[0u8; 32]);
    }

    #[test]
    // The descriptor recovery DB is encrypted under this key, so it must never change.
    fn descriptor_recovery_key_is_stable() {
        let seed = Seed([0x42; SEED_LEN].into());
        let mut preimage = b"alpen labs alpen descriptor recovery file 2024".to_vec();
        preimage.extend_from_slice(&[0x42; SEED_LEN]);
        let expected: [u8; 32] = Sha256::digest(&preimage).into();

        assert_eq!(*seed.descriptor_recovery_key(), expected);
    }
}
