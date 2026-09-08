use bdk_wallet::bitcoin::bip32::ChildNumber;

/// Length of salt used for password hashing
pub const PW_SALT_LEN: usize = 16;
/// Length of nonce in bytes
pub const AES_NONCE_LEN: usize = 12;
/// Length of seed in bytes
pub const SEED_LEN: usize = 16;
/// AES-256-GCM-SIV tag len
pub const AES_TAG_LEN: usize = 16;

/// Hardened branch reserved for Alpen CLI deposit-request reclaim keys.
///
/// Unregistered — picked above the 10001-19999 range BIP43 reserves for SLIPs, so it can't
/// collide with anything registered.
///
/// Separates this key material from the wallet's BIP-86 path (`m/86'/0'/0'`). Each deposit derives
/// `m/<DRT_RECLAIM_PURPOSE>'/<counter>'`, where `counter` is durable local state (see
/// `DescriptorRecovery::next_reclaim_counter` in the Bitcoin wallet library),
/// making the reclaim key recoverable from the seed alone rather than only from the descriptor DB.
///
/// Don't change this. A deposit's reclaim key can only be reconstructed from the seed if this
/// value is still the same as when that deposit was made.
pub const DRT_RECLAIM_PURPOSE: ChildNumber = ChildNumber::Hardened { index: 43_000 };

/// Alpen CLI [`DerivationPath`](bdk_wallet::bitcoin::bip32::DerivationPath) for Alpen EVM wallet
///
/// This corresponds to the path: `m/44'/60'/0'/0/0`.
pub const BIP44_ALPEN_EVM_WALLET_PATH: &[ChildNumber] = &[
    // Purpose index for HD wallets.
    ChildNumber::Hardened { index: 44 },
    // Coin type index for Ethereum mainnet
    ChildNumber::Hardened { index: 60 },
    // Account index for user wallets.
    ChildNumber::Hardened { index: 0 },
    // Change index for receiving (external) addresses.
    ChildNumber::Normal { index: 0 },
    // Address index.
    ChildNumber::Normal { index: 0 },
];
