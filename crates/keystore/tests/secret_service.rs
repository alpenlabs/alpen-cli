#![cfg(target_os = "linux")]
#![expect(
    unused_crate_dependencies,
    reason = "integration test exercises the public keystore API"
)]

use std::env;

use alpen_wallet_keys::{Seed, password::Password};
use alpen_wallet_keystore::{EncryptedSeedPersister, KeychainPersister};
use bip39::Language;
use rand_core::OsRng;

// Match the runtime used by the CLI, including its synchronous keyring calls.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires the isolated Secret Service setup in .github/workflows/unit.yml"]
async fn encrypted_seed_round_trip() {
    assert_eq!(
        env::var("ALPEN_SECRET_SERVICE_TEST").as_deref(),
        Ok("1"),
        "run only with the isolated CI keyring"
    );
    assert!(KeychainPersister.load().unwrap().is_none());

    let seed = Seed::from_entropy([0; 16]);
    let mut password = Password::new("secret service integration test".to_owned());
    let encrypted = seed.encrypt(&mut password, &mut OsRng).unwrap();
    KeychainPersister.save(&encrypted).unwrap();

    let stored = KeychainPersister.load().unwrap().unwrap();
    assert_eq!(stored.as_bytes(), encrypted.as_bytes());
    let decrypted = stored.decrypt(&mut password).unwrap();
    assert_eq!(
        decrypted.mnemonic(Language::English).to_string(),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    );

    let replacement = Seed::from_entropy([1; 16])
        .encrypt(&mut password, &mut OsRng)
        .unwrap();
    KeychainPersister.save(&replacement).unwrap();
    assert_eq!(
        KeychainPersister.load().unwrap().unwrap().as_bytes(),
        replacement.as_bytes()
    );

    KeychainPersister.delete().unwrap();
    assert!(KeychainPersister.load().unwrap().is_none());
    KeychainPersister.delete().unwrap();
}
