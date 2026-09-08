//! Encrypted seed persistence backends.

use alpen_wallet_keys::EncryptedSeed;
#[cfg(target_os = "linux")]
use std::io;
use terrors::OneOf;

#[cfg(not(target_os = "linux"))]
pub type PersisterErr = OneOf<(PlatformFailure, NoStorageAccess)>;
#[cfg(target_os = "linux")]
pub type PersisterErr = OneOf<(io::Error,)>;

pub trait EncryptedSeedPersister {
    fn save(&self, seed: &EncryptedSeed) -> Result<(), PersisterErr>;
    fn load(&self) -> Result<Option<EncryptedSeed>, PersisterErr>;
    fn delete(&self) -> Result<(), PersisterErr>;
}

#[cfg(target_os = "linux")]
pub use file::*;

#[cfg(target_os = "linux")]
mod file;

#[cfg(not(target_os = "linux"))]
mod keychain;

#[cfg(not(target_os = "linux"))]
pub use keychain::*;

#[cfg(test)]
mod tests {
    use super::*;
    use alpen_wallet_keys::{Seed, password::Password};
    use bip39::Language;
    use rand_core::OsRng;
    use std::cell::RefCell;

    #[derive(Default)]
    struct MemoryPersister(RefCell<Option<[u8; EncryptedSeed::LEN]>>);

    impl EncryptedSeedPersister for MemoryPersister {
        fn save(&self, seed: &EncryptedSeed) -> Result<(), PersisterErr> {
            self.0.replace(Some(*seed.as_bytes()));
            Ok(())
        }
        fn load(&self) -> Result<Option<EncryptedSeed>, PersisterErr> {
            Ok(self.0.borrow().map(EncryptedSeed::from_bytes))
        }
        fn delete(&self) -> Result<(), PersisterErr> {
            self.0.replace(None);
            Ok(())
        }
    }

    #[test]
    fn serialized_seed_survives_the_keystore_boundary() {
        let seed = Seed::from_entropy([0; 16]);
        let mut password = Password::new("wallet compatibility test".to_owned());
        let encrypted = seed.encrypt(&mut password, &mut OsRng).unwrap();
        let store = MemoryPersister::default();
        store.save(&encrypted).unwrap();
        let restored = store.load().unwrap().unwrap();
        assert_eq!(restored.as_bytes(), encrypted.as_bytes());
        let decrypted = restored.decrypt(&mut password).unwrap();
        assert_eq!(
            decrypted.mnemonic(Language::English).to_string(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        store.delete().unwrap();
        assert!(store.load().unwrap().is_none());
    }
}
