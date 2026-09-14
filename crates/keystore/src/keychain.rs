use std::error::Error as StdError;

use keyring::{Credential, Entry, Error};
use terrors::OneOf;

use super::{EncryptedSeed, EncryptedSeedPersister, PersisterErr};

#[derive(Debug, Clone, Copy)]
pub struct KeychainPersister;

impl KeychainPersister {
    fn entry() -> Result<Entry, OneOf<(PlatformFailure, NoStorageAccess)>> {
        Entry::new("alpen", "default")
            .map_err(keyring_oneof)
            .map_err(|e| {
                e.subset()
                    .unwrap_or_else(|e| panic!("errored subsetting keychain error: {e:?}"))
            })
    }
}

impl EncryptedSeedPersister for KeychainPersister {
    fn save(&self, seed: &EncryptedSeed) -> Result<(), PersisterErr> {
        let entry = Self::entry()?;
        entry
            .set_secret(seed.as_bytes())
            .map_err(keyring_oneof)
            .map_err(|e| {
                e.subset()
                    .unwrap_or_else(|e| panic!("errored subsetting keychain error: {e:?}"))
            })
    }

    fn load(&self) -> Result<Option<EncryptedSeed>, PersisterErr> {
        let entry = Self::entry()?;

        let secret = match entry.get_secret().map_err(keyring_oneof) {
            Ok(s) => s,
            Err(e) => {
                let no_entry = e.narrow::<NoEntry, _>();
                if no_entry.is_ok() {
                    return Ok(None);
                }

                let bad_encoding = no_entry.unwrap_err().narrow::<BadEncoding, _>();
                if bad_encoding.is_ok() {
                    let _ = entry.delete_credential();
                    return Ok(None);
                }

                return Err(bad_encoding
                    .unwrap_err()
                    .subset()
                    .unwrap_or_else(|e| panic!("errored subsetting keychain error: {e:?}")));
            }
        };

        if secret.len() == EncryptedSeed::LEN {
            Ok(Some(EncryptedSeed::from_bytes(secret.try_into().unwrap())))
        } else {
            let _ = entry.delete_credential();
            Ok(None)
        }
    }

    fn delete(&self) -> Result<(), PersisterErr> {
        let entry = Self::entry()?;
        match entry.delete_credential() {
            Ok(()) | Err(Error::NoEntry) => Ok(()),
            Err(Error::NoStorageAccess(error)) => Err(OneOf::new(NoStorageAccess::new(error))),
            Err(Error::PlatformFailure(error)) => Err(OneOf::new(PlatformFailure::new(error))),
            Err(error) => {
                // Preserve other backend errors without widening the public error type.
                Err(OneOf::new(PlatformFailure::new(error)))
            }
        }
    }
}

type BoxedErr = Box<dyn StdError + Send + Sync>;

// below is wrapper around [`keyring::Error`] so it can be used with OneOf to more precisely handle
// errors

/// This indicates runtime failure in the underlying platform storage system. The details of the
/// failure can be retrieved from the attached platform error.
#[derive(Debug)]
#[expect(unused, reason = "Error type for platform storage failures")]
pub struct PlatformFailure(BoxedErr);

impl PlatformFailure {
    pub fn new<E>(e: E) -> Self
    where
        E: Into<BoxedErr>,
    {
        Self(e.into())
    }
}

/// This indicates that the underlying secure storage holding saved items could not be accessed.
/// Typically this is because of access rules in the platform; for example, it might be that the
/// credential store is locked. The underlying platform error will typically give the reason.
#[derive(Debug)]
#[expect(unused, reason = "Error type for storage access failures")]
pub struct NoStorageAccess(BoxedErr);

impl NoStorageAccess {
    pub fn new<E>(e: E) -> Self
    where
        E: Into<BoxedErr>,
    {
        Self(e.into())
    }
}

/// This indicates that there is no underlying credential entry in the platform for this entry.
/// Either one was never set, or it was deleted.
#[derive(Debug)]
pub struct NoEntry;

/// This indicates that the retrieved password blob was not a UTF-8 string. The underlying bytes are
/// available for examination in the attached value.
#[derive(Debug)]
#[expect(unused, reason = "Error type for bad encoding in credential storage")]
pub struct BadEncoding(Vec<u8>);

/// This indicates that one of the entry's credential attributes exceeded a length limit in the
/// underlying platform. The attached values give the name of the attribute and the platform length
/// limit that was exceeded.
#[derive(Debug)]
#[expect(
    unused,
    reason = "Error type for credential attributes that are too long"
)]
pub struct TooLong {
    name: String,
    limit: u32,
}

/// This indicates that one of the entry's required credential attributes was invalid. The attached
/// value gives the name of the attribute and the reason it's invalid.
#[derive(Debug)]
#[expect(unused, reason = "Error type for invalid credential attributes")]
pub struct Invalid {
    name: String,
    reason: String,
}

/// This indicates that there is more than one credential found in the store that matches the entry.
/// Its value is a vector of the matching credentials.
#[derive(Debug)]
#[expect(unused, reason = "Error type for ambiguous credential matches")]
pub struct Ambiguous(Vec<Box<Credential>>);

type KeyRingErrors = (
    PlatformFailure,
    NoStorageAccess,
    NoEntry,
    BadEncoding,
    TooLong,
    Invalid,
    Ambiguous,
);

fn keyring_oneof(err: keyring::Error) -> OneOf<KeyRingErrors> {
    match err {
        Error::PlatformFailure(error) => OneOf::new(PlatformFailure::new(error)),
        Error::NoStorageAccess(error) => OneOf::new(NoStorageAccess::new(error)),
        Error::NoEntry => OneOf::new(NoEntry),
        Error::BadEncoding(vec) => OneOf::new(BadEncoding(vec)),
        Error::TooLong(name, limit) => OneOf::new(TooLong { name, limit }),
        Error::Invalid(name, reason) => OneOf::new(Invalid { name, reason }),
        Error::Ambiguous(vec) => OneOf::new(Ambiguous(vec)),
        _ => todo!(),
    }
}

#[cfg(test)]
mod tests {
    use std::any::Any;

    use keyring::{
        credential::CredentialBuilderApi, default, mock::MockCredential,
        set_default_credential_builder,
    };

    use super::*;

    struct FailingDeleteBuilder(fn() -> Error);

    impl CredentialBuilderApi for FailingDeleteBuilder {
        fn build(
            &self,
            _target: Option<&str>,
            _service: &str,
            _user: &str,
        ) -> Result<Box<Credential>, Error> {
            let credential = MockCredential::default();
            credential.set_error(self.0());
            Ok(Box::new(credential))
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn delete_returns_storage_errors_and_accepts_missing_entries() {
        // Only this unit test uses the global builder; Secret Service runs in a separate binary.
        set_default_credential_builder(Box::new(FailingDeleteBuilder(|| {
            Error::NoStorageAccess("keyring locked".into())
        })));
        let error = KeychainPersister
            .delete()
            .unwrap_err()
            .narrow::<NoStorageAccess, _>()
            .unwrap();
        assert!(format!("{error:?}").contains("keyring locked"));

        set_default_credential_builder(Box::new(FailingDeleteBuilder(|| {
            Error::PlatformFailure("service disconnected".into())
        })));
        let error = KeychainPersister
            .delete()
            .unwrap_err()
            .narrow::<PlatformFailure, _>()
            .unwrap();
        assert!(format!("{error:?}").contains("service disconnected"));

        set_default_credential_builder(Box::new(FailingDeleteBuilder(|| {
            Error::Ambiguous(Vec::new())
        })));
        assert!(
            KeychainPersister
                .delete()
                .unwrap_err()
                .narrow::<PlatformFailure, _>()
                .is_ok()
        );

        set_default_credential_builder(Box::new(FailingDeleteBuilder(|| Error::NoEntry)));
        KeychainPersister.delete().unwrap();
        set_default_credential_builder(default::default_credential_builder());
    }
}
