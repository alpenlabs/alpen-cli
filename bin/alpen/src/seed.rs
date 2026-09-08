pub use alpen_wallet_keys::{Seed, password};
use alpen_wallet_keys::{
    constants::SEED_LEN,
    password::{IncorrectPassword, Password},
};
pub use alpen_wallet_keystore::EncryptedSeedPersister;
#[cfg(target_os = "linux")]
pub use alpen_wallet_keystore::FilePersister;
#[cfg(not(target_os = "linux"))]
pub use alpen_wallet_keystore::{KeychainPersister, NoStorageAccess, PlatformFailure};
use bip39::Mnemonic;
use dialoguer::{Confirm, Input, Password as InputPassword};
use rand_core::OsRng;
#[cfg(target_os = "linux")]
use std::io;
use std::str::FromStr;
use terrors::OneOf;
use zeroize::Zeroizing;

/// Constructs a password from user interaction. (The complexity of the password is not
/// checked.)
pub fn read_password(new: bool) -> Result<Password, dialoguer::Error> {
    let mut input = InputPassword::new().allow_empty_password(true);
    if new {
        input = input
            .with_prompt("Create a new password (leave empty for no password, dangerous!)")
            .with_confirmation(
                "Confirm password (leave empty for no password, dangerous!)",
                "Passwords didn't match",
            );
    } else {
        input = input.with_prompt("Enter your password");
    }

    let password = input.interact()?;

    Ok(Password::new(password))
}

pub fn load_or_create(
    persister: &impl EncryptedSeedPersister,
) -> Result<Seed, OneOf<LoadOrCreateErr>> {
    println!("Loading encrypted seed...");
    let maybe_encrypted_seed = persister.load().map_err(OneOf::broaden)?;
    if let Some(encrypted_seed) = maybe_encrypted_seed {
        println!("Opening wallet...");
        let mut password = read_password(false).map_err(OneOf::new)?;
        match encrypted_seed.decrypt(&mut password) {
            Ok(seed) => {
                println!("Wallet unlocked");
                Ok(seed)
            }
            Err(e) => {
                let narrowed = e.narrow::<aes_gcm_siv::Error, _>();
                if let Ok(_aes_error) = narrowed {
                    return Err(OneOf::new(IncorrectPassword));
                }

                Err(narrowed.unwrap_err().broaden())
            }
        }
    } else {
        let restore = Confirm::new()
            .with_prompt("Do you want to restore a previously created wallet?")
            .interact()
            .map_err(OneOf::new)?;

        let seed = if restore {
            loop {
                let mnemonic: String = Input::new()
                    .with_prompt("Enter your mnemonic")
                    .interact_text()
                    .map_err(OneOf::new)?;

                let mnemonic = match Mnemonic::from_str(&mnemonic) {
                    Ok(m) => m,
                    Err(e) => {
                        println!("please try again: {e}");
                        continue;
                    }
                };
                let entropy = mnemonic.to_entropy();
                if entropy.len() != SEED_LEN {
                    println!("incorrect entropy length");
                    continue;
                }
                let mut buf = Zeroizing::new([0u8; SEED_LEN]);
                buf.copy_from_slice(&entropy);
                break Seed::from_entropy(*buf);
            }
        } else {
            println!("Creating new wallet");
            Seed::generate(&mut OsRng)
        };

        let mut password = read_password(true).map_err(OneOf::new)?;
        let password_validation: Result<(), String> = password.validate();
        if let Err(feedback) = password_validation {
            println!("Password is weak. {feedback}");
        };
        let encrypted_seed = match seed.encrypt(&mut password, &mut OsRng) {
            Ok(es) => es,
            Err(e) => {
                let narrowed = e.narrow::<aes_gcm_siv::Error, _>();
                if let Ok(aes_error) = narrowed {
                    panic!("Failed to encrypt seed: {aes_error:?}");
                }

                return Err(narrowed.unwrap_err().broaden());
            }
        };
        persister.save(&encrypted_seed).map_err(OneOf::broaden)?;
        Ok(seed)
    }
}

#[cfg(target_os = "linux")]
type LoadOrCreateErr = (
    io::Error,
    dialoguer::Error,
    argon2::Error,
    IncorrectPassword,
);

#[cfg(not(target_os = "linux"))]
type LoadOrCreateErr = (
    PlatformFailure,
    NoStorageAccess,
    dialoguer::Error,
    argon2::Error,
    IncorrectPassword,
);
