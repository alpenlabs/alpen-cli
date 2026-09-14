use std::{fs, io, path::Path};

use argh::FromArgs;
use colored::Colorize;
use dialoguer::Confirm;
use strata_cli_common::errors::{DisplayableError, DisplayedError};

use crate::{seed::EncryptedSeedPersister, settings::Settings};

/// DANGER: resets the CLI completely, destroying all keys and databases.
/// Keeps config.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "reset")]
pub struct ResetArgs {
    /// dangerous: permit to reset without further confirmation
    #[argh(switch, short = 'y')]
    assume_yes: bool,
}

pub async fn reset(
    args: ResetArgs,
    persister: impl EncryptedSeedPersister,
    settings: Settings,
) -> Result<(), DisplayedError> {
    let confirm = if args.assume_yes {
        true
    } else {
        println!("{}", "This will DESTROY ALL DATA.".to_string().red().bold());
        Confirm::new()
            .with_prompt("Do you REALLY want to continue?")
            .interact()
            .internal_error("Failed to read user confirmation")?
    };

    if confirm {
        persister
            .delete()
            .internal_error("Failed to wipe out seed")?;
        println!("Wiped seed");
        wipe_data_root(&settings.data_root).internal_error("Failed to delete data directory")?;
        println!("Wiped data directory");
    }

    Ok(())
}

fn wipe_data_root(data_root: &Path) -> io::Result<()> {
    fs::remove_dir_all(data_root)
}

#[cfg(test)]
mod tests {
    use std::fs::{create_dir_all, write};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn reset_wipes_every_profile_directory() {
        let parent = tempdir().unwrap();
        let data_root = parent.path().join("data");
        for profile in ["mainnet", "testnet"] {
            let profile_dir = data_root.join(profile);
            create_dir_all(&profile_dir).unwrap();
            write(profile_dir.join("wallet.sqlite"), profile).unwrap();
        }

        wipe_data_root(&data_root).unwrap();

        assert!(!data_root.exists());
    }
}
