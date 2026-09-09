use std::{error::Error, fs, io::Write, path::Path};

use argh::FromArgs;
use tempfile::NamedTempFile;
use toml_edit::{DocumentMut, value};

use crate::settings::{
    CONFIG_FILE, DeploymentProfile, active_deployment_profile, validate_deployment_profile,
};

/// Selects the active Alpen deployment profile.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "network")]
pub struct NetworkArgs {
    #[argh(subcommand)]
    command: NetworkCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum NetworkCommand {
    Show(NetworkShowArgs),
    Use(NetworkUseArgs),
}

/// Prints the active deployment profile.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "show")]
struct NetworkShowArgs {}

/// Selects the active deployment profile.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "use")]
struct NetworkUseArgs {
    /// deployment profile: mainnet or testnet
    #[argh(positional)]
    profile: DeploymentProfile,
}

pub async fn network(args: NetworkArgs) -> Result<(), Box<dyn Error>> {
    match args.command {
        NetworkCommand::Show(_) => {
            println!("{}", active_deployment_profile(CONFIG_FILE.as_path())?);
        }
        NetworkCommand::Use(args) => {
            set_active_profile(CONFIG_FILE.as_path(), args.profile)?;
            println!("Using {}", args.profile);
        }
    }
    Ok(())
}

fn set_active_profile(
    config_file: &Path,
    profile: DeploymentProfile,
) -> Result<(), Box<dyn Error>> {
    validate_deployment_profile(config_file, profile)?;
    let contents = fs::read_to_string(config_file)?;
    let updated = replace_active_profile(&contents, profile)?;
    let parent = config_parent(config_file);
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(updated.as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(config_file)
        .map_err(|error| error.error)?;
    Ok(())
}

fn config_parent(config_file: &Path) -> &Path {
    config_file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn replace_active_profile(
    contents: &str,
    profile: DeploymentProfile,
) -> Result<String, Box<dyn Error>> {
    let mut document = contents.parse::<DocumentMut>()?;
    if !document.as_table().contains_key("active_profile") {
        return Err(
            "config.toml is a legacy flat config; migrate it to profile format before using `alpen network use`"
                .into(),
        );
    }
    document["active_profile"] = value(profile.to_string());
    Ok(document.to_string())
}

#[cfg(test)]
mod tests {
    use std::fs::{read_to_string, write};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn replaces_only_the_active_profile() {
        let config = "active_profile = \"testnet\"\n\n[profiles]\ntestnet = \"testnet.toml\"\nmainnet = \"mainnet.toml\"\n";
        let updated = replace_active_profile(config, DeploymentProfile::Mainnet).unwrap();

        assert_eq!(
            updated,
            "active_profile = \"mainnet\"\n\n[profiles]\ntestnet = \"testnet.toml\"\nmainnet = \"mainnet.toml\"\n"
        );
    }

    #[test]
    fn rejects_legacy_flat_config() {
        let error = replace_active_profile("network = \"signet\"\n", DeploymentProfile::Mainnet)
            .unwrap_err();

        assert!(error.to_string().contains("legacy flat config"));
    }

    #[test]
    fn changes_only_the_root_active_profile() {
        let config =
            "active_profile = \"testnet\"\n\n[unrelated]\nactive_profile = \"unchanged\"\n";

        let updated = replace_active_profile(config, DeploymentProfile::Mainnet).unwrap();

        assert!(updated.starts_with("active_profile = \"mainnet\""));
        assert!(updated.contains("[unrelated]\nactive_profile = \"unchanged\""));
    }

    #[test]
    fn basename_config_uses_current_directory_as_parent() {
        assert_eq!(config_parent(Path::new("config.toml")), Path::new("."));
    }

    #[test]
    fn persists_selection_without_rewriting_other_fields() {
        let root = tempdir().unwrap();
        let config_file = root.path().join("config.toml");
        let config = "# selected deployment\nactive_profile = \"testnet\"\n\n[profiles]\ntestnet = \"testnet.toml\"\nmainnet = \"mainnet.toml\"\n";
        write(&config_file, config).unwrap();
        write(
            root.path().join("mainnet.toml"),
            r#"
                esplora = "https://esplora.example.com"
                alpen_endpoint = "https://rpc.mainnet.example.com"
                bridge_pubkey = "1d3e9c0417ba7d3551df5a1cc1dbe227aa4ce89161762454d92bfc2b1d5886f7"
                network = "bitcoin"
                magic_bytes = "ALPN"
                bridge_denomination_sats = 100000000
                recovery_delay = 36
                max_withdrawal_descriptor_len = 81
                seed = "000102030405060708090a0b0c0d0e0f"
            "#,
        )
        .unwrap();

        set_active_profile(&config_file, DeploymentProfile::Mainnet).unwrap();

        assert_eq!(
            read_to_string(config_file).unwrap(),
            "# selected deployment\nactive_profile = \"mainnet\"\n\n[profiles]\ntestnet = \"testnet.toml\"\nmainnet = \"mainnet.toml\"\n"
        );
    }
}
