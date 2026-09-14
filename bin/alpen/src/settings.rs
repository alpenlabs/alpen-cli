use crate::progress::terminal_progress;
use alpen_bitcoin_wallet::recover::RecoveryConfig;
use std::{
    env::var,
    error::Error,
    fmt,
    fs::{File, create_dir_all, rename},
    io,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, LazyLock},
};

use alloy::primitives::Address as AlpenAddress;
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client};
use bdk_wallet::bitcoin::{Amount, Network, XOnlyPublicKey};
use config::{Config, ConfigError};
use directories::ProjectDirs;
use serde::{Deserialize, Deserializer, Serialize, de};
#[cfg(feature = "test-mode")]
use shrex::Hex;
use strata_bridge_params::BridgeParams;
use strata_l1_txfmt::MagicBytes;
use terrors::OneOf;

use crate::{
    bitcoin::{
        BitcoinWallet, EsploraClient,
        backend::{BitcoinBackend, BitcoinCoreClient},
    },
    constants::*,
};
#[cfg(feature = "test-mode")]
use crate::{constants::SEED_LEN, seed::Seed};

/// Environment variable overriding the project directories root.
const PROJ_DIRS_ENV: &str = "PROJ_DIRS";
/// Environment variable overriding the CLI config file path.
const CONFIG_FILE_ENV: &str = "CLI_CONFIG";
/// Default file name for the CLI config within the config directory.
const DEFAULT_CONFIG_FILENAME: &str = "config.toml";

/// A complete Alpen deployment, including its Bitcoin anchor network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentProfile {
    Mainnet,
    Testnet,
}

/// Currently selected profile, or the Bitcoin network from a legacy flat config.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActiveDeployment {
    Profile(DeploymentProfile),
    Legacy(Network),
}

impl fmt::Display for ActiveDeployment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile(profile) => profile.fmt(f),
            Self::Legacy(network) => write!(f, "legacy ({network})"),
        }
    }
}

impl DeploymentProfile {
    pub fn expected_bitcoin_network(self) -> Network {
        match self {
            Self::Mainnet => Network::Bitcoin,
            Self::Testnet => Network::Signet,
        }
    }

    fn data_dir_name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }
}

impl fmt::Display for DeploymentProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.data_dir_name())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidDeploymentProfile;

impl fmt::Display for InvalidDeploymentProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected 'mainnet' or 'testnet'")
    }
}

impl Error for InvalidDeploymentProfile {}

impl FromStr for DeploymentProfile {
    type Err = InvalidDeploymentProfile;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            _ => Err(InvalidDeploymentProfile),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ProfileFiles {
    mainnet: PathBuf,
    testnet: PathBuf,
}

impl ProfileFiles {
    fn get(&self, profile: DeploymentProfile) -> &Path {
        match profile {
            DeploymentProfile::Mainnet => &self.mainnet,
            DeploymentProfile::Testnet => &self.testnet,
        }
    }
}

/// Optional dispatcher schema. A missing `active_profile` identifies a legacy flat config.
#[derive(Clone, Debug, Deserialize)]
struct ProfileSelector {
    active_profile: Option<DeploymentProfile>,
    profiles: Option<ProfileFiles>,
    /// Explicit destination for one-time migration of legacy flat-layout state.
    migrate_legacy_state: Option<DeploymentProfile>,
}

/// Settings deserialized from the config file.
#[derive(Debug, Serialize, Deserialize)]
pub struct SettingsFromFile {
    /// Esplora server endpoint.
    pub esplora: Option<String>,
    /// Bitcoind RPC username.
    pub bitcoind_rpc_user: Option<String>,
    /// Bitcoind RPC password.
    pub bitcoind_rpc_pw: Option<String>,
    /// Path to the Bitcoind RPC cookie file.
    pub bitcoind_rpc_cookie: Option<PathBuf>,
    /// Bitcoind RPC endpoint.
    pub bitcoind_rpc_endpoint: Option<String>,
    /// Alpen network RPC endpoint.
    pub alpen_endpoint: String,
    /// Mempool explorer endpoint.
    pub mempool_endpoint: Option<String>,
    /// Blockscout explorer endpoint.
    pub blockscout_endpoint: Option<String>,
    /// The aggregated Musig2 public key for the bridge.
    #[serde(deserialize_with = "deserialize_bridge_pubkey")]
    pub bridge_pubkey: XOnlyPublicKey,
    /// The address of the bridge precompile in alpen evm in hex.
    pub bridge_alpen_address: Option<String>,
    /// Fee to cover mining costs for the bridge to process deposits, in satoshis.
    pub bridge_fee_sats: Option<u64>,
    /// The number of confirmations to consider a Bitcoin transaction final.
    pub finality_depth: Option<u32>,
    /// L1 network the wallet operates on (for example, Bitcoin mainnet or signet).
    ///
    /// Must match the network the ASM is anchored to.
    pub network: Network,
    /// SPS-50 magic bytes tagging protocol transactions on L1 (e.g. "ALPN").
    ///
    /// Must match the magic bytes in the ASM params.
    pub magic_bytes: MagicBytes,
    /// Bridge denomination in satoshis, used for both deposits and
    /// withdrawals.
    ///
    /// Must match the Bridge subprotocol denomination in the ASM params and the
    /// bridge denomination in the OL params, which are the same network value.
    pub bridge_denomination_sats: u64,
    /// Number of Bitcoin blocks after which the depositor can reclaim an
    /// unprocessed deposit request.
    ///
    /// Must match the Bridge subprotocol recovery delay in the ASM params.
    pub recovery_delay: u16,
    /// Maximum withdrawal amount in satoshis. Defaults to leave withdrawals uncapped.
    ///
    /// Withdrawals are batched in multiples of the denomination up to this cap, so
    /// it must match the OL params to avoid submitting amounts the OL STF rejects.
    pub max_withdrawal_amount_sats: Option<u64>,
    /// Maximum withdrawal BOSD descriptor length in bytes, including the type tag.
    ///
    /// Must match the OL params.
    pub max_withdrawal_descriptor_len: u32,
    /// Seed that can be passed directly for functional test.
    #[cfg(feature = "test-mode")]
    pub seed: Hex<[u8; SEED_LEN]>,
}

/// Settings struct filled with either config values or
/// opinionated defaults
#[derive(Debug)]
pub struct Settings {
    pub esplora: Option<String>,
    pub alpen_endpoint: String,
    /// Root containing shared and per-profile wallet state.
    pub data_root: PathBuf,
    pub data_dir: PathBuf,
    pub bridge_musig2_pubkey: XOnlyPublicKey,
    pub descriptor_db: PathBuf,
    pub mempool_space_endpoint: Option<String>,
    pub blockscout_endpoint: Option<String>,
    pub bridge_alpen_address: AlpenAddress,
    pub linux_seed_file: PathBuf,
    pub config_file: PathBuf,
    /// Selected deployment profile.
    pub profile: Option<DeploymentProfile>,
    pub bitcoin_backend: Arc<dyn BitcoinBackend>,
    pub bridge_fee: Amount,
    pub finality_depth: u32,
    pub bridge_params: BridgeParams,
    /// L1 network the wallet operates on.
    pub network: Network,
    /// SPS-50 magic bytes tagging protocol transactions on L1.
    pub magic_bytes: MagicBytes,
    /// Deposit-request reclaim delay in Bitcoin blocks.
    pub recovery_delay: u16,
    #[cfg(feature = "test-mode")]
    pub seed: Seed,
}

pub static PROJ_DIRS: LazyLock<ProjectDirs> = LazyLock::new(|| match var(PROJ_DIRS_ENV).ok() {
    Some(path) => ProjectDirs::from_path(path.into()).expect("valid project path"),
    None => ProjectDirs::from("io", "alpenlabs", "alpen").expect("project dir should be available"),
});

pub static CONFIG_FILE: LazyLock<PathBuf> = LazyLock::new(|| match var(CONFIG_FILE_ENV).ok() {
    Some(path) => PathBuf::from_str(&path).expect("valid config path"),
    None => PROJ_DIRS
        .config_dir()
        .to_owned()
        .join(DEFAULT_CONFIG_FILENAME),
});

impl Settings {
    pub fn load() -> Result<Self, OneOf<(io::Error, config::ConfigError)>> {
        Self::load_from(&PROJ_DIRS, CONFIG_FILE.as_path())
    }

    #[cfg(test)]
    pub(crate) fn load_from_paths(
        project_root: PathBuf,
        config_file: &Path,
    ) -> Result<Self, OneOf<(io::Error, config::ConfigError)>> {
        let proj_dirs = ProjectDirs::from_path(project_root).expect("valid project path");
        Self::load_from(&proj_dirs, config_file)
    }

    fn load_from(
        proj_dirs: &ProjectDirs,
        config_file: &Path,
    ) -> Result<Self, OneOf<(io::Error, config::ConfigError)>> {
        let linux_seed_file = proj_dirs.data_dir().to_owned().join("seed");

        create_dir_all(proj_dirs.config_dir()).map_err(OneOf::new)?;
        create_dir_all(proj_dirs.data_dir()).map_err(OneOf::new)?;

        // create config file if not exists
        let _ = File::create_new(config_file);
        let root_config = Config::builder()
            .add_source(config::File::from(config_file))
            .build()
            .map_err(OneOf::new)?;

        let selector = root_config
            .clone()
            .try_deserialize::<ProfileSelector>()
            .map_err(OneOf::new)?;
        let profile_layout = selector.active_profile.is_some();
        let (from_file, profile, profile_data_dir) = if let Some(profile) = selector.active_profile
        {
            let profiles = selector.profiles.ok_or_else(|| {
                OneOf::new(ConfigError::Message(
                    "active_profile requires a [profiles] table".to_owned(),
                ))
            })?;
            let profile_file = resolve_profile_path(config_file, profiles.get(profile));
            let from_file = Config::builder()
                .add_source(config::File::from(profile_file.as_path()))
                .build()
                .map_err(OneOf::new)?
                .try_deserialize::<SettingsFromFile>()
                .map_err(OneOf::new)?;
            validate_profile_network(profile, from_file.network).map_err(OneOf::new)?;
            (
                from_file,
                Some(profile),
                proj_dirs.data_dir().join(profile.data_dir_name()),
            )
        } else {
            let from_file = root_config
                .try_deserialize::<SettingsFromFile>()
                .map_err(OneOf::new)?;
            (from_file, None, proj_dirs.data_dir().to_owned())
        };
        create_dir_all(&profile_data_dir).map_err(OneOf::new)?;

        let sync_backend: Arc<dyn BitcoinBackend> = match (
            from_file.esplora.clone(),
            from_file.bitcoind_rpc_user,
            from_file.bitcoind_rpc_pw,
            from_file.bitcoind_rpc_cookie,
            from_file.bitcoind_rpc_endpoint,
        ) {
            (Some(url), None, None, None, None) => Arc::new(
                EsploraClient::new(&url)
                    .expect("valid esplora url")
                    .with_progress(terminal_progress()),
            ),
            (None, Some(user), Some(pw), None, Some(url)) => Arc::new(
                BitcoinCoreClient::new(
                    Client::new(&url, Auth::UserPass(user, pw)).expect("valid bitcoin core client"),
                )
                .with_progress(terminal_progress()),
            ),
            (None, None, None, Some(cookie_file), Some(url)) => Arc::new(
                BitcoinCoreClient::new(
                    Client::new(&url, Auth::CookieFile(cookie_file))
                        .expect("valid bitcoin core client"),
                )
                .with_progress(terminal_progress()),
            ),
            _ => panic!("invalid Bitcoin config - configure Esplora or Bitcoin Core"),
        };

        let bridge_params = BridgeParams::new_with_descriptor_limit(
            from_file.bridge_denomination_sats,
            from_file.max_withdrawal_amount_sats,
            from_file.max_withdrawal_descriptor_len,
        )
        .map_err(|e| {
            OneOf::new(ConfigError::Message(format!(
                "invalid withdrawal params in config: {e}"
            )))
        })?;
        let bridge_alpen_address = AlpenAddress::from_str(
            from_file
                .bridge_alpen_address
                .as_deref()
                .unwrap_or(DEFAULT_BRIDGE_ALPEN_ADDRESS),
        )
        .map_err(|error| {
            OneOf::new(ConfigError::Message(format!(
                "invalid bridge Alpen address in config: {error}"
            )))
        })?;

        if let Some(profile) = profile {
            let legacy_state_exists = legacy_profile_state_exists(
                proj_dirs.data_dir(),
                &profile_data_dir,
                profile,
                from_file.network,
            );
            if selector.migrate_legacy_state == Some(profile) {
                migrate_legacy_profile_state(
                    proj_dirs.data_dir(),
                    &profile_data_dir,
                    profile,
                    from_file.network,
                )
                .map_err(OneOf::new)?;
            } else if legacy_state_exists {
                return Err(OneOf::new(ConfigError::Message(format!(
                    "legacy wallet state exists; set migrate_legacy_state = \"{profile}\" in config.toml to explicitly migrate it"
                ))));
            }
        }

        let descriptor_file = if profile_layout {
            profile_data_dir.join("descriptors")
        } else {
            profile_data_dir.join(match from_file.network {
                Network::Bitcoin => "descriptors-bitcoin",
                _ => "descriptors",
            })
        };

        Ok(Settings {
            esplora: from_file.esplora,
            alpen_endpoint: from_file.alpen_endpoint,
            data_root: proj_dirs.data_dir().to_owned(),
            data_dir: profile_data_dir,
            bridge_musig2_pubkey: from_file.bridge_pubkey,
            descriptor_db: descriptor_file,
            mempool_space_endpoint: from_file.mempool_endpoint,
            blockscout_endpoint: from_file.blockscout_endpoint,
            bridge_alpen_address,
            linux_seed_file,
            config_file: config_file.to_owned(),
            profile,
            bitcoin_backend: sync_backend,
            bridge_fee: from_file
                .bridge_fee_sats
                .map(Amount::from_sat)
                .unwrap_or(DEFAULT_BRIDGE_FEE),
            finality_depth: from_file.finality_depth.unwrap_or(DEFAULT_FINALITY_DEPTH),
            bridge_params,
            network: from_file.network,
            magic_bytes: from_file.magic_bytes,
            recovery_delay: from_file.recovery_delay,
            #[cfg(feature = "test-mode")]
            seed: Seed::from_entropy(*from_file.seed),
        })
    }
}

/// Reads the active deployment without constructing network clients or opening wallet state.
pub fn active_deployment_profile(config_file: &Path) -> Result<ActiveDeployment, ConfigError> {
    let config = Config::builder()
        .add_source(config::File::from(config_file))
        .build()?;
    let selector = config.clone().try_deserialize::<ProfileSelector>()?;
    if let Some(profile) = selector.active_profile {
        if selector.profiles.is_none() {
            return Err(ConfigError::Message(
                "active_profile requires a [profiles] table".to_owned(),
            ));
        }
        return Ok(ActiveDeployment::Profile(profile));
    }

    #[derive(Deserialize)]
    struct LegacyNetwork {
        network: Network,
    }

    Ok(ActiveDeployment::Legacy(
        config.try_deserialize::<LegacyNetwork>()?.network,
    ))
}

/// Validates that a dispatcher references a readable profile with the expected Bitcoin network.
pub fn validate_deployment_profile(
    config_file: &Path,
    profile: DeploymentProfile,
) -> Result<(), ConfigError> {
    let config = Config::builder()
        .add_source(config::File::from(config_file))
        .build()?;
    let selector = config.try_deserialize::<ProfileSelector>()?;
    let profiles = selector.profiles.ok_or_else(|| {
        ConfigError::Message("config.toml must contain a [profiles] table".to_owned())
    })?;
    let profile_file = resolve_profile_path(config_file, profiles.get(profile));

    let profile_settings = Config::builder()
        .add_source(config::File::from(profile_file))
        .build()?
        .try_deserialize::<SettingsFromFile>()?;
    validate_profile_network(profile, profile_settings.network)?;
    BridgeParams::new_with_descriptor_limit(
        profile_settings.bridge_denomination_sats,
        profile_settings.max_withdrawal_amount_sats,
        profile_settings.max_withdrawal_descriptor_len,
    )
    .map_err(|error| {
        ConfigError::Message(format!("invalid withdrawal params in config: {error}"))
    })?;
    AlpenAddress::from_str(
        profile_settings
            .bridge_alpen_address
            .as_deref()
            .unwrap_or(DEFAULT_BRIDGE_ALPEN_ADDRESS),
    )
    .map_err(|error| {
        ConfigError::Message(format!("invalid bridge Alpen address in config: {error}"))
    })?;
    Ok(())
}

fn resolve_profile_path(config_file: &Path, profile_file: &Path) -> PathBuf {
    if profile_file.is_absolute() {
        profile_file.to_owned()
    } else {
        config_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(profile_file)
    }
}

fn validate_profile_network(
    profile: DeploymentProfile,
    network: Network,
) -> Result<(), ConfigError> {
    let expected = profile.expected_bitcoin_network();
    if network != expected {
        return Err(ConfigError::Message(format!(
            "profile '{profile}' requires Bitcoin network '{expected}', but its config uses '{network}'"
        )));
    }
    Ok(())
}

fn migrate_legacy_profile_state(
    root_data_dir: &Path,
    profile_data_dir: &Path,
    profile: DeploymentProfile,
    network: Network,
) -> io::Result<()> {
    let paths = legacy_profile_state_paths(root_data_dir, profile_data_dir, profile, network);
    for (source, destination) in &paths {
        if source.exists() && destination.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "cannot migrate legacy state: both '{}' and '{}' exist",
                    source.display(),
                    destination.display()
                ),
            ));
        }
    }
    for (source, destination) in paths {
        migrate_path_if_needed(&source, &destination)?;
    }
    Ok(())
}

fn legacy_profile_state_exists(
    root_data_dir: &Path,
    profile_data_dir: &Path,
    profile: DeploymentProfile,
    network: Network,
) -> bool {
    legacy_profile_state_paths(root_data_dir, profile_data_dir, profile, network)
        .iter()
        .any(|(source, _)| source.exists())
}

fn legacy_profile_state_paths(
    root_data_dir: &Path,
    profile_data_dir: &Path,
    profile: DeploymentProfile,
    network: Network,
) -> [(PathBuf, PathBuf); 2] {
    let legacy_descriptors = match profile {
        DeploymentProfile::Mainnet => "descriptors-bitcoin",
        DeploymentProfile::Testnet => "descriptors",
    };
    [
        (
            BitcoinWallet::db_path("default", root_data_dir, network),
            BitcoinWallet::db_path("default", profile_data_dir, network),
        ),
        (
            root_data_dir.join(legacy_descriptors),
            profile_data_dir.join("descriptors"),
        ),
    ]
}

fn migrate_path_if_needed(source: &Path, destination: &Path) -> io::Result<()> {
    if source.exists() {
        rename(source, destination)?;
    }
    Ok(())
}

const X_ONLY_PUBLIC_KEY_HEX_LENGTH: usize = 64;

fn deserialize_bridge_pubkey<'de, D>(deserializer: D) -> Result<XOnlyPublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let actual_length = value.chars().count();
    if actual_length != X_ONLY_PUBLIC_KEY_HEX_LENGTH {
        return Err(de::Error::custom(format!(
            "expected exactly {X_ONLY_PUBLIC_KEY_HEX_LENGTH} hexadecimal characters (32 bytes), \
             got {actual_length}"
        )));
    }

    XOnlyPublicKey::from_str(&value)
        .map_err(|error| de::Error::custom(format!("invalid x-only public key: {error}")))
}

impl Settings {
    pub fn recovery(&self) -> RecoveryConfig {
        RecoveryConfig {
            network: self.network,
            bitcoin_backend: self.bitcoin_backend.clone(),
            descriptor_db: self.descriptor_db.clone(),
            bridge_musig2_pubkey: self.bridge_musig2_pubkey,
            recovery_delay: self.recovery_delay,
            finality_depth: self.finality_depth,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{create_dir, write};

    use serde::de::value::{Error as ValueError, StringDeserializer};
    use tempfile::tempdir;
    use toml;

    use super::*;

    fn profile_config(network: &str, alpen_endpoint: &str) -> String {
        format!(
            r#"
                esplora = "https://esplora.example.com"
                alpen_endpoint = "{alpen_endpoint}"
                bridge_pubkey = "1d3e9c0417ba7d3551df5a1cc1dbe227aa4ce89161762454d92bfc2b1d5886f7"
                network = "{network}"
                magic_bytes = "ALPN"
                bridge_denomination_sats = 100000000
                recovery_delay = 36
                max_withdrawal_descriptor_len = 81
                seed = "000102030405060708090a0b0c0d0e0f"
            "#
        )
    }

    #[test]
    fn loads_selected_profile_and_isolates_its_state() {
        let root = tempdir().unwrap();
        let config_file = root.path().join("config.toml");
        write(
            &config_file,
            r#"
                active_profile = "testnet"
                migrate_legacy_state = "testnet"

                [profiles]
                mainnet = "mainnet.toml"
                testnet = "testnet.toml"
            "#,
        )
        .unwrap();
        write(
            root.path().join("mainnet.toml"),
            profile_config("bitcoin", "https://rpc.mainnet.example.com"),
        )
        .unwrap();
        write(
            root.path().join("testnet.toml"),
            profile_config("signet", "https://rpc.testnet.example.com"),
        )
        .unwrap();
        write(root.path().join("default.sqlite"), b"legacy wallet").unwrap();
        create_dir(root.path().join("descriptors")).unwrap();
        write(
            root.path().join("descriptors").join("legacy"),
            b"legacy descriptors",
        )
        .unwrap();

        let settings = Settings::load_from_paths(root.path().to_owned(), &config_file).unwrap();

        assert_eq!(settings.profile, Some(DeploymentProfile::Testnet));
        assert_eq!(settings.network, Network::Signet);
        assert_eq!(settings.alpen_endpoint, "https://rpc.testnet.example.com");
        assert_eq!(settings.data_root, root.path());
        assert_eq!(settings.data_dir, root.path().join("testnet"));
        assert_eq!(
            settings.descriptor_db,
            root.path().join("testnet").join("descriptors")
        );
        assert_eq!(settings.linux_seed_file, root.path().join("seed"));
        assert!(root.path().join("testnet").join("default.sqlite").is_file());
        assert!(
            root.path()
                .join("testnet")
                .join("descriptors")
                .join("legacy")
                .is_file()
        );
        assert!(!root.path().join("default.sqlite").exists());
        assert!(!root.path().join("descriptors").exists());
    }

    #[test]
    fn requires_explicit_legacy_state_migration() {
        let root = tempdir().unwrap();
        let config_file = root.path().join("config.toml");
        write(
            &config_file,
            r#"
                active_profile = "testnet"

                [profiles]
                mainnet = "mainnet.toml"
                testnet = "testnet.toml"
            "#,
        )
        .unwrap();
        write(
            root.path().join("testnet.toml"),
            profile_config("signet", "https://rpc.testnet.example.com"),
        )
        .unwrap();
        write(root.path().join("default.sqlite"), b"legacy wallet").unwrap();

        let error = Settings::load_from_paths(root.path().to_owned(), &config_file).unwrap_err();

        assert!(format!("{error:?}").contains("migrate_legacy_state = \"testnet\""));
        assert!(root.path().join("default.sqlite").is_file());
        assert!(!root.path().join("testnet").join("default.sqlite").exists());
    }

    #[test]
    fn rejects_bitcoin_network_that_does_not_match_profile() {
        let root = tempdir().unwrap();
        let config_file = root.path().join("config.toml");
        write(
            &config_file,
            r#"
                active_profile = "testnet"

                [profiles]
                mainnet = "mainnet.toml"
                testnet = "testnet.toml"
            "#,
        )
        .unwrap();
        let mainnet = profile_config("bitcoin", "https://rpc.example.com");
        write(root.path().join("mainnet.toml"), &mainnet).unwrap();
        write(root.path().join("testnet.toml"), mainnet).unwrap();

        let error = Settings::load_from_paths(root.path().to_owned(), &config_file).unwrap_err();

        assert!(
            format!("{error:?}").contains("profile 'testnet' requires Bitcoin network 'signet'")
        );
    }

    #[test]
    fn reads_active_profile_from_legacy_and_dispatcher_configs() {
        let root = tempdir().unwrap();
        let config_file = root.path().join("config.toml");
        write(&config_file, "network = \"signet\"\n").unwrap();
        assert_eq!(
            active_deployment_profile(&config_file).unwrap(),
            ActiveDeployment::Legacy(Network::Signet)
        );

        write(
            &config_file,
            "active_profile = \"mainnet\"\n[profiles]\nmainnet = \"mainnet.toml\"\ntestnet = \"testnet.toml\"\n",
        )
        .unwrap();
        assert_eq!(
            active_deployment_profile(&config_file).unwrap(),
            ActiveDeployment::Profile(DeploymentProfile::Mainnet)
        );
    }

    #[test]
    fn legacy_flat_configs_keep_all_previously_supported_bitcoin_networks() {
        for (name, expected) in [
            ("regtest", Network::Regtest),
            ("testnet", Network::Testnet),
            ("testnet4", Network::Testnet4),
        ] {
            let root = tempdir().unwrap();
            let config_file = root.path().join("config.toml");
            write(
                &config_file,
                profile_config(name, "https://rpc.example.com"),
            )
            .unwrap();

            let settings = Settings::load_from_paths(root.path().to_owned(), &config_file).unwrap();

            assert_eq!(settings.profile, None);
            assert_eq!(settings.network, expected);
            assert_eq!(
                active_deployment_profile(&config_file).unwrap(),
                ActiveDeployment::Legacy(expected)
            );
        }
    }

    #[test]
    fn test_parses_datatool_network_profile_snippet() {
        // Verbatim output of `strata-datatool gen-asm-params --cli-config`.
        // Must stay byte-identical to the literal pinned by
        // `cli_network_profile_matches_cli_config_schema` in bin/datatool, so
        // a field rename on either side fails one of the two tests.
        let snippet = "# Alpen CLI network profile derived from the ASM params.\n\
             # Merge these fields into the CLI's config.toml.\n\
             network = \"signet\"\n\
             magic_bytes = \"ALPN\"\n\
             bridge_pubkey = \"14ebfa9a90fee3020686b5334b297b675a9f29282f44b6c3a4ab1f0582021839\"\n\
             bridge_denomination_sats = 100000000\n\
             recovery_delay = 1008\n\
             max_withdrawal_amount_sats = 1000000000\n\
             max_withdrawal_descriptor_len = 81\n";

        let config = format!(
            "{snippet}\n\
             alpen_endpoint = \"https://rpc.testnet.alpenlabs.io\"\n\
             faucet_endpoint = \"https://faucet-api.testnet.alpenlabs.io\"\n\
             seed = \"000102030405060708090a0b0c0d0e0f\"\n"
        );

        // Deserialized through the `config` crate, not `toml`, because that is
        // the path `Settings::load` actually takes: the crate round-trips values
        // through its own `Value` layer, which can diverge from direct TOML
        // deserialization for custom visitors.
        let parsed: SettingsFromFile = Config::builder()
            .add_source(config::File::from_str(&config, config::FileFormat::Toml))
            .build()
            .expect("generated snippet should build as CLI config")
            .try_deserialize()
            .expect("generated snippet should parse as CLI config");

        assert_eq!(parsed.network, Network::Signet);
        assert_eq!(parsed.magic_bytes, MagicBytes::new(*b"ALPN"));
        assert_eq!(parsed.bridge_denomination_sats, 100_000_000);
        assert_eq!(parsed.recovery_delay, 1_008);
        assert_eq!(parsed.max_withdrawal_amount_sats, Some(1_000_000_000));
        assert_eq!(parsed.max_withdrawal_descriptor_len, 81);
    }

    #[test]
    fn test_settings_from_file_serde_roundtrip() {
        let config = r#"
            esplora = "https://esplora.testnet.alpenlabs.io"
            bitcoind_rpc_user = "user"
            bitcoind_rpc_pw = "pass"
            bitcoind_rpc_endpoint = "http://127.0.0.1:38332"
            alpen_endpoint = "https://rpc.testnet.alpenlabs.io"
            mempool_endpoint = "https://bitcoin.testnet.alpenlabs.io"
            blockscout_endpoint = "https://explorer.testnet.alpenlabs.io"
            bridge_pubkey = "1d3e9c0417ba7d3551df5a1cc1dbe227aa4ce89161762454d92bfc2b1d5886f7"
            network = "bitcoin"
            magic_bytes = "ALPN"
            bridge_denomination_sats = 100_000_000
            recovery_delay = 1008
            max_withdrawal_descriptor_len = 81
            seed = "000102030405060708090a0b0c0d0e0f"
        "#;

        // Deserialize from TOML string
        let parsed: SettingsFromFile =
            toml::from_str(config).expect("failed to parse SettingsFromFile from TOML");

        // Serialize back to TOML string
        let serialized =
            toml::to_string(&parsed).expect("failed to serialize SettingsFromFile to TOML");
        assert!(serialized.contains(
            r#"bridge_pubkey = "1d3e9c0417ba7d3551df5a1cc1dbe227aa4ce89161762454d92bfc2b1d5886f7""#
        ));

        // Deserialize again
        let reparsed: SettingsFromFile =
            toml::from_str(&serialized).expect("failed to deserialize serialized SettingsFromFile");

        // Assert important fields survived round-trip
        assert_eq!(parsed.esplora, reparsed.esplora);
        assert_eq!(parsed.alpen_endpoint, reparsed.alpen_endpoint);
        assert_eq!(parsed.bridge_pubkey, reparsed.bridge_pubkey);
        assert_eq!(parsed.network, reparsed.network);
        assert_eq!(parsed.network, Network::Bitcoin);
        assert_eq!(parsed.magic_bytes, reparsed.magic_bytes);
        assert_eq!(
            parsed.bridge_denomination_sats,
            reparsed.bridge_denomination_sats
        );
        assert_eq!(parsed.recovery_delay, reparsed.recovery_delay);
        assert_eq!(
            parsed.max_withdrawal_descriptor_len,
            reparsed.max_withdrawal_descriptor_len
        );
    }

    #[test]
    fn test_bridge_pubkey_requires_exact_hex_length() {
        for value in ["11".repeat(31), "11".repeat(33)] {
            let deserializer = StringDeserializer::<ValueError>::new(value.clone());
            let error =
                deserialize_bridge_pubkey(deserializer).expect_err("wrong length should fail");
            let message = error.to_string();
            assert!(message.contains("exactly 64 hexadecimal characters"));
            assert!(message.contains(&format!("got {}", value.len())));
        }
    }

    #[test]
    fn test_bridge_pubkey_rejects_invalid_hex() {
        let value = "z".repeat(X_ONLY_PUBLIC_KEY_HEX_LENGTH);
        let deserializer = StringDeserializer::<ValueError>::new(value);
        let error = deserialize_bridge_pubkey(deserializer).expect_err("invalid hex should fail");
        assert!(error.to_string().starts_with("invalid x-only public key:"));
    }

    #[test]
    fn test_bridge_pubkey_accepts_valid_key() {
        let value = "1d3e9c0417ba7d3551df5a1cc1dbe227aa4ce89161762454d92bfc2b1d5886f7";
        let deserializer = StringDeserializer::<ValueError>::new(value.to_owned());
        let parsed = deserialize_bridge_pubkey(deserializer).expect("valid x-only public key");
        assert_eq!(parsed.to_string(), value);
    }
}
