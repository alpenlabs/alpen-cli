use bdk_wallet::bitcoin::Amount;
use std::time::Duration;

pub use alpen_wallet_keys::constants::SEED_LEN;

/// Number of blocks that the wallet considers a transaction "buried" or final taking into account
/// reorgs that might happen.
pub const DEFAULT_FINALITY_DEPTH: u32 = 6;

/// Fee to cover the mining fees for creating the deposit transaction from the deposit request
/// transaction. This includes the cost for the bridge to spend the deposit request output into the
/// federation.
pub const DEFAULT_BRIDGE_FEE: Amount = Amount::from_sat(1_000);

pub const DEFAULT_BRIDGE_ALPEN_ADDRESS: &str = "0x5400000000000000000000000000000000000001";
pub const BITCOIN_BLOCK_TIME: Duration = Duration::from_secs(10 * 60); // 10 minutes
