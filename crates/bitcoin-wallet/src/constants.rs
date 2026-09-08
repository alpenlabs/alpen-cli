pub const RECOVERY_DESC_CLEANUP_DELAY: u32 = 100;

/// Number of consecutive unused reclaim-key counters `recover --from-seed` tries before giving
/// up. There's no persisted "last used counter" to resume from when reconstructing purely from the
/// seed, so this is the only signal for when to stop scanning.
pub const SEED_RECOVERY_GAP_LIMIT: u32 = 50;
