use bdk_wallet::bitcoin::FeeRate;

pub const RECOVERY_DESC_CLEANUP_DELAY: u32 = 100;

/// Default for the configurable fee-rate cap (`max_fee_rate_sat_per_vb`), in sat/vB.
///
/// This is a rule of thumb, not a protocol limit. Mainnet next-block rates usually range from
/// single digits to the low hundreds of sat/vB, and only short, extreme spikes such as the April
/// 2024 halving pushed them past 1,000 sat/vB. The default is still 10x below Bitcoin Core's
/// default `-maxfeerate` (0.1 BTC/kvB, or 10,000 sat/vB), which only guards broadcasts that go
/// through Bitcoin Core.
///
/// At this rate a one-input, two-output taproot spend (about 154 vB) costs about 154,000 sats,
/// which bounds the loss from a bad backend estimate or a typo in `--fee-rate`. Users who need a
/// different cap set `max_fee_rate_sat_per_vb` in the config.
pub const DEFAULT_MAX_FEE_RATE_SAT_PER_VB: u64 = 1_000;

/// [`DEFAULT_MAX_FEE_RATE_SAT_PER_VB`] as a [`FeeRate`] (1 vB = 4 weight units).
pub const DEFAULT_MAX_FEE_RATE: FeeRate =
    FeeRate::from_sat_per_kwu(DEFAULT_MAX_FEE_RATE_SAT_PER_VB * 250);
