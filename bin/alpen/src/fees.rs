use bdk_wallet::bitcoin::FeeRate;
use colored::Colorize;

pub(crate) fn log_fee_rate(fr: &FeeRate) {
    println!(
        "Using {} as feerate",
        format!("{} sat/vb", fr.to_sat_per_vb_ceil()).green(),
    )
}
