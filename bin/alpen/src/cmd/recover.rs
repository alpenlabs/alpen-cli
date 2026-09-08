use crate::{
    fees::log_fee_rate,
    link::{OnchainObject, PrettyPrint},
    seed::Seed,
    settings::Settings,
};
use alpen_bitcoin_wallet::recover::{self, RecoveryEvent};
use argh::FromArgs;
use colored::Colorize;
use strata_cli_common::errors::DisplayedError;

/// Attempts a recovery of old deposit transactions
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "recover")]
pub struct RecoverArgs {
    /// override Bitcoin fee rate in sat/vbyte; the effective rate is at least 1
    #[argh(option)]
    fee_rate: Option<u64>,
}

pub async fn recover(
    args: RecoverArgs,
    seed: Seed,
    settings: Settings,
) -> Result<(), DisplayedError> {
    recover::recover(
        args.fee_rate,
        seed,
        settings.recovery(),
        &|event| match event {
            RecoveryEvent::Opening => println!("Opening descriptor recovery"),
            RecoveryEvent::Height(height) => println!("Current Bitcoin chain height: {height}"),
            RecoveryEvent::NoDescriptors => println!("No descriptors in the local database"),
            RecoveryEvent::FeeRate(rate) => log_fee_rate(&rate),
            RecoveryEvent::Removed(height) => {
                println!("removed old, already claimed descriptor due for recovery at {height}")
            }
            RecoveryEvent::Recovering {
                address,
                counter: None,
            } => println!(
                "Recovering a deposit transaction from recovery address {}",
                address.to_string().yellow()
            ),
            RecoveryEvent::Recovering {
                address,
                counter: Some(counter),
            } => println!(
                "Recovering a deposit transaction (counter {counter}) from recovery address {}",
                address.to_string().yellow()
            ),
            RecoveryEvent::Destination(address) => println!(
                "Recovering to wallet address {}",
                address.to_string().yellow()
            ),
            RecoveryEvent::Broadcast(txid) => println!(
                "{}",
                OnchainObject::from(&txid)
                    .with_maybe_explorer(settings.mempool_space_endpoint.as_deref())
                    .pretty()
            ),
            RecoveryEvent::Scanning => {
                println!("Scanning for deposits reconstructable from the seed alone...")
            }
            RecoveryEvent::NothingFound => println!("Nothing found to recover from the seed."),
        },
    )
    .await
}

pub(crate) async fn reconstruct_reclaim_counter(
    seed: &Seed,
    settings: &Settings,
) -> Result<u32, DisplayedError> {
    recover::reconstruct_reclaim_counter(seed, &settings.recovery()).await
}
