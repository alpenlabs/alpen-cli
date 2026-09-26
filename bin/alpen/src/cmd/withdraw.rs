use alpen_wallet::withdrawal::{resolve_withdrawal_amount, withdrawal_request};
use std::{str::FromStr, time::Duration};

use alloy::providers::Provider;
use argh::FromArgs;
use bdk_wallet::{KeychainKind, bitcoin::Address};
use indicatif::ProgressBar;
use strata_cli_common::errors::{DisplayableError, DisplayedError};
use strata_primitives::bitcoin_bosd::Descriptor;

use crate::{
    alpen::AlpenWallet,
    bitcoin::BitcoinWallet,
    link::{OnchainObject, PrettyPrint},
    seed::Seed,
    settings::Settings,
};

/// Withdraws BTC from Alpen to Bitcoin
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "withdraw")]
pub struct WithdrawArgs {
    /// the Bitcoin address to send funds to. defaults to a new internal wallet address
    #[argh(positional)]
    address: Option<String>,

    /// amount to withdraw in sats (must be a positive multiple of the denomination).
    /// defaults to one denomination unit.
    #[argh(option)]
    amount: Option<u64>,

    /// selected operator index for withdrawal assignment
    #[argh(option)]
    operator: Option<u32>,
}

pub async fn withdraw(
    args: WithdrawArgs,
    seed: Seed,
    settings: Settings,
) -> Result<(), DisplayedError> {
    let address = args
        .address
        .map(|a| {
            let unchecked = Address::from_str(&a).user_error(format!(
                "Invalid Bitcoin address: '{a}'. Must be a valid Bitcoin address."
            ))?;
            let checked = unchecked
                .require_network(settings.network)
                .user_error(format!(
                    "Provided address '{a}' is not valid for network '{}'",
                    settings.network
                ))?;
            Ok(checked)
        })
        .transpose()?;

    let mut l1w = BitcoinWallet::new(
        seed.bitcoin_wallet(settings.network),
        settings.network,
        settings.recovery_lookahead,
        settings.bitcoin_backend.clone(),
    )
    .internal_error("Failed to load Bitcoin wallet")?;
    l1w.sync()
        .await
        .internal_error("Failed to sync Bitcoin wallet")?;
    let l2w = AlpenWallet::new(seed.get_alpen_wallet(), &settings.alpen_endpoint)
        .user_error("Invalid Alpen endpoint URL. Check the configuration")?;

    let address = match address {
        Some(a) => a,
        None => {
            let info = l1w.reveal_next_address(KeychainKind::External);
            l1w.persist()
                .internal_error("Failed to persist Bitcoin wallet")?;
            info.address
        }
    };

    let bridge_out_amount = resolve_withdrawal_amount(args.amount, &settings.bridge_params)?;
    println!("Bridging out {} to {address}", bridge_out_amount);

    let bosd: Descriptor = address
        .try_into()
        .user_error("Failed to convert address to BOSD descriptor")?;

    let tx = withdrawal_request(
        settings.bridge_alpen_address,
        bridge_out_amount,
        bosd,
        args.operator,
    );

    let pb = ProgressBar::new_spinner().with_message("Broadcasting transaction");
    pb.enable_steady_tick(Duration::from_millis(100));
    let res = l2w
        .send_transaction(tx)
        .await
        .internal_error("Failed to broadcast Alpen transaction")?;
    pb.finish_with_message("Broadcast successful");
    println!(
        "{}",
        OnchainObject::from(res.tx_hash())
            .with_maybe_explorer(settings.blockscout_endpoint.as_deref())
            .pretty(),
    );

    Ok(())
}
