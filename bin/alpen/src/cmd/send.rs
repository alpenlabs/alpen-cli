use crate::fees::log_fee_rate;
use alpen_bitcoin_wallet::transfer::build_transfer;
use std::str::FromStr;

use alloy::primitives::Address as AlpenAddress;
use argh::FromArgs;
use bdk_wallet::bitcoin::{Address, Amount};
use strata_cli_common::errors::{DisplayableError, DisplayedError};

use crate::{
    alpen::AlpenWallet,
    bitcoin::{BitcoinWallet, get_fee_rate},
    chain::Chain,
    link::{OnchainObject, PrettyPrint},
    seed::Seed,
    settings::Settings,
};

/// Sends BTC from the internal wallet
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "send")]
pub struct SendArgs {
    /// either "bitcoin" or "alpen"
    #[argh(positional)]
    chain: String,

    /// amount to send in sats
    #[argh(positional)]
    amount: u64,

    /// address to send to
    #[argh(positional)]
    address: String,

    /// override Bitcoin fee rate in sat/vbyte; the effective rate is at least 1
    #[argh(option)]
    fee_rate: Option<u64>,
}

pub async fn send(args: SendArgs, seed: Seed, settings: Settings) -> Result<(), DisplayedError> {
    let chain = args
        .chain
        .parse()
        .user_error(format!("invalid chain '{}'", args.chain))?;

    match chain {
        Chain::Bitcoin => {
            let amount = Amount::from_sat(args.amount);
            let address = Address::from_str(&args.address)
                .user_error(format!(
                    "Invalid Bitcoin address: '{}'. Must be a valid Bitcoin address.",
                    args.address
                ))?
                .require_network(settings.network)
                .user_error(format!(
                    "Provided address '{}' is not valid for network '{}'",
                    args.address, settings.network
                ))?;
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
            let fee_rate = get_fee_rate(args.fee_rate, settings.bitcoin_backend.as_ref()).await;
            log_fee_rate(&fee_rate);
            let tx = build_transfer(&mut l1w, &address, amount, fee_rate)?;
            settings
                .bitcoin_backend
                .broadcast_tx(&tx)
                .await
                .internal_error("Failed to broadcast Bitcoin transaction")?;
            let txid = tx.compute_txid();
            println!(
                "{}",
                OnchainObject::from(&txid)
                    .with_maybe_explorer(settings.mempool_space_endpoint.as_deref())
                    .pretty(),
            );
        }
        Chain::Alpen => {
            let l2w = AlpenWallet::new(seed.get_alpen_wallet(), &settings.alpen_endpoint)
                .user_error("Invalid Alpen endpoint URL. Check the configuration.")?;
            let address = AlpenAddress::from_str(&args.address).user_error(format!(
                "Invalid Alpen address {}. Must be an EVM-compatible address",
                args.address
            ))?;
            let txid = l2w.send(address, args.amount).await?;
            println!(
                "{}",
                OnchainObject::from(&txid)
                    .with_maybe_explorer(settings.blockscout_endpoint.as_deref())
                    .pretty(),
            );
        }
    };

    println!("Sent {} to {}", Amount::from_sat(args.amount), args.address,);
    Ok(())
}
