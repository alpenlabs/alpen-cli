use crate::fees::log_fee_rate;
use alpen_bitcoin_wallet::transfer::build_drain;
use alpen_wallet::{SATS_TO_WEI, drain::DrainOutcome};
use std::str::FromStr;

use alloy::primitives::{Address as AlpenAddress, U256};
use argh::FromArgs;
use bdk_wallet::bitcoin::{Address, Amount};
use colored::Colorize;
use strata_cli_common::errors::{DisplayableError, DisplayedError};

use crate::{
    alpen::AlpenWallet,
    bitcoin::{BitcoinWallet, get_fee_rate},
    link::{OnchainObject, PrettyPrint},
    seed::Seed,
    settings::Settings,
};

/// Drains the internal wallet to the provided Bitcoin or Alpen address
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "drain")]
pub struct DrainArgs {
    /// a Bitcoin address for Bitcoin funds to be drained to
    #[argh(option, short = 'b')]
    bitcoin_address: Option<String>,

    /// an Alpen address for Alpen funds to be drained to
    #[argh(option, short = 'r')]
    alpen_address: Option<String>,

    /// override Bitcoin fee rate in sat/vbyte; the effective rate is at least 1
    #[argh(option)]
    fee_rate: Option<u64>,
}

/// Target address not provided
#[derive(Debug, Clone, Copy)]
pub struct MissingTargetAddress;

pub async fn drain(
    DrainArgs {
        bitcoin_address,
        alpen_address,
        fee_rate,
    }: DrainArgs,
    seed: Seed,
    settings: Settings,
) -> Result<(), DisplayedError> {
    if alpen_address.is_none() && bitcoin_address.is_none() {
        return Err(DisplayedError::UserError(
            "Missing target address. Must provide a Bitcoin address or Alpen address.".into(),
            Box::new(MissingTargetAddress),
        ));
    }

    let bitcoin_address = bitcoin_address
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

    let alpen_address = alpen_address
        .map(|a| {
            AlpenAddress::from_str(&a).user_error(format!(
                "Invalid Alpen address '{a}'. Must be an EVM-compatible address"
            ))
        })
        .transpose()?;

    if let Some(address) = bitcoin_address {
        let mut l1w = BitcoinWallet::new(
            seed.bitcoin_wallet(settings.network),
            settings.network,
            settings.bitcoin_backend.clone(),
        )
        .internal_error("Failed to load Bitcoin wallet")?;
        l1w.sync()
            .await
            .internal_error("Failed to sync Bitcoin wallet")?;
        let balance = l1w.balance();
        if balance.untrusted_pending > Amount::ZERO {
            println!(
                "{}",
                "You have pending Bitcoin funds that won't be included in the drain".yellow()
            );
        }
        let fee_rate = get_fee_rate(fee_rate, settings.bitcoin_backend.as_ref()).await;
        log_fee_rate(&fee_rate);

        let tx = build_drain(&mut l1w, &address, fee_rate)?;
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
                .pretty()
        );
        println!("Drained Bitcoin wallet to {address}",);
    }

    if let Some(address) = alpen_address {
        let l2w = AlpenWallet::new(seed.get_alpen_wallet(), &settings.alpen_endpoint)
            .user_error("Invalid Alpen endpoint URL. Check the config file")?;
        match l2w.drain(address).await? {
            DrainOutcome::Empty => println!("No Alpen bitcoin to send"),
            DrainOutcome::InsufficientGas => {
                println!("No Alpen bitcoin to send after reserving gas")
            }
            DrainOutcome::Sent { txid, value } => {
                println!(
                    "{}",
                    OnchainObject::from(&txid)
                        .with_maybe_explorer(settings.blockscout_endpoint.as_deref())
                        .pretty()
                );
                println!(
                    "Drained {} from Alpen wallet to {}",
                    Amount::from_sat((value / U256::from(SATS_TO_WEI)).wrapping_to()),
                    address
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bitcoin_address_option() {
        let args = DrainArgs::from_args(&["alpen", "drain"], &["--bitcoin-address", "destination"])
            .unwrap();

        assert_eq!(args.bitcoin_address.as_deref(), Some("destination"));
    }

    #[test]
    fn rejects_removed_signet_address_option() {
        assert!(
            DrainArgs::from_args(&["alpen", "drain"], &["--signet-address", "destination"],)
                .is_err()
        );
    }
}
