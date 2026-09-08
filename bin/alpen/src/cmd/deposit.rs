use crate::{
    alpen::AlpenWallet,
    bitcoin::{BitcoinWallet, get_fee_rate},
    cmd::recover::reconstruct_reclaim_counter,
    constants::BITCOIN_BLOCK_TIME,
    fees::log_fee_rate,
    link::{OnchainObject, PrettyPrint},
    recovery::DescriptorRecovery,
    seed::Seed,
    settings::Settings,
};
use alloy::primitives::Address as AlpenAddress;
use alpen_bitcoin_wallet::bridge::{
    build_deposit_request_tx, compute_recover_at_height, prepare_deposit_request,
};
use argh::FromArgs;
use bdk_wallet::{bitcoin::Amount, chain::ChainOracle};
use colored::Colorize;
use indicatif::ProgressBar;
use shrex::encode;
use std::{str::FromStr, time::Duration};
use strata_cli_common::errors::{DisplayableError, DisplayedError};

/// Deposits BTC from Bitcoin into Alpen
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "deposit")]
pub struct DepositArgs {
    /// the Alpen address to deposit the funds into. defaults to the
    /// wallet's internal address.
    #[argh(positional)]
    alpen_address: Option<String>,

    /// override Bitcoin fee rate in sat/vbyte; the effective rate is at least 1
    #[argh(option)]
    fee_rate: Option<u64>,
}

pub async fn deposit(
    DepositArgs {
        alpen_address,
        fee_rate,
    }: DepositArgs,
    seed: Seed,
    settings: Settings,
) -> Result<(), DisplayedError> {
    let mut l1w = BitcoinWallet::new(
        seed.bitcoin_wallet(settings.network),
        settings.network,
        settings.bitcoin_backend.clone(),
    )
    .internal_error("Failed to load Bitcoin wallet")?;
    let l2w = AlpenWallet::new(seed.get_alpen_wallet(), &settings.alpen_endpoint)
        .user_error("Invalid Alpen endpoint URL. Check the config file")?;

    l1w.sync()
        .await
        .internal_error("Failed to sync Bitcoin wallet")?;

    let requested_alpen_address = alpen_address
        .map(|a| {
            AlpenAddress::from_str(&a).user_error(format!(
                "Invalid Alpen address '{a}'. Must be an EVM-compatible address"
            ))
        })
        .transpose()?;
    let alpen_address = requested_alpen_address.unwrap_or(l2w.address());
    let drt_amount = Amount::from_sat(settings.bridge_params.denomination()) + settings.bridge_fee;
    println!(
        "Bridging {} to Alpen address {}",
        drt_amount.to_string().green(),
        alpen_address.to_string().cyan(),
    );

    let mut desc_file = DescriptorRecovery::open(&seed, &settings.descriptor_db)
        .await
        .internal_error("Failed to open descriptor recovery file")?;
    if desc_file
        .current_reclaim_counter()
        .internal_error("Failed to read the deposit reclaim counter")?
        .is_none()
    {
        println!("Reconstructing the missing deposit reclaim counter...");
        let reconstructed_counter = reconstruct_reclaim_counter(&seed, &settings).await?;
        desc_file
            .ensure_reclaim_counter_at_least(reconstructed_counter)
            .await
            .internal_error("Failed to save the reconstructed deposit reclaim counter")?;
    }
    let reclaim_counter = desc_file
        .next_reclaim_counter()
        .await
        .internal_error("Failed to reserve a deposit reclaim key counter")?;
    let reclaim_keypair = seed.drt_reclaim_keypair(reclaim_counter);

    let (bridge_in_desc, bridge_in_address, header_aux, deposit_output) = prepare_deposit_request(
        settings.bridge_musig2_pubkey,
        settings.network,
        settings.recovery_delay,
        alpen_address,
        drt_amount,
        reclaim_keypair,
    );

    println!(
        "Recovery public key: {}",
        encode(header_aux.recovery_pk()).yellow()
    );

    let current_block_height = l1w
        .local_chain()
        .get_chain_tip()
        .expect("valid chain tip")
        .height;

    let recover_at = compute_recover_at_height(
        current_block_height,
        settings.recovery_delay as u32,
        settings.finality_depth,
    );

    println!(
        "Using {} as bridge in address",
        bridge_in_address.to_string().yellow()
    );

    let fee_rate = get_fee_rate(fee_rate, settings.bitcoin_backend.as_ref()).await;
    log_fee_rate(&fee_rate);

    let tx = build_deposit_request_tx(
        &mut l1w,
        &header_aux,
        &deposit_output,
        settings.magic_bytes,
        fee_rate,
    )?;
    println!("Built transaction");

    l1w.persist()
        .internal_error("Failed to persist Bitcoin wallet")?;

    let pb = ProgressBar::new_spinner().with_message("Saving output descriptor");
    pb.enable_steady_tick(Duration::from_millis(100));

    desc_file
        .add_desc(recover_at, &bridge_in_desc)
        .await
        .internal_error("Failed to save recovery descriptor to recovery file")?;
    pb.finish_with_message("Saved output descriptor");

    let pb = ProgressBar::new_spinner().with_message("Broadcasting transaction");
    pb.enable_steady_tick(Duration::from_millis(100));
    settings
        .bitcoin_backend
        .broadcast_tx(&tx)
        .await
        .internal_error("Failed to broadcast Bitcoin transaction")?;
    let txid = tx.compute_txid();
    pb.finish_with_message(
        OnchainObject::from(&txid)
            .with_maybe_explorer(settings.mempool_space_endpoint.as_deref())
            .pretty(),
    );
    println!(
        "Expect transaction confirmation in ~{BITCOIN_BLOCK_TIME:?}. Funds will take longer than this to be available on Alpen."
    );
    Ok(())
}
