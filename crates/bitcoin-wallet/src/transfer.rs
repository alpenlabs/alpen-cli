//! Bitcoin transfer and drain transaction construction.
use crate::BitcoinWallet;
use bdk_wallet::{
    bitcoin::{Address, Amount, FeeRate, Transaction},
    coin_selection::InsufficientFunds,
    error::CreateTxError,
};
use strata_cli_common::errors::{DisplayableError, DisplayedError};

/// Builds, persists, and signs a transfer to the checked address.
pub fn build_transfer(
    wallet: &mut BitcoinWallet,
    address: &Address,
    amount: Amount,
    fee_rate: FeeRate,
) -> Result<Transaction, DisplayedError> {
    let mut psbt = {
        let mut builder = wallet.build_tx();
        builder.add_recipient(address.script_pubkey(), amount);
        builder.fee_rate(fee_rate);
        match builder.finish() {
            Ok(psbt) => psbt,
            Err(e @ CreateTxError::OutputBelowDustLimit(_)) => {
                return Err(DisplayedError::UserError(
                    "Failed to create PSBT".to_string(),
                    Box::new(e),
                ));
            }
            Err(e) => panic!("Unexpected error in creating PSBT: {e:?}"),
        }
    };
    wallet
        .persist()
        .internal_error("Failed to persist Bitcoin wallet")?;
    wallet
        .sign(&mut psbt, Default::default())
        .expect("tx should be signed");
    let tx = psbt.extract_tx().expect("tx should be signed and ready");
    Ok(tx)
}

/// Builds and signs a transaction draining spendable wallet funds.
pub fn build_drain(
    wallet: &mut BitcoinWallet,
    address: &Address,
    fee_rate: FeeRate,
) -> Result<Transaction, DisplayedError> {
    let mut psbt = {
        let mut builder = wallet.build_tx();
        builder.drain_wallet();
        builder.drain_to(address.script_pubkey());
        builder.fee_rate(fee_rate);
        match builder.finish() {
            Ok(psbt) => psbt,
            Err(CreateTxError::CoinSelection(e @ InsufficientFunds { .. })) => {
                return Err(DisplayedError::UserError(
                    "Failed to create PSBT".to_string(),
                    Box::new(e),
                ));
            }
            Err(e) => panic!("Unexpected error in creating PSBT: {e:?}"),
        }
    };
    wallet
        .sign(&mut psbt, Default::default())
        .expect("tx should be signed");
    let tx = psbt.extract_tx().expect("tx should be signed and ready");
    Ok(tx)
}
