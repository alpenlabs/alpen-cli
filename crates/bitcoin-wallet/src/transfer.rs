//! Bitcoin transfer and drain transaction construction.
use crate::{BitcoinWallet, sign_psbt};
use bdk_wallet::{
    bitcoin::{Address, Amount, FeeRate, Psbt, Transaction, psbt::GetKey},
    coin_selection::InsufficientFunds,
    error::CreateTxError,
};
use strata_cli_common::errors::{DisplayableError, DisplayedError};

/// The absolute fee of a transaction is larger than the amount it delivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeExceedsAmount {
    pub fee: Amount,
    pub amount: Amount,
}

/// Rejects paying more in fees than the transaction delivers.
///
/// This catches overpayment the fee-rate cap cannot, such as a small send or drain from a wallet
/// with many inputs.
fn check_fee_against_amount(fee: Amount, amount: Amount) -> Result<(), DisplayedError> {
    if fee > amount {
        return Err(DisplayedError::UserError(
            format!(
                "Transaction fee of {fee} is larger than the {amount} it sends. Lower --fee-rate \
                 and try again"
            ),
            Box::new(FeeExceedsAmount { fee, amount }),
        ));
    }
    Ok(())
}

/// Returns the fee paid by an unsigned PSBT built by the wallet.
fn psbt_fee(psbt: &Psbt) -> Result<Amount, DisplayedError> {
    psbt.fee()
        .internal_error("Failed to compute the transaction fee")
}

/// Builds, persists, and signs a transfer to the checked address.
///
/// Fails if the fee is larger than `amount`.
pub fn build_transfer(
    wallet: &mut BitcoinWallet,
    signer: &impl GetKey,
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
    check_fee_against_amount(psbt_fee(&psbt)?, amount)?;
    wallet
        .persist()
        .internal_error("Failed to persist Bitcoin wallet")?;
    let finalized = sign_psbt(wallet, signer, &mut psbt).expect("tx should be signed");
    assert!(finalized, "tx should be finalized");
    let tx = psbt.extract_tx().expect("tx should be signed and ready");
    Ok(tx)
}

/// Builds and signs a transaction draining spendable wallet funds.
///
/// Fails if the fee is larger than the amount reaching `address`.
pub fn build_drain(
    wallet: &mut BitcoinWallet,
    signer: &impl GetKey,
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
    let script_pubkey = address.script_pubkey();
    let drained: Amount = psbt
        .unsigned_tx
        .output
        .iter()
        .filter(|txout| txout.script_pubkey == script_pubkey)
        .map(|txout| txout.value)
        .sum();
    check_fee_against_amount(psbt_fee(&psbt)?, drained)?;
    let finalized = sign_psbt(wallet, signer, &mut psbt).expect("tx should be signed");
    assert!(finalized, "tx should be finalized");
    let tx = psbt.extract_tx().expect("tx should be signed and ready");
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::Amount;
    use strata_cli_common::errors::DisplayedError;

    use super::{FeeExceedsAmount, check_fee_against_amount};

    #[test]
    fn accepts_fee_up_to_amount() {
        let amount = Amount::from_sat(10_000);

        assert!(check_fee_against_amount(Amount::from_sat(1_000), amount).is_ok());
        assert!(check_fee_against_amount(amount, amount).is_ok());
    }

    #[test]
    fn rejects_fee_above_amount() {
        let fee = Amount::from_sat(10_001);
        let amount = Amount::from_sat(10_000);

        let err = check_fee_against_amount(fee, amount).unwrap_err();

        let DisplayedError::UserError(msg, source) = err else {
            panic!("expected a user error, got {err:?}");
        };
        assert!(msg.contains("--fee-rate"), "{msg}");
        assert_eq!(
            format!("{source:?}"),
            format!("{:?}", FeeExceedsAmount { fee, amount })
        );
    }
}
