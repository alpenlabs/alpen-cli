//! Bridge withdrawal amount validation and transaction encoding.
use crate::SATS_TO_WEI;
use alloy::{
    network::TransactionBuilder,
    primitives::{Address, U256},
    rpc::types::{TransactionInput, TransactionRequest},
};
use alpen_reth_primitives::WithdrawalCalldata;
use bdk_wallet::bitcoin::Amount;
use strata_bridge_params::BridgeParams;
use strata_cli_common::errors::DisplayedError;
use strata_ol_bridge_types::OperatorSelection;
use strata_primitives::bitcoin_bosd::Descriptor;

/// Builds the withdrawal call using the configured bridge address.
pub fn withdrawal_request(
    bridge: Address,
    amount: Amount,
    bosd: Descriptor,
    operator: Option<u32>,
) -> TransactionRequest {
    let selected_operator = match operator {
        Some(idx) => OperatorSelection::specific(idx),
        None => OperatorSelection::any(),
    };
    let calldata = WithdrawalCalldata {
        selected_operator,
        bosd: bosd.to_bytes(),
    }
    .encode();
    TransactionRequest::default()
        .with_to(bridge)
        .with_value(U256::from(amount.to_sat() as u128 * SATS_TO_WEI))
        .input(TransactionInput::new(calldata.into()))
}

/// Resolves the withdrawal amount from an optional user-provided value.
///
/// Defaults to one denomination if no amount is provided.
pub fn resolve_withdrawal_amount(
    amount_sats: Option<u64>,
    bridge_params: &BridgeParams,
) -> Result<Amount, DisplayedError> {
    let sats = amount_sats.unwrap_or(bridge_params.denomination());
    if !bridge_params.validate_withdrawal_amount(sats) {
        let denom = bridge_params.denomination();
        let mut msg = format!("Amount must be a positive multiple of {denom} sats");
        if let Some(max) = bridge_params.max_withdrawal_amount() {
            msg.push_str(&format!(" and at most {max} sats"));
        }
        return Err(DisplayedError::UserError(msg, Box::new(())));
    }
    Ok(Amount::from_sat(sats))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> BridgeParams {
        BridgeParams::new(100_000_000, Some(1_000_000_000)).unwrap()
    }

    #[test]
    fn test_none_defaults_to_denomination() {
        let result = resolve_withdrawal_amount(None, &params()).unwrap();
        assert_eq!(result, Amount::from_sat(100_000_000));
    }

    #[test]
    fn test_exact_denomination_accepted() {
        let result = resolve_withdrawal_amount(Some(100_000_000), &params()).unwrap();
        assert_eq!(result, Amount::from_sat(100_000_000));
    }

    #[test]
    fn test_exact_multiple_accepted() {
        let result = resolve_withdrawal_amount(Some(300_000_000), &params()).unwrap();
        assert_eq!(result, Amount::from_sat(300_000_000));
    }

    #[test]
    fn test_zero_rejected() {
        assert!(resolve_withdrawal_amount(Some(0), &params()).is_err());
    }

    #[test]
    fn test_non_multiple_rejected() {
        assert!(resolve_withdrawal_amount(Some(150_000_000), &params()).is_err());
    }

    #[test]
    fn test_below_denomination_rejected() {
        assert!(resolve_withdrawal_amount(Some(50_000_000), &params()).is_err());
    }

    #[test]
    fn test_exceeds_cap_rejected() {
        assert!(resolve_withdrawal_amount(Some(1_100_000_000), &params()).is_err());
    }

    #[test]
    fn test_at_cap_accepted() {
        let result = resolve_withdrawal_amount(Some(1_000_000_000), &params()).unwrap();
        assert_eq!(result, Amount::from_sat(1_000_000_000));
    }
}
