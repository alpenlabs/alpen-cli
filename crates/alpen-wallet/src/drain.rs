//! Alpen drain amount and fee calculation.
use crate::AlpenWallet;
use alloy::{
    primitives::{Address, B256, U256},
    providers::{Provider, WalletProvider},
};
use strata_cli_common::errors::{DisplayableError, DisplayedError};

/// Outcome of attempting to drain an Alpen wallet.
#[derive(Debug)]
pub enum DrainOutcome {
    Empty,
    InsufficientGas,
    Sent { txid: B256, value: U256 },
}

fn alpen_drain_fee(gas_limit: u64, gas_price: u128) -> U256 {
    U256::from(gas_limit) * U256::from(gas_price)
}

fn max_alpen_drain_value(balance: U256, gas_limit: u64, gas_price: u128) -> Option<U256> {
    let max_send_amount = balance.checked_sub(alpen_drain_fee(gas_limit, gas_price))?;
    if max_send_amount == U256::ZERO {
        return None;
    }
    Some(max_send_amount)
}

impl AlpenWallet {
    /// Reserves the estimated gas cost and broadcasts the remaining balance.
    pub async fn drain(&self, address: Address) -> Result<DrainOutcome, DisplayedError> {
        let balance = self
            .get_balance(self.default_signer_address())
            .await
            .internal_error("Failed to fetch Alpen balance")?;
        if balance == U256::ZERO {
            return Ok(DrainOutcome::Empty);
        }
        let estimate_tx = self
            .transaction_request()
            .from(self.default_signer_address())
            .to(address)
            .value(U256::from(1));
        let gas_price = self
            .get_gas_price()
            .await
            .internal_error("Failed to fetch Alpen gas price.")?;
        let gas_estimate = self
            .estimate_gas(estimate_tx)
            .await
            .internal_error("Failed to estimate Alpen gas")?;
        let Some(value) = max_alpen_drain_value(balance, gas_estimate, gas_price) else {
            return Ok(DrainOutcome::InsufficientGas);
        };
        let tx = self
            .transaction_request()
            .to(address)
            .value(value)
            .gas_limit(gas_estimate)
            .gas_price(gas_price);
        let res = self
            .send_transaction(tx)
            .await
            .internal_error("Failed to broadcast strata transaction")?;
        Ok(DrainOutcome::Sent {
            txid: *res.tx_hash(),
            value,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn alpen_drain_value_reserves_exact_fee() {
        let balance = U256::from(1_000_000_000_000_000_000u128);
        let gas_limit = 21_000;
        let gas_price = 1_000_000_000;

        let amount = max_alpen_drain_value(balance, gas_limit, gas_price).unwrap();

        assert_eq!(amount, U256::from(999_979_000_000_000_000u128));
        assert_eq!(amount + alpen_drain_fee(gas_limit, gas_price), balance);
    }

    #[test]
    fn alpen_drain_value_rejects_balance_equal_to_fee() {
        let gas_limit = 21_000;
        let gas_price = 1_000_000_000;
        let balance = alpen_drain_fee(gas_limit, gas_price);

        assert_eq!(max_alpen_drain_value(balance, gas_limit, gas_price), None);
    }

    #[test]
    fn alpen_drain_value_rejects_balance_below_fee() {
        let gas_limit = 21_000;
        let gas_price = 1_000_000_000;
        let balance = alpen_drain_fee(gas_limit, gas_price) - U256::from(1);

        assert_eq!(max_alpen_drain_value(balance, gas_limit, gas_price), None);
    }

    #[test]
    fn alpen_drain_fee_uses_wide_arithmetic() {
        let gas_limit = u64::MAX;
        let gas_price = u128::MAX;

        assert_eq!(
            alpen_drain_fee(gas_limit, gas_price),
            U256::from(gas_limit) * U256::from(gas_price)
        );
    }
}
