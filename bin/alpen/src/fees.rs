use alpen_wallet::Eip1559Fees;
use bdk_wallet::bitcoin::FeeRate;
use colored::Colorize;
use strata_cli_common::errors::DisplayedError;

const WEI_PER_GWEI: u128 = 1_000_000_000;

pub(crate) fn log_fee_rate(fr: &FeeRate) {
    println!(
        "Using {} as feerate",
        format!("{} sat/vb", fr.to_sat_per_vb_ceil()).green(),
    )
}

pub(crate) fn resolve_eip1559_fees(
    max_fee_per_gas_gwei: Option<u128>,
    max_priority_fee_per_gas_gwei: Option<u128>,
) -> Result<Option<Eip1559Fees>, DisplayedError> {
    let (max_fee, priority_fee) = match (max_fee_per_gas_gwei, max_priority_fee_per_gas_gwei) {
        (None, None) => return Ok(None),
        (Some(max_fee), Some(priority_fee)) => (max_fee, priority_fee),
        _ => {
            return Err(DisplayedError::UserError(
                "--max-fee-per-gas and --max-priority-fee-per-gas must be provided together"
                    .to_owned(),
                Box::new(()),
            ));
        }
    };

    if max_fee == 0 {
        return Err(DisplayedError::UserError(
            "--max-fee-per-gas must be greater than 0".to_owned(),
            Box::new(()),
        ));
    }
    if priority_fee > max_fee {
        return Err(DisplayedError::UserError(
            "--max-priority-fee-per-gas must not exceed --max-fee-per-gas".to_owned(),
            Box::new(()),
        ));
    }

    let max_fee_per_gas = max_fee.checked_mul(WEI_PER_GWEI).ok_or_else(|| {
        DisplayedError::UserError("--max-fee-per-gas is too large".to_owned(), Box::new(()))
    })?;
    let max_priority_fee_per_gas = priority_fee.checked_mul(WEI_PER_GWEI).ok_or_else(|| {
        DisplayedError::UserError(
            "--max-priority-fee-per-gas is too large".to_owned(),
            Box::new(()),
        )
    })?;

    Ok(Some(Eip1559Fees {
        max_fee_per_gas,
        max_priority_fee_per_gas,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_eip1559_fees() {
        assert_eq!(
            resolve_eip1559_fees(Some(3), Some(1)).unwrap(),
            Some(Eip1559Fees {
                max_fee_per_gas: 3_000_000_000,
                max_priority_fee_per_gas: 1_000_000_000,
            })
        );
    }

    #[test]
    fn requires_both_eip1559_fees() {
        assert!(resolve_eip1559_fees(Some(3), None).is_err());
        assert!(resolve_eip1559_fees(None, Some(1)).is_err());
    }

    #[test]
    fn rejects_priority_fee_above_max_fee() {
        assert!(resolve_eip1559_fees(Some(1), Some(2)).is_err());
    }
}
