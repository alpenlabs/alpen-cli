use alpen_wallet::Eip1559Fees;
use bdk_wallet::bitcoin::FeeRate;
use colored::Colorize;
use std::str::FromStr;
use strata_cli_common::errors::DisplayedError;

const WEI_PER_GWEI: u128 = 1_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Gwei(u128);

impl FromStr for Gwei {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (whole, fractional) = match value.split_once('.') {
            Some((whole, fractional)) if !whole.is_empty() && !fractional.is_empty() => {
                if fractional.contains('.') {
                    return Err("must be a decimal gwei value".to_owned());
                }
                (whole, fractional)
            }
            Some(_) => return Err("must be a decimal gwei value".to_owned()),
            None => (value, ""),
        };
        if fractional.len() > 9 {
            return Err("cannot have more than 9 decimal places".to_owned());
        }

        let whole = whole
            .parse::<u128>()
            .map_err(|_| "must be a non-negative decimal gwei value".to_owned())?;
        let fractional = if fractional.is_empty() {
            0
        } else {
            fractional
                .parse::<u128>()
                .map_err(|_| "must be a non-negative decimal gwei value".to_owned())?
                .checked_mul(10_u128.pow(9 - fractional.len() as u32))
                .ok_or_else(|| "gwei value is too large".to_owned())?
        };
        let wei = whole
            .checked_mul(WEI_PER_GWEI)
            .and_then(|wei| wei.checked_add(fractional))
            .ok_or_else(|| "gwei value is too large".to_owned())?;
        Ok(Self(wei))
    }
}

pub(crate) fn log_fee_rate(fr: &FeeRate) {
    println!(
        "Using {} as feerate",
        format!("{} sat/vb", fr.to_sat_per_vb_ceil()).green(),
    )
}

pub(crate) fn resolve_eip1559_fees(
    max_fee_per_gas_gwei: Option<Gwei>,
    max_priority_fee_per_gas_gwei: Option<Gwei>,
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

    if max_fee.0 == 0 {
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

    Ok(Some(Eip1559Fees {
        max_fee_per_gas: max_fee.0,
        max_priority_fee_per_gas: priority_fee.0,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_eip1559_fees() {
        assert_eq!(
            resolve_eip1559_fees(
                Some("0.002".parse().unwrap()),
                Some("0.001".parse().unwrap())
            )
            .unwrap(),
            Some(Eip1559Fees {
                max_fee_per_gas: 2_000_000,
                max_priority_fee_per_gas: 1_000_000,
            })
        );
    }

    #[test]
    fn requires_both_eip1559_fees() {
        assert!(resolve_eip1559_fees(Some("3".parse().unwrap()), None).is_err());
        assert!(resolve_eip1559_fees(None, Some("1".parse().unwrap())).is_err());
    }

    #[test]
    fn rejects_priority_fee_above_max_fee() {
        assert!(
            resolve_eip1559_fees(Some("1".parse().unwrap()), Some("2".parse().unwrap())).is_err()
        );
    }

    #[test]
    fn parses_decimal_gwei_exactly() {
        assert_eq!("3".parse::<Gwei>().unwrap(), Gwei(3_000_000_000));
        assert_eq!("0.002".parse::<Gwei>().unwrap(), Gwei(2_000_000));
        assert_eq!("0.000000001".parse::<Gwei>().unwrap(), Gwei(1));
    }

    #[test]
    fn rejects_sub_wei_precision() {
        assert!("0.0000000001".parse::<Gwei>().is_err());
    }
}
