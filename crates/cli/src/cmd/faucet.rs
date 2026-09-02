use std::{fmt, str::FromStr};

use alloy::{primitives::Address as AlpenAddress, providers::WalletProvider};
use argh::FromArgs;
use bdk_wallet::{KeychainKind, bitcoin::Address};
use indicatif::ProgressBar;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shrex::{Hex, encode};
use strata_cli_common::errors::{DisplayableError, DisplayedError};

use crate::{
    alpen::AlpenWallet, bitcoin::BitcoinWallet, chain::Chain, seed::Seed, settings::Settings,
};

/// Requests funds from the faucet.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "faucet")]
pub struct FaucetArgs {
    /// either "bitcoin" or "alpen"
    #[argh(positional)]
    chain: String,
    /// address that funds will be sent to; defaults to an internal wallet address
    #[argh(positional)]
    address: Option<String>,
}

type Nonce = [u8; 16];
type Solution = [u8; 8];

#[derive(Debug, Serialize, Deserialize)]
pub struct PowChallenge {
    nonce: Hex<Nonce>,
    difficulty: u8,
}

enum FaucetChain {
    L1,
    L2,
}

impl FaucetChain {
    fn from_chain(chain: &Chain) -> Self {
        match chain {
            Chain::Bitcoin => Self::L1,
            Chain::Alpen => Self::L2,
        }
    }
}

impl fmt::Display for FaucetChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::L1 => "l1",
            Self::L2 => "l2",
        })
    }
}

pub async fn faucet(
    args: FaucetArgs,
    seed: Seed,
    settings: Settings,
) -> Result<(), DisplayedError> {
    let chain: Chain = args
        .chain
        .parse()
        .user_error(format!("invalid chain '{}'", args.chain))?;

    let (address, claim) = match &chain {
        Chain::Bitcoin => {
            let mut wallet =
                BitcoinWallet::new(&seed, settings.network, settings.bitcoin_backend.clone())
                    .internal_error("Failed to load Bitcoin wallet")?;

            let address = match &args.address {
                None => {
                    let address_info = wallet.reveal_next_address(KeychainKind::External);
                    wallet
                        .persist()
                        .internal_error("Failed to persist Bitcoin wallet")?;
                    address_info.address
                }
                Some(address) => {
                    let unchecked = Address::from_str(address).user_error(format!(
                        "Invalid Bitcoin address: '{address}'. Must be a valid Bitcoin address.",
                    ))?;
                    unchecked
                        .require_network(settings.network)
                        .user_error(format!(
                            "Provided address '{address}' is not valid for network '{}'",
                            settings.network
                        ))?
                }
            };
            (address.to_string(), "claim_l1")
        }
        Chain::Alpen => {
            let wallet = AlpenWallet::new(&seed, &settings.alpen_endpoint)
                .user_error("Invalid Alpen endpoint URL. Check the config file")?;
            let address = match &args.address {
                Some(address) => AlpenAddress::from_str(address).user_error(format!(
                    "Invalid Alpen address {address}. Must be an EVM-compatible address"
                ))?,
                None => wallet.default_signer_address(),
            };
            (address.to_string(), "claim_l2")
        }
    };

    println!("Fetching challenge from faucet");

    let client = reqwest::Client::new();
    let mut base_url = Url::from_str(&settings.faucet_endpoint)
        .user_error("Invalid faucet endpoint. Check the config file")?;
    base_url = ensure_trailing_slash(base_url);

    let faucet_chain = FaucetChain::from_chain(&chain);
    let endpoint = base_url
        .join(&format!("pow_challenge/{faucet_chain}"))
        .expect("a valid URL");

    let response = client
        .get(endpoint)
        .send()
        .await
        .internal_error("Failed to fetch PoW challenge")?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or("unknown error".to_string());
        let faucet_error = format!("{status}: {error_text}");
        return Err(DisplayedError::InternalError(
            "Faucet returned an error".to_string(),
            Box::new(faucet_error),
        ));
    }

    let challenge = response
        .json::<PowChallenge>()
        .await
        .internal_error("Failed to parse faucet response")?;
    println!(
        "Received POW challenge with difficulty 2^{} from faucet: {:?}. Solving...",
        challenge.difficulty, challenge.nonce
    );

    let mut solution = 0u64;
    let prehash = {
        let mut hasher = Sha256::new();
        hasher.update(b"alpen faucet 2024");
        hasher.update(challenge.nonce.0);
        hasher
    };
    let progress = ProgressBar::new_spinner();
    let mut counter = 0u64;
    while !pow_valid(
        prehash.clone(),
        challenge.difficulty,
        solution.to_le_bytes(),
    ) {
        solution += 1;
        if counter.is_multiple_of(100) {
            progress.set_message(format!("Trying {solution}"));
        }
        counter += 1;
    }
    progress.finish_with_message(format!(
        "✔ Solved challenge after {solution} attempts. Claiming now."
    ));

    println!("Claiming to {chain} address {address}");

    let url = format!(
        "{base_url}{}/{}/{}",
        claim,
        encode(&solution.to_le_bytes()),
        address
    );
    let response = client
        .get(url)
        .send()
        .await
        .internal_error("Failed to claim from faucet")?;

    let status = response.status();
    let body = response
        .text()
        .await
        .internal_error("Failed to parse faucet response")?;
    if status == StatusCode::OK {
        println!("Faucet claim successfully queued. The funds should appear in your wallet soon.");
    } else {
        println!("Failed: faucet responded with {status}: {body}");
    }

    Ok(())
}

fn count_leading_zeros(data: &[u8]) -> u8 {
    data.iter()
        .map(|&byte| byte.leading_zeros() as u8)
        .take_while(|&zeros| zeros == 8)
        .sum::<u8>()
}

fn pow_valid(mut hasher: Sha256, difficulty: u8, solution: Solution) -> bool {
    hasher.update(solution);
    count_leading_zeros(&hasher.finalize()) >= difficulty
}

fn ensure_trailing_slash(mut url: Url) -> Url {
    let new_path = format!("{}/", url.path().trim_end_matches('/'));
    url.set_path(&new_path);
    url
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_trailing_slash_when_missing() {
        let url = Url::parse("https://example.com").unwrap();
        assert_eq!(ensure_trailing_slash(url).as_str(), "https://example.com/");
    }

    #[test]
    fn leaves_trailing_slash_when_present() {
        let url = Url::parse("https://example.com/").unwrap();
        assert_eq!(ensure_trailing_slash(url).as_str(), "https://example.com/");
    }

    #[test]
    fn handles_multiple_trailing_slashes() {
        let url = Url::parse("https://example.com//").unwrap();
        assert_eq!(ensure_trailing_slash(url).as_str(), "https://example.com/");
    }
}
