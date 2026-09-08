//! Alpen wallet operations and bridge withdrawals.

pub mod drain;
pub mod withdrawal;
use alloy::{
    consensus::constants::ETH_TO_WEI,
    network::TransactionBuilder,
    primitives::{Address, B256, U256},
    rpc::types::TransactionRequest,
};
use strata_cli_common::errors::{DisplayableError, DisplayedError};
/// Number of wei corresponding to one satoshi.
pub const SATS_TO_WEI: u128 = ETH_TO_WEI / 100_000_000;

use std::ops::{Deref, DerefMut};

use alloy::{
    network::EthereumWallet,
    providers::{
        Identity, Provider as ProviderTrait, ProviderBuilder, RootProvider, WalletProvider,
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            WalletFiller,
        },
    },
};

// alloy moment 💀
type Provider = FillProvider<
    JoinFill<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

#[derive(Debug)]
pub struct AlpenWallet(Provider);

impl DerefMut for AlpenWallet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for AlpenWallet {
    type Target = Provider;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct AlpenEndpointParseError;

impl AlpenWallet {
    pub fn new(
        wallet: EthereumWallet,
        alpen_http_endpoint: &str,
    ) -> Result<Self, AlpenEndpointParseError> {
        let provider = ProviderBuilder::new().wallet(wallet).connect_http(
            alpen_http_endpoint
                .parse()
                .map_err(|_| AlpenEndpointParseError)?,
        );

        Ok(Self(provider))
    }
}

impl AlpenWallet {
    /// Returns the address of the configured signer.
    pub fn address(&self) -> Address {
        self.default_signer_address()
    }

    /// Fetches the wallet balance in satoshis.
    pub async fn balance_sats(&self) -> Result<u64, DisplayedError> {
        let balance = self
            .get_balance(self.address())
            .await
            .internal_error("Failed to fetch Alpen balance")?;
        Ok((balance / U256::from(SATS_TO_WEI))
            .try_into()
            .expect("to fit into u64"))
    }

    /// Broadcasts a transfer of the requested number of satoshis.
    pub async fn send(&self, address: Address, amount_sats: u64) -> Result<B256, DisplayedError> {
        let tx = TransactionRequest::default()
            .with_to(address)
            .with_value(U256::from(amount_sats as u128 * SATS_TO_WEI));
        let res = self
            .send_transaction(tx)
            .await
            .internal_error("Failed to broadcast Alpen transaction")?;
        Ok(*res.tx_hash())
    }
}
