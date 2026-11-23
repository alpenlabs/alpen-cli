//! Local regtest `bitcoind` harness for integration tests.

use bdk_wallet::bitcoin::constants::COINBASE_MATURITY;
use bitcoind::BitcoinD;

/// Maximum blocks to request in a single `generatetoaddress` RPC call so long
/// maturity or timelock advances do not trip the HTTP client timeout.
const MAX_BLOCKS_PER_RPC: usize = 100;

/// Regtest `bitcoind` process wrapper for wallet and bridge tests.
#[derive(Debug)]
pub(crate) struct RegtestHarness {
    bitcoind: BitcoinD,
}

impl RegtestHarness {
    /// Starts a fresh regtest `bitcoind` node and mines past coinbase maturity.
    pub(crate) fn new_with_coinbase_maturity() -> Self {
        let bitcoind = BitcoinD::new("bitcoind").expect("bitcoind regtest node should start");
        let harness = Self { bitcoind };
        harness.mine_blocks((COINBASE_MATURITY + 1) as usize);
        harness
    }

    /// Returns the underlying `bitcoind::BitcoinD`.
    pub(crate) fn bitcoind(&self) -> &BitcoinD {
        &self.bitcoind
    }

    /// Mines `count` regtest blocks to a fresh node wallet address.
    pub(crate) fn mine_blocks(&self, mut count: usize) {
        let coinbase_address = self
            .bitcoind
            .client
            .new_address()
            .expect("regtest wallet should generate a coinbase address");
        while count > 0 {
            let batch = count.min(MAX_BLOCKS_PER_RPC);
            self.bitcoind
                .client
                .generate_to_address(batch, &coinbase_address)
                .expect("regtest blocks should be mined");
            count -= batch;
        }
    }
}
