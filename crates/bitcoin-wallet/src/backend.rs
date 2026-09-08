use std::{
    collections::{BTreeSet, HashSet},
    error, fmt,
    fmt::Debug,
    marker::Send,
    ops,
    sync::Arc,
    time::Instant,
};

use async_trait::async_trait;
use bdk_bitcoind_rpc::{
    BlockEvent, Emitter, MempoolEvent, NO_EXPECTED_MEMPOOL_TXS,
    bitcoincore_rpc::{self, RpcApi, json::EstimateMode},
};
use bdk_esplora::EsploraAsyncExt;
use bdk_wallet::{
    KeychainKind,
    bitcoin::{Block, FeeRate, ScriptBuf, Transaction, consensus::encode},
    chain::{
        CheckPoint,
        spk_client::{
            FullScanRequestBuilder, FullScanResponse, SyncRequest, SyncRequestBuilder, SyncResponse,
        },
    },
};
use terrors::OneOf;
use tokio::{sync::mpsc::UnboundedSender, task};

use super::{
    EsploraClient,
    progress::{BackendEvent, Progress},
};

pub type BoxedInner = dyn error::Error + Send + Sync;
pub type BoxedErr = Box<BoxedInner>;

macro_rules! boxed_err {
    ($name:ident) => {
        impl $name {
            pub fn from_err<E>(err: E) -> Self
            where
                E: error::Error + Send + Sync + 'static,
            {
                Self::from(Box::new(err) as BoxedErr)
            }
        }

        impl ops::Deref for $name {
            type Target = BoxedInner;
            fn deref(&self) -> &Self::Target {
                self.0.as_ref()
            }
        }

        impl From<BoxedErr> for $name {
            fn from(err: BoxedErr) -> Self {
                Self(err)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl error::Error for $name {
            fn source(&self) -> Option<&(dyn error::Error + 'static)> {
                self.0.source()
            }
        }
    };
}

#[derive(Debug)]
pub struct UpdateError(BoxedErr);
boxed_err!(UpdateError);

#[derive(Debug)]
pub struct SyncError(BoxedErr);
boxed_err!(SyncError);

#[derive(Debug)]
pub struct ScanError(BoxedErr);
boxed_err!(ScanError);

#[derive(Debug)]
pub struct BroadcastTxError(BoxedErr);
boxed_err!(BroadcastTxError);

#[derive(Debug)]
pub struct GetFeeRateError(BoxedErr);
boxed_err!(GetFeeRateError);

#[derive(Debug)]
pub enum WalletUpdate {
    SpkSync(SyncResponse),
    SpkScan(FullScanResponse<KeychainKind>),
    NewBlock(BlockEvent<Block>),
    Mempool(MempoolEvent),
}

pub type UpdateSender = UnboundedSender<WalletUpdate>;

#[async_trait]
pub trait BitcoinBackend: Debug + Send + Sync {
    /// Scans a batch of script pubkeys and returns the ones with transaction history.
    async fn scan_scripts(
        &self,
        scripts: Vec<ScriptBuf>,
        last_cp: CheckPoint,
    ) -> Result<HashSet<ScriptBuf>, ScanError>;
    async fn sync_wallet(
        &self,
        req: SyncRequestBuilder<(KeychainKind, u32)>,
        last_cp: CheckPoint,
        send_update: UpdateSender,
    ) -> Result<(), SyncError>;
    async fn scan_wallet(
        &self,
        req: FullScanRequestBuilder<KeychainKind>,
        last_cp: CheckPoint,
        send_update: UpdateSender,
    ) -> Result<(), ScanError>;
    async fn broadcast_tx(&self, tx: &Transaction) -> Result<(), BroadcastTxError>;
    async fn get_fee_rate(
        &self,
        target: u16,
    ) -> Result<Option<FeeRate>, OneOf<(InvalidFee, GetFeeRateError)>>;
}

/// Number of consecutive unused addresses to check before a full scan gives up
/// looking for more funds. This follows the BIP-44 gap-limit convention used
/// by Bitcoin Core and most wallets; a lower value can make a scan miss real
/// funds sitting past a short run of unused addresses.
const STOP_GAP: usize = 20;
const PARALLEL_REQUESTS: usize = 3;

#[async_trait]
impl BitcoinBackend for EsploraClient {
    async fn scan_scripts(
        &self,
        scripts: Vec<ScriptBuf>,
        last_cp: CheckPoint,
    ) -> Result<HashSet<ScriptBuf>, ScanError> {
        let requested_scripts = scripts.iter().cloned().collect::<HashSet<_>>();
        let request = SyncRequest::builder()
            .chain_tip(last_cp)
            .spks(scripts)
            .build();
        let response = self
            .sync(request, 3)
            .await
            .map_err(|err| ScanError(Box::new(err) as BoxedErr))?;

        let mut used_scripts = HashSet::new();
        record_used_scripts(
            &requested_scripts,
            &mut used_scripts,
            response.tx_update.txs.iter().map(AsRef::as_ref),
        );
        for txout in response.tx_update.txouts.values() {
            if requested_scripts.contains(&txout.script_pubkey) {
                used_scripts.insert(txout.script_pubkey.clone());
            }
        }

        Ok(used_scripts)
    }

    async fn sync_wallet(
        &self,
        req: SyncRequestBuilder<(KeychainKind, u32)>,
        _last_cp: CheckPoint,
        send_update: UpdateSender,
    ) -> Result<(), SyncError> {
        self.1.report(BackendEvent::SyncStarted);
        let observer = self.1.clone();
        let req = req
            .inspect(move |item, progress| {
                observer.report(BackendEvent::SyncItem {
                    item: format!("{item}"),
                    outpoints: (
                        progress.total_outpoints() as u64,
                        progress.outpoints_consumed as u64,
                    ),
                    scripts: (progress.total_spks() as u64, progress.spks_consumed as u64),
                    transactions: (
                        progress.total_txids() as u64,
                        progress.txids_consumed as u64,
                    ),
                });
            })
            .build();

        let update = self
            .sync(req, PARALLEL_REQUESTS)
            .await
            .map_err(|e| Box::new(e) as BoxedErr)?;
        self.1.report(BackendEvent::Updating);
        send_update.send(WalletUpdate::SpkSync(update)).unwrap();
        self.1.report(BackendEvent::Synced);
        Ok(())
    }

    async fn scan_wallet(
        &self,
        req: FullScanRequestBuilder<KeychainKind>,
        _last_cp: CheckPoint,
        send_update: UpdateSender,
    ) -> Result<(), ScanError> {
        self.1.report(BackendEvent::ScanStarted);
        let observer = self.1.clone();
        let req = req
            .inspect({
                let mut once = BTreeSet::<KeychainKind>::new();
                move |keychain, index, script| {
                    if once.insert(keychain) {
                        observer.report(BackendEvent::ScanKeychain(keychain));
                    }
                    observer.report(BackendEvent::ScanScript {
                        index,
                        script: script.to_owned(),
                    });
                }
            })
            .build();

        let update = self
            .full_scan(req, STOP_GAP, PARALLEL_REQUESTS)
            .await
            .map_err(|e| Box::new(e) as BoxedErr)?;
        self.1.report(BackendEvent::Persisting);
        send_update.send(WalletUpdate::SpkScan(update)).unwrap();
        self.1.report(BackendEvent::ScanFinished);
        Ok(())
    }

    async fn broadcast_tx(&self, tx: &Transaction) -> Result<(), BroadcastTxError> {
        self.broadcast(tx)
            .await
            .map_err(|e| (Box::new(e) as BoxedErr).into())
    }

    async fn get_fee_rate(
        &self,
        target: u16,
    ) -> Result<Option<FeeRate>, OneOf<(InvalidFee, GetFeeRateError)>> {
        match self
            .get_fee_estimates()
            .await
            .map_err(|e| GetFeeRateError(Box::new(e) as BoxedErr))
            .map_err(OneOf::new)?
            .get(&target)
            .cloned()
        {
            Some(fr) => Ok(Some(
                FeeRate::from_sat_per_vb(fr as u64).ok_or(OneOf::new(InvalidFee))?,
            )),
            None => Ok(None),
        }
    }
}

/// Bitcoin Core backend with an optional progress observer.
#[derive(Clone, Debug)]
pub struct BitcoinCoreClient {
    client: Arc<bitcoincore_rpc::Client>,
    progress: Progress,
}
impl BitcoinCoreClient {
    /// Wraps a Bitcoin Core RPC client.
    pub fn new(client: bitcoincore_rpc::Client) -> Self {
        Self {
            client: Arc::new(client),
            progress: Progress::default(),
        }
    }
    /// Installs an observer for synchronization and scan progress.
    pub fn with_progress(mut self, progress: Progress) -> Self {
        self.progress = progress;
        self
    }
}

#[async_trait]
impl BitcoinBackend for BitcoinCoreClient {
    async fn scan_scripts(
        &self,
        scripts: Vec<ScriptBuf>,
        last_cp: CheckPoint,
    ) -> Result<HashSet<ScriptBuf>, ScanError> {
        let requested_scripts = scripts.into_iter().collect::<HashSet<_>>();
        self.progress.report(BackendEvent::CoreStarted);
        let observer = self.progress.clone();

        let used_scripts = spawn_bitcoin_core(self.client.clone(), move |client| {
            let mut emitter = Emitter::new(client, last_cp, 0, NO_EXPECTED_MEMPOOL_TXS);
            let mut used_scripts = HashSet::new();
            let mut blocks_scanned = 0;

            while let Some(event) = emitter.next_block()? {
                blocks_scanned += 1;
                record_used_scripts(
                    &requested_scripts,
                    &mut used_scripts,
                    event.block.txdata.iter(),
                );
                observer.report(BackendEvent::CoreScanBlock {
                    height: event.block_height(),
                    scanned: blocks_scanned,
                });
            }

            observer.report(BackendEvent::MempoolStarted);
            let mempool = emitter.mempool()?;
            record_used_scripts(
                &requested_scripts,
                &mut used_scripts,
                mempool.update.iter().map(|(tx, _)| tx.as_ref()),
            );

            Ok(used_scripts)
        })
        .await
        .map_err(|err| ScanError(Box::new(err) as BoxedErr))?;

        self.progress.report(BackendEvent::ScriptScanFinished);
        Ok(used_scripts)
    }

    async fn sync_wallet(
        &self,
        _req: SyncRequestBuilder<(KeychainKind, u32)>,
        last_cp: CheckPoint,
        send_update: UpdateSender,
    ) -> Result<(), SyncError> {
        sync_wallet_with_core(
            self.client.clone(),
            last_cp,
            false,
            send_update,
            self.progress.clone(),
        )
        .await
        .map_err(|e| (Box::new(e) as BoxedErr).into())
    }

    async fn scan_wallet(
        &self,
        _req: FullScanRequestBuilder<KeychainKind>,
        last_cp: CheckPoint,
        send_update: UpdateSender,
    ) -> Result<(), ScanError> {
        sync_wallet_with_core(
            self.client.clone(),
            last_cp,
            true,
            send_update,
            self.progress.clone(),
        )
        .await
        .map_err(|e| (Box::new(e) as BoxedErr).into())
    }

    async fn broadcast_tx(&self, tx: &Transaction) -> Result<(), BroadcastTxError> {
        let hex = encode::serialize_hex(tx);

        spawn_bitcoin_core(self.client.clone(), move |c| c.send_raw_transaction(hex))
            .await
            .map_err(|e| BroadcastTxError(Box::new(e) as BoxedErr))?;
        Ok(())
    }

    async fn get_fee_rate(
        &self,
        target: u16,
    ) -> Result<Option<FeeRate>, OneOf<(InvalidFee, GetFeeRateError)>> {
        let res = spawn_bitcoin_core(self.client.clone(), move |c| {
            c.estimate_smart_fee(target, Some(EstimateMode::Conservative))
        })
        .await
        .map_err(|e| GetFeeRateError(Box::new(e) as BoxedErr))
        .map_err(OneOf::new)?;

        match res.fee_rate {
            Some(per_kw) => Ok(Some(
                FeeRate::from_sat_per_vb((per_kw / 1000).to_sat()).ok_or(OneOf::new(InvalidFee))?,
            )),
            None => Ok(None),
        }
    }
}

fn record_used_scripts<'a>(
    requested_scripts: &HashSet<ScriptBuf>,
    used_scripts: &mut HashSet<ScriptBuf>,
    transactions: impl IntoIterator<Item = &'a Transaction>,
) {
    for txout in transactions.into_iter().flat_map(|tx| &tx.output) {
        if requested_scripts.contains(&txout.script_pubkey) {
            used_scripts.insert(txout.script_pubkey.clone());
        }
    }
}

async fn spawn_bitcoin_core<T, F>(
    client: Arc<bitcoincore_rpc::Client>,
    func: F,
) -> Result<T, bitcoincore_rpc::Error>
where
    T: Send + 'static,
    F: FnOnce(&bitcoincore_rpc::Client) -> Result<T, bitcoincore_rpc::Error> + Send + 'static,
{
    let handle = task::spawn_blocking(move || func(&client));
    handle.await.expect("thread should be fine")
}

async fn sync_wallet_with_core(
    client: Arc<bitcoincore_rpc::Client>,
    last_cp: CheckPoint,
    should_scan: bool,
    send_update: UpdateSender,
    observer: Progress,
) -> Result<(), bitcoincore_rpc::Error> {
    observer.report(BackendEvent::CoreStarted);

    let start_height = match should_scan {
        true => 0,
        false => last_cp.height(),
    };

    let mut blocks_scanned = 0;

    spawn_bitcoin_core(client.clone(), move |client| {
        let mut emitter = Emitter::new(client, last_cp, start_height, NO_EXPECTED_MEMPOOL_TXS);
        while let Some(ev) = emitter.next_block().unwrap() {
            blocks_scanned += 1;
            let height = ev.block_height();
            let hash = ev.block_hash();
            let start_apply_block = Instant::now();
            send_update.send(WalletUpdate::NewBlock(ev)).unwrap();
            let elapsed = start_apply_block.elapsed();
            observer.report(BackendEvent::CoreBlock {
                hash,
                height,
                scanned: blocks_scanned,
                elapsed,
            });
        }
        observer.report(BackendEvent::MempoolStarted);
        let mempool = emitter.mempool().unwrap();
        let txs_len = mempool.update.len();
        let apply_start = Instant::now();
        send_update.send(WalletUpdate::Mempool(mempool)).unwrap();
        let elapsed = apply_start.elapsed();
        observer.report(BackendEvent::MempoolApplied {
            count: txs_len,
            elapsed,
        });
        Ok(())
    })
    .await
}

#[derive(Debug)]
pub struct InvalidFee;

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use strata_test_utils_btcio::BtcioTestHarness;

    use bdk_wallet::bitcoin::{Amount, TxOut, absolute, transaction};

    use super::*;

    #[test]
    fn record_used_scripts_only_returns_requested_outputs() {
        let requested = ScriptBuf::from_bytes(vec![0x51]);
        let unrelated = ScriptBuf::from_bytes(vec![0x52]);
        let transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: requested.clone(),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: unrelated.clone(),
                },
            ],
        };
        let requested_scripts = HashSet::from([requested.clone()]);
        let mut used_scripts = HashSet::new();

        record_used_scripts(&requested_scripts, &mut used_scripts, [&transaction]);

        assert_eq!(used_scripts, HashSet::from([requested]));
        assert!(!used_scripts.contains(&unrelated));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bitcoin_core_backend_reports_progress_and_syncs_funded_wallet() {
        use crate::sync_wallet;
        use alpen_wallet_keys::Seed;
        use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client};
        use bdk_wallet::{Wallet, bitcoin::Network, chain::BlockId};

        let harness = BtcioTestHarness::new_with_coinbase_maturity().expect("Bitcoin node");
        let node = harness.bitcoind();
        let cookie = node.params.get_cookie_values().unwrap().unwrap();
        let client = Client::new(
            &node.rpc_url(),
            Auth::UserPass(cookie.user, cookie.password),
        )
        .unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let observed = events.clone();
        let backend = BitcoinCoreClient::new(client).with_progress(Progress::new(move |event| {
            observed.lock().unwrap().push(event);
        }));
        let checkpoint = CheckPoint::new(BlockId {
            height: 0,
            hash: backend.client.get_block_hash(0).unwrap(),
        });
        let (_, create) = Seed::from_entropy([0; 16])
            .bitcoin_wallet(Network::Regtest)
            .split();
        let mut wallet: Wallet = create
            .network(Network::Regtest)
            .create_wallet_no_persist()
            .unwrap();
        let address = wallet.reveal_next_address(KeychainKind::External).address;
        let amount = Amount::from_sat(500_000);
        node.client.send_to_address(&address, amount).unwrap();
        harness.mine_blocks_blocking(1, None).unwrap();

        let script = address.script_pubkey();
        let used = backend
            .scan_scripts(
                vec![script.clone(), ScriptBuf::from_bytes(vec![0x51])],
                checkpoint,
            )
            .await
            .unwrap();
        assert_eq!(used, HashSet::from([script]));
        sync_wallet(&mut wallet, Arc::new(backend)).await.unwrap();
        assert_eq!(wallet.balance().confirmed, amount);
        let events = events.lock().unwrap();
        assert!(
            events
                .iter()
                .any(|event| matches!(event, BackendEvent::ScriptScanFinished))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, BackendEvent::MempoolApplied { .. }))
        );
    }
}
