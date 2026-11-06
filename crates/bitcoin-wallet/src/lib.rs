//! Bitcoin wallets, chain backends, deposit transactions, and recovery.

pub mod bridge;
pub mod constants;
pub mod recover;
pub mod recovery;
pub mod transfer;

pub mod backend;
pub mod progress;
use progress::Progress;
pub mod persist;

use std::{
    fmt::{self, Debug},
    io::{self},
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::Arc,
};

use backend::{
    BitcoinBackend, GetFeeRateError, InvalidFee, ScanError, SyncError, UpdateError, WalletUpdate,
};
use bdk_esplora::esplora_client::{self, AsyncClient};
use bdk_wallet::{
    PersistedWallet, SignOptions, Wallet,
    bitcoin::{
        FeeRate, Network, Psbt,
        psbt::{GetKey, SigningErrors},
    },
    chain::keychain_txout::DEFAULT_LOOKAHEAD,
    signer::SignerError,
};
use persist::Persister;
use rusqlite::{self, Connection};
use strata_cli_common::errors::DisplayedError;
use terrors::OneOf;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use alpen_wallet_keys::BaseWallet;

/// Why [`get_fee_rate`] refused to produce a fee rate.
#[derive(Debug)]
pub enum FeeRateError {
    /// The backend estimate is above the configured cap. It is never clamped, since an estimate
    /// that high points to a misbehaving or malicious backend.
    EstimateAboveMax { estimate: FeeRate, max: FeeRate },
    /// The user-supplied rate, in sat/vB, is above the configured cap.
    UserRateAboveMax { sat_per_vb: u64, max: FeeRate },
    /// The user-supplied rate, in sat/vB, does not fit in a [`FeeRate`].
    UserRateOutOfRange(u64),
    /// The backend could not produce an estimate.
    Backend(OneOf<(InvalidFee, GetFeeRateError)>),
}

impl fmt::Display for FeeRateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EstimateAboveMax { estimate, max } => write!(
                f,
                "The Bitcoin backend estimated a fee rate of {} sat/vB, above the {} sat/vB cap. \
                 Refusing to use it; pass a lower --fee-rate, or raise max_fee_rate_sat_per_vb in \
                 the config to pay it",
                estimate.to_sat_per_vb_ceil(),
                max.to_sat_per_vb_floor()
            ),
            Self::UserRateAboveMax { sat_per_vb, max } => write!(
                f,
                "Fee rate of {sat_per_vb} sat/vB is above the {} sat/vB cap. Raise \
                 max_fee_rate_sat_per_vb in the config to use it",
                max.to_sat_per_vb_floor()
            ),
            Self::UserRateOutOfRange(sat_per_vb) => {
                write!(f, "Fee rate of {sat_per_vb} sat/vB is out of range")
            }
            Self::Backend(_) => write!(
                f,
                "Failed to get a fee rate estimate from the Bitcoin backend"
            ),
        }
    }
}

impl FeeRateError {
    /// Converts into a [`DisplayedError`]. Only a backend failure counts as an internal error.
    ///
    /// This is a method rather than a `From` impl because a second `From` impl on
    /// [`DisplayedError`] breaks type inference for `?` in closures that return it.
    pub fn into_displayed_error(self) -> DisplayedError {
        let msg = self.to_string();
        match self {
            Self::Backend(e) => DisplayedError::InternalError(msg, Box::new(e)),
            err => DisplayedError::UserError(msg, Box::new(err)),
        }
    }
}

/// Picks the fee rate for a transaction: the user-supplied rate if there is one, otherwise the
/// backend's next-block estimate, never below [`FeeRate::BROADCAST_MIN`].
///
/// A rate above `max_fee_rate` is rejected, not clamped, whether it came from the user or the
/// backend. The cap is the user's `max_fee_rate_sat_per_vb` config setting, which defaults to
/// [`DEFAULT_MAX_FEE_RATE`](constants::DEFAULT_MAX_FEE_RATE).
pub async fn get_fee_rate(
    user_provided_sats_per_vb: Option<u64>,
    max_fee_rate: FeeRate,
    bitcoin_backend: &dyn BitcoinBackend,
) -> Result<FeeRate, FeeRateError> {
    let fee_rate = match user_provided_sats_per_vb {
        Some(sat_per_vb) => {
            let fee_rate = FeeRate::from_sat_per_vb(sat_per_vb)
                .ok_or(FeeRateError::UserRateOutOfRange(sat_per_vb))?;
            if fee_rate > max_fee_rate {
                return Err(FeeRateError::UserRateAboveMax {
                    sat_per_vb,
                    max: max_fee_rate,
                });
            }
            fee_rate
        }
        None => {
            let estimate = bitcoin_backend
                .get_fee_rate(1)
                .await
                .map_err(FeeRateError::Backend)?
                .unwrap_or(FeeRate::BROADCAST_MIN);
            if estimate > max_fee_rate {
                return Err(FeeRateError::EstimateAboveMax {
                    estimate,
                    max: max_fee_rate,
                });
            }
            estimate
        }
    };

    Ok(fee_rate.max(FeeRate::BROADCAST_MIN))
}

/// Signs `psbt` with the caller-owned `signer`, then finalizes it against `wallet`'s descriptors.
///
/// Returns whether every input was finalized.
pub fn sign_psbt(
    wallet: &Wallet,
    signer: &impl GetKey,
    psbt: &mut Psbt,
) -> Result<bool, OneOf<(SigningErrors, SignerError)>> {
    psbt.sign(signer, wallet.secp_ctx())
        .map_err(|(_, errors)| OneOf::new(errors))?;
    wallet
        .finalize_psbt(psbt, SignOptions::default())
        .map_err(OneOf::new)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        collections::HashSet,
        io::ErrorKind,
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use async_trait::async_trait;
    use bdk_wallet::{
        KeychainKind, Wallet,
        bitcoin::{
            Amount, FeeRate, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid,
            XOnlyPublicKey, absolute,
            hashes::Hash,
            secp256k1::Message,
            sighash::{Prevouts, SighashCache, TapSighashType},
            taproot, transaction,
        },
        chain::{
            CheckPoint,
            spk_client::{FullScanRequestBuilder, SyncRequestBuilder},
        },
    };
    use terrors::OneOf;

    use alpen_wallet_keys::{SECP256K1, Seed};

    use super::{
        BitcoinBackend, BitcoinWallet, DEFAULT_LOOKAHEAD, FeeRateError, SyncError,
        backend::{BroadcastTxError, GetFeeRateError, InvalidFee, ScanError, UpdateSender},
        constants::{DEFAULT_MAX_FEE_RATE, DEFAULT_MAX_FEE_RATE_SAT_PER_VB},
        get_fee_rate, lookahead_for_scan_state, scan_wallet, sign_psbt,
    };
    use strata_cli_common::errors::DisplayedError;

    #[derive(Debug, Default)]
    pub(crate) struct TestBitcoinBackend {
        pub(crate) fee_rate: Option<FeeRate>,
        pub(crate) used_scripts: HashSet<ScriptBuf>,
        pub(crate) scan_stop_gap: AtomicUsize,
    }

    #[async_trait]
    impl BitcoinBackend for TestBitcoinBackend {
        async fn scan_scripts(
            &self,
            scripts: Vec<ScriptBuf>,
            _last_cp: CheckPoint,
        ) -> Result<HashSet<ScriptBuf>, ScanError> {
            Ok(scripts
                .into_iter()
                .filter(|script| self.used_scripts.contains(script))
                .collect())
        }

        async fn sync_wallet(
            &self,
            _req: SyncRequestBuilder<(KeychainKind, u32)>,
            _last_cp: CheckPoint,
            _send_update: UpdateSender,
        ) -> Result<(), SyncError> {
            Ok(())
        }

        async fn scan_wallet(
            &self,
            _req: FullScanRequestBuilder<KeychainKind>,
            _last_cp: CheckPoint,
            _send_update: UpdateSender,
            stop_gap: usize,
        ) -> Result<(), ScanError> {
            self.scan_stop_gap.store(stop_gap, Ordering::Relaxed);
            Ok(())
        }

        async fn broadcast_tx(&self, _tx: &Transaction) -> Result<(), BroadcastTxError> {
            Ok(())
        }

        async fn get_fee_rate(
            &self,
            _target: u16,
        ) -> Result<Option<FeeRate>, OneOf<(InvalidFee, GetFeeRateError)>> {
            Ok(self.fee_rate)
        }
    }

    fn sat_per_vb(rate: u64) -> FeeRate {
        FeeRate::from_sat_per_vb(rate).unwrap()
    }

    fn backend_estimating(rate: FeeRate) -> TestBitcoinBackend {
        TestBitcoinBackend {
            fee_rate: Some(rate),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_get_fee_rate_clamps_backend_zero_to_broadcast_minimum() {
        let backend = backend_estimating(FeeRate::ZERO);

        let fee_rate = get_fee_rate(None, DEFAULT_MAX_FEE_RATE, &backend)
            .await
            .unwrap();

        assert_eq!(fee_rate, FeeRate::BROADCAST_MIN);
    }

    #[tokio::test]
    async fn test_get_fee_rate_uses_broadcast_minimum_when_backend_has_no_estimate() {
        let backend = TestBitcoinBackend::default();

        let fee_rate = get_fee_rate(None, DEFAULT_MAX_FEE_RATE, &backend)
            .await
            .unwrap();

        assert_eq!(fee_rate, FeeRate::BROADCAST_MIN);
    }

    #[tokio::test]
    async fn test_get_fee_rate_clamps_user_zero_to_broadcast_minimum() {
        let backend = TestBitcoinBackend::default();

        let fee_rate = get_fee_rate(Some(0), DEFAULT_MAX_FEE_RATE, &backend)
            .await
            .unwrap();

        assert_eq!(fee_rate, FeeRate::BROADCAST_MIN);
    }

    #[test]
    fn default_max_fee_rate_matches_sat_per_vb_constant() {
        assert_eq!(
            DEFAULT_MAX_FEE_RATE,
            sat_per_vb(DEFAULT_MAX_FEE_RATE_SAT_PER_VB)
        );
    }

    #[tokio::test]
    async fn test_get_fee_rate_accepts_backend_estimate_at_cap() {
        let backend = backend_estimating(DEFAULT_MAX_FEE_RATE);

        let fee_rate = get_fee_rate(None, DEFAULT_MAX_FEE_RATE, &backend)
            .await
            .unwrap();

        assert_eq!(fee_rate, DEFAULT_MAX_FEE_RATE);
    }

    #[tokio::test]
    async fn test_get_fee_rate_rejects_backend_estimate_above_cap() {
        let above_max = sat_per_vb(DEFAULT_MAX_FEE_RATE_SAT_PER_VB + 1);
        let backend = backend_estimating(above_max);

        let err = get_fee_rate(None, DEFAULT_MAX_FEE_RATE, &backend)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            FeeRateError::EstimateAboveMax { estimate, max }
                if estimate == above_max && max == DEFAULT_MAX_FEE_RATE
        ));
        assert!(matches!(
            err.into_displayed_error(),
            DisplayedError::UserError(msg, _)
                if msg.contains("max_fee_rate_sat_per_vb")
        ));
    }

    #[tokio::test]
    async fn test_get_fee_rate_accepts_user_rate_at_cap() {
        let backend = TestBitcoinBackend::default();

        let fee_rate = get_fee_rate(
            Some(DEFAULT_MAX_FEE_RATE_SAT_PER_VB),
            DEFAULT_MAX_FEE_RATE,
            &backend,
        )
        .await
        .unwrap();

        assert_eq!(fee_rate, DEFAULT_MAX_FEE_RATE);
    }

    #[tokio::test]
    async fn test_get_fee_rate_rejects_user_rate_above_cap_without_override() {
        let backend = TestBitcoinBackend::default();
        let above_max = DEFAULT_MAX_FEE_RATE_SAT_PER_VB + 1;

        let err = get_fee_rate(Some(above_max), DEFAULT_MAX_FEE_RATE, &backend)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            FeeRateError::UserRateAboveMax { sat_per_vb, max }
                if sat_per_vb == above_max && max == DEFAULT_MAX_FEE_RATE
        ));
        assert!(matches!(
            err.into_displayed_error(),
            DisplayedError::UserError(msg, _) if msg.contains("max_fee_rate_sat_per_vb")
        ));
    }

    #[tokio::test]
    async fn test_get_fee_rate_enforces_configured_cap() {
        let max = sat_per_vb(50);

        let backend = backend_estimating(sat_per_vb(50));
        assert_eq!(get_fee_rate(None, max, &backend).await.unwrap(), max);
        assert_eq!(get_fee_rate(Some(50), max, &backend).await.unwrap(), max);

        let backend = backend_estimating(sat_per_vb(51));
        assert!(matches!(
            get_fee_rate(None, max, &backend).await,
            Err(FeeRateError::EstimateAboveMax { max: reported, .. }) if reported == max
        ));
        assert!(matches!(
            get_fee_rate(Some(51), max, &backend).await,
            Err(FeeRateError::UserRateAboveMax { sat_per_vb: 51, .. })
        ));
    }

    #[tokio::test]
    async fn test_get_fee_rate_allows_rates_above_default_when_cap_is_raised() {
        let max = sat_per_vb(60_000);
        let backend = backend_estimating(sat_per_vb(50_000));

        assert_eq!(
            get_fee_rate(None, max, &backend).await.unwrap(),
            sat_per_vb(50_000)
        );
        // The backend estimate must not be consulted when the user supplies a rate.
        assert_eq!(
            get_fee_rate(Some(5_000), max, &backend).await.unwrap(),
            sat_per_vb(5_000)
        );
    }

    #[tokio::test]
    async fn test_get_fee_rate_rejects_unrepresentable_user_rate() {
        let backend = TestBitcoinBackend::default();

        let err = get_fee_rate(Some(u64::MAX), DEFAULT_MAX_FEE_RATE, &backend)
            .await
            .unwrap_err();

        assert!(matches!(err, FeeRateError::UserRateOutOfRange(u64::MAX)));
    }

    #[tokio::test]
    async fn test_get_fee_rate_reports_backend_failure_as_error() {
        #[derive(Debug, Default)]
        struct InvalidFeeBackend(TestBitcoinBackend);

        #[async_trait]
        impl BitcoinBackend for InvalidFeeBackend {
            async fn scan_scripts(
                &self,
                scripts: Vec<ScriptBuf>,
                last_cp: CheckPoint,
            ) -> Result<HashSet<ScriptBuf>, ScanError> {
                self.0.scan_scripts(scripts, last_cp).await
            }

            async fn sync_wallet(
                &self,
                req: SyncRequestBuilder<(KeychainKind, u32)>,
                last_cp: CheckPoint,
                send_update: UpdateSender,
            ) -> Result<(), SyncError> {
                self.0.sync_wallet(req, last_cp, send_update).await
            }

            async fn scan_wallet(
                &self,
                req: FullScanRequestBuilder<KeychainKind>,
                last_cp: CheckPoint,
                send_update: UpdateSender,
                stop_gap: usize,
            ) -> Result<(), ScanError> {
                self.0
                    .scan_wallet(req, last_cp, send_update, stop_gap)
                    .await
            }

            async fn broadcast_tx(&self, tx: &Transaction) -> Result<(), BroadcastTxError> {
                self.0.broadcast_tx(tx).await
            }

            async fn get_fee_rate(
                &self,
                _target: u16,
            ) -> Result<Option<FeeRate>, OneOf<(InvalidFee, GetFeeRateError)>> {
                Err(OneOf::new(InvalidFee))
            }
        }

        let err = get_fee_rate(None, DEFAULT_MAX_FEE_RATE, &InvalidFeeBackend::default())
            .await
            .unwrap_err();

        assert!(matches!(
            err.into_displayed_error(),
            DisplayedError::InternalError(..)
        ));
    }

    #[test]
    fn uses_distinct_mainnet_database_path() {
        let data_dir = Path::new("wallet-data");
        assert_eq!(
            BitcoinWallet::db_path("default", data_dir, Network::Bitcoin),
            data_dir.join("default-bitcoin.sqlite")
        );
        assert_eq!(
            BitcoinWallet::db_path("default", data_dir, Network::Signet),
            data_dir.join("default.sqlite")
        );
    }

    #[test]
    fn uses_recovery_lookahead_until_full_scan_completes() {
        assert_eq!(lookahead_for_scan_state(Ok(false), 50), 50);
        assert_eq!(lookahead_for_scan_state(Ok(true), 50), DEFAULT_LOOKAHEAD);
    }

    #[test]
    fn uses_recovery_lookahead_when_scan_state_cannot_be_read() {
        assert_eq!(
            lookahead_for_scan_state(Err(rusqlite::Error::InvalidQuery), 50),
            50
        );
    }

    #[test]
    fn rejects_zero_recovery_lookahead_at_wallet_boundary() {
        let base_wallet = Seed::from_entropy([0; 16]).bitcoin_wallet(Network::Signet);

        let error = BitcoinWallet::new(
            base_wallet,
            Network::Signet,
            0,
            Arc::new(TestBitcoinBackend::default()),
        )
        .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            "recovery_lookahead must be greater than 0"
        );
    }

    #[tokio::test]
    async fn passes_recovery_lookahead_to_full_scan_backend() {
        let seed = Seed::from_entropy([0; 16]);
        let (_, create) = seed.bitcoin_wallet(Network::Signet).split();
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        let mut wallet = create
            .network(Network::Signet)
            .create_wallet(&mut connection)
            .unwrap();
        let backend = Arc::new(TestBitcoinBackend::default());

        scan_wallet(&mut wallet, backend.clone(), 500)
            .await
            .unwrap();

        assert_eq!(backend.scan_stop_gap.load(Ordering::Relaxed), 500);
    }

    #[test]
    fn loads_wallets_created_from_private_descriptors() {
        // Wallets created before the BDK 3.2 upgrade were built from xprv descriptors.
        let seed = Seed::from_entropy([0; 16]);
        let signer = seed.bitcoin_signer(Network::Signet);
        let rootpriv = signer.as_xpriv();
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        Wallet::create(
            format!("tr({rootpriv}/86h/0h/0h/0/*)"),
            format!("tr({rootpriv}/86h/0h/0h/1/*)"),
        )
        .network(Network::Signet)
        .create_wallet(&mut connection)
        .unwrap();

        let (load, _) = seed.bitcoin_wallet(Network::Signet).split();
        let loaded = load
            .check_network(Network::Signet)
            .load_wallet(&mut connection)
            .unwrap();

        assert!(loaded.is_some());
    }

    #[test]
    fn seed_signer_signs_seed_wallet_spends() {
        let seed = Seed::from_entropy([0; 16]);
        let (_, create) = seed.bitcoin_wallet(Network::Regtest).split();
        let mut wallet = create
            .network(Network::Regtest)
            .create_wallet_no_persist()
            .unwrap();
        let address = wallet.reveal_next_address(KeychainKind::External).address;
        let funding = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([1; 32]), 0),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: address.script_pubkey(),
            }],
        };
        wallet.apply_unconfirmed_txs([(funding.clone(), 0)]);
        let mut psbt = {
            let mut builder = wallet.build_tx();
            builder.drain_wallet().drain_to(address.script_pubkey());
            builder.finish().unwrap()
        };

        assert!(sign_psbt(&wallet, &seed.bitcoin_signer(Network::Regtest), &mut psbt).unwrap());

        // The finalizer does not check signatures, so verify the key-path spend here.
        let tx = psbt.extract_tx().unwrap();
        let sighash = SighashCache::new(&tx)
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&funding.output),
                TapSighashType::Default,
            )
            .unwrap();
        let signature = taproot::Signature::from_slice(&tx.input[0].witness[0]).unwrap();
        let output_key =
            XOnlyPublicKey::from_slice(&address.script_pubkey().as_bytes()[2..]).unwrap();
        SECP256K1
            .verify_schnorr(
                &signature.signature,
                &Message::from_digest(sighash.to_byte_array()),
                &output_key,
            )
            .unwrap();
    }
}

#[derive(Clone, Debug)]
pub struct EsploraClient(AsyncClient, Progress);

impl DerefMut for EsploraClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for EsploraClient {
    type Target = AsyncClient;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl EsploraClient {
    /// Installs an observer for synchronization and scan progress.
    pub fn with_progress(mut self, progress: Progress) -> Self {
        self.1 = progress;
        self
    }

    pub fn new(esplora_url: &str) -> Result<Self, esplora_client::Error> {
        Ok(Self(
            esplora_client::Builder::new(esplora_url).build_async()?,
            Progress::default(),
        ))
    }
}

#[derive(Debug)]
/// A wrapper around BDK's wallet with some custom logic
pub struct BitcoinWallet {
    wallet: PersistedWallet<Persister>,
    sync_backend: Arc<dyn BitcoinBackend>,
    recovery_lookahead: u32,
}

impl BitcoinWallet {
    fn db_path(wallet: &str, data_dir: &Path, network: Network) -> PathBuf {
        let wallet = match network {
            Network::Bitcoin => format!("{wallet}-bitcoin"),
            _ => wallet.to_string(),
        };
        data_dir.join(wallet).with_extension("sqlite")
    }

    pub fn persister(data_dir: &Path, network: Network) -> Result<Connection, rusqlite::Error> {
        Connection::open(Self::db_path("default", data_dir, network))
    }

    pub fn new(
        base_wallet: BaseWallet,
        network: Network,
        recovery_lookahead: u32,
        sync_backend: Arc<dyn BitcoinBackend>,
    ) -> io::Result<Self> {
        if recovery_lookahead == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recovery_lookahead must be greater than 0",
            ));
        }

        let (load, create) = base_wallet.split();
        let lookahead = selected_lookahead(recovery_lookahead);
        Ok(Self {
            wallet: load
                .check_network(network)
                .lookahead(lookahead)
                .load_wallet(&mut Persister)
                .expect("should be able to load wallet")
                .unwrap_or_else(|| {
                    create
                        .network(network)
                        .lookahead(lookahead)
                        .create_wallet(&mut Persister)
                        .expect("wallet creation to succeed")
                }),
            sync_backend,
            recovery_lookahead,
        })
    }

    /// Syncs already-revealed addresses. Until a full scan has completed at
    /// least once for this wallet (e.g. right after a fresh recovery from
    /// seed), this runs a full scan instead, since a plain sync can never
    /// discover funds sitting at indices the wallet doesn't know about yet.
    pub async fn sync(
        &mut self,
    ) -> Result<(), OneOf<(UpdateError, SyncError, ScanError, rusqlite::Error)>> {
        let needs_full_scan = !Persister::full_scan_completed().map_err(OneOf::new)?;
        if needs_full_scan {
            scan_wallet(
                &mut self.wallet,
                self.sync_backend.clone(),
                self.recovery_lookahead,
            )
            .await
            .map_err(OneOf::broaden)?;
        } else {
            sync_wallet(&mut self.wallet, self.sync_backend.clone())
                .await
                .map_err(OneOf::broaden)?;
        }
        // Persist the scan results before recording completion, so a crash
        // in between leaves us re-scanning next time rather than silently
        // skipping a scan we never actually saved the results of.
        self.persist().map_err(OneOf::new)?;
        if needs_full_scan {
            Persister::mark_full_scan_completed().map_err(OneOf::new)?;
        }
        Ok(())
    }

    pub async fn scan(&mut self) -> Result<(), OneOf<(UpdateError, ScanError, rusqlite::Error)>> {
        scan_wallet(
            &mut self.wallet,
            self.sync_backend.clone(),
            self.recovery_lookahead,
        )
        .await?;
        self.persist().map_err(OneOf::new)?;
        Persister::mark_full_scan_completed().map_err(OneOf::new)?;
        Ok(())
    }

    pub fn persist(&mut self) -> Result<bool, rusqlite::Error> {
        self.wallet.persist(&mut Persister)
    }
}

/// Picks how many addresses to cache beyond the last known one.
///
/// The Bitcoin Core backend never uses the Esplora `stop_gap`. It replays
/// each block once and only recognizes an address already held in this
/// cache, so a payment that confirms out of derivation order is missed for
/// good. That one pass from genesis to the tip is the only chance to find
/// old addresses, because the emitter resumes from the agreed tip
/// afterwards. The configured `recovery_lookahead` controls how many such
/// addresses are cached.
///
/// Only the scan that follows a restore uses the configured recovery cache;
/// every later command uses the default. A database error is treated as an
/// incomplete scan and therefore uses the configured recovery lookahead.
fn selected_lookahead(recovery_lookahead: u32) -> u32 {
    lookahead_for_scan_state(Persister::full_scan_completed(), recovery_lookahead)
}

fn lookahead_for_scan_state(
    full_scan_completed: Result<bool, rusqlite::Error>,
    recovery_lookahead: u32,
) -> u32 {
    match full_scan_completed {
        Ok(true) => DEFAULT_LOOKAHEAD,
        Ok(false) | Err(_) => recovery_lookahead,
    }
}

pub async fn scan_wallet(
    wallet: &mut Wallet,
    sync_backend: Arc<dyn BitcoinBackend>,
    stop_gap: u32,
) -> Result<(), OneOf<(UpdateError, ScanError, rusqlite::Error)>> {
    let req = wallet.start_full_scan();
    let last_cp = wallet.latest_checkpoint();
    let (tx, rx) = unbounded_channel();

    let stop_gap = usize::try_from(stop_gap).expect("u32 fits in usize");
    let handle =
        tokio::spawn(async move { sync_backend.scan_wallet(req, last_cp, tx, stop_gap).await });

    apply_update_stream(wallet, rx).await.map_err(OneOf::new)?;

    handle
        .await
        .expect("thread to be fine")
        .map_err(OneOf::new)?;

    Ok(())
}

pub async fn sync_wallet(
    wallet: &mut Wallet,
    sync_backend: Arc<dyn BitcoinBackend>,
) -> Result<(), OneOf<(UpdateError, SyncError, rusqlite::Error)>> {
    let req = wallet.start_sync_with_revealed_spks();
    let last_cp = wallet.latest_checkpoint();
    let (tx, rx) = unbounded_channel();

    let handle = tokio::spawn(async move { sync_backend.sync_wallet(req, last_cp, tx).await });

    apply_update_stream(wallet, rx).await.map_err(OneOf::new)?;

    handle
        .await
        .expect("thread to be fine")
        .map_err(OneOf::new)?;

    Ok(())
}

async fn apply_update_stream(
    wallet: &mut Wallet,
    mut rx: UnboundedReceiver<WalletUpdate>,
) -> Result<(), UpdateError> {
    while let Some(update) = rx.recv().await {
        match update {
            WalletUpdate::SpkSync(update) => {
                wallet.apply_update(update).map_err(UpdateError::from_err)?
            }
            WalletUpdate::SpkScan(update) => {
                wallet.apply_update(update).map_err(UpdateError::from_err)?
            }
            WalletUpdate::NewBlock(ev) => {
                let height = ev.block_height();
                let connected_to = ev.connected_to();
                wallet
                    .apply_block_connected_to(&ev.block, height, connected_to)
                    .map_err(UpdateError::from_err)?
            }
            WalletUpdate::Mempool(event) => {
                wallet.apply_unconfirmed_txs(event.update);
                wallet.apply_evicted_txs(event.evicted);
            }
        }
    }

    Ok(())
}

impl Deref for BitcoinWallet {
    type Target = PersistedWallet<Persister>;

    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}

impl DerefMut for BitcoinWallet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wallet
    }
}
