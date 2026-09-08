//! Optional progress reporting for Bitcoin chain backends.
use bdk_wallet::{
    KeychainKind,
    bitcoin::{BlockHash, ScriptBuf},
};
use std::{fmt, sync::Arc, time::Duration};

/// Backend progress delivered without terminal or logging side effects.
#[derive(Debug)]
pub enum BackendEvent {
    SyncStarted,
    SyncItem {
        item: String,
        outpoints: (u64, u64),
        scripts: (u64, u64),
        transactions: (u64, u64),
    },
    Updating,
    Synced,
    ScanStarted,
    ScanKeychain(KeychainKind),
    ScanScript {
        index: u32,
        script: ScriptBuf,
    },
    Persisting,
    ScanFinished,
    CoreStarted,
    CoreScanBlock {
        height: u32,
        scanned: u64,
    },
    CoreBlock {
        hash: BlockHash,
        height: u32,
        scanned: u64,
        elapsed: Duration,
    },
    MempoolStarted,
    MempoolApplied {
        count: usize,
        elapsed: Duration,
    },
    ScriptScanFinished,
}

/// Cloneable observer; the default discards progress events.
#[derive(Clone, Default)]
pub struct Progress(Option<Arc<dyn Fn(BackendEvent) + Send + Sync>>);
impl fmt::Debug for Progress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Progress").finish_non_exhaustive()
    }
}
impl Progress {
    /// Installs a callback invoked as the backend makes progress.
    pub fn new(callback: impl Fn(BackendEvent) + Send + Sync + 'static) -> Self {
        Self(Some(Arc::new(callback)))
    }
    pub(crate) fn report(&self, event: BackendEvent) {
        if let Some(callback) = &self.0 {
            callback(event);
        }
    }
}
