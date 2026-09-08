use alpen_bitcoin_wallet::progress::{BackendEvent, Progress};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::{sync::Mutex, time::Duration};

#[derive(Default)]
struct Display {
    group: MultiProgress,
    bars: Vec<ProgressBar>,
}
impl Display {
    fn spinner(&mut self, core: bool) {
        self.finish();
        let bar = self.group.add(ProgressBar::new_spinner());
        if core {
            bar.set_style(
                ProgressStyle::with_template("{spinner} [{elapsed_precise}] {msg}").unwrap(),
            );
        }
        bar.enable_steady_tick(Duration::from_millis(100));
        self.bars.push(bar);
    }
    fn finish(&mut self) {
        for bar in self.bars.drain(..) {
            bar.finish();
        }
    }
    fn message(&self, message: &str) {
        if let Some(bar) = self.bars.first() {
            bar.set_message(message.to_owned());
        }
    }
    fn line(&self, message: &str) {
        let _ = self.group.println(message);
    }
    fn event(&mut self, event: BackendEvent) {
        match event {
            BackendEvent::SyncStarted => {
                self.finish();
                println!("Syncing wallet...");
                let style = ProgressStyle::with_template(
                    "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}",
                )
                .unwrap()
                .progress_chars("##-");
                for name in ["outpoints", "script public keys", "transactions"] {
                    let bar = self.group.add(ProgressBar::new(1));
                    bar.set_style(style.clone());
                    bar.set_message(name);
                    self.bars.push(bar);
                }
            }
            BackendEvent::SyncItem {
                item,
                outpoints,
                scripts,
                transactions,
            } => {
                self.line(&item);
                for (bar, (total, position)) in
                    self.bars.iter().zip([outpoints, scripts, transactions])
                {
                    bar.set_length(total);
                    bar.set_position(position);
                }
            }
            BackendEvent::Updating => {
                self.finish();
                println!("Updating wallet");
            }
            BackendEvent::Synced => println!("Wallet synced"),
            BackendEvent::ScanStarted => self.spinner(false),
            BackendEvent::CoreStarted => self.spinner(true),
            BackendEvent::ScanKeychain(keychain) => {
                self.line(&format!("\nScanning keychain [{keychain:?}]"))
            }
            BackendEvent::ScanScript { index, script } => {
                self.line(&format!("- idx {index}: {script}"))
            }
            BackendEvent::Persisting => self.message("Persisting updates"),
            BackendEvent::ScanFinished => {
                self.message("Scan complete");
                self.finish();
            }
            BackendEvent::CoreScanBlock { height, scanned } => self.message(&format!(
                "Current height: {height}, scanned {scanned} blocks"
            )),
            BackendEvent::CoreBlock {
                hash,
                height,
                scanned,
                elapsed,
            } => {
                self.line(&format!(
                    "Applied block {hash} at height {height} in {elapsed:?}"
                ));
                self.message(&format!(
                    "Current height: {height}, scanned {scanned} blocks"
                ));
            }
            BackendEvent::MempoolStarted => self.line("Scanning mempool"),
            BackendEvent::MempoolApplied { count, elapsed } => {
                self.line(&format!(
                    "Applied {count} unconfirmed transactions in {elapsed:?}"
                ));
                self.finish();
            }
            BackendEvent::ScriptScanFinished => {
                self.message("Script scan complete");
                self.finish();
            }
        }
    }
}

pub(crate) fn terminal_progress() -> Progress {
    let display = Mutex::new(Display::default());
    Progress::new(move |event| display.lock().expect("progress display lock").event(event))
}
