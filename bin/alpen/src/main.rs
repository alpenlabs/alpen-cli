//! Alpen CLI

pub use alpen_bitcoin_wallet as bitcoin;
pub use alpen_wallet as alpen;
pub mod chain;
pub mod cmd;
pub mod constants;
mod fees;
mod link;
mod progress;
pub use alpen_bitcoin_wallet::recovery;
pub mod seed;
pub mod settings;

use std::process::exit;

use alpen_cli as _;
use bitcoin::persist::set_data_dir;
use cmd::{
    Commands, TopLevel, backup::backup, balance::balance, config::config, deposit::deposit,
    drain::drain, receive::receive, recover::recover, scan::scan, send::send, withdraw::withdraw,
};
use cmd::{change_pwd::change_pwd, reset::reset};
use seed::KeychainPersister;
use settings::Settings;

use crate::cmd::debug::debug;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let TopLevel { cmd } = argh::from_env();

    if let Commands::Config(args) = cmd {
        config(args).await;
        return;
    }

    let settings = Settings::load().unwrap_or_else(|e| {
        eprintln!("Configuration error: {e:?}");
        exit(1);
    });

    if let Commands::Reset(args) = cmd {
        let result = reset(args, KeychainPersister, settings).await;
        if let Err(err) = result {
            eprintln!("{err}");
        }
        return;
    }

    assert!(set_data_dir(settings.data_dir.clone(), settings.network));

    let seed = seed::load_or_create(&KeychainPersister).unwrap_or_else(|e| {
        eprintln!("{e:?}");
        exit(1);
    });

    let result = match cmd {
        Commands::Recover(args) => recover(args, seed, settings).await,
        Commands::Drain(args) => drain(args, seed, settings).await,
        Commands::Balance(args) => balance(args, seed, settings).await,
        Commands::Backup(_) => backup(seed).await,
        Commands::Deposit(args) => deposit(args, seed, settings).await,
        Commands::Withdraw(args) => withdraw(args, seed, settings).await,
        Commands::Send(args) => send(args, seed, settings).await,
        Commands::Receive(args) => receive(args, seed, settings).await,
        Commands::ChangePwd(args) => change_pwd(args, seed, KeychainPersister).await,
        Commands::Scan(args) => scan(args, seed, settings).await,
        Commands::Debug(args) => debug(args, seed, settings).await,
        Commands::Config(_) => unreachable!("handled prior"),
        Commands::Reset(_) => unreachable!("handled prior"),
    };

    if let Err(err) = result {
        eprintln!("{err}");
        exit(1);
    }
}
