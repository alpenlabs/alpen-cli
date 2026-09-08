//! Deposit recovery from persisted descriptors and deterministic seed-derived keys.
use crate::{
    BitcoinWallet,
    backend::BitcoinBackend,
    bridge::{bridge_in_descriptor, compute_recover_at_height},
    constants::RECOVERY_DESC_CLEANUP_DELAY,
    get_fee_rate,
    recovery::DescriptorRecovery,
    sync_wallet,
};
use alpen_wallet_keys::Seed;
use bdk_wallet::{
    KeychainKind, Wallet,
    bitcoin::{
        Address, Amount, FeeRate, Network, PrivateKey, ScriptBuf, Txid, XOnlyPublicKey,
        secp256k1::SECP256K1,
    },
    chain::ChainOracle,
    coin_selection::InsufficientFunds,
    descriptor::IntoWalletDescriptor,
    error::CreateTxError,
};
use chrono::Utc;
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::Arc,
};
use strata_cli_common::errors::{DisplayableError, DisplayedError};
use strata_primitives::crypto::even_kp;

/// Network and storage inputs required by deposit recovery.
#[derive(Clone, Debug)]
pub struct RecoveryConfig {
    pub network: Network,
    pub bitcoin_backend: Arc<dyn BitcoinBackend>,
    pub descriptor_db: PathBuf,
    pub bridge_musig2_pubkey: XOnlyPublicKey,
    pub recovery_delay: u16,
    pub finality_depth: u32,
    pub recovery_lookahead: u32,
    pub seed_recovery_gap_limit: u32,
}

/// Recovery progress reported to the caller for presentation.
#[derive(Debug)]
pub enum RecoveryEvent {
    Opening,
    Height(u32),
    NoDescriptors,
    FeeRate(FeeRate),
    Removed(u32),
    Recovering {
        address: Address,
        counter: Option<u32>,
    },
    Destination(Address),
    Broadcast(Txid),
    Scanning,
    NothingFound,
}

/// Returns whether an already-claimed descriptor's cleanup grace window has elapsed.
fn cleanup_delay_elapsed(recover_at: u32, current_height: u32) -> bool {
    current_height >= recover_at.saturating_add(RECOVERY_DESC_CLEANUP_DELAY)
}

pub async fn recover(
    fee_rate: Option<u64>,
    seed: Seed,
    settings: RecoveryConfig,
    report: &dyn Fn(RecoveryEvent),
) -> Result<(), DisplayedError> {
    let mut l1w = BitcoinWallet::new(
        seed.bitcoin_wallet(settings.network),
        settings.network,
        settings.recovery_lookahead,
        settings.bitcoin_backend.clone(),
    )
    .internal_error("Failed to load Bitcoin wallet")?;
    l1w.sync()
        .await
        .internal_error("Failed to sync Bitcoin wallet")?;

    report(RecoveryEvent::Opening);
    let mut descriptor_file = DescriptorRecovery::open(&seed, &settings.descriptor_db)
        .await
        .internal_error("Failed to open descriptor recovery file")?;
    let current_height = l1w
        .local_chain()
        .get_chain_tip()
        .expect("valid chain tip")
        .height;

    report(RecoveryEvent::Height(current_height));
    let descs = descriptor_file
        .read_descs(..=current_height)
        .await
        .internal_error("Failed to read descriptors after chain height")?;

    if descs.is_empty() {
        report(RecoveryEvent::NoDescriptors);
    }

    let fee_rate = get_fee_rate(fee_rate, settings.bitcoin_backend.as_ref()).await;
    report(RecoveryEvent::FeeRate(fee_rate));

    let mut drained_recovery_scripts = HashSet::new();
    for (key, desc) in descs {
        let desc = desc
            .clone()
            .into_wallet_descriptor(l1w.secp_ctx(), settings.network.into())
            .internal_error("Failed to convert to wallet descriptor")?;

        let mut recovery_wallet = Wallet::create_single(desc)
            .network(settings.network)
            .create_wallet_no_persist()
            .internal_error("Failed to create recovery wallet")?;

        // reveal the address for the wallet so we can sync it
        let address = recovery_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        sync_wallet(&mut recovery_wallet, settings.bitcoin_backend.clone())
            .await
            .internal_error("Failed to sync recovery wallet")?;
        let needs_recovery = recovery_wallet.balance().confirmed > Amount::ZERO;

        if !needs_recovery {
            if cleanup_delay_elapsed(key.recover_at, current_height) {
                descriptor_file
                    .remove(&key)
                    .internal_error("Failed to remove old descriptor")?;
                report(RecoveryEvent::Removed(key.recover_at));
            }
            continue;
        }

        report(RecoveryEvent::Recovering {
            address: address.clone(),
            counter: None,
        });
        drain_recovery_path(&mut recovery_wallet, &mut l1w, &settings, fee_rate, report).await?;
        drained_recovery_scripts.insert(address.script_pubkey());
    }

    let highest_discovered_counter = recover_from_seed(
        &seed,
        &settings,
        &mut l1w,
        fee_rate,
        &drained_recovery_scripts,
        report,
    )
    .await?;
    descriptor_file
        .ensure_reclaim_counter_at_least(highest_discovered_counter.unwrap_or(0))
        .await
        .internal_error("Failed to save the reconstructed reclaim counter")?;

    Ok(())
}

/// Drains `recovery_wallet`'s reclaim path (policy path index 1: recovery pubkey + timelock,
/// see [`bridge_in_descriptor`]) to `l1w`, signing and broadcasting the spend.
async fn drain_recovery_path(
    recovery_wallet: &mut Wallet,
    l1w: &mut BitcoinWallet,
    settings: &RecoveryConfig,
    fee_rate: FeeRate,
    report: &dyn Fn(RecoveryEvent),
) -> Result<(), DisplayedError> {
    recovery_wallet.transactions().for_each(|tx| {
        l1w.apply_unconfirmed_txs([(tx.tx_node.tx, Utc::now().timestamp() as u64)]);
    });

    let recover_to = l1w.reveal_next_address(KeychainKind::External).address;
    l1w.persist()
        .internal_error("Failed to persist Bitcoin wallet")?;
    report(RecoveryEvent::Destination(recover_to.clone()));

    let policy = recovery_wallet
        .policies(KeychainKind::External)
        .expect("valid descriptor use")
        .expect("a policy");

    // we want to drain the recovery path to the l1 wallet
    let mut psbt = {
        let mut builder = recovery_wallet.build_tx();
        // we want to spend via the 2nd option - the recovery + delay
        builder.policy_path(
            BTreeMap::from([(policy.id, vec![1])]),
            KeychainKind::External,
        );
        builder.drain_wallet();
        builder.drain_to(recover_to.script_pubkey());
        builder.fee_rate(fee_rate);
        match builder.finish() {
            Ok(psbt) => psbt,
            Err(CreateTxError::CoinSelection(e @ InsufficientFunds { .. })) => {
                return Err(DisplayedError::UserError(
                    "Failed to create PSBT".to_string(),
                    Box::new(e),
                ));
            }
            Err(e) => panic!("Unexpected error in creating PSBT: {e:?}"),
        }
    };

    assert!(
        recovery_wallet
            .sign(&mut psbt, Default::default())
            .expect("sign to be ok"),
        "transaction should be finalized"
    );

    let tx = psbt.extract_tx().expect("tx should be signed and ready");
    settings
        .bitcoin_backend
        .broadcast_tx(&tx)
        .await
        .internal_error("Failed to broadcast Bitcoin transaction")?;

    report(RecoveryEvent::Broadcast(tx.compute_txid()));

    Ok(())
}

#[derive(Debug)]
struct SeedRecoveryCandidate {
    counter: u32,
    script_pubkey: ScriptBuf,
}

fn seed_recovery_wallet(
    seed: &Seed,
    settings: &RecoveryConfig,
    counter: u32,
) -> Result<Wallet, DisplayedError> {
    let reclaim_keypair = seed.drt_reclaim_keypair(counter);
    let (secret_key, _) = even_kp((reclaim_keypair.secret_key, reclaim_keypair.public_key));
    let recovery_private_key = PrivateKey::new(secret_key.into(), settings.network);
    let descriptor = bridge_in_descriptor(
        settings.bridge_musig2_pubkey,
        recovery_private_key,
        settings.recovery_delay,
    );
    let wallet_descriptor = descriptor
        .into_wallet_descriptor(SECP256K1, settings.network.into())
        .internal_error("Failed to convert to wallet descriptor")?;

    Wallet::create_single(wallet_descriptor)
        .network(settings.network)
        .create_wallet_no_persist()
        .internal_error("Failed to create recovery wallet")
}

/// Finds reclaim-key counters with on-chain history in gap-limit-sized backend scans.
async fn discover_seed_candidates(
    seed: &Seed,
    settings: &RecoveryConfig,
    known_used_scripts: &HashSet<ScriptBuf>,
) -> Result<Vec<SeedRecoveryCandidate>, DisplayedError> {
    let mut discovered = Vec::new();
    let mut batch_start = 0u32;
    let scan_checkpoint = seed_recovery_wallet(seed, settings, 0)?.latest_checkpoint();

    loop {
        let batch_end = batch_start
            .checked_add(settings.seed_recovery_gap_limit)
            .expect("reclaim-key scan range must fit in u32");
        let mut candidates = Vec::with_capacity(settings.seed_recovery_gap_limit as usize);
        let mut scripts_to_scan = Vec::with_capacity(settings.seed_recovery_gap_limit as usize);

        for counter in batch_start..batch_end {
            let mut wallet = seed_recovery_wallet(seed, settings, counter)?;
            let script_pubkey = wallet
                .reveal_next_address(KeychainKind::External)
                .address
                .script_pubkey();
            if !known_used_scripts.contains(&script_pubkey) {
                scripts_to_scan.push(script_pubkey.clone());
            }
            candidates.push(SeedRecoveryCandidate {
                counter,
                script_pubkey,
            });
        }

        let backend_used_scripts = if scripts_to_scan.is_empty() {
            HashSet::new()
        } else {
            settings
                .bitcoin_backend
                .scan_scripts(scripts_to_scan, scan_checkpoint.clone())
                .await
                .internal_error("Failed to scan seed recovery scripts")?
        };
        let mut discovered_in_batch = candidates
            .into_iter()
            .filter(|candidate| {
                known_used_scripts.contains(&candidate.script_pubkey)
                    || backend_used_scripts.contains(&candidate.script_pubkey)
            })
            .collect::<Vec<_>>();

        if discovered_in_batch.is_empty() {
            break;
        }

        discovered.append(&mut discovered_in_batch);
        batch_start = batch_end;
    }

    Ok(discovered)
}

/// Reconstructs the allocator high-water mark without spending any recovered outputs.
pub async fn reconstruct_reclaim_counter(
    seed: &Seed,
    settings: &RecoveryConfig,
) -> Result<u32, DisplayedError> {
    let candidates = discover_seed_candidates(seed, settings, &HashSet::new()).await?;
    Ok(candidates
        .last()
        .map(|candidate| candidate.counter)
        .unwrap_or(0))
}

/// Reconstructs and recovers deposits directly from the seed, for deposits whose descriptor DB
/// entry is missing. Candidate scripts are scanned in batches so Bitcoin Core only replays the
/// chain once per gap-limit window, rather than once per candidate. Descriptors use the network's
/// *current* bridge pubkey and recovery delay; if either changed since a deposit was created, that
/// deposit won't be found here.
async fn recover_from_seed(
    seed: &Seed,
    settings: &RecoveryConfig,
    l1w: &mut BitcoinWallet,
    fee_rate: FeeRate,
    drained_recovery_scripts: &HashSet<ScriptBuf>,
    report: &dyn Fn(RecoveryEvent),
) -> Result<Option<u32>, DisplayedError> {
    report(RecoveryEvent::Scanning);

    let candidates = discover_seed_candidates(seed, settings, drained_recovery_scripts).await?;
    let highest_discovered_counter = candidates.last().map(|candidate| candidate.counter);
    let mut found_any = false;
    for candidate in candidates {
        if drained_recovery_scripts.contains(&candidate.script_pubkey) {
            continue;
        }

        let counter = candidate.counter;
        let mut recovery_wallet = seed_recovery_wallet(seed, settings, counter)?;
        let address = recovery_wallet
            .reveal_next_address(KeychainKind::External)
            .address;
        debug_assert_eq!(address.script_pubkey(), candidate.script_pubkey);

        sync_wallet(&mut recovery_wallet, settings.bitcoin_backend.clone())
            .await
            .internal_error("Failed to sync recovery wallet")?;

        if recovery_wallet.transactions().next().is_none() {
            continue;
        }

        let current_height = recovery_wallet
            .local_chain()
            .get_chain_tip()
            .expect("valid chain tip")
            .height;
        let matured = recovery_wallet
            .list_unspent()
            .filter_map(|utxo| utxo.chain_position.confirmation_height_upper_bound())
            .all(|confirmed_at| {
                current_height
                    >= compute_recover_at_height(
                        confirmed_at,
                        settings.recovery_delay as u32,
                        settings.finality_depth,
                    )
            });

        if matured && recovery_wallet.balance().confirmed > Amount::ZERO {
            found_any = true;
            report(RecoveryEvent::Recovering {
                address,
                counter: Some(counter),
            });
            drain_recovery_path(&mut recovery_wallet, l1w, settings, fee_rate, report).await?;
        }
    }

    if !found_any {
        report(RecoveryEvent::NothingFound);
    }

    Ok(highest_discovered_counter)
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, str::FromStr};

    use super::*;
    use crate::tests::TestBitcoinBackend;

    #[tokio::test]
    async fn minimum_gap_limit_discovers_first_allocated_counter() {
        let seed = Seed::from_entropy([0; 16]);
        let mut settings = RecoveryConfig {
            network: Network::Signet,
            bitcoin_backend: Arc::new(TestBitcoinBackend::default()),
            descriptor_db: PathBuf::new(),
            bridge_musig2_pubkey: XOnlyPublicKey::from_str(
                "1d3e9c0417ba7d3551df5a1cc1dbe227aa4ce89161762454d92bfc2b1d5886f7",
            )
            .unwrap(),
            recovery_delay: 36,
            finality_depth: 6,
            recovery_lookahead: 50,
            seed_recovery_gap_limit: 2,
        };
        let mut counter_one_wallet = seed_recovery_wallet(&seed, &settings, 1).unwrap();
        let counter_one_script = counter_one_wallet
            .reveal_next_address(KeychainKind::External)
            .address
            .script_pubkey();
        settings.bitcoin_backend = Arc::new(TestBitcoinBackend {
            used_scripts: HashSet::from([counter_one_script]),
            ..Default::default()
        });

        let candidates = discover_seed_candidates(&seed, &settings, &HashSet::new())
            .await
            .unwrap();

        assert_eq!(
            candidates
                .into_iter()
                .map(|candidate| candidate.counter)
                .collect::<Vec<_>>(),
            vec![1]
        );
    }

    #[test]
    fn test_cleanup_delay_not_elapsed_keeps_descriptor() {
        let recover_at = 1_000;

        assert!(!cleanup_delay_elapsed(recover_at, recover_at));
        assert!(!cleanup_delay_elapsed(
            recover_at,
            recover_at + RECOVERY_DESC_CLEANUP_DELAY - 1
        ));
    }

    #[test]
    fn test_cleanup_delay_exactly_elapsed_removes_descriptor() {
        let recover_at = 1_000;

        assert!(cleanup_delay_elapsed(
            recover_at,
            recover_at + RECOVERY_DESC_CLEANUP_DELAY
        ));
    }

    #[test]
    fn test_cleanup_delay_well_past_removes_descriptor() {
        let recover_at = 1_000;

        assert!(cleanup_delay_elapsed(
            recover_at,
            recover_at + RECOVERY_DESC_CLEANUP_DELAY + 1_000
        ));
    }

    #[test]
    fn test_cleanup_delay_saturates_near_max_height() {
        let recover_at = u32::MAX;

        assert!(cleanup_delay_elapsed(recover_at, u32::MAX));
        assert!(!cleanup_delay_elapsed(recover_at, u32::MAX - 1));
    }
}
