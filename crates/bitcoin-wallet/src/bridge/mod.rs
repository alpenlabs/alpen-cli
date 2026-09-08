//! Bitcoin deposit-request construction for the Alpen bridge.
use alloy::primitives::Address as AlpenAddress;
use alpen_wallet_keys::DrtReclaimKeypair;
use bdk_wallet::{
    KeychainKind, TxOrdering, Wallet,
    bitcoin::{
        Address as BitcoinAddress, Amount, FeeRate, Network, PrivateKey, Transaction, TxOut,
        XOnlyPublicKey, secp256k1::SECP256K1,
    },
    coin_selection::InsufficientFunds,
    descriptor::IntoWalletDescriptor,
    error::CreateTxError,
    template::DescriptorTemplateOut,
};
use strata_asm_proto_bridge_txs::deposit_request::DrtHeaderAux;
use strata_cli_common::errors::DisplayedError;
use strata_identifiers::{AccountSerial, SYSTEM_RESERVED_ACCTS, SubjectIdBytes};
use strata_l1_txfmt::{MagicBytes, ParseConfig};
use strata_ol_bridge_types::DepositDescriptor;
use strata_primitives::crypto::even_kp;

/// Serial of the Alpen EE account used in deposit descriptors.
///
/// System serials occupy `0..SYSTEM_RESERVED_ACCTS`, so the Alpen EE account
/// currently lands at `SYSTEM_RESERVED_ACCTS` by genesis registration order.
pub const ALPEN_EE_ACCT_SERIAL: AccountSerial = AccountSerial::new(SYSTEM_RESERVED_ACCTS);

/// Build and sign the deposit-request transaction with the SPS-50 OP_RETURN in output 0 and the
/// bridge output in 1.
pub fn build_deposit_request_tx(
    l1w: &mut Wallet,
    header_aux: &DrtHeaderAux,
    deposit_output: &TxOut,
    magic_bytes: MagicBytes,
    fee_rate: FeeRate,
) -> Result<Transaction, DisplayedError> {
    let drt_sps50_tag = header_aux.build_tag_data();

    let sps50_script = ParseConfig::new(magic_bytes)
        .encode_script_buf(&drt_sps50_tag.as_ref())
        .expect("drt metadata should be created");
    let mut builder = l1w.build_tx();
    // Important: the deposit won't be found by the sequencer if the order isn't correct.
    // Per SPS-50 spec: OP_RETURN must be at index 0, P2TR at index 1
    builder.ordering(TxOrdering::Untouched);
    builder.add_recipient(sps50_script, Amount::ZERO);
    builder.add_recipient(deposit_output.script_pubkey.clone(), deposit_output.value);
    builder.fee_rate(fee_rate);
    let mut psbt = match builder.finish() {
        Ok(psbt) => Ok(psbt),
        Err(CreateTxError::CoinSelection(e @ InsufficientFunds { .. })) => {
            Err(DisplayedError::UserError(
                "Failed to create bridge transaction".to_string(),
                Box::new(e),
            ))
        }
        Err(e) => panic!("Unexpected error in creating PSBT: {e:?}"),
    }?;

    l1w.sign(&mut psbt, Default::default())
        .expect("tx should be signed");
    Ok(psbt.extract_tx().expect("tx should be signed and ready"))
}

/// Prepare the bridge-in descriptor, address, and SPS-50 aux data for a deposit request.
pub fn prepare_deposit_request(
    bridge_pubkey: XOnlyPublicKey,
    network: Network,
    recover_delay: u16,
    alpen_address: AlpenAddress,
    bridge_in_amount: Amount,
    reclaim_keypair: DrtReclaimKeypair,
) -> (DescriptorTemplateOut, BitcoinAddress, DrtHeaderAux, TxOut) {
    let (secret_key, recovery_public_key) =
        even_kp((reclaim_keypair.secret_key, reclaim_keypair.public_key));
    let recovery_public_key = recovery_public_key.x_only_public_key().0;
    let recovery_private_key = PrivateKey::new(secret_key.into(), network);

    let bridge_in_desc = bridge_in_descriptor(bridge_pubkey, recovery_private_key, recover_delay);
    let bridge_in_address = {
        let desc = bridge_in_desc
            .clone()
            .into_wallet_descriptor(SECP256K1, network.into())
            .expect("valid descriptor");
        let mut temp_wallet = Wallet::create_single(desc)
            .network(network)
            .create_wallet_no_persist()
            .expect("valid descriptor");
        temp_wallet
            .reveal_next_address(KeychainKind::External)
            .address
    };

    let alpen_subject_bytes =
        SubjectIdBytes::try_new(alpen_address.to_vec()).expect("must be valid subject bytes");
    let deposit_descriptor = DepositDescriptor::new(ALPEN_EE_ACCT_SERIAL, alpen_subject_bytes)
        .expect("EE serial is within valid range");
    let header_aux = DrtHeaderAux::new(
        recovery_public_key.serialize(),
        deposit_descriptor.encode_to_varvec(),
    )
    .expect("header aux creation should succeed");
    let deposit_output = TxOut {
        value: bridge_in_amount,
        script_pubkey: bridge_in_address.script_pubkey(),
    };
    (
        bridge_in_desc,
        bridge_in_address,
        header_aux,
        deposit_output,
    )
}

/// Generates a bridge-in descriptor for a given bridge public key and recovery address.
///
/// Returns a P2TR descriptor template for the bridge-in transaction.
///
/// # Implementation Details
///
/// This is a P2TR address that the key path spend is locked to the bridge aggregated public key
/// and the single script path spend is locked to the user's recovery address with a timelock of
pub fn bridge_in_descriptor(
    bridge_pubkey: XOnlyPublicKey,
    private_key: PrivateKey,
    recover_delay: u16,
) -> DescriptorTemplateOut {
    bdk_wallet::descriptor!(
        tr(bridge_pubkey,
            and_v(v:pk(private_key),older(recover_delay as u32))
        )
    )
    .expect("valid descriptor")
}

/// Computes the height at which a deposit's relative timelock (`recovery_delay` blocks past
/// `from_height`) becomes spendable, with `finality_depth` added as a reorg safety margin.
///
/// `from_height` is the current chain tip when called at deposit time (an estimate, since the
/// deposit hasn't confirmed yet), or a deposit's actual funding confirmation height when called
/// during recovery.
pub fn compute_recover_at_height(
    from_height: u32,
    recovery_delay: u32,
    finality_depth: u32,
) -> u32 {
    from_height
        .saturating_add(recovery_delay)
        .saturating_add(finality_depth)
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use bdk_wallet::{
        bitcoin::{Amount, FeeRate, Network, bip32::Xpriv, secp256k1::SECP256K1},
        keys::{DescriptorPublicKey, SinglePub, SinglePubKey},
        miniscript::{Descriptor, Miniscript, descriptor::TapTree},
    };
    use rand_core::OsRng;
    use strata_asm_proto_bridge_txs::deposit_request::parse_drt;
    use strata_primitives::constants::RECOVER_DELAY;
    use strata_test_utils_btcio::BtcioTestHarness;

    use super::*;

    /// Populate the wallet with on-chain data by replaying blocks from the corepc node.
    fn sync_wallet_from_node(wallet: &mut Wallet, harness: &BtcioTestHarness) {
        let node = harness.bitcoind();
        let tip_height = node.client.get_block_count().expect("block count").0;
        for height in 1..=tip_height {
            let block_hash = node
                .client
                .get_block_hash(height)
                .expect("block hash")
                .0
                .parse()
                .expect("block hash parse");
            let block = node.client.get_block(block_hash).expect("block");
            wallet
                .apply_block(&block, height as u32)
                .expect("apply block");
        }
    }

    #[test]
    fn bridge_in_desc() {
        let bridge_pubkey = XOnlyPublicKey::from_str(
            "89f96f834e39766f97e245d70b27236681f741ae51c117df19761af7cb2f657e",
        )
        .expect("valid pubkey");

        let (secret_key, public_key) = SECP256K1.generate_keypair(&mut OsRng);

        let recovery_private_key = PrivateKey::new(secret_key, Network::Bitcoin);

        let (desc, _key_map, _network) =
            bridge_in_descriptor(bridge_pubkey, recovery_private_key, RECOVER_DELAY);
        assert!(desc.sanity_check().is_ok());
        let Descriptor::Tr(tr_desc) = desc else {
            panic!("should be taproot descriptor")
        };

        let expected_recovery_script = format!("and_v(v:pk({public_key}),older({RECOVER_DELAY}))",);

        let expected_taptree = TapTree::Leaf(Arc::new(
            Miniscript::from_str(&expected_recovery_script).expect("valid miniscript"),
        ));

        let expected_internal_key = DescriptorPublicKey::Single(SinglePub {
            origin: None,
            key: SinglePubKey::XOnly(bridge_pubkey),
        });

        assert_eq!(
            tr_desc.internal_key(),
            &expected_internal_key,
            "internal key should be the bridge pubkey"
        );

        assert_eq!(
            tr_desc.tap_tree().as_ref().expect("taptree to be present"),
            &expected_taptree,
            "tap tree should be the expected taptree"
        )
    }

    #[test]
    fn deposit_request_tx_parses_in_asm() {
        let bridge_pubkey = XOnlyPublicKey::from_str(
            "89f96f834e39766f97e245d70b27236681f741ae51c117df19761af7cb2f657e",
        )
        .expect("valid pubkey");
        let alpen_address = AlpenAddress::from_str("0x5400000000000000000000000000000000000001")
            .expect("valid Alpen address");

        let harness =
            BtcioTestHarness::new_with_coinbase_maturity().expect("bitcoind harness should start");

        let xpriv = Xpriv::new_master(Network::Regtest, &[0u8; 32]).expect("valid xpriv");
        let base_desc = format!("tr({xpriv}/86h/0h/0h");
        let external_desc = format!("{base_desc}/0/*)");
        let internal_desc = format!("{base_desc}/1/*)");
        let mut wallet = Wallet::create(external_desc, internal_desc)
            .network(Network::Regtest)
            .create_wallet_no_persist()
            .expect("valid test wallet");

        let fund_address = wallet.reveal_next_address(KeychainKind::External).address;
        // Fund and confirm the wallet so PSBT construction has spendable inputs.
        let node = harness.bitcoind();
        node.client
            .send_to_address(&fund_address, Amount::from_sat(500_000))
            .expect("funding transaction should be created");
        harness
            .mine_blocks_blocking(1, None)
            .expect("block should be mined");
        sync_wallet_from_node(&mut wallet, &harness);

        let bridge_in_amount = Amount::from_sat(100_000);
        let (secret_key, public_key) = SECP256K1.generate_keypair(&mut OsRng);
        let (_bridge_in_desc, bridge_in_address, header_aux, deposit_output) =
            prepare_deposit_request(
                bridge_pubkey,
                Network::Regtest,
                RECOVER_DELAY,
                alpen_address,
                bridge_in_amount,
                DrtReclaimKeypair {
                    secret_key,
                    public_key,
                },
            );

        let tx = build_deposit_request_tx(
            &mut wallet,
            &header_aux,
            &deposit_output,
            MagicBytes::new(*b"ALPN"),
            FeeRate::from_sat_per_vb(1).expect("valid fee rate"),
        )
        .expect("tx should be built");
        let parsed = parse_drt(&tx).expect("tx should parse as DRT");
        assert_eq!(parsed.header_aux(), &header_aux);

        let parsed_output = parsed.deposit_request_output().inner();
        assert_eq!(parsed_output.value, bridge_in_amount);
        assert_eq!(
            parsed_output.script_pubkey,
            bridge_in_address.script_pubkey()
        );
    }
}
