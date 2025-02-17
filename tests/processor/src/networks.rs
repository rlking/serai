use std::collections::HashSet;

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use scale::Encode;

use serai_client::{
  primitives::{Amount, NetworkId, Coin, Balance, ExternalAddress},
  validator_sets::primitives::ExternalKey,
  in_instructions::primitives::{InInstruction, RefundableInInstruction, Shorthand},
};

use dockertest::{PullPolicy, Image, StartPolicy, TestBodySpecification, DockerOperations};

use crate::*;

pub const RPC_USER: &str = "serai";
pub const RPC_PASS: &str = "seraidex";

pub const BTC_PORT: u32 = 8332;
pub const ETH_PORT: u32 = 8545;
pub const XMR_PORT: u32 = 18081;

pub fn bitcoin_instance() -> (TestBodySpecification, u32) {
  serai_docker_tests::build("bitcoin".to_string());

  let composition = TestBodySpecification::with_image(
    Image::with_repository("serai-dev-bitcoin").pull_policy(PullPolicy::Never),
  )
  .set_publish_all_ports(true);
  (composition, BTC_PORT)
}

pub fn ethereum_instance() -> (TestBodySpecification, u32) {
  serai_docker_tests::build("ethereum".to_string());

  let composition = TestBodySpecification::with_image(
    Image::with_repository("serai-dev-ethereum").pull_policy(PullPolicy::Never),
  )
  .set_start_policy(StartPolicy::Strict)
  .set_publish_all_ports(true);
  (composition, ETH_PORT)
}

pub fn monero_instance() -> (TestBodySpecification, u32) {
  serai_docker_tests::build("monero".to_string());

  let composition = TestBodySpecification::with_image(
    Image::with_repository("serai-dev-monero").pull_policy(PullPolicy::Never),
  )
  .set_start_policy(StartPolicy::Strict)
  .set_publish_all_ports(true);
  (composition, XMR_PORT)
}

pub fn network_instance(network: NetworkId) -> (TestBodySpecification, u32) {
  match network {
    NetworkId::Bitcoin => bitcoin_instance(),
    NetworkId::Ethereum => ethereum_instance(),
    NetworkId::Monero => monero_instance(),
    NetworkId::Serai => {
      panic!("Serai is not a valid network to spawn an instance of for a processor")
    }
  }
}

pub fn network_rpc(network: NetworkId, ops: &DockerOperations, handle: &str) -> String {
  let (ip, port) = ops
    .handle(handle)
    .host_port(match network {
      NetworkId::Bitcoin => BTC_PORT,
      NetworkId::Ethereum => ETH_PORT,
      NetworkId::Monero => XMR_PORT,
      NetworkId::Serai => panic!("getting port for external network yet it was Serai"),
    })
    .unwrap();
  format!("http://{RPC_USER}:{RPC_PASS}@{ip}:{port}")
}

pub fn confirmations(network: NetworkId) -> usize {
  use processor::networks::*;
  match network {
    NetworkId::Bitcoin => Bitcoin::CONFIRMATIONS,
    NetworkId::Ethereum => Ethereum::<serai_db::MemDb>::CONFIRMATIONS,
    NetworkId::Monero => Monero::CONFIRMATIONS,
    NetworkId::Serai => panic!("getting confirmations required for Serai"),
  }
}

#[derive(Clone)]
pub enum Wallet {
  Bitcoin {
    private_key: bitcoin_serai::bitcoin::PrivateKey,
    public_key: bitcoin_serai::bitcoin::PublicKey,
    input_tx: bitcoin_serai::bitcoin::Transaction,
  },
  Ethereum {
    rpc_url: String,
    key: <ciphersuite::Secp256k1 as Ciphersuite>::F,
    nonce: u64,
  },
  Monero {
    handle: String,
    spend_key: Zeroizing<curve25519_dalek::scalar::Scalar>,
    view_pair: monero_serai::wallet::ViewPair,
    inputs: Vec<monero_serai::wallet::ReceivedOutput>,
  },
}

// TODO: Merge these functions with the processor's tests, which offers very similar functionality
impl Wallet {
  pub async fn new(network: NetworkId, ops: &DockerOperations, handle: String) -> Wallet {
    let rpc_url = network_rpc(network, ops, &handle);

    match network {
      NetworkId::Bitcoin => {
        use bitcoin_serai::{
          bitcoin::{
            secp256k1::{SECP256K1, SecretKey},
            PrivateKey, PublicKey, ScriptBuf, Network, Address,
          },
          rpc::Rpc,
        };

        let secret_key = SecretKey::new(&mut rand_core::OsRng);
        let private_key = PrivateKey::new(secret_key, Network::Regtest);
        let public_key = PublicKey::from_private_key(SECP256K1, &private_key);
        let main_addr = Address::p2pkh(public_key, Network::Regtest);

        let rpc = Rpc::new(rpc_url).await.expect("couldn't connect to the Bitcoin RPC");

        let new_block = rpc.get_latest_block_number().await.unwrap() + 1;
        rpc
          .rpc_call::<Vec<String>>("generatetoaddress", serde_json::json!([1, main_addr]))
          .await
          .unwrap();

        // Mine it to maturity
        rpc
          .rpc_call::<Vec<String>>(
            "generatetoaddress",
            serde_json::json!([100, Address::p2sh(&ScriptBuf::new(), Network::Regtest).unwrap()]),
          )
          .await
          .unwrap();

        let funds = rpc
          .get_block(&rpc.get_block_hash(new_block).await.unwrap())
          .await
          .unwrap()
          .txdata
          .swap_remove(0);

        Wallet::Bitcoin { private_key, public_key, input_tx: funds }
      }

      NetworkId::Ethereum => {
        use ciphersuite::{group::ff::Field, Secp256k1};
        use ethereum_serai::alloy::{
          primitives::{U256, Address},
          simple_request_transport::SimpleRequest,
          rpc_client::ClientBuilder,
          provider::{Provider, RootProvider},
          network::Ethereum,
        };

        let key = <Secp256k1 as Ciphersuite>::F::random(&mut OsRng);
        let address =
          ethereum_serai::crypto::address(&(<Secp256k1 as Ciphersuite>::generator() * key));

        let provider = RootProvider::<_, Ethereum>::new(
          ClientBuilder::default().transport(SimpleRequest::new(rpc_url.clone()), true),
        );

        provider
          .raw_request::<_, ()>(
            "anvil_setBalance".into(),
            [Address(address.into()).to_string(), {
              let nine_decimals = U256::from(1_000_000_000u64);
              (U256::from(100u64) * nine_decimals * nine_decimals).to_string()
            }],
          )
          .await
          .unwrap();

        Wallet::Ethereum { rpc_url: rpc_url.clone(), key, nonce: 0 }
      }

      NetworkId::Monero => {
        use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
        use monero_serai::{
          wallet::{
            ViewPair, Scanner,
            address::{Network, AddressSpec},
          },
          rpc::HttpRpc,
        };

        let mut bytes = [0; 64];
        OsRng.fill_bytes(&mut bytes);
        let spend_key = Scalar::from_bytes_mod_order_wide(&bytes);
        OsRng.fill_bytes(&mut bytes);
        let view_key = Scalar::from_bytes_mod_order_wide(&bytes);

        let view_pair =
          ViewPair::new(ED25519_BASEPOINT_POINT * spend_key, Zeroizing::new(view_key));

        let rpc = HttpRpc::new(rpc_url).await.expect("couldn't connect to the Monero RPC");

        let height = rpc.get_height().await.unwrap();
        // Mines 200 blocks so sufficient decoys exist, as only 60 is needed for maturity
        let _: EmptyResponse = rpc
          .json_rpc_call(
            "generateblocks",
            Some(serde_json::json!({
              "wallet_address": view_pair.address(
                Network::Mainnet,
                AddressSpec::Standard
              ).to_string(),
              "amount_of_blocks": 200,
            })),
          )
          .await
          .unwrap();
        let block = rpc.get_block(rpc.get_block_hash(height).await.unwrap()).await.unwrap();

        let output = Scanner::from_view(view_pair.clone(), Some(HashSet::new()))
          .scan(&rpc, &block)
          .await
          .unwrap()
          .remove(0)
          .ignore_timelock()
          .remove(0);

        Wallet::Monero {
          handle,
          spend_key: Zeroizing::new(spend_key),
          view_pair,
          inputs: vec![output.output.clone()],
        }
      }
      NetworkId::Serai => panic!("creating a wallet for for Serai"),
    }
  }

  pub async fn send_to_address(
    &mut self,
    ops: &DockerOperations,
    to: &ExternalKey,
    instruction: Option<InInstruction>,
  ) -> (Vec<u8>, Balance) {
    match self {
      Wallet::Bitcoin { private_key, public_key, ref mut input_tx } => {
        use bitcoin_serai::bitcoin::{
          secp256k1::{SECP256K1, Message},
          key::{XOnlyPublicKey, TweakedPublicKey},
          consensus::Encodable,
          sighash::{EcdsaSighashType, SighashCache},
          script::{PushBytesBuf, Script, ScriptBuf, Builder},
          OutPoint, Sequence, Witness, TxIn, Amount, TxOut,
          absolute::LockTime,
          transaction::{Version, Transaction},
        };

        const AMOUNT: u64 = 100000000;
        let mut tx = Transaction {
          version: Version(2),
          lock_time: LockTime::ZERO,
          input: vec![TxIn {
            previous_output: OutPoint { txid: input_tx.compute_txid(), vout: 0 },
            script_sig: Script::new().into(),
            sequence: Sequence(u32::MAX),
            witness: Witness::default(),
          }],
          output: vec![
            TxOut {
              value: Amount::from_sat(input_tx.output[0].value.to_sat() - AMOUNT - 10000),
              script_pubkey: input_tx.output[0].script_pubkey.clone(),
            },
            TxOut {
              value: Amount::from_sat(AMOUNT),
              script_pubkey: ScriptBuf::new_p2tr_tweaked(
                TweakedPublicKey::dangerous_assume_tweaked(
                  XOnlyPublicKey::from_slice(&to[1 ..]).unwrap(),
                ),
              ),
            },
          ],
        };

        if let Some(instruction) = instruction {
          tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return(
              PushBytesBuf::try_from(
                Shorthand::Raw(RefundableInInstruction { origin: None, instruction }).encode(),
              )
              .unwrap(),
            ),
          });
        }

        let mut der = SECP256K1
          .sign_ecdsa_low_r(
            &Message::from_digest_slice(
              SighashCache::new(&tx)
                .legacy_signature_hash(
                  0,
                  &input_tx.output[0].script_pubkey,
                  EcdsaSighashType::All.to_u32(),
                )
                .unwrap()
                .to_raw_hash()
                .as_ref(),
            )
            .unwrap(),
            &private_key.inner,
          )
          .serialize_der()
          .to_vec();
        der.push(1);
        tx.input[0].script_sig = Builder::new()
          .push_slice(PushBytesBuf::try_from(der).unwrap())
          .push_key(public_key)
          .into_script();

        let mut buf = vec![];
        tx.consensus_encode(&mut buf).unwrap();
        *input_tx = tx;
        (buf, Balance { coin: Coin::Bitcoin, amount: Amount(AMOUNT) })
      }

      Wallet::Ethereum { rpc_url, key, ref mut nonce } => {
        use std::sync::Arc;
        use ethereum_serai::{
          alloy::{
            primitives::{U256, TxKind},
            sol_types::SolCall,
            simple_request_transport::SimpleRequest,
            consensus::{TxLegacy, SignableTransaction},
            rpc_client::ClientBuilder,
            provider::{Provider, RootProvider},
            network::Ethereum,
          },
          crypto::PublicKey,
          deployer::Deployer,
        };

        let eight_decimals = U256::from(100_000_000u64);
        let nine_decimals = eight_decimals * U256::from(10u64);
        let eighteen_decimals = nine_decimals * nine_decimals;
        let one_eth = eighteen_decimals;

        let provider = Arc::new(RootProvider::<_, Ethereum>::new(
          ClientBuilder::default().transport(SimpleRequest::new(rpc_url.clone()), true),
        ));

        let to_as_key = PublicKey::new(
          <ciphersuite::Secp256k1 as Ciphersuite>::read_G(&mut to.as_slice()).unwrap(),
        )
        .unwrap();
        let router_addr = {
          // Find the deployer
          let deployer = Deployer::new(provider.clone()).await.unwrap().unwrap();

          // Find the router, deploying if non-existent
          let router = if let Some(router) =
            deployer.find_router(provider.clone(), &to_as_key).await.unwrap()
          {
            router
          } else {
            let mut tx = deployer.deploy_router(&to_as_key);
            tx.gas_price = 1_000_000_000u64.into();
            let tx = ethereum_serai::crypto::deterministically_sign(&tx);
            let signer = tx.recover_signer().unwrap();
            let (tx, sig, _) = tx.into_parts();

            provider
              .raw_request::<_, ()>(
                "anvil_setBalance".into(),
                [signer.to_string(), (tx.gas_limit * tx.gas_price).to_string()],
              )
              .await
              .unwrap();

            let mut bytes = vec![];
            tx.encode_with_signature_fields(&sig, &mut bytes);
            let _ = provider.send_raw_transaction(&bytes).await.unwrap();

            provider.raw_request::<_, ()>("anvil_mine".into(), [96]).await.unwrap();

            deployer.find_router(provider.clone(), &to_as_key).await.unwrap().unwrap()
          };

          router.address()
        };

        let tx = TxLegacy {
          chain_id: None,
          nonce: *nonce,
          gas_price: 1_000_000_000u128,
          gas_limit: 200_000u128,
          to: TxKind::Call(router_addr.into()),
          // 1 ETH
          value: one_eth,
          input: ethereum_serai::router::abi::inInstructionCall::new((
            [0; 20].into(),
            one_eth,
            if let Some(instruction) = instruction {
              Shorthand::Raw(RefundableInInstruction { origin: None, instruction }).encode().into()
            } else {
              vec![].into()
            },
          ))
          .abi_encode()
          .into(),
        };

        *nonce += 1;

        let sig =
          k256::ecdsa::SigningKey::from(k256::elliptic_curve::NonZeroScalar::new(*key).unwrap())
            .sign_prehash_recoverable(tx.signature_hash().as_ref())
            .unwrap();

        let mut bytes = vec![];
        tx.encode_with_signature_fields(&sig.into(), &mut bytes);

        // We drop the bottom 10 decimals
        (
          bytes,
          Balance { coin: Coin::Ether, amount: Amount(u64::try_from(eight_decimals).unwrap()) },
        )
      }

      Wallet::Monero { handle, ref spend_key, ref view_pair, ref mut inputs } => {
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        use monero_serai::{
          Protocol,
          wallet::{
            address::{Network, AddressType, AddressMeta, Address},
            SpendableOutput, Decoys, Change, FeePriority, Scanner, SignableTransaction,
          },
          rpc::HttpRpc,
          decompress_point,
        };
        use processor::{additional_key, networks::Monero};

        let rpc_url = network_rpc(NetworkId::Monero, ops, handle);
        let rpc = HttpRpc::new(rpc_url).await.expect("couldn't connect to the Monero RPC");

        // Prepare inputs
        let outputs = std::mem::take(inputs);
        let mut these_inputs = vec![];
        for output in outputs {
          these_inputs.push(
            SpendableOutput::from(&rpc, output)
              .await
              .expect("prior transaction was never published"),
          );
        }
        let mut decoys = Decoys::fingerprintable_canonical_select(
          &mut OsRng,
          &rpc,
          Protocol::v16.ring_len(),
          rpc.get_height().await.unwrap(),
          &these_inputs,
        )
        .await
        .unwrap();

        let to_spend_key = decompress_point(<[u8; 32]>::try_from(to.as_ref()).unwrap()).unwrap();
        let to_view_key = additional_key::<Monero>(0);
        let to_addr = Address::new(
          AddressMeta::new(
            Network::Mainnet,
            AddressType::Featured { subaddress: false, payment_id: None, guaranteed: true },
          ),
          to_spend_key,
          ED25519_BASEPOINT_POINT * to_view_key.0,
        );

        // Create and sign the TX
        const AMOUNT: u64 = 1_000_000_000_000;
        let mut data = vec![];
        if let Some(instruction) = instruction {
          data.push(Shorthand::Raw(RefundableInInstruction { origin: None, instruction }).encode());
        }
        let tx = SignableTransaction::new(
          Protocol::v16,
          None,
          these_inputs.drain(..).zip(decoys.drain(..)).collect(),
          vec![(to_addr, AMOUNT)],
          &Change::new(view_pair, false),
          data,
          rpc.get_fee(Protocol::v16, FeePriority::Unimportant).await.unwrap(),
        )
        .unwrap()
        .sign(&mut OsRng, spend_key)
        .unwrap();

        // Push the change output
        inputs.push(
          Scanner::from_view(view_pair.clone(), Some(HashSet::new()))
            .scan_transaction(&tx)
            .ignore_timelock()
            .remove(0),
        );

        (tx.serialize(), Balance { coin: Coin::Monero, amount: Amount(AMOUNT) })
      }
    }
  }

  pub fn address(&self) -> ExternalAddress {
    use serai_client::networks;

    match self {
      Wallet::Bitcoin { public_key, .. } => {
        use bitcoin_serai::bitcoin::ScriptBuf;
        ExternalAddress::new(
          networks::bitcoin::Address::new(ScriptBuf::new_p2pkh(&public_key.pubkey_hash()))
            .unwrap()
            .into(),
        )
        .unwrap()
      }
      Wallet::Ethereum { key, .. } => ExternalAddress::new(
        ethereum_serai::crypto::address(&(ciphersuite::Secp256k1::generator() * key)).into(),
      )
      .unwrap(),
      Wallet::Monero { view_pair, .. } => {
        use monero_serai::wallet::address::{Network, AddressSpec};
        ExternalAddress::new(
          networks::monero::Address::new(
            view_pair.address(Network::Mainnet, AddressSpec::Standard),
          )
          .unwrap()
          .into(),
        )
        .unwrap()
      }
    }
  }
}
