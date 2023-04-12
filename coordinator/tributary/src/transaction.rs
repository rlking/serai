use core::fmt::Debug;
use std::{
  io,
  collections::{HashSet, HashMap},
};

use thiserror::Error;

use blake2::{Digest, Blake2b512};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use schnorr::SchnorrSignature;

use crate::ReadWrite;

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum TransactionError {
  /// This transaction was perceived as invalid against the current state.
  #[error("transaction temporally invalid")]
  Temporal,
  /// This transaction is definitively invalid.
  #[error("transaction definitively invalid")]
  Fatal,
}

/// Data for a signed transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signed {
  pub signer: <Ristretto as Ciphersuite>::G,
  pub nonce: u32,
  pub signature: SchnorrSignature<Ristretto>,
}

impl ReadWrite for Signed {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let signer = Ristretto::read_G(reader)?;

    let mut nonce = [0; 4];
    reader.read_exact(&mut nonce)?;
    let nonce = u32::from_le_bytes(nonce);

    let signature = SchnorrSignature::<Ristretto>::read(reader)?;

    Ok(Signed { signer, nonce, signature })
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.signer.to_bytes())?;
    writer.write_all(&self.nonce.to_le_bytes())?;
    self.signature.write(writer)
  }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TransactionKind {
  /// This tranaction should be provided by every validator, solely ordered by the block producer.
  ///
  /// This transaction is only valid if a supermajority of validators provided it.
  Provided,

  /// An unsigned transaction, only able to be included by the block producer.
  Unsigned,

  /// A signed transaction.
  Signed(Signed),
}

pub trait Transaction: Send + Sync + Clone + Eq + Debug + ReadWrite {
  fn kind(&self) -> TransactionKind;
  /// Return the hash of this transaction.
  ///
  /// The hash must NOT commit to the signature.
  fn hash(&self) -> [u8; 32];

  fn verify(&self) -> Result<(), TransactionError>;

  fn sig_hash(&self, genesis: [u8; 32]) -> <Ristretto as Ciphersuite>::F {
    <Ristretto as Ciphersuite>::F::from_bytes_mod_order_wide(
      &Blake2b512::digest([genesis, self.hash()].concat()).into(),
    )
  }
}

pub(crate) fn verify_transaction<T: Transaction>(
  tx: &T,
  genesis: [u8; 32],
  locally_provided: &mut HashSet<[u8; 32]>,
  next_nonces: &mut HashMap<<Ristretto as Ciphersuite>::G, u32>,
) -> Result<(), TransactionError> {
  match tx.kind() {
    TransactionKind::Provided => {
      if !locally_provided.remove(&tx.hash()) {
        Err(TransactionError::Temporal)?;
      }
    }
    TransactionKind::Unsigned => {}
    TransactionKind::Signed(Signed { signer, nonce, signature }) => {
      // TODO: Use presence as a whitelist, erroring on lack of
      if next_nonces.get(&signer).cloned().unwrap_or(0) != nonce {
        Err(TransactionError::Temporal)?;
      }
      next_nonces.insert(signer, nonce + 1);

      // TODO: Use Schnorr half-aggregation and a batch verification here
      if !signature.verify(signer, tx.sig_hash(genesis)) {
        Err(TransactionError::Fatal)?;
      }
    }
  }

  tx.verify()
}
