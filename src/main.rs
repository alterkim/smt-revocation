mod snark;
mod node;
mod ledger;

use bellman::groth16::{VerifyingKey, self};
use blake3::Hasher;
use bls12_381::Bls12;
use monotree::{Monotree, utils::random_hash, Result, Proof};
use snark::{create_params, create_pvk, create_proof, verify_proof};
use node::Transaction;

fn main() -> Result<()>{
    // Proof generation
    let parameters = create_params();
    let pvk = create_pvk(&parameters.vk);
    let proof = create_proof(&parameters, 1, 1, 1, 1);

    // Create tranaction & proof verification
    let txn = Transaction::new("1".to_string(), proof, parameters.vk, 1);
    let verified = verify_proof(&pvk, &txn.payload.proof);
    assert_eq!(verified, true);

    // Hash transaction
    let hashed_txn = txn.hash().unwrap();

    // Store transaction to Sparse Merkle Tree
    let mut tree = Monotree::default();

    let root = None;

    let seq_no = txn.metadata.seq_no;
    let set_no_bytes = seq_no.to_be_bytes();
    let mut hasher = Hasher::new();
    hasher.update(&set_no_bytes);
    let hash = hasher.finalize();
    let key = hash.as_bytes();
    let value: [u8; 32] = hashed_txn.try_into().expect("Wrong length");
    let root = tree.insert(root.as_ref(), key, &value)?;
    assert_ne!(root, None);

    Ok(())
}

