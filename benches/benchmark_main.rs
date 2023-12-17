

use bellman::groth16::{Proof, VerifyingKey};
use blake3::Hasher;
use bls12_381::Bls12;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use monotree::Monotree;
use smt_revocation::{snark::{create_params, create_pvk, create_proof, verify_proof}, node::Transaction};

fn generate_proof() -> (Proof<Bls12>, VerifyingKey<Bls12>) {
    let msb = 1;
    let name_type = 1;
    let email_type = 1;
    let date_type = 1;
    let parameters = create_params();
    let proof = create_proof(&parameters, msb, name_type, email_type, date_type);
    (proof, parameters.vk)
}

fn verify_proof_transaction(proof: Proof<Bls12>, vk: VerifyingKey<Bls12>) ->(bool, Vec<u8>) {
    let txn = Transaction::new("1".to_string(), proof, vk, 1);
    let pvk = create_pvk(&txn.payload.verifying_key);
    let verified = verify_proof(&pvk, &txn.payload.proof);
    let hashed_txn = txn.hash().unwrap();
    (verified, hashed_txn)
}

fn store_transaction(tree: Monotree, seq_no: u64, hashed_txn: Vec<u8>) -> Monotree {
    let root = None;
    let set_no_bytes = seq_no.to_be_bytes();
    let mut hasher = Hasher::new();
    hasher.update(&set_no_bytes);
    let hash = hasher.finalize();
    let key = hash.as_bytes();
    let value: [u8; 32] = hashed_txn.try_into().expect("Wrong length");
    let root = tree.insert(root.as_ref(), key, &value).unwrap();
    root
}


fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("generate_proof 100", |b| {
        b.iter(|| {
            for _ in 0..100 {
                black_box(generate_proof());
            }
        })
    });
}

fn criterion_benchmark2(c: &mut Criterion) {
    c.bench_function("verify_proof_transaction", |b| {
        b.iter_with_setup(
            || generate_proof(),
            |(proof, vk)| {
                for _ in 0..10{
                    black_box(verify_proof_transaction(proof.clone(), vk.clone()));
                }
            },
        )
    });
}

criterion_group!(benches, criterion_benchmark2);
criterion_main!(benches);