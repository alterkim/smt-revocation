

use bellman::groth16::{Proof, VerifyingKey};
use blake3::Hasher;
use bls12_381::Bls12;
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use monotree::{Monotree, utils::random_hash, Result, hasher};
use rand::Rng;
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

fn verify_proof_transaction(proof: Proof<Bls12>, vk: VerifyingKey<Bls12>, seq_no: u64) ->(bool, Vec<u8>) {
    let txn = Transaction::new("1".to_string(), proof, vk, seq_no);
    let pvk = create_pvk(&txn.payload.verifying_key);
    let verified = verify_proof(&pvk, &txn.payload.proof);
    let hashed_txn = txn.hash().unwrap();
    (verified, hashed_txn)
}

fn setup_smt(n: u64) -> (Monotree, Option<[u8; 32]>) {
    let mut tree = Monotree::default();
    let mut root = None;

    (1..n).for_each(|seq_no: u64| {
        let seq_no_bytes = seq_no.to_be_bytes();
        let hashed_txn = random_hash();
        let mut hasher = Hasher::new();
        hasher.update(&seq_no_bytes);
        let hash = hasher.finalize();
        let key = hash.as_bytes();

        root = tree.insert(root.as_ref(), key, &hashed_txn).unwrap();
        assert_ne!(root, None);
    });

    (tree, root)
}

fn non_inclusion_proof(tree: &mut Monotree, root: Option<[u8; 32]> ,n: u64) {
    let mut rng = rand::thread_rng();
    let random_seq_no = rng.gen_range(n+1..=n+100);
    let seq_no_bytes = random_seq_no.to_be_bytes();
    let mut hasher = Hasher::new();
    hasher.update(&seq_no_bytes);
    let hash = hasher.finalize();
    let key = hash.as_bytes();

    // Generate the merkle proof for the root and the key
    assert_eq!(tree.get(root.as_ref(), &key).unwrap(), None);
    
}

fn remove(tree: &mut Monotree, root: Option<[u8; 32]>, n: u64) {
    let mut rng = rand::thread_rng();
    let random_seq_no =rng.gen_range(1..=n);
    let seq_no_bytes = random_seq_no.to_be_bytes();
    let mut hasher = Hasher::new();
    hasher.update(&seq_no_bytes);
    let hash = hasher.finalize();
    let key = hash.as_bytes();

    let root = tree.remove(root.as_ref(), key).unwrap();
    assert_eq!(tree.get(root.as_ref(), key).unwrap(), None);
}

// Generate proof benchmark
fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("generate_proof", |b| {
        b.iter(|| {
            for _ in 0..100 {
                black_box(generate_proof());
            }
        })
    });
}

// Verify proof & create transaction benchmark
fn criterion_benchmark2(c: &mut Criterion) {
    c.bench_function("verify_proof_transaction", |b| {
        b.iter_with_setup(
            || generate_proof(),
            |(proof, vk)| {
                for n in 0..100{
                    black_box(verify_proof_transaction(proof.clone(), vk.clone(), n));
                }
            },
        )
    });
}

// SMT setup benchmark
fn criterion_benchmark3(c: &mut Criterion) {
    let mut group = c.benchmark_group("setup_benchmark");
    for n in (100..=100000).step_by(1000) {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| setup_smt(black_box(n)));
        });
    }
    group.finish();
}

// Non-inclusion proof benchmark
fn criterion_benchmark4(c: &mut Criterion) {
    let mut group = c.benchmark_group("non-inclusion_proof");
    for n in (1000..100000).step_by(4000) {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_with_setup(
                || setup_smt(n),
                |(mut tree, root)| {
                    non_inclusion_proof(&mut tree, root, n);
                },
            )
        });
    }
    group.finish();
}

// Remove benchmark
fn criterion_benchmark5(c: &mut Criterion) {
    let mut group = c.benchmark_group("remove");
    for n in (1000..100000).step_by(4000) {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter_with_setup(
                || setup_smt(n),
                |(mut tree, root)| {
                    criterion::black_box(remove(&mut tree, root, n));
                },
            )
        });
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark2);
criterion_main!(benches);