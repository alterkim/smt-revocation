use std::time::SystemTime;

use bincode::serialize;
use blake3::Hasher;
use bellman::groth16::{Proof, VerifyingKey};
use bls12_381::Bls12;
use serde::ser::{Serialize, Serializer, SerializeStruct};

pub struct Transaction {
    pub ver: String,
    pub payload: Payload,
    pub metadata: Metadata,
}

impl Transaction {
    pub fn new(txn_type: String, proof: Proof<Bls12>, vk: VerifyingKey<Bls12>, seq_no: u64) -> Self {
        let payload = Payload {txn_type, proof, verifying_key: vk};
        let metadata = Metadata::new(seq_no);

        Transaction {ver: "1".to_string(), payload, metadata}
    }

    pub fn hash(&self) -> Result<Vec<u8>, Box<bincode::ErrorKind>> {
        let bytes = serialize(self)?;
        let mut hasher = Hasher::new();
        hasher.update(&bytes);
        let hash = hasher.finalize();
        Ok(hash.as_bytes().to_vec())
    }
}

impl Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer {
        let mut state = serializer.serialize_struct("Transaction", 3)?;
        state.serialize_field("ver", &self.ver)?;
        state.serialize_field("payload", &self.payload)?;
        state.serialize_field("metadata", &self.metadata)?;
        state.end()
    }
}

pub struct Payload {
    pub txn_type: String,
    pub proof: Proof<Bls12>,
    pub verifying_key: VerifyingKey<Bls12>,
}

impl Serialize for Payload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer {
        let mut state = serializer.serialize_struct("Payload", 3)?;
        state.serialize_field("txn_type", &self.txn_type)?;

        // Serialize proof
        let mut proof_bytes = vec![];
        self.proof.write(&mut proof_bytes).unwrap();

        // Serilaize verifying key
        let mut vk_bytes = vec![];
        self.verifying_key.write(&mut vk_bytes).unwrap();

        // Add proof and verifying key to state
        state.serialize_field("proof", &proof_bytes)?;
        state.serialize_field("verifying_key", &vk_bytes)?;
        state.end()
    }
}

pub struct Metadata {
    pub seq_no: u64,
    pub txn_time: u64,
}

impl Metadata {
    pub fn new(seq_no:u64) -> Self {
        let txn_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Metadata {seq_no, txn_time}
    }
}

impl Serialize for Metadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer {
        let mut state = serializer.serialize_struct("Metadata", 2)?;
        state.serialize_field("seq_no", &self.seq_no)?;
        state.serialize_field("txn_time", &self.txn_time)?;
        state.end()
    }
}
