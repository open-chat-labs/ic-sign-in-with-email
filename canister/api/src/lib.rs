use candid::CandidType;
use serde::{Deserialize, Serialize};

mod lifecycle;
mod queries;
mod updates;

pub use lifecycle::*;
pub use queries::*;
pub use updates::*;

pub type Milliseconds = u64;
pub type Nanoseconds = u64;
pub type TimestampNanos = u64;

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct Delegation {
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>,
    pub expiration: TimestampNanos,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct SignedDelegation {
    pub delegation: Delegation,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}