use candid::CandidType;
use serde::{Deserialize, Serialize};

mod lifecycle;
mod queries;
mod updates;

pub use lifecycle::*;
pub use queries::*;
pub use updates::*;

pub const ONE_MINUTE: Milliseconds = 60 * 1000;
pub const ONE_DAY: Milliseconds = 24 * 60 * ONE_MINUTE;
pub const NANOS_PER_MILLISECOND: u64 = 1_000_000;
pub const DEFAULT_SESSION_EXPIRATION_PERIOD: Nanoseconds = 30 * ONE_DAY * NANOS_PER_MILLISECOND;
pub const MAX_SESSION_EXPIRATION_PERIOD: Nanoseconds = 90 * ONE_DAY * NANOS_PER_MILLISECOND;

pub type Hash = [u8; 32];
pub type Milliseconds = u64;
pub type Nanoseconds = u64;
pub type TimestampMillis = u64;
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

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum EncryptedEmailSenderConfig {
    Aws(EncryptedAwsEmailSenderConfig),
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedAwsEmailSenderConfig {
    pub region: String,
    pub target_arn: String,
    pub access_key_encrypted: String,
    pub secret_key_encrypted: String,
}
