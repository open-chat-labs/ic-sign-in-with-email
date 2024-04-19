use crate::{Nanoseconds, TimestampMillis, TimestampNanos};
use candid::{CandidType, Deserialize};
use serde::Serialize;

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct SubmitVerificationCodeArgs {
    pub email: String,
    pub code: String,
    #[serde(with = "serde_bytes")]
    pub session_key: Vec<u8>,
    pub max_time_to_live: Option<Nanoseconds>,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub enum SubmitVerificationCodeResponse {
    Success(SubmitVerificationCodeSuccess),
    IncorrectCode(IncorrectCode),
    NotFound,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct SubmitVerificationCodeSuccess {
    #[serde(with = "serde_bytes")]
    pub user_key: Vec<u8>,
    pub expiration: TimestampNanos,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct IncorrectCode {
    pub attempts_remaining: u32,
    pub blocked_until: Option<TimestampMillis>,
}
