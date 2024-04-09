use crate::{Nanoseconds, TimestampNanos};
use candid::{CandidType, Deserialize};
use serde::Serialize;

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct SubmitVerificationCodeArgs {
    pub code: String,
    #[serde(with = "serde_bytes")]
    pub session_key: Vec<u8>,
    pub max_time_to_live: Option<Nanoseconds>,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub enum SubmitVerificationCodeResponse {
    Success(SubmitVerificationCodeSuccess),
    CodeInvalid,
    NotFound,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct SubmitVerificationCodeSuccess {
    #[serde(with = "serde_bytes")]
    pub user_key: Vec<u8>,
    pub expiration: TimestampNanos,
}
