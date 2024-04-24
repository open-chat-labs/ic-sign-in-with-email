use crate::{Milliseconds, Nanoseconds};
use candid::{CandidType, Deserialize};
use serde::Serialize;

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct GenerateVerificationCodeArgs {
    pub email: String,
    #[serde(with = "serde_bytes")]
    pub session_key: Vec<u8>,
    pub max_time_to_live: Option<Nanoseconds>,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub enum GenerateVerificationCodeResponse {
    Success,
    Blocked(Milliseconds),
    EmailInvalid,
    FailedToSendEmail(String),
}
