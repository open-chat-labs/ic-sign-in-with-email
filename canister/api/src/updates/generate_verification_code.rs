use crate::TimestampMillis;
use candid::{CandidType, Deserialize};
use serde::Serialize;

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct GenerateVerificationCodeArgs {
    pub email: String,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub enum GenerateVerificationCodeResponse {
    Success,
    Blocked(TimestampMillis),
    EmailInvalid,
}
