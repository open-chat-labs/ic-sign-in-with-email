use candid::{CandidType, Deserialize};
use serde::Serialize;

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct InitArgs {
    pub salt: Option<[u8; 32]>,
}
