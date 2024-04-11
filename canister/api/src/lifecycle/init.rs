use crate::EncryptedEmailSenderConfig;
use candid::{CandidType, Deserialize};
use serde::Serialize;

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct InitOrUpgradeArgs {
    pub salt: Option<[u8; 32]>,
    pub email_sender_config: Option<EncryptedEmailSenderConfig>,
}
