use crate::EncryptedEmailSenderConfig;
use candid::{CandidType, Deserialize};
use serde::Serialize;

#[derive(CandidType, Serialize, Deserialize, Debug, Default)]
pub struct InitOrUpgradeArgs {
    pub email_sender_config: Option<EncryptedEmailSenderConfig>,
    pub test_mode: Option<bool>,
}
