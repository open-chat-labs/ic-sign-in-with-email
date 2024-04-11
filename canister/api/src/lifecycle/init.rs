use candid::{CandidType, Deserialize};
use serde::Serialize;

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct InitOrUpgradeArgs {
    pub salt: Option<[u8; 32]>,
    pub email_sender_config: Option<EmailSenderConfig>,
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub enum EmailSenderConfig {
    Aws(AwsEmailSenderConfig),
}

#[derive(CandidType, Serialize, Deserialize, Debug)]
pub struct AwsEmailSenderConfig {
    pub region: String,
    pub target_arn: String,
}
