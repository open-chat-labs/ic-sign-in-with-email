use crate::{env, rng};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use candid::{CandidType, Deserialize};
use email_sender_core::EmailSender;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use serde::Serialize;
use sign_in_with_email_canister::{EncryptedAwsEmailSenderConfig, EncryptedEmailSenderConfig};
use std::sync::OnceLock;

static EMAIL_SENDER: OnceLock<Box<dyn EmailSender>> = OnceLock::new();

pub fn init_from_config(config: EmailSenderConfig) {
    #[allow(unused_variables)]
    match config {
        EmailSenderConfig::Aws(aws) => {
            #[cfg(feature = "email_sender_aws")]
            {
                init(email_sender_aws::AwsEmailSender::new(
                    aws.region,
                    aws.target_arn,
                    aws.access_key,
                    aws.secret_key,
                ));
            }

            #[cfg(not(feature = "email_sender_aws"))]
            panic!("Canister must be built with the \"aws\" feature enabled in order to use the AWS email sender");
        }
    }
}

pub fn init(email_sender: impl EmailSender + 'static) {
    EMAIL_SENDER
        .set(Box::new(email_sender))
        .unwrap_or_else(|_| panic!("Email sender already set"));
}

pub async fn send_verification_code_email(email: String, code: String) -> Result<(), String> {
    let sender = EMAIL_SENDER.get().expect("Email sender has not been set");
    let idempotency_id = rng::gen();

    sender.send(email, code, idempotency_id, env::now()).await
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub enum EmailSenderConfig {
    Aws(AwsEmailSenderConfig),
}

impl EmailSenderConfig {
    pub fn from_encrypted(
        config: EncryptedEmailSenderConfig,
        rsa_private_key: RsaPrivateKey,
    ) -> EmailSenderConfig {
        match config {
            EncryptedEmailSenderConfig::Aws(aws) => {
                EmailSenderConfig::Aws(AwsEmailSenderConfig::from_encrypted(aws, rsa_private_key))
            }
        }
    }
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug)]
pub struct AwsEmailSenderConfig {
    pub region: String,
    pub target_arn: String,
    pub access_key: String,
    pub secret_key: String,
}

impl AwsEmailSenderConfig {
    pub fn from_encrypted(
        config: EncryptedAwsEmailSenderConfig,
        rsa_private_key: RsaPrivateKey,
    ) -> AwsEmailSenderConfig {
        AwsEmailSenderConfig {
            region: config.region,
            target_arn: config.target_arn,
            access_key: decrypt(&config.access_key_encrypted, &rsa_private_key),
            secret_key: decrypt(&config.secret_key_encrypted, &rsa_private_key),
        }
    }
}

fn decrypt(value: &str, rsa_private_key: &RsaPrivateKey) -> String {
    String::from_utf8(
        rsa_private_key
            .decrypt(Pkcs1v15Encrypt, &BASE64_STANDARD.decode(value).unwrap())
            .unwrap(),
    )
    .unwrap()
}
