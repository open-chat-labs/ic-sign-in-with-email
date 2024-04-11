use crate::rng;
use email_sender_core::EmailSender;
use sign_in_with_email_canister::EmailSenderConfig;
use std::sync::OnceLock;

static EMAIL_SENDER: OnceLock<Box<dyn EmailSender>> = OnceLock::new();

pub fn init(config: EmailSenderConfig) {
    #[allow(unused_variables)]
    match config {
        EmailSenderConfig::Aws(aws) => {
            #[cfg(feature = "email_sender_aws")]
            init_internal(email_sender_aws::AwsEmailSender::new(
                aws.region,
                aws.target_arn,
            ));

            #[cfg(not(feature = "email_sender_aws"))]
            panic!("Canister must be built with the \"aws\" feature enabled in order to use the AWS email sender");
        }
    }
}

#[allow(dead_code)]
fn init_internal(email_sender: impl EmailSender + 'static) {
    EMAIL_SENDER
        .set(Box::new(email_sender))
        .unwrap_or_else(|_| panic!("Email sender already set"));
}

pub async fn send_verification_code_email(email: String, code: String) -> Result<(), String> {
    let sender = EMAIL_SENDER.get().expect("Email sender has not been set");
    let idempotency_id = rng::gen();

    sender.send(email, code, idempotency_id).await
}
