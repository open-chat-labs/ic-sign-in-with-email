use email_sender_core::EmailSender;
use std::sync::OnceLock;

static EMAIL_SENDER: OnceLock<Box<dyn EmailSender>> = OnceLock::new();

#[allow(dead_code)]
pub fn init(email_sender: impl EmailSender + 'static) {
    EMAIL_SENDER
        .set(Box::new(email_sender))
        .unwrap_or_else(|_| panic!("Email sender already set"));
}

pub async fn send_verification_code_email(email: String, code: String) -> Result<(), String> {
    let sender = EMAIL_SENDER.get().expect("Email sender has not been set");

    sender.send(email, code).await
}
