use async_trait::async_trait;
use email_sender_core::EmailSender;

pub struct AwsEmailSender {}

#[async_trait]
impl EmailSender for AwsEmailSender {
    async fn send(&self, _email: String, _code: String) -> Result<(), String> {
        todo!()
    }
}
