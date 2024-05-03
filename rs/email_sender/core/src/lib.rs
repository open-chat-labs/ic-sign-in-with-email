use async_trait::async_trait;
use magic_links::EncryptedMagicLink;

#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send(
        &self,
        email: String,
        magic_link: EncryptedMagicLink,
        idempotency_id: u64,
        now_millis: u64,
    ) -> Result<(), String>;
}

#[derive(Default)]
pub struct NullEmailSender {}

#[async_trait]
impl EmailSender for NullEmailSender {
    async fn send(
        &self,
        _email: String,
        _magic_link: EncryptedMagicLink,
        _idempotency_id: u64,
        _now_millis: u64,
    ) -> Result<(), String> {
        Ok(())
    }
}
