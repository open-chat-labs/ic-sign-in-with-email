use async_trait::async_trait;

#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send(
        &self,
        email: String,
        code: String,
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
        _code: String,
        _idempotency_id: u64,
        _now_millis: u64,
    ) -> Result<(), String> {
        Ok(())
    }
}
