use async_trait::async_trait;

#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send(&self, email: String, code: String) -> Result<(), String>;
}
