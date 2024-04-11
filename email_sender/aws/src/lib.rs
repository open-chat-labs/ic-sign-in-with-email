use async_trait::async_trait;
use email_sender_core::EmailSender;
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpMethod, HttpResponse,
};
use query_string_builder::QueryString;
use serde::Serialize;

pub struct AwsEmailSender {
    region: String,
    target_arn: String,
}

impl AwsEmailSender {
    pub fn new(region: String, target_arn: String) -> AwsEmailSender {
        AwsEmailSender { region, target_arn }
    }

    fn build_url(&self, email: String, code: String, idempotency_id: u64) -> String {
        let message = EmailAndCode { email, code };

        let query_string = QueryString::new()
            .with_value("Action", "Publish")
            .with_value("TargetArn", &self.target_arn)
            .with_value("MessageStructure", "JSON")
            .with_value("Message", serde_json::to_string(&message).unwrap())
            .with_value("MessageDeduplicationId", idempotency_id.to_string());

        let region = &self.region;

        format!("https://sns.{region}.amazonaws.com/{query_string}")
    }
}

#[derive(Serialize)]
struct EmailAndCode {
    email: String,
    code: String,
}

#[async_trait]
impl EmailSender for AwsEmailSender {
    async fn send(&self, email: String, code: String, idempotency_id: u64) -> Result<(), String> {
        let args = CanisterHttpRequestArgument {
            url: self.build_url(email, code, idempotency_id),
            max_response_bytes: Some(5 * 1024), // 5KB
            method: HttpMethod::POST,
            headers: Vec::new(),
            body: None,
            transform: None,
        };

        let status_code: u32 =
            ic_cdk::api::management_canister::http_request::http_request_with_closure(
                args,
                100_000_000,
                |response| HttpResponse {
                    status: response.status,
                    ..Default::default()
                },
            )
            .await
            .map(|(r,)| r.status.0.try_into().unwrap())
            .map_err(|e| format!("{e:?}"))?;

        if status_code == 200 {
            Ok(())
        } else {
            Err(format!("Response code: {status_code}"))
        }
    }
}
