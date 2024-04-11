use async_trait::async_trait;
use email_sender_core::EmailSender;
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpHeader, HttpMethod, HttpResponse,
};
use query_string_builder::QueryString;
use reqwest::header::HeaderMap;
use serde::Serialize;

pub struct AwsEmailSender {
    region: String,
    target_arn: String,
    access_key: String,
    secret_key: String,
}

impl AwsEmailSender {
    pub fn new(
        region: String,
        target_arn: String,
        access_key: String,
        secret_key: String,
    ) -> AwsEmailSender {
        AwsEmailSender {
            region,
            target_arn,
            access_key,
            secret_key,
        }
    }

    fn build_headers_and_url(
        &self,
        email: String,
        code: String,
        idempotency_id: u64,
        now_millis: u64,
    ) -> (Vec<HttpHeader>, String) {
        let datetime = chrono::DateTime::from_timestamp_millis(now_millis as i64).unwrap();

        let mut header_map = HeaderMap::new();
        header_map.insert(
            "X-Amz-Date",
            datetime
                .format("%Y%m%dT%H%M%SZ")
                .to_string()
                .parse()
                .unwrap(),
        );

        let message = EmailAndCode { email, code };

        let query_string = QueryString::new()
            .with_value("Action", "Publish")
            .with_value("TargetArn", &self.target_arn)
            .with_value("MessageStructure", "JSON")
            .with_value("Message", serde_json::to_string(&message).unwrap())
            .with_value("MessageDeduplicationId", idempotency_id.to_string());

        let region = &self.region;
        let url = format!("https://sns.{region}.amazonaws.com/{query_string}");

        let signature = aws_sign_v4::AwsSign::new(
            "POST",
            &url,
            &datetime,
            &header_map,
            &self.region,
            &self.access_key,
            &self.secret_key,
            "SNS",
            "",
        )
        .sign();

        header_map.insert(reqwest::header::AUTHORIZATION, signature.parse().unwrap());

        let headers = header_map
            .into_iter()
            .map(|h| HttpHeader {
                name: h.0.unwrap().to_string(),
                value: h.1.to_str().unwrap().to_string(),
            })
            .collect();

        (headers, url)
    }
}

#[derive(Serialize)]
struct EmailAndCode {
    email: String,
    code: String,
}

#[async_trait]
impl EmailSender for AwsEmailSender {
    async fn send(
        &self,
        email: String,
        code: String,
        idempotency_id: u64,
        now_millis: u64,
    ) -> Result<(), String> {
        let (headers, url) = self.build_headers_and_url(email, code, idempotency_id, now_millis);

        let args = CanisterHttpRequestArgument {
            url,
            max_response_bytes: Some(5 * 1024), // 5KB
            method: HttpMethod::POST,
            headers,
            body: None,
            transform: None,
        };

        let status_code: u32 =
            ic_cdk::api::management_canister::http_request::http_request_with_closure(
                args,
                1_000_000_000,
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
