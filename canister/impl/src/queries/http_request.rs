use crate::state;
use ic_cdk::query;
use ic_http_certification::{HttpRequest, HttpResponse};
use magic_links::{EncryptedMagicLink, SignedMagicLink};
use querystring::QueryParams;

#[query]
fn http_request(request: HttpRequest) -> HttpResponse {
    let Ok(path) = request.get_path() else {
        return not_found();
    };

    match path.as_str() {
        "auth" => {
            let query = request.get_query().unwrap().unwrap_or_default();
            let params = querystring::querify(&query);
            let link = get_query_param_value(&params, "link").unwrap();
            let signature = get_query_param_value(&params, "signature").unwrap();

            let signed_magic_link = SignedMagicLink::new(EncryptedMagicLink::from(link), signature);
            if state::read(|s| s.verify_magic_link(signed_magic_link)) {
                HttpResponse {
                    status_code: 200,
                    headers: Vec::new(),
                    body: Vec::new(),
                    upgrade: Some(true),
                }
            } else {
                let text = b"Magic link expired".to_vec();

                HttpResponse {
                    status_code: 200,
                    headers: vec![
                        ("content-type".to_string(), "application/text".to_string()),
                        ("content-length".to_string(), text.len().to_string()),
                    ],
                    body: text,
                    upgrade: Some(true),
                }
            }
        }
        _ => not_found(),
    }
}

fn get_query_param_value(params: &QueryParams, key: &str) -> Option<String> {
    params
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.to_string())
}

fn not_found() -> HttpResponse {
    HttpResponse {
        status_code: 404,
        headers: Vec::new(),
        body: Vec::new(),
        upgrade: None,
    }
}
