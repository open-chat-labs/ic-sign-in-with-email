use crate::state::AuthResult;
use crate::{env, state};
use ic_cdk::{query, update};
use ic_http_certification::{HttpRequest, HttpResponse};
use magic_links::SignedMagicLink;
use querystring::QueryParams;

#[query]
fn http_request(request: HttpRequest) -> HttpResponse {
    handle_http_request(request, false)
}

#[update]
fn http_request_update(request: HttpRequest) -> HttpResponse {
    handle_http_request(request, true)
}

fn handle_http_request(request: HttpRequest, update: bool) -> HttpResponse {
    let Ok(path) = request.get_path() else {
        return not_found();
    };

    match path.as_str() {
        "/auth" => {
            let query = request.get_query().unwrap().unwrap_or_default();
            let params = querystring::querify(&query);
            let ciphertext = get_query_param_value(&params, "c").unwrap();
            let encrypted_key = get_query_param_value(&params, "k").unwrap();
            let nonce = get_query_param_value(&params, "n").unwrap();
            let signature = get_query_param_value(&params, "s").unwrap();

            let signed_magic_link =
                SignedMagicLink::from_hex_strings(&ciphertext, &encrypted_key, &nonce, &signature);

            let (status_code, body, upgrade) = match state::mutate(|s| {
                s.process_auth_request(signed_magic_link, update, env::now())
            }) {
                AuthResult::Success => (
                    200,
                    "Successfully signed in! You may now close this tab and return to OpenChat"
                        .to_string(),
                    false,
                ),
                AuthResult::RequiresUpgrade => (200, "".to_string(), true),
                AuthResult::LinkExpired => (400, "Link expired".to_string(), false),
                AuthResult::LinkInvalid(error) => (400, format!("Link invalid: {error}"), false),
            };

            HttpResponse {
                status_code,
                headers: vec![
                    ("content-type".to_string(), "text/plain".to_string()),
                    ("content-length".to_string(), body.len().to_string()),
                ],
                body: body.into_bytes(),
                upgrade: upgrade.then_some(true),
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
