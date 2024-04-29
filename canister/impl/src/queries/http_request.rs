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
        "auth" => {
            let query = request.get_query().unwrap().unwrap_or_default();
            let params = querystring::querify(&query);
            let ciphertext = get_query_param_value(&params, "c").unwrap();
            let encrypted_key = get_query_param_value(&params, "k").unwrap();
            let nonce = get_query_param_value(&params, "n").unwrap();
            let signature = get_query_param_value(&params, "s").unwrap();

            let signed_magic_link = SignedMagicLink::new_from_hex_strings(
                &ciphertext,
                &encrypted_key,
                &nonce,
                &signature,
            );

            if let Ok(magic_link) = state::read(|s| s.unwrap_magic_link(signed_magic_link)) {
                if update {
                    let success = state::mutate(|s| s.process_magic_link(magic_link, env::now()));
                    if success {
                        return HttpResponse {
                            status_code: 200,
                            headers: Vec::new(),
                            body: Vec::new(),
                            upgrade: Some(true),
                        };
                    }
                } else if !magic_link.expired(env::now()) {
                    return HttpResponse {
                        status_code: 200,
                        headers: Vec::new(),
                        body: Vec::new(),
                        upgrade: None,
                    };
                }
            }

            let text = b"Magic link expired".to_vec();

            HttpResponse {
                status_code: 200,
                headers: vec![
                    ("content-type".to_string(), "application/text".to_string()),
                    ("content-length".to_string(), text.len().to_string()),
                ],
                body: text,
                upgrade: None,
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
