use crate::{
    env, get_query_param_value,
    state::{self, AuthResult},
};
use ic_cdk::update;
use magic_links::SignedMagicLink;
use sign_in_with_email_canister::{HandleMagicLinkArgs, HandleMagicLinkResponse};

#[update]
async fn handle_magic_link(args: HandleMagicLinkArgs) -> HandleMagicLinkResponse {
    let params = querystring::querify(&args.link);
    let ciphertext = get_query_param_value(&params, "c").unwrap();
    let encrypted_key = get_query_param_value(&params, "k").unwrap();
    let nonce = get_query_param_value(&params, "n").unwrap();
    let signature = get_query_param_value(&params, "s").unwrap();

    let signed_magic_link =
        SignedMagicLink::from_hex_strings(&ciphertext, &encrypted_key, &nonce, &signature);

    match state::mutate(|s| s.process_auth_request(signed_magic_link, true, env::now())) {
        AuthResult::Success => HandleMagicLinkResponse::Success,
        AuthResult::LinkExpired => HandleMagicLinkResponse::LinkExpired,
        AuthResult::LinkInvalid(error) => HandleMagicLinkResponse::LinkInvalid(error),
        AuthResult::RequiresUpgrade => unreachable!(),
    }
}
