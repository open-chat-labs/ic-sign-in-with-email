use crate::identity::create_session_identity;
use crate::rng::random_principal;
use crate::{client, TestEnv};
use ic_agent::Identity;
use ic_http_certification::HttpRequest;
use sign_in_with_email_canister::{
    GenerateMagicLinkArgs, GenerateMagicLinkResponse, GetDelegationArgs, GetDelegationResponse,
};
use test_utils::generate_magic_link;

#[test]
fn end_to_end() {
    let TestEnv {
        mut env,
        canister_id,
        ..
    } = client::install_canister();

    let sender = random_principal();
    let email = "blah@blah.com";
    let identity = create_session_identity();
    let session_key = identity.public_key().unwrap();

    let generate_magic_link_response = client::generate_magic_link(
        &mut env,
        sender,
        canister_id,
        &GenerateMagicLinkArgs {
            email: email.to_string(),
            session_key: session_key.clone(),
            max_time_to_live: None,
        },
    );

    let GenerateMagicLinkResponse::Success(generate_magic_link_success) =
        generate_magic_link_response
    else {
        panic!();
    };

    let signed = generate_magic_link(
        email,
        session_key.clone(),
        generate_magic_link_success.created,
        generate_magic_link_success.expiration,
    );

    let http_request = HttpRequest {
        method: "GET".to_string(),
        url: format!(
            "https://canister_id.icp0.io/auth{}",
            signed.build_querystring()
        ),
        headers: Vec::new(),
        body: Vec::new(),
    };

    let http_response = client::http_request(&env, sender, canister_id, &http_request);

    assert_eq!(http_response.status_code, 200);
    assert!(http_response.upgrade.unwrap());

    let http_response = client::http_request_update(&mut env, sender, canister_id, &http_request);

    assert_eq!(http_response.status_code, 200);

    let get_delegation_response = client::get_delegation(
        &env,
        sender,
        canister_id,
        &GetDelegationArgs {
            email: email.to_string(),
            session_key,
            expiration: generate_magic_link_success.expiration,
        },
    );

    assert!(matches!(
        get_delegation_response,
        GetDelegationResponse::Success(_)
    ));
}

#[test]
fn upgrade_canister_succeeds() {
    let TestEnv {
        mut env,
        canister_id,
        controller,
    } = client::install_canister();

    env.tick();

    client::upgrade_canister(&mut env, canister_id, controller, None);
}
