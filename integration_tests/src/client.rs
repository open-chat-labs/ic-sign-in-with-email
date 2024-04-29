use crate::rng::random_principal;
use crate::rsa::generate_rsa_private_key_from_seed;
use crate::setup::setup_new_env;
use crate::{canister_wasm, TestEnv, EMAIL_SENDER_RSA_SEED, TEST_SALT};
use candid::{CandidType, Principal};
use ic_http_certification::{HttpRequest, HttpResponse};
use pocket_ic::{PocketIc, UserError, WasmResult};
use rsa::pkcs1::LineEnding;
use rsa::pkcs8::EncodePublicKey;
use serde::de::DeserializeOwned;
use sign_in_with_email_canister::{
    GenerateMagicLinkArgs, GenerateMagicLinkResponse, GetDelegationArgs, GetDelegationResponse,
    InitArgs, InitOrUpgradeArgs, UpgradeArgs,
};

pub fn generate_magic_link(
    env: &mut PocketIc,
    sender: Principal,
    canister_id: Principal,
    args: &GenerateMagicLinkArgs,
) -> GenerateMagicLinkResponse {
    execute_update(env, sender, canister_id, "generate_magic_link", args)
}

pub fn http_request(
    env: &PocketIc,
    sender: Principal,
    canister_id: Principal,
    args: &HttpRequest,
) -> HttpResponse {
    execute_query(env, sender, canister_id, "http_request", args)
}

pub fn http_request_update(
    env: &mut PocketIc,
    sender: Principal,
    canister_id: Principal,
    args: &HttpRequest,
) -> HttpResponse {
    execute_update(env, sender, canister_id, "http_request_update", args)
}

pub fn get_delegation(
    env: &PocketIc,
    sender: Principal,
    canister_id: Principal,
    args: &GetDelegationArgs,
) -> GetDelegationResponse {
    execute_query(env, sender, canister_id, "get_delegation", args)
}

pub fn install_canister() -> TestEnv {
    let env = setup_new_env();
    let controller = random_principal();
    let wasm = canister_wasm();
    let init_args = InitOrUpgradeArgs::Init(InitArgs {
        email_sender_public_key_pem: generate_rsa_private_key_from_seed(EMAIL_SENDER_RSA_SEED)
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap(),
        salt: Some(TEST_SALT),
    });

    let canister_id = env.create_canister_with_settings(Some(controller), None);
    env.add_cycles(canister_id, 1_000_000_000_000);
    env.install_canister(
        canister_id,
        wasm,
        candid::encode_one(init_args).unwrap(),
        Some(controller),
    );
    env.tick();

    TestEnv {
        env,
        canister_id,
        controller,
    }
}

pub fn upgrade_canister(
    env: &mut PocketIc,
    canister_id: Principal,
    sender: Principal,
    args: Option<UpgradeArgs>,
) {
    let wasm = canister_wasm();
    let args = InitOrUpgradeArgs::Upgrade(args.unwrap_or_default());

    // Tick a few times otherwise the upgrade is rate limited
    for _ in 0..20 {
        env.tick();
    }

    env.upgrade_canister(
        canister_id,
        wasm,
        candid::encode_one(args).unwrap(),
        Some(sender),
    )
    .unwrap();
}

fn execute_query<P: CandidType, R: CandidType + DeserializeOwned>(
    env: &PocketIc,
    sender: Principal,
    canister_id: Principal,
    method_name: &str,
    payload: &P,
) -> R {
    unwrap_response(env.query_call(
        canister_id,
        sender,
        method_name,
        candid::encode_one(payload).unwrap(),
    ))
}

fn execute_update<P: CandidType, R: CandidType + DeserializeOwned>(
    env: &mut PocketIc,
    sender: Principal,
    canister_id: Principal,
    method_name: &str,
    payload: &P,
) -> R {
    unwrap_response(env.update_call(
        canister_id,
        sender,
        method_name,
        candid::encode_one(payload).unwrap(),
    ))
}

fn unwrap_response<R: CandidType + DeserializeOwned>(response: Result<WasmResult, UserError>) -> R {
    match response.unwrap() {
        WasmResult::Reply(bytes) => candid::decode_one(&bytes).unwrap(),
        WasmResult::Reject(error) => panic!("{error}"),
    }
}
