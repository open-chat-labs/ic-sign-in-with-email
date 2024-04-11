#![cfg(test)]
use crate::identity::create_session_identity;
use crate::rng::random_principal;
use crate::setup::setup_new_env;
use candid::Principal;
use ic_agent::Identity;
use pocket_ic::PocketIc;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sign_in_with_email_canister::{
    GenerateVerificationCodeArgs, GenerateVerificationCodeResponse, GetDelegationArgs,
    GetDelegationResponse, InitOrUpgradeArgs, SubmitVerificationCodeArgs,
    SubmitVerificationCodeResponse,
};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

mod client;
mod identity;
mod rng;
mod setup;

pub struct TestEnv {
    pub env: PocketIc,
    pub canister_id: Principal,
}

#[test]
fn end_to_end_success() {
    let TestEnv {
        mut env,
        canister_id,
    } = install_canister(Some(InitOrUpgradeArgs {
        email_sender_config: None,
    }));

    let sender = random_principal();
    let email = "blah@blah.com";
    let identity = create_session_identity();

    let generate_verification_code_response = client::generate_verification_code(
        &mut env,
        sender,
        canister_id,
        &GenerateVerificationCodeArgs {
            email: email.to_string(),
        },
    );

    assert!(matches!(
        generate_verification_code_response,
        GenerateVerificationCodeResponse::Success
    ));

    let submit_verification_code_response = client::submit_verification_code(
        &mut env,
        sender,
        canister_id,
        &SubmitVerificationCodeArgs {
            email: email.to_string(),
            code: generate_verification_code([0; 32]),
            session_key: identity.public_key().unwrap(),
            max_time_to_live: None,
        },
    );

    let SubmitVerificationCodeResponse::Success(result) = submit_verification_code_response else {
        panic!("{submit_verification_code_response:?}");
    };

    let get_delegation_response = client::get_delegation(
        &env,
        sender,
        canister_id,
        &GetDelegationArgs {
            email: email.to_string(),
            session_key: identity.public_key().unwrap(),
            expiration: result.expiration,
        },
    );

    assert!(matches!(
        get_delegation_response,
        GetDelegationResponse::Success(_)
    ));
}

fn install_canister(init_args: Option<InitOrUpgradeArgs>) -> TestEnv {
    let env = setup_new_env();
    let controller = random_principal();
    let wasm = canister_wasm();
    let init_args = init_args.unwrap_or_default();

    let canister_id = env.create_canister_with_settings(Some(controller), None);
    env.add_cycles(canister_id, 1_000_000_000_000);
    env.install_canister(
        canister_id,
        wasm,
        candid::encode_one(init_args).unwrap(),
        Some(controller),
    );

    // Tick twice to initialize the `salt`
    env.tick();
    env.tick();

    TestEnv { env, canister_id }
}

fn canister_wasm() -> Vec<u8> {
    let file_path = canister_wasm_path();

    let mut file = File::open(&file_path).unwrap_or_else(|e| {
        panic!(
            "Failed to open file: {}. Error: {e:?}",
            file_path.to_str().unwrap()
        )
    });
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("Failed to read file");
    bytes
}

fn canister_wasm_path() -> PathBuf {
    PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("Failed to read CARGO_MANIFEST_DIR env variable"),
    )
    .parent()
    .unwrap()
    .join("target")
    .join("wasm32-unknown-unknown")
    .join("release")
    .join("sign_in_with_email_canister_impl.wasm")
}

fn generate_verification_code(seed: [u8; 32]) -> String {
    let mut rng = StdRng::from_seed(seed);
    let random = rng.gen::<u128>().to_string();
    random.chars().rev().take(8).collect()
}
