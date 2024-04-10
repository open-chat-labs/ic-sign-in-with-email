use candid::{CandidType, Principal};
use pocket_ic::{PocketIc, UserError, WasmResult};
use serde::de::DeserializeOwned;
use sign_in_with_email_canister::{
    GenerateVerificationCodeArgs, GenerateVerificationCodeResponse, GetDelegationArgs,
    GetDelegationResponse, SubmitVerificationCodeArgs, SubmitVerificationCodeResponse,
};

pub fn generate_verification_code(
    env: &mut PocketIc,
    sender: Principal,
    canister_id: Principal,
    args: &GenerateVerificationCodeArgs,
) -> GenerateVerificationCodeResponse {
    execute_update(env, sender, canister_id, "generate_verification_code", args)
}

pub fn submit_verification_code(
    env: &mut PocketIc,
    sender: Principal,
    canister_id: Principal,
    args: &SubmitVerificationCodeArgs,
) -> SubmitVerificationCodeResponse {
    execute_update(env, sender, canister_id, "submit_verification_code", args)
}

pub fn get_delegation(
    env: &PocketIc,
    sender: Principal,
    canister_id: Principal,
    args: &GetDelegationArgs,
) -> GetDelegationResponse {
    execute_query(env, sender, canister_id, "get_delegation", args)
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
