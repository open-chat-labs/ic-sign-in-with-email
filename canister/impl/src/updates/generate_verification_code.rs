use crate::state;
use ic_cdk::update;
use sign_in_with_email_canister::{GenerateVerificationCodeArgs, GenerateVerificationCodeResponse};

#[update]
fn generate_verification_code(
    args: GenerateVerificationCodeArgs,
) -> GenerateVerificationCodeResponse {
    state::mutate(|s| s.generate_verification_code(args.email))
}
