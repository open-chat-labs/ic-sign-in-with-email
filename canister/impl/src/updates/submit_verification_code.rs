use crate::state;
use ic_cdk::update;
use sign_in_with_email_canister::{SubmitVerificationCodeArgs, SubmitVerificationCodeResponse};

#[update]
fn submit_verification_code(args: SubmitVerificationCodeArgs) -> SubmitVerificationCodeResponse {
    state::mutate(|s| s.submit_verification_code(args))
}
