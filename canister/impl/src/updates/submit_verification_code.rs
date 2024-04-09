use sign_in_with_email_canister::{SubmitVerificationCodeArgs, SubmitVerificationCodeResponse};
use ic_cdk::update;

#[update]
fn submit_verification_code(_args: SubmitVerificationCodeArgs) -> SubmitVerificationCodeResponse {
    unimplemented!()
}
