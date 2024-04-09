use sign_in_with_email_canister::{GenerateVerificationCodeArgs, GenerateVerificationCodeResponse};
use ic_cdk::update;

#[update]
fn generate_verification_code(_args: GenerateVerificationCodeArgs) -> GenerateVerificationCodeResponse {
    unimplemented!()
}
