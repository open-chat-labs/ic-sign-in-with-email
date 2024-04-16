use crate::state;
use crate::utils::verify_and_clean_email;
use ic_cdk::update;
use sign_in_with_email_canister::{SubmitVerificationCodeArgs, SubmitVerificationCodeResponse};

#[update]
fn submit_verification_code(args: SubmitVerificationCodeArgs) -> SubmitVerificationCodeResponse {
    let Some(email) = verify_and_clean_email(args.email) else {
        return SubmitVerificationCodeResponse::NotFound;
    };

    state::mutate(|s| {
        s.submit_verification_code(email, args.code, args.session_key, args.max_time_to_live)
    })
}
