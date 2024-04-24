use crate::model::validated_email::ValidatedEmail;
use crate::state;
use ic_cdk::update;
use sign_in_with_email_canister::{SubmitVerificationCodeArgs, SubmitVerificationCodeResponse};

#[update]
fn submit_verification_code(args: SubmitVerificationCodeArgs) -> SubmitVerificationCodeResponse {
    let Ok(email) = ValidatedEmail::try_from(args.email) else {
        return SubmitVerificationCodeResponse::NotFound;
    };

    state::mutate(|s| s.submit_verification_code(email, args.code))
}
