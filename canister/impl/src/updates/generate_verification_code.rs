use crate::utils::verify_and_clean_email;
use crate::{email_sender, rng, state};
use ic_cdk::update;
use sign_in_with_email_canister::{
    GenerateVerificationCodeArgs, GenerateVerificationCodeResponse,
    GenerateVerificationCodeResponse::*,
};

#[update]
async fn generate_verification_code(
    args: GenerateVerificationCodeArgs,
) -> GenerateVerificationCodeResponse {
    let test_mode = state::read(|s| s.test_mode());

    let code = if test_mode {
        "12345678".to_string()
    } else {
        rng::generate_verification_code()
    };

    let Some(email) = verify_and_clean_email(args.email) else {
        return EmailInvalid;
    };

    let response = state::mutate(|s| s.store_verification_code(email.clone(), code.clone()));

    if matches!(response, Success) {
        if let Err(error) = email_sender::send_verification_code_email(email, code).await {
            return FailedToSendEmail(error);
        }
    }

    response
}
