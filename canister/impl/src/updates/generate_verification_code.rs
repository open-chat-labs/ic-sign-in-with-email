use crate::model::validated_email::ValidatedEmail;
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
        "123456".to_string()
    } else {
        rng::generate_verification_code()
    };

    let Ok(email) = ValidatedEmail::try_from(args.email) else {
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
