use crate::model::validated_email::ValidatedEmail;
use crate::{email_sender, env, rng, state};
use ic_cdk::update;
use sign_in_with_email_canister::{
    GenerateMagicLinkArgs, GenerateMagicLinkResponse, GenerateMagicLinkResponse::*,
};

#[update]
async fn generate_magic_link(args: GenerateMagicLinkArgs) -> GenerateMagicLinkResponse {
    let Ok(email) = ValidatedEmail::try_from(args.email) else {
        return EmailInvalid;
    };

    let (seed, encrypted_magic_link) = state::read(|s| {
        let magic_link =
            s.generate_magic_link(email.clone(), args.session_key, args.max_time_to_live);
        let public_key = s.rsa_public_key().unwrap();
        let encrypted = rng::with_rng(|rng| magic_link.encrypt(public_key, rng));

        (magic_link.seed(), encrypted)
    });

    if let Err(error) = email_sender::send_magic_link(email, encrypted_magic_link).await {
        FailedToSendEmail(error)
    } else {
        state::mutate(|s| s.record_email_sent(seed, env::now()));
        Success
    }
}
