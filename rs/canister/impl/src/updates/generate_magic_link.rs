use crate::{email_sender, env, rng, state};
use ic_cdk::update;
use sign_in_with_email_canister::{
    GenerateMagicLinkArgs, GenerateMagicLinkResponse, GenerateMagicLinkResponse::*,
    GenerateMagicLinkSuccess,
};
use utils::ValidatedEmail;

#[update]
async fn generate_magic_link(args: GenerateMagicLinkArgs) -> GenerateMagicLinkResponse {
    let Ok(email) = ValidatedEmail::try_from(args.email) else {
        return EmailInvalid;
    };

    let start = env::now();

    let (magic_link, encrypted_magic_link) = state::read(|s| {
        let seed = s.calculate_seed(&email);
        let magic_link =
            magic_links::generate(seed, args.session_key, args.max_time_to_live, start);
        let public_key = s.rsa_public_key().unwrap();
        let encrypted = rng::with_rng(|rng| magic_link.encrypt(public_key, rng));

        (magic_link, encrypted)
    });

    if let Err(error) = email_sender::send_magic_link(email, encrypted_magic_link).await {
        FailedToSendEmail(error)
    } else {
        let seed = magic_link.seed();
        let delegation = magic_link.delegation();

        state::mutate(|s| {
            s.record_magic_link_sent(seed, delegation, env::now());

            Success(GenerateMagicLinkSuccess {
                created: start,
                user_key: s.der_encode_canister_sig_key(seed),
                expiration: delegation.expiration,
            })
        })
    }
}
