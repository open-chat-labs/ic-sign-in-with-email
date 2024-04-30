use crate::{env, state};
use ic_cdk::query;
use sign_in_with_email_canister::{Delegation, GetDelegationArgs, GetDelegationResponse};
use utils::ValidatedEmail;

#[query]
fn get_delegation(args: GetDelegationArgs) -> GetDelegationResponse {
    let Ok(email) = ValidatedEmail::try_from(args.email) else {
        return GetDelegationResponse::NotFound;
    };

    state::read(|s| {
        s.get_delegation(
            email,
            Delegation {
                pubkey: args.session_key,
                expiration: args.expiration,
            },
            env::now(),
        )
    })
}
