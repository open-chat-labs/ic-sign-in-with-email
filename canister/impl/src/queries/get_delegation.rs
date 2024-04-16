use crate::state;
use crate::utils::verify_and_clean_email;
use ic_cdk::query;
use sign_in_with_email_canister::{Delegation, GetDelegationArgs, GetDelegationResponse};

#[query]
fn get_delegation(args: GetDelegationArgs) -> GetDelegationResponse {
    let Some(email) = verify_and_clean_email(args.email) else {
        return GetDelegationResponse::NotFound;
    };

    state::read(|s| {
        s.get_delegation(
            email,
            Delegation {
                pubkey: args.session_key,
                expiration: args.expiration,
            },
        )
    })
}
