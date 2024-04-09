use crate::state;
use ic_cdk::query;
use sign_in_with_email_canister::{GetDelegationArgs, GetDelegationResponse};

#[query]
fn get_delegation(args: GetDelegationArgs) -> GetDelegationResponse {
    state::read(|s| s.get_delegation(args))
}
