use sign_in_with_email_canister::{GetDelegationArgs, GetDelegationResponse};
use ic_cdk::query;

#[query]
fn get_delegation(_args: GetDelegationArgs) -> GetDelegationResponse {
    unimplemented!()
}
