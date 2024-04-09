use candid::Principal;
use sign_in_with_email_canister::TimestampMillis;

pub fn time() -> TimestampMillis {
    ic_cdk::api::time() / 1_000_000
}

pub fn caller() -> Principal {
    ic_cdk::caller()
}
