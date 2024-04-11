use crate::NANOS_PER_MILLISECOND;
use candid::Principal;
use sign_in_with_email_canister::{TimestampMillis, TimestampNanos};

pub fn now() -> TimestampMillis {
    now_nanos() / NANOS_PER_MILLISECOND
}

pub fn now_nanos() -> TimestampNanos {
    ic_cdk::api::time()
}

pub fn canister_id() -> Principal {
    ic_cdk::id()
}
