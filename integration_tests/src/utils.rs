use pocket_ic::PocketIc;
use sign_in_with_email_canister::TimestampMillis;
use std::time::UNIX_EPOCH;

pub fn now(env: &PocketIc) -> TimestampMillis {
    env.get_time()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as TimestampMillis
}
