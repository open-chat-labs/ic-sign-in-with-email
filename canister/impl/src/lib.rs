use sign_in_with_email_canister::{Milliseconds, Nanoseconds};

mod email_sender;
mod env;
mod guards;
mod hash;
mod lifecycle;
mod memory;
mod model;
mod queries;
mod rng;
mod state;
mod updates;
mod utils;

type Hash = [u8; 32];

const ONE_MINUTE: Milliseconds = 60 * 1000;
const ONE_DAY: Milliseconds = 24 * 60 * ONE_MINUTE;
const NANOS_PER_MILLISECOND: u64 = 1_000_000;
const DEFAULT_EXPIRATION_PERIOD: Nanoseconds = 30 * ONE_DAY * NANOS_PER_MILLISECOND;
const MAX_EXPIRATION_PERIOD: Nanoseconds = 90 * ONE_DAY * NANOS_PER_MILLISECOND;

#[cfg(test)]
mod generate_candid_file {
    use ic_cdk::export_candid;
    use sign_in_with_email_canister::*;
    use std::env;
    use std::fs::write;
    use std::path::PathBuf;

    #[test]
    fn save_candid() {
        let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let dir = dir.parent().unwrap().join("api");

        export_candid!();
        write(dir.join("can.did"), __export_service()).unwrap()
    }
}
