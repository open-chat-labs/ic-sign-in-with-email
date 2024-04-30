use crate::hash::{hash_bytes, hash_of_map, hash_with_domain};
pub use crate::validated_email::ValidatedEmail;
use magic_links::MagicLink;
use sign_in_with_email_canister::{Delegation, Hash, Milliseconds, Nanoseconds, TimestampMillis};
use std::collections::HashMap;

mod hash;
mod validated_email;

const ONE_MINUTE: Milliseconds = 60 * 1000;
const ONE_DAY: Milliseconds = 24 * 60 * ONE_MINUTE;
const NANOS_PER_MILLISECOND: u64 = 1_000_000;
const DEFAULT_SESSION_EXPIRATION_PERIOD: Nanoseconds = 30 * ONE_DAY * NANOS_PER_MILLISECOND;
const MAX_SESSION_EXPIRATION_PERIOD: Nanoseconds = 90 * ONE_DAY * NANOS_PER_MILLISECOND;

pub fn generate_magic_link(
    email: ValidatedEmail,
    session_key: Vec<u8>,
    max_time_to_live: Option<Nanoseconds>,
    salt: [u8; 32],
    now: TimestampMillis,
) -> MagicLink {
    let seed = calculate_seed(salt, &email);

    let delta = Nanoseconds::min(
        max_time_to_live.unwrap_or(DEFAULT_SESSION_EXPIRATION_PERIOD),
        MAX_SESSION_EXPIRATION_PERIOD,
    );

    let now_nanos = now * NANOS_PER_MILLISECOND;
    let expiration = now_nanos.saturating_add(delta);
    let delegation = Delegation {
        pubkey: session_key,
        expiration,
    };

    MagicLink::new(seed, delegation, now)
}

pub fn calculate_seed(salt: [u8; 32], email: &ValidatedEmail) -> [u8; 32] {
    let mut bytes: Vec<u8> = vec![];
    bytes.push(salt.len() as u8);
    bytes.extend_from_slice(&salt);

    let email_bytes = email.as_str().bytes();
    bytes.push(email_bytes.len() as u8);
    bytes.extend(email_bytes);

    hash_bytes(&bytes)
}

pub fn delegation_signature_msg_hash(d: &Delegation) -> Hash {
    use crate::hash::Value;
    let mut m = HashMap::new();
    m.insert("pubkey", Value::Bytes(d.pubkey.as_slice()));
    m.insert("expiration", Value::U64(d.expiration));
    let map_hash = hash_of_map(m);
    hash_with_domain(b"ic-request-auth-delegation", &map_hash)
}
