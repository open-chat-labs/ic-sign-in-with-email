use crate::Hash;
use serde::{Deserialize, Serialize};
use sign_in_with_email_canister::TimestampMillis;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Default)]
pub struct MagicLinks {
    in_flight: HashMap<(Hash, Hash), TimestampMillis>,
}

impl MagicLinks {
    pub fn push(
        &mut self,
        seed: Hash,
        msg_hash: Hash,
        expiration: TimestampMillis,
        now: TimestampMillis,
    ) {
        self.prune(now);
        self.in_flight.insert((seed, msg_hash), expiration);
    }

    pub fn get(&self, seed: Hash, msg_hash: Hash, now: TimestampMillis) -> Option<TimestampMillis> {
        self.in_flight
            .get(&(seed, msg_hash))
            .filter(|&ts| *ts > now)
            .copied()
    }

    fn prune(&mut self, now: TimestampMillis) {
        self.in_flight.retain(|_, ts| *ts > now)
    }
}
