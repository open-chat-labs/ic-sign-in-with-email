use crate::Hash;
use serde::{Deserialize, Serialize};
use sign_in_with_email_canister::TimestampMillis;
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Default)]
pub struct EmailStatsMap {
    map: BTreeMap<Hash, EmailStats>,
}

#[derive(Serialize, Deserialize)]
pub struct EmailStats {
    pub first_seen: TimestampMillis,
    pub emails_sent: u32,
    pub latest_email_sent: TimestampMillis,
    pub successful_links: u32,
    pub latest_successful_link: Option<TimestampMillis>,
}

impl EmailStatsMap {
    pub fn record_email_sent(&mut self, seed: Hash, now: TimestampMillis) {
        self.map
            .entry(seed)
            .and_modify(|s| {
                s.emails_sent += 1;
                s.latest_email_sent = now;
            })
            .or_insert(EmailStats {
                first_seen: now,
                emails_sent: 1,
                latest_email_sent: now,
                successful_links: 0,
                latest_successful_link: None,
            });
    }
}
