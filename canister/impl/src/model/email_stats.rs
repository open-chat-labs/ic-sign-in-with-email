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
    pub successful_codes: u32,
    pub latest_successful_code: Option<TimestampMillis>,
    pub failed_codes: u32,
    pub latest_failed_code: Option<TimestampMillis>,
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
                successful_codes: 0,
                latest_successful_code: None,
                failed_codes: 0,
                latest_failed_code: None,
            });
    }

    pub fn record_code_submitted(&mut self, seed: Hash, success: bool, now: TimestampMillis) {
        if let Some(stats) = self.map.get_mut(&seed) {
            if success {
                stats.successful_codes += 1;
                stats.latest_successful_code = Some(now);
            } else {
                stats.failed_codes += 1;
                stats.latest_failed_code = Some(now);
            }
        }
    }
}
