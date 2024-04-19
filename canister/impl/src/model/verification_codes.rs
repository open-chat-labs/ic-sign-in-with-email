use crate::model::validated_email::ValidatedEmail;
use crate::ONE_MINUTE;
use serde::{Deserialize, Serialize};
use sign_in_with_email_canister::{IncorrectCode, Milliseconds, TimestampMillis};
use std::collections::HashMap;

const VERIFICATION_CODE_TTL: Milliseconds = 5 * ONE_MINUTE; // 5 minutes

#[derive(Serialize, Deserialize, Default)]
pub struct VerificationCodes {
    codes: HashMap<String, VerificationCode>,
    failed_attempts: FailedAttemptsMap,
}

#[derive(Serialize, Deserialize)]
struct VerificationCode {
    code: String,
    created: TimestampMillis,
    attempts: Vec<TimestampMillis>,
}

#[derive(Serialize, Deserialize, Default)]
struct FailedAttemptsMap {
    map: HashMap<String, FailedAttempts>,
}

impl VerificationCodes {
    pub fn push(
        &mut self,
        email: ValidatedEmail,
        code: String,
        now: TimestampMillis,
    ) -> Result<(), TimestampMillis> {
        self.clear_expired(now);

        if let Some(existing) = self.codes.remove(email.as_str()) {
            if !existing.attempts.is_empty() {
                self.failed_attempts
                    .mark_failed_attempt(email.as_str(), now);
            }
        }

        if let Some(blocked_until) = self.failed_attempts.blocked_until(email.as_str(), now) {
            Err(blocked_until)
        } else {
            self.codes
                .insert(email.into(), VerificationCode::new(code, now));
            Ok(())
        }
    }

    pub fn check(
        &mut self,
        email: &ValidatedEmail,
        attempt: &str,
        now: TimestampMillis,
    ) -> Result<(), CheckVerificationCodeError> {
        self.clear_expired(now);

        let email_str = email.as_str();

        let Some(code) = self.codes.get_mut(email_str) else {
            return Err(CheckVerificationCodeError::NotFound);
        };

        if code.check(attempt, now) {
            self.failed_attempts.remove(email_str);
            Ok(())
        } else {
            let attempts_remaining = 2u32.saturating_sub(code.attempts.len() as u32);
            let mut blocked_until = None;
            if attempts_remaining == 0 {
                self.codes.remove(email_str);
                blocked_until = Some(self.failed_attempts.mark_failed_attempt(email_str, now));
            }
            Err(CheckVerificationCodeError::Incorrect(IncorrectCode {
                attempts_remaining,
                blocked_until,
            }))
        }
    }

    fn clear_expired(&mut self, now: TimestampMillis) {
        self.codes.retain(|e, c| {
            let expiry = c.expiry();
            let expired = expiry < now;
            if expired {
                if !c.attempts.is_empty() {
                    self.failed_attempts.mark_failed_attempt(e.as_str(), expiry);
                }
                false
            } else {
                true
            }
        });
    }
}

impl FailedAttemptsMap {
    fn blocked_until(&self, email: &str, now: TimestampMillis) -> Option<TimestampMillis> {
        self.map
            .get(email)
            .map(|f| f.blocked_until)
            .filter(|ts| *ts > now)
    }

    fn remove(&mut self, email: &str) {
        self.map.remove(email);
    }

    fn mark_failed_attempt(&mut self, email: &str, now: TimestampMillis) -> TimestampMillis {
        let failed_attempts = self.map.entry(email.to_string()).or_default();
        failed_attempts.mark_failed_attempt(now);
        failed_attempts.blocked_until
    }
}

impl VerificationCode {
    fn new(code: String, now: TimestampMillis) -> VerificationCode {
        VerificationCode {
            code,
            created: now,
            attempts: Vec::new(),
        }
    }

    fn check(&mut self, attempt: &str, now: TimestampMillis) -> bool {
        if attempt == self.code {
            true
        } else {
            self.attempts.push(now);
            false
        }
    }

    fn expiry(&self) -> TimestampMillis {
        self.created + VERIFICATION_CODE_TTL
    }
}

#[derive(Serialize, Deserialize, Default)]
struct FailedAttempts {
    blocked_until: TimestampMillis,
    failed_attempts: u32,
}

impl FailedAttempts {
    fn mark_failed_attempt(&mut self, now: TimestampMillis) {
        self.failed_attempts += 1;

        let blocked_duration = match self.failed_attempts {
            0 => 0,
            1 => ONE_MINUTE,
            2 => 2 * ONE_MINUTE,
            3 => 5 * ONE_MINUTE,
            4 => 15 * ONE_MINUTE,
            5 => 60 * ONE_MINUTE,
            _ => 12 * 60 * ONE_MINUTE,
        };

        self.blocked_until = now + blocked_duration;
    }
}

pub enum CheckVerificationCodeError {
    Incorrect(IncorrectCode),
    NotFound,
}
