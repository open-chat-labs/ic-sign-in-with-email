use crate::ONE_MINUTE;
use serde::{Deserialize, Serialize};
use sign_in_with_email_canister::{Milliseconds, TimestampMillis};
use std::collections::HashMap;

const VERIFICATION_CODE_TTL: Milliseconds = 5 * ONE_MINUTE; // 5 minutes

#[derive(Serialize, Deserialize, Default)]
pub struct VerificationCodes {
    codes: HashMap<String, VerificationCode>,
    failed_attempts: HashMap<String, FailedAttempts>,
}

#[derive(Serialize, Deserialize)]
struct VerificationCode {
    code: String,
    created: TimestampMillis,
    attempts: Vec<TimestampMillis>,
}

impl VerificationCodes {
    pub fn push(
        &mut self,
        email: String,
        code: String,
        now: TimestampMillis,
    ) -> Result<(), TimestampMillis> {
        self.clear_expired(now);

        if let Some(blocked_until) = self
            .failed_attempts
            .get(&email)
            .map(|f| f.blocked_until)
            .filter(|ts| *ts > now)
        {
            Err(blocked_until)
        } else {
            self.codes.insert(email, VerificationCode::new(code, now));
            Ok(())
        }
    }

    pub fn check(
        &mut self,
        email: &str,
        attempt: &str,
        now: TimestampMillis,
    ) -> Result<(), CheckVerificationCodeError> {
        self.clear_expired(now);

        let Some(code) = self.codes.get_mut(email) else {
            return Err(CheckVerificationCodeError::NotFound);
        };

        if code.check(attempt, now) {
            self.failed_attempts.remove(email);
            Ok(())
        } else {
            if code.attempts.len() >= 3 {
                self.codes.remove(email);
                self.failed_attempts
                    .entry(email.to_string())
                    .or_default()
                    .mark_failed_attempt(now);
            }
            Err(CheckVerificationCodeError::Incorrect)
        }
    }

    fn clear_expired(&mut self, now: TimestampMillis) {
        self.codes.retain(|_, c| !c.expired(now));
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

    fn expired(&self, now: TimestampMillis) -> bool {
        now.saturating_sub(self.created) > VERIFICATION_CODE_TTL
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
            1 => ONE_MINUTE,
            2 => 5 * ONE_MINUTE,
            3 => 60 * ONE_MINUTE,
            _ => 12 * 60 * ONE_MINUTE,
        };

        self.blocked_until = now + blocked_duration;
    }
}

pub enum CheckVerificationCodeError {
    Incorrect,
    NotFound,
}
