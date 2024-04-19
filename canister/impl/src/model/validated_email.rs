use email_address::EmailAddress;
use std::fmt::{Display, Formatter};

#[derive(Clone)]
pub struct ValidatedEmail(String);

impl ValidatedEmail {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ValidatedEmail {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let email = value.trim().to_lowercase();

        if EmailAddress::is_valid(&email) {
            Ok(ValidatedEmail(email))
        } else {
            Err(())
        }
    }
}

impl Display for ValidatedEmail {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<ValidatedEmail> for String {
    fn from(value: ValidatedEmail) -> Self {
        value.0
    }
}
