use email_address::EmailAddress;

pub fn verify_and_clean_email(email: String) -> Option<String> {
    let email = email.trim().to_lowercase();

    EmailAddress::is_valid(&email).then_some(email)
}
