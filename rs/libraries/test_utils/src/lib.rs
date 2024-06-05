use magic_links::{generate_random_3digit_code, MagicLink, SignedMagicLink};
use rand::rngs::StdRng;
use rand::{thread_rng, SeedableRng};
use rsa::pkcs1::LineEnding;
use rsa::pkcs8::EncodePublicKey;
use rsa::RsaPrivateKey;
use sign_in_with_email_canister::{Delegation, InitArgs, InitOrUpgradeArgs, TimestampNanos};
use utils::ValidatedEmail;

pub const TEST_SALT: [u8; 32] = [1; 32];
pub const EMAIL_SENDER_RSA_SEED: [u8; 32] = [2; 32];

pub fn default_init_args() -> InitOrUpgradeArgs {
    InitOrUpgradeArgs::Init(InitArgs {
        email_sender_public_key_pem: email_sender_public_key_pem(),
        salt: Some(TEST_SALT),
    })
}

pub fn generate_magic_link(
    email: &str,
    session_key: Vec<u8>,
    created: TimestampNanos,
    expiration: TimestampNanos,
) -> SignedMagicLink {
    let seed = utils::calculate_seed(
        TEST_SALT,
        &ValidatedEmail::try_from(email.to_string()).unwrap(),
    );
    let delegation = Delegation {
        pubkey: session_key,
        expiration,
    };
    let code = generate_random_3digit_code(&mut thread_rng());
    let magic_link = MagicLink::new(seed, delegation, code, created);
    let private_key = rsa_private_key();
    let encrypted = magic_link.encrypt(private_key.to_public_key(), &mut thread_rng());

    encrypted.sign(email_sender_rsa_private_key())
}

fn rsa_private_key() -> RsaPrivateKey {
    generate_rsa_private_key_from_seed(TEST_SALT)
}

fn email_sender_rsa_private_key() -> RsaPrivateKey {
    generate_rsa_private_key_from_seed(EMAIL_SENDER_RSA_SEED)
}

fn email_sender_public_key_pem() -> String {
    email_sender_rsa_private_key()
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap()
}

fn generate_rsa_private_key_from_seed(seed: [u8; 32]) -> RsaPrivateKey {
    let mut rng = StdRng::from_seed(seed);
    RsaPrivateKey::new(&mut rng, 2048).unwrap()
}
