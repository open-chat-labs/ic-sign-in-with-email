use rand::rngs::StdRng;
use rand::SeedableRng;
use rsa::pkcs1::LineEnding;
use rsa::pkcs8::EncodePublicKey;
use rsa::RsaPrivateKey;
use sign_in_with_email_canister::{InitArgs, InitOrUpgradeArgs};

pub const TEST_SALT: [u8; 32] = [1; 32];
pub const EMAIL_SENDER_RSA_SEED: [u8; 32] = [2; 32];

pub fn default_init_args() -> InitOrUpgradeArgs {
    InitOrUpgradeArgs::Init(InitArgs {
        email_sender_public_key_pem: email_sender_public_key_pem(),
        salt: Some(TEST_SALT),
    })
}

pub fn rsa_private_key() -> RsaPrivateKey {
    generate_rsa_private_key_from_seed(TEST_SALT)
}

pub fn email_sender_rsa_private_key() -> RsaPrivateKey {
    generate_rsa_private_key_from_seed(EMAIL_SENDER_RSA_SEED)
}

pub fn email_sender_public_key_pem() -> String {
    email_sender_rsa_private_key()
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap()
}

pub fn generate_rsa_private_key_from_seed(seed: [u8; 32]) -> RsaPrivateKey {
    let mut rng = StdRng::from_seed(seed);
    RsaPrivateKey::new(&mut rng, 2048).unwrap()
}
