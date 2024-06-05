use clap::Parser;
use magic_links::generate;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rsa::RsaPrivateKey;
use utils::{calculate_seed, ValidatedEmail};

const TEST_SALT: [u8; 32] = [1; 32];
const EMAIL_SENDER_RSA_SEED: [u8; 32] = [2; 32];

fn main() {
    let opts = Opts::parse();
    let email = ValidatedEmail::try_from(opts.email).expect("Invalid email");
    let session_key = hex::decode(opts.session_key).expect("Invalid session key");

    let mut rng = StdRng::from_seed(TEST_SALT);
    let rsa_private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let rsa_public_key = rsa_private_key.to_public_key();
    let email_sender_rsa_private_key =
        RsaPrivateKey::new(&mut StdRng::from_seed(EMAIL_SENDER_RSA_SEED), 2048).unwrap();
    let seed = calculate_seed(TEST_SALT, &email);
    let magic_link = generate(seed, session_key, None, &mut rng, opts.timestamp);
    let encrypted = magic_link.encrypt(rsa_public_key, &mut rng);
    let signed = encrypted.sign(email_sender_rsa_private_key);

    let querystring = signed.build_querystring();

    println!("/auth?{}", querystring)
}

#[derive(Parser)]
struct Opts {
    #[arg(long)]
    email: String,

    #[arg(long)]
    session_key: String,

    #[arg(long)]
    timestamp: u64,
}
