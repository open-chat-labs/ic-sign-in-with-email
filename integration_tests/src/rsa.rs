use rand::rngs::StdRng;
use rand::SeedableRng;
use rsa::RsaPrivateKey;

pub fn generate_rsa_private_key_from_seed(seed: [u8; 32]) -> RsaPrivateKey {
    let mut rng = StdRng::from_seed(seed);
    RsaPrivateKey::new(&mut rng, 2048).unwrap()
}
