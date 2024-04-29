use rand::distributions::{Distribution, Standard};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rsa::RsaPrivateKey;
use std::cell::RefCell;

thread_local! {
    static RNG: RefCell<Option<StdRng>> = RefCell::default();
}

pub fn set_seed(salt: [u8; 32], entropy: u64) {
    let mut seed = salt;
    if entropy > 0 {
        seed[..8].copy_from_slice(&entropy.to_be_bytes());
    }

    RNG.set(Some(StdRng::from_seed(seed)));
}

pub fn generate_verification_code() -> String {
    let random = gen::<u128>().to_string();
    random.chars().rev().take(6).collect()
}

pub fn generate_rsa_private_key() -> RsaPrivateKey {
    RNG.with_borrow_mut(|rng| RsaPrivateKey::new(rng.as_mut().unwrap(), 2048).unwrap())
}

pub fn gen<T>() -> T
where
    Standard: Distribution<T>,
{
    RNG.with_borrow_mut(|rng| rng.as_mut().unwrap().gen())
}
