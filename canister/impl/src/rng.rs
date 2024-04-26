use rand::distributions::{Distribution, Standard};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rsa::RsaPrivateKey;
use sign_in_with_email_canister::TimestampMillis;
use std::cell::RefCell;

thread_local! {
    static RNG: RefCell<Option<StdRng>> = RefCell::default();
}

pub fn set_seed(salt: [u8; 32], now: TimestampMillis) {
    let mut seed = salt;
    seed[..8].copy_from_slice(&now.to_be_bytes());

    RNG.set(Some(StdRng::from_seed(seed)));
}

pub fn generate_rsa_private_key() -> RsaPrivateKey {
    with_rng(|rng| RsaPrivateKey::new(rng, 2048).unwrap())
}

pub fn gen<T>() -> T
where
    Standard: Distribution<T>,
{
    with_rng(|rng| rng.gen())
}

pub fn with_rng<F: FnOnce(&mut StdRng) -> T, T>(f: F) -> T {
    RNG.with_borrow_mut(|rng| f(rng.as_mut().unwrap()))
}
