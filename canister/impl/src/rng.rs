use rand::distributions::{Distribution, Standard};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::cell::RefCell;

thread_local! {
    static RNG: RefCell<Option<StdRng>> = RefCell::default();
}

pub fn set(seed: [u8; 32]) {
    RNG.set(Some(StdRng::from_seed(seed)));
}

pub fn generate_verification_code() -> String {
    let random = gen::<u128>().to_string();
    random.chars().rev().take(8).collect()
}

pub fn gen<T>() -> T
where
    Standard: Distribution<T>,
{
    RNG.with_borrow_mut(|rng| rng.as_mut().unwrap().gen())
}
