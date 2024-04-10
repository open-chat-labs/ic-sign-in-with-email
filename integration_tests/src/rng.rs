use candid::Principal;
use rand::distributions::{Distribution, Standard};

pub fn random<T>() -> T
where
    Standard: Distribution<T>,
{
    rand::random()
}

pub fn random_principal() -> Principal {
    let random_bytes = random::<u32>().to_ne_bytes();

    Principal::from_slice(&random_bytes)
}

pub fn random_bytes() -> [u8; 32] {
    random()
}
