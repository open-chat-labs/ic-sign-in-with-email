use crate::rng;
use ic_agent::identity::BasicIdentity;

pub fn create_session_identity() -> BasicIdentity {
    let ed25519_seed: [u8; 32] = rng::random();
    let ed25519_keypair =
        ring::signature::Ed25519KeyPair::from_seed_unchecked(&ed25519_seed).unwrap();
    BasicIdentity::from_key_pair(ed25519_keypair)
}
