use crate::state;
use ic_cdk::query;
use rsa::pkcs8::{EncodePublicKey, LineEnding};

#[query]
fn rsa_public_key() -> Option<String> {
    state::read(|s| {
        s.rsa_public_key()
            .map(|k| k.to_public_key_pem(LineEnding::LF).unwrap())
    })
}
