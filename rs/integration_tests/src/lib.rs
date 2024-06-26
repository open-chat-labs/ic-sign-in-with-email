#![cfg(test)]
use candid::Principal;
use pocket_ic::PocketIc;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

mod client;
mod identity;
mod rng;
mod setup;
mod tests;

pub struct TestEnv {
    pub env: PocketIc,
    pub canister_id: Principal,
    controller: Principal,
}

fn canister_wasm() -> Vec<u8> {
    let file_path = canister_wasm_path();

    let mut file = File::open(&file_path).unwrap_or_else(|e| {
        panic!(
            "Failed to open file: {}. Error: {e:?}",
            file_path.to_str().unwrap()
        )
    });
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("Failed to read file");
    bytes
}

fn canister_wasm_path() -> PathBuf {
    PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("Failed to read CARGO_MANIFEST_DIR env variable"),
    )
    .parent()
    .unwrap()
    .parent()
    .unwrap()
    .join(".dfx")
    .join("ic")
    .join("canisters")
    .join("sign_in_with_email")
    .join("sign_in_with_email.wasm.gz")
}
