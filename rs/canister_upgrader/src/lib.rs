use candid::Principal;
use ic_agent::agent::http_transport::ReqwestTransport;
use ic_agent::identity::BasicIdentity;
use ic_agent::{Agent, Identity};
use ic_utils::interfaces::management_canister::builders::InstallMode;
use ic_utils::interfaces::ManagementCanister;
use rand::thread_rng;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use sign_in_with_email_canister::{EmailSenderConfig, InitOrUpgradeArgs, UpgradeArgs};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub async fn upgrade_canister(
    identity: Box<dyn Identity>,
    ic_url: String,
    canister_id: Principal,
    email_sender_public_key_pem: Option<String>,
    email_sender_config: EmailSenderConfig,
) {
    let agent = build_ic_agent(ic_url, identity).await;

    let rsa_public_key_pem: Option<String> = candid::decode_one(
        &agent
            .query(&canister_id, "rsa_public_key")
            .with_arg(candid::encode_one(()).unwrap())
            .call()
            .await
            .unwrap(),
    )
    .unwrap();

    let rsa_public_key = RsaPublicKey::from_public_key_pem(&rsa_public_key_pem.unwrap()).unwrap();

    let encrypted_config = email_sender_config.encrypt(&rsa_public_key, &mut thread_rng());

    let management_canister = ManagementCanister::create(&agent);
    let wasm = read_canister_wasm();

    management_canister
        .install(&canister_id, &wasm)
        .with_arg(InitOrUpgradeArgs::Upgrade(UpgradeArgs {
            email_sender_public_key_pem,
            email_sender_config: Some(encrypted_config),
        }))
        .with_mode(InstallMode::Upgrade(None))
        .call_and_wait()
        .await
        .unwrap();
}

async fn build_ic_agent(url: String, identity: Box<dyn Identity>) -> Agent {
    let mainnet = is_mainnet(&url);
    let transport = ReqwestTransport::create(url).expect("Failed to create Reqwest transport");
    let timeout = std::time::Duration::from_secs(60 * 5);

    let agent = Agent::builder()
        .with_transport(transport)
        .with_boxed_identity(identity)
        .with_ingress_expiry(Some(timeout))
        .build()
        .expect("Failed to build IC agent");

    if !mainnet {
        agent
            .fetch_root_key()
            .await
            .expect("Couldn't fetch root key");
    }

    agent
}

fn read_canister_wasm() -> Vec<u8> {
    let wasms_directory = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("Failed to read CARGO_MANIFEST_DIR env variable"),
    )
    .parent()
    .unwrap()
    .parent()
    .unwrap()
    .join("wasms");

    let file_path = wasms_directory.join("sign_in_with_email.wasm.gz");

    let mut file = File::open(&file_path)
        .unwrap_or_else(|_| panic!("Failed to open file: {}", file_path.to_str().unwrap()));
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("Failed to read file");
    bytes
}

pub fn get_dfx_identity(name: &str) -> Box<dyn Identity> {
    let config_dfx_dir_path = get_user_dfx_config_dir().unwrap();
    let pem_path = config_dfx_dir_path
        .join("identity")
        .join(name)
        .join("identity.pem");
    if !Path::exists(pem_path.as_path()) {
        panic!("Pem file not found at: {}", pem_path.as_path().display());
    }
    Box::new(BasicIdentity::from_pem_file(pem_path.as_path()).unwrap())
}

fn get_user_dfx_config_dir() -> Option<PathBuf> {
    let config_root = std::env::var_os("DFX_CONFIG_ROOT");
    let home = std::env::var_os("HOME")?;
    let root = config_root.unwrap_or(home);
    Some(PathBuf::from(root).join(".config").join("dfx"))
}

fn is_mainnet(url: &str) -> bool {
    url.contains("ic0.app")
}
