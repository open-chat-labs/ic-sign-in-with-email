mod env;
mod guards;
mod lifecycle;
mod memory;
mod model;
mod queries;
mod state;
mod updates;

#[cfg(test)]
mod generate_candid_file {
    use sign_in_with_email_canister::*;
    use ic_cdk::export_candid;
    use std::env;
    use std::fs::write;
    use std::path::PathBuf;

    #[test]
    fn save_candid() {
        let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let dir = dir.parent().unwrap().join("api");

        export_candid!();
        write(dir.join("can.did"), __export_service()).unwrap()
    }
}
