use crate::state::State;
use crate::{email_sender, env, rng, state};
use email_sender_core::NullEmailSender;
use ic_cdk::init;
use sign_in_with_email_canister::InitOrUpgradeArgs;
use std::time::Duration;

#[init]
fn init(args: InitOrUpgradeArgs) {
    let init_args = args.to_init_args();
    let test_mode = init_args.salt.is_some();

    state::init(State::new(test_mode));

    if let Some(salt) = init_args.salt {
        email_sender::init(NullEmailSender::default());
        set_salt(salt, 0)
    } else {
        ic_cdk_timers::set_timer(Duration::ZERO, || {
            ic_cdk::spawn(async {
                let salt: [u8; 32] = ic_cdk::api::management_canister::main::raw_rand()
                    .await
                    .unwrap()
                    .0
                    .try_into()
                    .unwrap();

                set_salt(salt, env::now());
            })
        });
    }
}

fn set_salt(salt: [u8; 32], entropy: u64) {
    rng::set_seed(salt, entropy);

    state::mutate(|s| {
        s.set_rsa_private_key(rng::generate_rsa_private_key());
        s.set_salt(salt);
    });
}
