use crate::state::State;
use crate::{email_sender, env, rng, state};
use email_sender_core::NullEmailSender;
use ic_cdk::init;
use sign_in_with_email_canister::InitOrUpgradeArgs;
use std::time::Duration;

#[init]
fn init(args: InitOrUpgradeArgs) {
    let test_mode = args.test_mode.unwrap_or_default();

    state::init(State::new(test_mode));

    if test_mode {
        email_sender::init(NullEmailSender::default());
    }

    ic_cdk_timers::set_timer(Duration::ZERO, || {
        ic_cdk::spawn(async {
            let salt: [u8; 32] = ic_cdk::api::management_canister::main::raw_rand()
                .await
                .unwrap()
                .0
                .try_into()
                .unwrap();

            rng::set_seed(salt, env::now());

            state::mutate(|s| {
                s.set_rsa_private_key(rng::generate_rsa_private_key());
                s.set_salt(salt);
            });
        })
    });
}
