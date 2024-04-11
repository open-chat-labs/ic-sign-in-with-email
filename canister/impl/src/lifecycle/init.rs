use crate::state::State;
use crate::{env, rng, state};
use ic_cdk::init;
use sign_in_with_email_canister::InitOrUpgradeArgs;
use std::time::Duration;

#[init]
fn init(args: InitOrUpgradeArgs) {
    state::init(State::new());

    if let Some(config) = args.email_sender_config {
        crate::email_sender::init(config);
    }

    if let Some(salt) = args.salt {
        state::mutate(|s| s.set_salt(salt));
    } else {
        ic_cdk_timers::set_timer(Duration::ZERO, || {
            ic_cdk::spawn(async {
                let salt: [u8; 32] = ic_cdk::api::management_canister::main::raw_rand()
                    .await
                    .unwrap()
                    .0
                    .try_into()
                    .unwrap();

                state::mutate(|s| s.set_salt(salt));
                rng::set_seed(salt, env::now());
            })
        });
    }
}
