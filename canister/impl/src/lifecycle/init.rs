use crate::state;
use crate::state::State;
use ic_cdk::init;
use sign_in_with_email_canister::InitArgs;
use std::time::Duration;

#[init]
fn init(args: InitArgs) {
    state::init(State::new());

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
            })
        });
    }
}
