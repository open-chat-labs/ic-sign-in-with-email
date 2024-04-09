use crate::state;
use crate::state::State;
use sign_in_with_email_canister::InitArgs;
use ic_cdk::init;
use std::time::Duration;

#[init]
fn init(_args: InitArgs) {
    state::init(State::new());

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
