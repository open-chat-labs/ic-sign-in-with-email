use crate::lifecycle::READER_WRITER_BUFFER_SIZE;
use crate::memory::get_upgrades_memory;
use crate::state::State;
use crate::{env, rng, state};
use ic_cdk::post_upgrade;
use ic_stable_structures::reader::{BufferedReader, Reader};
use serde::Deserialize;
use sign_in_with_email_canister::InitOrUpgradeArgs;

#[post_upgrade]
fn post_upgrade(args: InitOrUpgradeArgs) {
    let memory = get_upgrades_memory();
    let reader = BufferedReader::new(READER_WRITER_BUFFER_SIZE, Reader::new(&memory, 0));
    let mut deserializer = rmp_serde::Deserializer::new(reader);

    let mut state = State::deserialize(&mut deserializer).unwrap();
    rng::set_seed(state.salt(), env::now());

    if let Some(config) = args.email_sender_config {
        state.set_email_sender_config(config);
    }

    crate::email_sender::init(state.email_sender_config().clone());
    state::init(state);
}
