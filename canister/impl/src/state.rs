use crate::hash::{hash_bytes, hash_of_map, hash_with_domain};
use crate::model::salt::Salt;
use crate::model::verification_codes::{CheckVerificationCodeError, VerificationCodes};
use crate::{env, rng, Hash, DEFAULT_EXPIRATION_PERIOD, MAX_EXPIRATION_PERIOD};
use canister_sig_util::signature_map::{SignatureMap, LABEL_SIG};
use canister_sig_util::CanisterSigPublicKey;
use ic_cdk::api::set_certified_data;
use serde::{Deserialize, Serialize};
use sign_in_with_email_canister::{
    Delegation, GenerateVerificationCodeResponse, GetDelegationArgs, GetDelegationResponse,
    Nanoseconds, SignedDelegation, SubmitVerificationCodeArgs, SubmitVerificationCodeResponse,
    SubmitVerificationCodeSuccess,
};
use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    static STATE: RefCell<Option<State>> = RefCell::default();
}

#[derive(Serialize, Deserialize)]
pub struct State {
    verification_codes: VerificationCodes,
    #[serde(skip)]
    signature_map: SignatureMap,
    salt: Salt,
    rng_seed: [u8; 32],
}

const STATE_ALREADY_INITIALIZED: &str = "State has already been initialized";
const STATE_NOT_INITIALIZED: &str = "State has not been initialized";

pub fn init(state: State) {
    STATE.with_borrow_mut(|s| {
        if s.is_some() {
            panic!("{}", STATE_ALREADY_INITIALIZED);
        } else {
            *s = Some(state);
        }
    })
}

pub fn read<F: FnOnce(&State) -> R, R>(f: F) -> R {
    STATE.with_borrow(|s| f(s.as_ref().expect(STATE_NOT_INITIALIZED)))
}

pub fn mutate<F: FnOnce(&mut State) -> R, R>(f: F) -> R {
    STATE.with_borrow_mut(|s| f(s.as_mut().expect(STATE_NOT_INITIALIZED)))
}

pub fn take() -> State {
    STATE.take().expect(STATE_NOT_INITIALIZED)
}

impl State {
    pub fn new() -> State {
        State {
            verification_codes: VerificationCodes::default(),
            signature_map: SignatureMap::default(),
            salt: Salt::default(),
            rng_seed: [0; 32],
        }
    }

    pub fn set_salt(&mut self, salt: [u8; 32]) {
        self.salt.set(salt);
        self.rng_seed = salt;
        rng::set(salt);
    }

    pub fn rng_seed(&self) -> [u8; 32] {
        self.rng_seed
    }

    pub fn recalculate_rng_seed(&mut self) {
        self.rng_seed = rng::gen();
    }

    pub fn generate_verification_code(
        &mut self,
        email: String,
    ) -> GenerateVerificationCodeResponse {
        let code = rng::generate_verification_code();
        let now = env::now();

        match self.verification_codes.push(email, code, now) {
            Ok(()) => GenerateVerificationCodeResponse::Success,
            Err(blocked_until) => GenerateVerificationCodeResponse::Blocked(blocked_until),
        }
    }

    pub fn submit_verification_code(
        &mut self,
        args: SubmitVerificationCodeArgs,
    ) -> SubmitVerificationCodeResponse {
        let now = env::now();

        match self.verification_codes.check(&args.email, &args.code, now) {
            Ok(_) => {
                let seed = self.calculate_seed(&args.email);
                SubmitVerificationCodeResponse::Success(self.prepare_delegation(
                    seed,
                    args.session_key,
                    args.max_time_to_live,
                ))
            }
            Err(CheckVerificationCodeError::Incorrect) => {
                SubmitVerificationCodeResponse::IncorrectCode
            }
            Err(CheckVerificationCodeError::NotFound) => SubmitVerificationCodeResponse::NotFound,
        }
    }

    pub fn get_delegation(&self, args: GetDelegationArgs) -> GetDelegationResponse {
        let delegation = Delegation {
            pubkey: args.session_key,
            expiration: args.expiration,
        };
        let message_hash = delegation_signature_msg_hash(&delegation);
        let seed = self.calculate_seed(&args.email);

        if let Ok(signature) = self
            .signature_map
            .get_signature_as_cbor(&seed, message_hash, None)
        {
            GetDelegationResponse::Success(SignedDelegation {
                delegation,
                signature,
            })
        } else {
            GetDelegationResponse::NotFound
        }
    }

    fn prepare_delegation(
        &mut self,
        seed: [u8; 32],
        session_key: Vec<u8>,
        max_time_to_live: Option<Nanoseconds>,
    ) -> SubmitVerificationCodeSuccess {
        let delta = Nanoseconds::min(
            max_time_to_live.unwrap_or(DEFAULT_EXPIRATION_PERIOD),
            MAX_EXPIRATION_PERIOD,
        );

        let expiration = env::now_nanos().saturating_add(delta);
        let delegation = Delegation {
            pubkey: session_key,
            expiration,
        };
        let msg_hash = delegation_signature_msg_hash(&delegation);

        self.signature_map.add_signature(&seed, msg_hash);
        self.update_root_hash();

        SubmitVerificationCodeSuccess {
            user_key: self.der_encode_canister_sig_key(seed),
            expiration,
        }
    }

    fn update_root_hash(&mut self) {
        let prefixed_root_hash =
            ic_certification::labeled_hash(LABEL_SIG, &self.signature_map.root_hash());
        set_certified_data(&prefixed_root_hash[..]);
    }

    fn der_encode_canister_sig_key(&self, seed: [u8; 32]) -> Vec<u8> {
        let canister_id = env::canister_id();
        CanisterSigPublicKey::new(canister_id, seed.to_vec()).to_der()
    }

    fn calculate_seed(&self, email: &str) -> [u8; 32] {
        let salt = self.salt.get();

        let mut bytes: Vec<u8> = vec![];
        bytes.push(salt.len() as u8);
        bytes.extend_from_slice(&salt);

        let email_bytes = email.bytes();
        bytes.push(email_bytes.len() as u8);
        bytes.extend(email_bytes);

        hash_bytes(&bytes)
    }
}

fn delegation_signature_msg_hash(d: &Delegation) -> Hash {
    use crate::hash::Value;
    let mut m = HashMap::new();
    m.insert("pubkey", Value::Bytes(d.pubkey.as_slice()));
    m.insert("expiration", Value::U64(d.expiration));
    let map_hash = hash_of_map(m);
    hash_with_domain(b"ic-request-auth-delegation", &map_hash)
}
