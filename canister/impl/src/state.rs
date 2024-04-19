use crate::email_sender::EmailSenderConfig;
use crate::hash::{hash_bytes, hash_of_map, hash_with_domain};
use crate::model::salt::Salt;
use crate::model::validated_email::ValidatedEmail;
use crate::model::verification_codes::{CheckVerificationCodeError, VerificationCodes};
use crate::{env, Hash, DEFAULT_EXPIRATION_PERIOD, MAX_EXPIRATION_PERIOD};
use canister_sig_util::signature_map::{SignatureMap, LABEL_SIG};
use canister_sig_util::CanisterSigPublicKey;
use ic_cdk::api::set_certified_data;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sign_in_with_email_canister::{
    Delegation, GenerateVerificationCodeResponse, GetDelegationResponse, Nanoseconds,
    SignedDelegation, SubmitVerificationCodeResponse, SubmitVerificationCodeSuccess,
};
use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    static STATE: RefCell<Option<State>> = RefCell::default();
}

#[derive(Serialize, Deserialize, Default)]
pub struct State {
    verification_codes: VerificationCodes,
    #[serde(skip)]
    signature_map: SignatureMap,
    email_sender_config: Option<EmailSenderConfig>,
    rsa_private_key: Option<RsaPrivateKey>,
    salt: Salt,
    test_mode: bool,
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
    pub fn new(test_mode: bool) -> State {
        State {
            test_mode,
            ..Default::default()
        }
    }

    pub fn email_sender_config(&self) -> Option<&EmailSenderConfig> {
        self.email_sender_config.as_ref()
    }

    pub fn set_email_sender_config(&mut self, config: EmailSenderConfig) {
        self.email_sender_config = Some(config);
    }

    pub fn rsa_public_key(&self) -> Option<RsaPublicKey> {
        self.rsa_private_key.as_ref().map(RsaPublicKey::from)
    }

    pub fn rsa_private_key(&self) -> Option<&RsaPrivateKey> {
        self.rsa_private_key.as_ref()
    }

    pub fn set_rsa_private_key(&mut self, private_key: RsaPrivateKey) {
        self.rsa_private_key = Some(private_key);
    }

    pub fn salt(&self) -> [u8; 32] {
        self.salt.get()
    }

    pub fn set_salt(&mut self, salt: [u8; 32]) {
        self.salt.set(salt);
    }

    pub fn test_mode(&self) -> bool {
        self.test_mode
    }

    pub fn store_verification_code(
        &mut self,
        email: ValidatedEmail,
        code: String,
    ) -> GenerateVerificationCodeResponse {
        let now = env::now();

        match self.verification_codes.push(email, code, now) {
            Ok(()) => GenerateVerificationCodeResponse::Success,
            Err(blocked_until) => GenerateVerificationCodeResponse::Blocked(blocked_until),
        }
    }

    pub fn submit_verification_code(
        &mut self,
        email: ValidatedEmail,
        code: String,
        session_key: Vec<u8>,
        max_time_to_live: Option<Nanoseconds>,
    ) -> SubmitVerificationCodeResponse {
        let now = env::now();

        match self.verification_codes.check(&email, &code, now) {
            Ok(_) => {
                let seed = self.calculate_seed(&email);
                SubmitVerificationCodeResponse::Success(self.prepare_delegation(
                    seed,
                    session_key,
                    max_time_to_live,
                ))
            }
            Err(CheckVerificationCodeError::Incorrect(ic)) => {
                SubmitVerificationCodeResponse::IncorrectCode(ic)
            }
            Err(CheckVerificationCodeError::NotFound) => SubmitVerificationCodeResponse::NotFound,
        }
    }

    pub fn get_delegation(
        &self,
        email: ValidatedEmail,
        delegation: Delegation,
    ) -> GetDelegationResponse {
        let message_hash = delegation_signature_msg_hash(&delegation);
        let seed = self.calculate_seed(&email);

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

    fn calculate_seed(&self, email: &ValidatedEmail) -> [u8; 32] {
        let salt = self.salt.get();

        let mut bytes: Vec<u8> = vec![];
        bytes.push(salt.len() as u8);
        bytes.extend_from_slice(&salt);

        let email_bytes = email.as_str().bytes();
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
