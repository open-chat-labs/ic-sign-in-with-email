use crate::model::magic_links::MagicLinks;
use crate::model::salt::Salt;
use crate::{env, Hash};
use canister_sig_util::signature_map::{SignatureMap, LABEL_SIG};
use canister_sig_util::CanisterSigPublicKey;
use ic_cdk::api::set_certified_data;
use magic_links::SignedMagicLink;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sign_in_with_email_canister::{
    Delegation, EmailSenderConfig, SignedDelegation, TimestampMillis, NANOS_PER_MILLISECOND,
};
use std::cell::RefCell;
use utils::{calculate_seed, delegation_signature_msg_hash, ValidatedEmail};

thread_local! {
    static STATE: RefCell<Option<State>> = RefCell::default();
}

#[derive(Serialize, Deserialize)]
pub struct State {
    #[serde(skip)]
    signature_map: SignatureMap,
    email_sender_config: Option<EmailSenderConfig>,
    email_sender_rsa_public_key: RsaPublicKey,
    magic_links: MagicLinks,
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
    pub fn new(email_sender_public_key: RsaPublicKey, test_mode: bool) -> State {
        State {
            signature_map: SignatureMap::default(),
            email_sender_config: None,
            email_sender_rsa_public_key: email_sender_public_key,
            magic_links: MagicLinks::default(),
            rsa_private_key: None,
            salt: Salt::default(),
            test_mode,
        }
    }

    pub fn email_sender_rsa_public_key(&self) -> &RsaPublicKey {
        &self.email_sender_rsa_public_key
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

    pub fn process_auth_request(
        &mut self,
        signed_magic_link: SignedMagicLink,
        code: String,
        is_update: bool,
        now: TimestampMillis,
    ) -> AuthResult {
        let private_key = self.rsa_private_key.clone().unwrap();

        let magic_link =
            match signed_magic_link.unwrap(self.email_sender_rsa_public_key.clone(), private_key) {
                Ok(m) => m,
                Err(error) => return AuthResult::LinkInvalid(error),
            };

        if magic_link.expired(now) {
            return AuthResult::LinkExpired;
        }
        let msg_hash = delegation_signature_msg_hash(magic_link.delegation());

        if self
            .signature_map
            .get_signature_as_cbor(&magic_link.seed(), msg_hash, None)
            .is_ok()
        {
            if magic_link.code() == code {
                AuthResult::Success
            } else {
                AuthResult::CodeIncorrect
            }
        } else if !is_update {
            AuthResult::RequiresUpgrade
        } else {
            self.signature_map
                .add_signature(&magic_link.seed(), msg_hash);
            self.update_root_hash();
            self.magic_links
                .mark_success(magic_link.seed(), msg_hash, now);

            AuthResult::Success
        }
    }

    pub fn get_delegation(&self, seed: Hash, delegation: Delegation) -> Option<SignedDelegation> {
        let msg_hash = delegation_signature_msg_hash(&delegation);

        self.signature_map
            .get_signature_as_cbor(&seed, msg_hash, None)
            .ok()
            .map(|s| SignedDelegation {
                delegation,
                signature: s,
            })
    }

    pub fn record_magic_link_sent(
        &mut self,
        seed: Hash,
        delegation: &Delegation,
        now: TimestampMillis,
    ) {
        let msg_hash = delegation_signature_msg_hash(delegation);
        self.magic_links.mark_magic_link_sent(
            seed,
            msg_hash,
            delegation.expiration / NANOS_PER_MILLISECOND,
            now,
        );
    }

    pub fn calculate_seed(&self, email: &ValidatedEmail) -> Hash {
        calculate_seed(self.salt.get(), email)
    }

    pub fn der_encode_canister_sig_key(&self, seed: Hash) -> Vec<u8> {
        let canister_id = env::canister_id();
        CanisterSigPublicKey::new(canister_id, seed.to_vec()).to_der()
    }

    fn update_root_hash(&mut self) {
        let prefixed_root_hash =
            ic_certification::labeled_hash(LABEL_SIG, &self.signature_map.root_hash());
        set_certified_data(&prefixed_root_hash[..]);
    }
}

pub enum AuthResult {
    Success,
    RequiresUpgrade,
    LinkExpired,
    CodeIncorrect,
    LinkInvalid(String),
}
