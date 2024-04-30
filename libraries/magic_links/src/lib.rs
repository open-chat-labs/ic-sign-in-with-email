use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::{AeadCore, Aes128Gcm, KeyInit};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::rand_core::CryptoRngCore;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sign_in_with_email_canister::{Delegation, Milliseconds, TimestampMillis};

const MAGIC_LINK_EXPIRATION: Milliseconds = 10 * 60 * 1000; // 10 minutes

#[derive(Serialize, Deserialize)]
pub struct MagicLink {
    created: TimestampMillis,
    seed: [u8; 32],
    delegation: Delegation,
}

impl MagicLink {
    pub fn new(seed: [u8; 32], delegation: Delegation, now: TimestampMillis) -> MagicLink {
        MagicLink {
            created: now,
            seed,
            delegation,
        }
    }

    pub fn encrypt<R: CryptoRngCore>(
        &self,
        public_key: RsaPublicKey,
        rng: &mut R,
    ) -> EncryptedMagicLink {
        let bytes = serde_json::to_vec(self).unwrap();
        let key = Aes128Gcm::generate_key(StdRng::from_seed(rng.gen()));
        let cipher = Aes128Gcm::new(&key);
        let nonce = Aes128Gcm::generate_nonce(StdRng::from_seed(rng.gen()));

        let ciphertext = cipher.encrypt(&nonce, bytes.as_slice()).unwrap();
        let encrypted_key = public_key
            .encrypt(rng, Pkcs1v15Encrypt, key.as_slice())
            .unwrap();

        EncryptedMagicLink {
            ciphertext,
            encrypted_key,
            nonce: nonce.to_vec(),
        }
    }

    pub fn created(&self) -> TimestampMillis {
        self.created
    }

    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    pub fn delegation(&self) -> &Delegation {
        &self.delegation
    }

    pub fn expired(&self, now: TimestampMillis) -> bool {
        self.created + MAGIC_LINK_EXPIRATION < now
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct EncryptedMagicLink {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub ciphertext: Vec<u8>,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub encrypted_key: Vec<u8>,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub nonce: Vec<u8>,
}

impl EncryptedMagicLink {
    pub fn sign(self, private_key: RsaPrivateKey) -> SignedMagicLink {
        let signing_key: SigningKey<Sha256> = SigningKey::new(private_key);
        let signature = signing_key.sign(&self.encrypted_key).to_vec();

        SignedMagicLink {
            ciphertext: self.ciphertext,
            encrypted_key: self.encrypted_key,
            nonce: self.nonce,
            signature,
        }
    }

    pub fn decrypt(&self, private_key: RsaPrivateKey) -> Result<MagicLink, String> {
        let key = private_key
            .decrypt(Pkcs1v15Encrypt, &self.encrypted_key)
            .map_err(|e| e.to_string())?;

        let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
        let nonce = GenericArray::from_slice(self.nonce.as_slice());
        let decrypted = cipher.decrypt(nonce, self.ciphertext.as_slice()).unwrap();

        serde_json::from_slice(&decrypted).map_err(|e| e.to_string())
    }
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SignedMagicLink {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub ciphertext: Vec<u8>,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub encrypted_key: Vec<u8>,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub nonce: Vec<u8>,
    #[serde_as(as = "serde_with::hex::Hex")]
    pub signature: Vec<u8>,
}

impl SignedMagicLink {
    pub fn from_hex_strings(
        ciphertext: &str,
        encrypted_key: &str,
        nonce: &str,
        signature: &str,
    ) -> SignedMagicLink {
        SignedMagicLink {
            ciphertext: string_to_hex(ciphertext),
            encrypted_key: string_to_hex(encrypted_key),
            nonce: string_to_hex(nonce),
            signature: string_to_hex(signature),
        }
    }

    pub fn unwrap(
        self,
        signing_public_key: RsaPublicKey,
        decryption_key: RsaPrivateKey,
    ) -> Result<MagicLink, String> {
        if !self.verify(signing_public_key) {
            return Err("Invalid signature".to_string());
        }

        let encrypted = EncryptedMagicLink {
            ciphertext: self.ciphertext,
            encrypted_key: self.encrypted_key,
            nonce: self.nonce,
        };
        encrypted
            .decrypt(decryption_key)
            .map_err(|_| "Decryption failed".to_string())
    }

    pub fn ciphertext_string(&self) -> String {
        hex_to_string(&self.ciphertext)
    }

    pub fn encrypted_key_string(&self) -> String {
        hex_to_string(&self.encrypted_key)
    }

    pub fn nonce_string(&self) -> String {
        hex_to_string(&self.nonce)
    }

    pub fn signature_string(&self) -> String {
        hex_to_string(&self.signature)
    }

    fn verify(&self, public_key: RsaPublicKey) -> bool {
        let Ok(signature) = Signature::try_from(self.signature.as_slice()) else {
            return false;
        };

        let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(public_key);
        verifying_key
            .verify(&self.encrypted_key, &signature)
            .is_ok()
    }
}

fn hex_to_string(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn string_to_hex(str: &str) -> Vec<u8> {
    hex::decode(str).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let input = MagicLink {
            created: 1000,
            seed: [1; 32],
            delegation: Delegation {
                pubkey: vec![2; 32],
                expiration: 1000000000,
            },
        };

        let mut rng = rand::thread_rng();
        let private_key1 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key1 = private_key1.to_public_key();

        let private_key2 = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key2 = private_key2.to_public_key();

        let encrypted = input.encrypt(public_key1, &mut rng);
        let signed = encrypted.sign(private_key2);

        let output = signed.unwrap(public_key2, private_key1).unwrap();

        assert_eq!(output.created, input.created);
        assert_eq!(output.seed, input.seed);
        assert_eq!(output.delegation.pubkey, input.delegation.pubkey);
        assert_eq!(output.delegation.expiration, input.delegation.expiration);
    }
}
