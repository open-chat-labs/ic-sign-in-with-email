use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::rand_core::CryptoRngCore;
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sign_in_with_email_canister::{Delegation, TimestampMillis};
use std::fmt::{Display, Formatter};

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
        let encrypted = public_key.encrypt(rng, Pkcs1v15Encrypt, &bytes).unwrap();
        let str = hex::encode(encrypted);

        EncryptedMagicLink(str)
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
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedMagicLink(String);

impl EncryptedMagicLink {
    pub fn decrypt(&self, private_key: RsaPrivateKey) -> Result<MagicLink, String> {
        let encrypted = hex::decode(&self.0).map_err(|e| e.to_string())?;
        let bytes = private_key
            .decrypt(Pkcs1v15Encrypt, &encrypted)
            .map_err(|e| e.to_string())?;

        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
    }
}

impl From<String> for EncryptedMagicLink {
    fn from(value: String) -> Self {
        EncryptedMagicLink(value)
    }
}

impl Display for EncryptedMagicLink {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub struct SignedMagicLink {
    link: EncryptedMagicLink,
    // Hex encoded
    signature: String,
}

impl SignedMagicLink {
    pub fn new(link: EncryptedMagicLink, signature: String) -> SignedMagicLink {
        SignedMagicLink { link, signature }
    }

    pub fn verify(&self, public_key: RsaPublicKey) -> bool {
        let Ok(signature_bytes) = hex::decode(&self.signature) else {
            return false;
        };

        let Ok(signature) = Signature::try_from(signature_bytes.as_slice()) else {
            return false;
        };

        let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(public_key);
        verifying_key
            .verify(self.link.0.as_bytes(), &signature)
            .is_ok()
    }

    pub fn link(&self) -> &EncryptedMagicLink {
        &self.link
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};

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

        let signing_key: SigningKey<Sha256> = SigningKey::new(private_key2);
        let signature_bytes = signing_key.sign(encrypted.to_string().as_bytes()).to_vec();
        let signature = hex::encode(signature_bytes);

        let signed = SignedMagicLink {
            link: encrypted,
            signature,
        };

        assert!(signed.verify(public_key2));

        let output = signed.link.decrypt(private_key1).unwrap();

        assert_eq!(output.created, input.created);
        assert_eq!(output.seed, input.seed);
        assert_eq!(output.delegation.pubkey, input.delegation.pubkey);
        assert_eq!(output.delegation.expiration, input.delegation.expiration);
    }
}
