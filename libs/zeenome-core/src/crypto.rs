use crate::errors::{Result, ZeenomeError};
use ed25519_dalek::{SecretKey, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: String,
    pub private_key: String, // Base64 encoded for storage
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        // Generate random bytes for secret key
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        // In ed25519-dalek 2.x, SecretKey is [u8; 32]
        let secret_key: SecretKey = secret_bytes;
        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();

        // Store the full keypair (64 bytes: 32 secret + 32 public)
        let keypair_bytes = signing_key.to_keypair_bytes();

        Self {
            public_key: hex::encode(verifying_key.as_bytes()),
            private_key: {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode(keypair_bytes)
            },
        }
    }

    pub fn signing_key(&self) -> Result<SigningKey> {
        let bytes = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.decode(&self.private_key)
        }
        .map_err(|e| ZeenomeError::Crypto(format!("Failed to decode private key: {}", e)))?;

        // Try 64-byte keypair first, then 32-byte secret key
        if bytes.len() == 64 {
            let keypair_array: [u8; 64] = bytes
                .try_into()
                .map_err(|_| ZeenomeError::Crypto("Invalid keypair length".to_string()))?;
            SigningKey::from_keypair_bytes(&keypair_array)
                .map_err(|e| ZeenomeError::Crypto(format!("Failed to create signing key: {:?}", e)))
        } else if bytes.len() == 32 {
            // For 32-byte secret keys, we need to expand to keypair
            // In ed25519-dalek 2.x, we need the full keypair
            Err(ZeenomeError::Crypto(
                "32-byte keys not supported, use 64-byte keypair format".to_string(),
            ))
        } else {
            Err(ZeenomeError::Crypto(format!(
                "Invalid key length: expected 64 bytes, got {}",
                bytes.len()
            )))
        }
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        let bytes = hex::decode(&self.public_key)
            .map_err(|e| ZeenomeError::Crypto(format!("Failed to decode public key: {}", e)))?;
        let key_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ZeenomeError::Crypto("Invalid key length".to_string()))?;
        VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| ZeenomeError::Crypto(format!("Failed to create verifying key: {:?}", e)))
    }
}

pub fn hash_data(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn sign_message(message: &[u8], keypair: &KeyPair) -> Result<String> {
    let signing_key = keypair.signing_key()?;
    let signature = signing_key.sign(message);
    Ok(hex::encode(signature.to_bytes()))
}
