use anyhow::anyhow;
use super::{super::hash::HashType, KeyExchange};
use crate::SshResult;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

pub(super) struct CURVE25519 {
    pub private_key: EphemeralSecret,
    pub public_key: PublicKey,
}

impl KeyExchange for CURVE25519 {
    fn new() -> SshResult<Self> {
        let private_key = EphemeralSecret::random();
        let pub_key = PublicKey::from(&private_key);
        Ok(Self {
            public_key: pub_key,
            private_key,
        })
    }

    fn get_public_key(&self) -> &[u8] {
        self.public_key.as_ref()
    }

    fn get_shared_secret(&self, puk: Vec<u8>) -> SshResult<SharedSecret> {
        let mut public_key = [0u8; 32];
        if puk.len() != 32 {
            Err(anyhow!("Public key should be 32 bytes"))
        }
        public_key.copy_from_slice(&puk);
        Ok(self
            .private_key
            .diffie_hellman(&PublicKey::from(public_key)))
    }

    fn get_hash_type(&self) -> HashType {
        HashType::SHA256
    }
}
