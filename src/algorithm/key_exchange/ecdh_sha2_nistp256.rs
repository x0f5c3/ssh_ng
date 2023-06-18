use super::{super::hash::HashType, KeyExchange};
use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
use p256::ecdh::SharedSecret;
use rand::rngs::OsRng;

use crate::SshResult;

pub(super) struct EcdhP256 {
    pub private_key: EphemeralSecret,
    pub public_key: EncodedPoint,
}

impl KeyExchange for EcdhP256 {
    fn new() -> SshResult<Self> {
        let private_key = EphemeralSecret::random(&mut OsRng);
        let public_key = EncodedPoint::from(private_key.public_key());
        Ok(Self {
            private_key,
            public_key,
        })
    }

    fn get_public_key(&self) -> &[u8] {
        self.public_key.as_ref()
    }

    fn get_shared_secret(&self, puk: Vec<u8>) -> SshResult<SharedSecret> {
        let server_pub = PublicKey::from_sec1_bytes(puk.as_ref())?;
        Ok(self.private_key.diffie_hellman(&server_pub))
    }

    fn get_hash_type(&self) -> HashType {
        HashType::SHA256
    }
}
