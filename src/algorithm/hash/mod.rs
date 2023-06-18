#[allow(clippy::module_inception)]
mod hash;
mod hash_ctx;
mod hash_type;

use sha1::Digest;

pub(crate) use hash::Hash;
pub(crate) use hash_ctx::HashCtx;
pub(crate) use hash_type::HashType;

pub fn digest(data: &[u8], hash_type: HashType) -> Vec<u8> {
    let mut hasher = match hash_type {
        // HashType::SHA1 => ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data),
        // HashType::SHA256 => ring::digest::digest(&ring::digest::SHA256, data),
        // HashType::None => ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data), // actually doesn't need
        HashType::SHA1 => sha1::Sha1::new(),
        HashType::SHA256 => sha2::Sha256::new(),
        HashType::None => sha1::Sha1::new(),
    };
    hasher.update(data);
    hasher.finalize().to_vec()
}
