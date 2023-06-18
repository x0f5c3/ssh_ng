use hmac::Hmac;
use sha2::Sha256;
use sha2::Sha512;
use blake3::Hasher;

const BSIZE_256: usize = 32;
const BSIZE_512: usize = 64;

pub type HmacSha256 = Hmac<Sha256>;
pub type HmacSha512 = Hmac<Sha512>;
pub type HmacBlake3 = Hmac<Hasher>;