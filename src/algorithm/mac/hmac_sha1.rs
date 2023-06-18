use hmac::{Hmac};
use sha1::Sha1;

const BSIZE: usize = 20;

pub type HmacSha1 = Hmac<Sha1>;
