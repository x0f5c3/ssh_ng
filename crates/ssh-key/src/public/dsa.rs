//! Digital Signature Algorithm (DSA) public keys.

use crate::{Error, Mpint, Result};
use dsa::{Components, SigningKey, VerifyingKey};
use encoding::{CheckedSum, Decode, Encode, Reader, Writer};

/// Digital Signature Algorithm (DSA) public key.
///
/// Described in [FIPS 186-4 § 4.1](https://csrc.nist.gov/publications/detail/fips/186/4/final).
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct DsaPublicKey {
    k: VerifyingKey,
    /// Prime modulus.
    pub p: Mpint,

    /// Prime divisor of `p - 1`.
    pub q: Mpint,

    /// Generator of a subgroup of order `q` in the multiplicative group
    /// `GF(p)`, such that `1 < g < p`.
    pub g: Mpint,

    /// The public key, where `y = gˣ mod p`.
    pub y: Mpint,
}

impl Decode for DsaPublicKey {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let p = Mpint::decode(reader)?;
        let q = Mpint::decode(reader)?;
        let g = Mpint::decode(reader)?;
        let y = Mpint::decode(reader)?;
        let comp = Components::from_components(p.try_into()?, q.try_into()?, g.try_into()?)?;
        let key = VerifyingKey::from_components(comp, y.try_into()?)?;
        Ok(Self { k: key, p, q, g, y })
    }
}

impl Encode for DsaPublicKey {
    fn encoded_len(&self) -> encoding::Result<usize> {
        [
            self.p.encoded_len()?,
            self.q.encoded_len()?,
            self.g.encoded_len()?,
            self.y.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        self.p.encode(writer)?;
        self.q.encode(writer)?;
        self.g.encode(writer)?;
        self.y.encode(writer)
    }
}

// #[cfg(feature = "dsa")]
impl TryFrom<DsaPublicKey> for VerifyingKey {
    type Error = Error;

    fn try_from(key: DsaPublicKey) -> Result<VerifyingKey> {
        dsa::VerifyingKey::try_from(&key)
    }
}

// #[cfg(feature = "dsa")]
impl TryFrom<&DsaPublicKey> for VerifyingKey {
    type Error = Error;

    fn try_from(key: &DsaPublicKey) -> Result<VerifyingKey> {
        let components = Components::from_components(
            dsa::BigUint::try_from(&key.p)?,
            dsa::BigUint::try_from(&key.q)?,
            dsa::BigUint::try_from(&key.g)?,
        )?;

        dsa::VerifyingKey::from_components(components, dsa::BigUint::try_from(&key.y)?)
            .map_err(|_| Error::Crypto)
    }
}

// #[cfg(feature = "dsa")]
impl TryFrom<VerifyingKey> for DsaPublicKey {
    type Error = Error;

    fn try_from(key: VerifyingKey) -> Result<DsaPublicKey> {
        DsaPublicKey::try_from(&key)
    }
}

// #[cfg(feature = "dsa")]
impl TryFrom<&VerifyingKey> for DsaPublicKey {
    type Error = Error;

    fn try_from(key: &VerifyingKey) -> Result<DsaPublicKey> {
        Ok(DsaPublicKey {
            k: key.clone(),
            p: key.components().p().try_into()?,
            q: key.components().q().try_into()?,
            g: key.components().g().try_into()?,
            y: key.y().try_into()?,
        })
    }
}
