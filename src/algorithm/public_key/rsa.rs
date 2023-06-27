use crate::algorithm::public_key::PublicKey as PubK;
use crate::model::Data;
use crate::SshError;
use crypto::digest::{Digest, FixedOutput};
use crypto::signature::{Signer, Verifier};
use rsa::traits::{PaddingScheme, SignatureScheme};
use rsa::{Pkcs1v15Sign, PublicKey};
use signature::digest::const_oid::AssociatedOid;
use signature::{DigestSigner, DigestVerifier, Error};
use ssh_key::Signature;
use std::marker::PhantomData;

pub(super) struct RsaSha<D: Digest + AssociatedOid> {
    k: rsa::pkcs1v15::VerifyingKey<D>,
    s: rsa::pkcs1v15::SigningKey<D>,
    phantom: PhantomData<D>,
}

impl<D: Digest + AssociatedOid> DigestSigner<D, Signature> for RsaSha<D> {
    fn try_sign_digest(&self, digest: D) -> Result<Signature, Error> {
        self.s.try_sign_digest(digest).into()
    }
}

impl<D: Digest + AssociatedOid> DigestVerifier<D, Signature> for RsaSha<D> {}

pub(super) struct RsaSha256;

impl PubK for RsaSha256 {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self
    }

    fn verify_signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, SshError> {
        let mut data = Data::from(ks[4..].to_vec());
        data.get_u8s();

        let e = rsa::BigUint::from_bytes_be(data.get_u8s().as_slice());
        let n = rsa::BigUint::from_bytes_be(data.get_u8s().as_slice());
        let public_key = rsa::RsaPublicKey::new(n, e).unwrap();
        let scheme = rsa::pkcs1v15::Pkcs1v15Sign::new::<sha2::Sha256>();
        let mut dig = sha2::Sha256::default();
        dig.update(message);
        let msg = dig.finalize_fixed();

        Ok(public_key.verify(scheme, msg.as_slice(), sig).is_ok())
    }
}

pub(super) struct RsaSha512;

impl PubK for RsaSha512 {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self
    }

    fn verify_signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, SshError> {
        let mut data = Data::from(ks[4..].to_vec());
        data.get_u8s();

        let e = rsa::BigUint::from_bytes_be(data.get_u8s().as_slice());
        let n = rsa::BigUint::from_bytes_be(data.get_u8s().as_slice());
        let public_key = rsa::RsaPublicKey::new(n, e).unwrap();
        let scheme = rsa::PaddingScheme::new_pkcs1v15_sign::<sha2::Sha512>();

        let digest = ring::digest::digest(&ring::digest::SHA512, message);
        let msg = digest.as_ref();

        Ok(public_key.verify(scheme, msg, sig).is_ok())
    }
}

#[cfg(feature = "dangerous-rsa-sha1")]
pub(super) struct RsaSha1;
#[cfg(feature = "dangerous-rsa-sha1")]
impl PubK for RsaSha1 {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self
    }

    fn verify_signature(&self, ks: &[u8], message: &[u8], sig: &[u8]) -> Result<bool, SshError> {
        let mut data = Data::from(ks[4..].to_vec());
        data.get_u8s();

        let e = rsa::BigUint::from_bytes_be(data.get_u8s().as_slice());
        let n = rsa::BigUint::from_bytes_be(data.get_u8s().as_slice());
        let public_key = rsa::RsaPublicKey::new(n, e).unwrap();
        let scheme = rsa::PaddingScheme::new_pkcs1v15_sign::<sha1::Sha1>();

        let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, message);
        let msg = digest.as_ref();

        Ok(public_key.verify(scheme, msg, sig).is_ok())
    }
}
