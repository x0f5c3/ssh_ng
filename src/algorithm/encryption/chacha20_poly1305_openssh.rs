use aead::consts::{U32, U64, U4, U16, U12};
use aead::{KeyInit, KeySizeUser};
use aead::generic_array::{ArrayLength, GenericArray};
use aead::rand_core::{CryptoRng, RngCore};
use crypto::cipher::inout::InOutBuf;
use crypto::cipher::{IvState, InnerIvInit, StreamCipherCore, StreamCipherSeek};
use crypto::cipher::{InvalidLength, KeyIvInit, StreamCipher};
use subtle::ConstantTimeEq;


const KEY_SIZE: usize = 32;
// use ring::aead::chacha20_poly1305_openssh::{OpeningKey, SealingKey};

// const BSIZE: usize = 64;
//
// pub(super) struct ChaCha20Poly1305 {
//     client_key: SealingKey,
//     server_key: OpeningKey,
// }
//
// impl Encryption for ChaCha20Poly1305 {
//     fn bsize(&self) -> usize {
//         0
//     }
//
//     fn iv_size(&self) -> usize {
//         0
//     }
//
//     fn group_size(&self) -> usize {
//         64
//     }
//
//     fn new(hash: Hash, _mac: Box<dyn Mac>) -> ChaCha20Poly1305 {
//         let (ck, sk) = hash.mix_ek(BSIZE);
//         let mut sealing_key = [0_u8; BSIZE];
//         let mut opening_key = [0_u8; BSIZE];
//         sealing_key.copy_from_slice(&ck);
//         opening_key.copy_from_slice(&sk);
//
//         ChaCha20Poly1305 {
//             client_key: SealingKey::new(&sealing_key),
//             server_key: OpeningKey::new(&opening_key),
//         }
//     }
//
//     fn encrypt(&mut self, sequence_number: u32, buf: &mut Vec<u8>) {
//         let mut tag = [0_u8; 16];
//         self.client_key
//             .seal_in_place(sequence_number, buf, &mut tag);
//         buf.append(&mut tag.to_vec());
//     }
//
//     fn decrypt(&mut self, sequence_number: u32, buf: &mut [u8]) -> SshResult<Vec<u8>> {
//         let mut packet_len_slice = [0_u8; 4];
//         let len = &buf[..4];
//         packet_len_slice.copy_from_slice(len);
//         let packet_len_slice = self
//             .server_key
//             .decrypt_packet_length(sequence_number, packet_len_slice);
//         let packet_len = u32::from_be_bytes(packet_len_slice);
//         let (buf, tag_) = buf.split_at_mut((packet_len + 4) as usize);
//         let mut tag = [0_u8; 16];
//         tag.copy_from_slice(tag_);
//         match self.server_key.open_in_place(sequence_number, buf, &tag) {
//             Ok(result) => Ok([&packet_len_slice[..], result].concat()),
//             Err(_) => Err(SshError::from("encryption error.")),
//         }
//     }
//
//     fn packet_len(&mut self, sequence_number: u32, buf: &[u8]) -> usize {
//         let mut packet_len_slice = [0_u8; 4];
//         packet_len_slice.copy_from_slice(&buf[..4]);
//         let packet_len_slice = self
//             .server_key
//             .decrypt_packet_length(sequence_number, packet_len_slice);
//         u32::from_be_bytes(packet_len_slice) as usize
//     }
//
//     fn data_len(&mut self, sequence_number: u32, buf: &[u8]) -> usize {
//         let packet_len = self.packet_len(sequence_number, buf);
//         packet_len + 4 + 16
//     }
//
//     fn is_cp(&self) -> bool {
//         true
//     }
// }

use chacha20::{ChaCha20, Key as ChaChaKey};
use poly1305::Poly1305;
use crate::error::CrateError;
use crate::SshResult;


type Tag = GenericArray<u8, U16>;

type Nonce = GenericArray<u8, U12>;

// pub struct Key {
//     k1: ChaChaKey,
//     k2: ChaChaKey,
// }
//
// impl Key {
//     /// Seals (encrypts and signs) a packet.
//     ///
//     /// On input, `plaintext_in_ciphertext_out` must contain the unencrypted
//     /// `packet_length||plaintext` where `plaintext` is the
//     /// `padding_length||payload||random padding`. It will be overwritten by
//     /// `encrypted_packet_length||ciphertext`, where `encrypted_packet_length`
//     /// is encrypted with `K_1` and `ciphertext` is encrypted by `K_2`.
//     pub fn seal_in_place(
//         &self,
//         sequence_number: u32,
//         plaintext_in_ciphertext_out: &mut [u8],
//         tag_out: &mut Tag,
//     ) {
//         let mut counter = make_counter(sequence_number);
//         let poly_key =
//             derive_poly1305_key(&self.key.k_2, counter.increment(), self.key.cpu_features);
//
//         {
//             let (len_in_out, data_and_padding_in_out) =
//                 plaintext_in_ciphertext_out.split_at_mut(PACKET_LENGTH_LEN);
//
//             self.key
//                 .k_1
//                 .encrypt_in_place(make_counter(sequence_number), len_in_out);
//             self.key
//                 .k_2
//                 .encrypt_in_place(counter, data_and_padding_in_out);
//         }
//         let tag = poly1305::Poly1305::new(poly_key).compute_unpadded(&plaintext_in_ciphertext_out);
//         let Tag(tag) = poly1305::sign(poly_key, plaintext_in_ciphertext_out);
//         tag_out.copy_from_slice(tag.as_ref());
//     }
// }
//
// impl From<GenericArray<u8, U64>> for Key {
//     fn from(value: GenericArray<u8, U64>) -> Self {
//         let (k_1, k_2) = value.split_at(32);
//         Self {
//             k1: ChaChaKey::clone_from_slice(k_1),
//             k2: ChaChaKey::clone_from_slice(k_2),
//         }
//     }
// k_2}

pub struct ChaCha20Poly1305OpenSSH {
    cipher: ChaCha20,
    mac: Poly1305,
}

impl KeySizeUser for ChaCha20Poly1305OpenSSH {
    type KeySize = U32;
}

impl ChaCha20Poly1305OpenSSH {
    /// Create a new [`ChaCha20Poly1305`] instance with a 64-byte key.
    /// From [PROTOCOL.chacha20poly1305]:
    ///
    /// > The chacha20-poly1305@openssh.com cipher requires 512 bits of key
    /// > material as output from the SSH key exchange. This forms two 256 bit
    /// > keys (K_1 and K_2), used by two separate instances of chacha20.
    /// > The first 256 bits constitute K_2 and the second 256 bits become
    /// > K_1.
    /// >
    /// > The instance keyed by K_1 is a stream cipher that is used only
    /// > to encrypt the 4 byte packet length field. The second instance,
    /// > keyed by K_2, is used in conjunction with poly1305 to build an AEAD
    /// > (Authenticated Encryption with Associated Data) that is used to encrypt
    /// > and authenticate the entire packet.
    ///
    /// [PROTOCOL.chacha20poly1305]: https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
    pub fn new(key: &[u8], nonce: &[u8]) -> SshResult<Self> {
        #[allow(clippy::integer_arithmetic)]
        if key.len() != KEY_SIZE * 2 {
            return Err(CrateError::from("Wrong key size"));
        }

        // TODO(tarcieri): support for using both keys
        let (k_2, _k_1) = key.split_at(KEY_SIZE);
        let key = Key::from_slice(k_2);

        let nonce = if nonce.is_empty() {
            // For key encryption
            Nonce::default()
        } else {
            Nonce::try_from(nonce).map_err(|_| CrateError::from("IV length error"))?
        };

        let mut cipher = ChaCha20::new(key, &nonce.into());
        let mut poly1305_key = poly1305::Key::default();
        cipher.apply_keystream(&mut poly1305_key);

        let mac = Poly1305::new(&poly1305_key);

        // Seek to block 1
        cipher.seek(64);

        Ok(Self { cipher, mac })
    }

    #[inline]
    pub fn encrypt(mut self, buffer: &mut [u8]) -> Tag {
        self.cipher.apply_keystream(buffer);
        self.mac.compute_unpadded(buffer).into()
    }

    #[inline]
    pub fn decrypt(mut self, buffer: &mut [u8], tag: Tag) -> SshResult<()> {
        let expected_tag = self.mac.compute_unpadded(buffer);

        if expected_tag.ct_eq(&tag).into() {
            self.cipher.apply_keystream(buffer);
            Ok(())
        } else {
            Err(CrateError::from("Decryption failure"))
        }
    }
}

/// Counter || Nonce, all native endian.
#[repr(transparent)]
pub struct Counter(GenericArray<u32, U4>);

impl Counter {
    pub fn zero(nonce: Nonce) -> Self {
        Self::from_nonce_and_ctr(nonce, 0)
    }

    fn from_nonce_and_ctr(nonce: Nonce, ctr: u32) -> Self {
        let nonce = nonce.chunks_exact(4).collect::<&[[u8; 4]]>();
        let inner = [
            ctr,
            u32::from_le_bytes(nonce[0]),
            u32::from_le_bytes(nonce[1]),
            u32::from_le_bytes(nonce[2]),
        ].into();
        Self(inner)
    }

    pub fn increment(&mut self) -> Iv {
        let iv = Iv(self.0);
        self.0[0] += 1;
        iv
    }

    /// This is "less safe" because it hands off management of the counter to
    /// the caller.
    #[cfg(any(
        test,
        not(any(
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "x86",
            target_arch = "x86_64"
        ))
    ))]
    fn into_words_less_safe(self) -> [u32; 4] {
        self.0
    }
}

/// The IV for a single block encryption.
///
/// Intentionally not `Clone` to ensure each is used only once.
pub struct Iv(GenericArray<u32, U4>);

impl Iv {
    fn assume_unique_for_key(value: &GenericArray<u8, U16>) -> Self {
        let value = value.chunks_exact(4);
        Self(value.iter().map(u32::from_le_bytes))
    }

    fn into_counter_for_single_block_less_safe(self) -> Counter {
        Counter(self.0)
    }
}

fn make_counter(sequence_number: u32) -> Counter {
    let nonce = [
        u32::to_be_bytes(0),
        u32::to_be_bytes(0),
        u32::to_be_bytes(sequence_number)
    ];
    Counter::zero(Nonce::from_slice(nonce.concat().as_ref()))
}

fn derive_poly1305_key(chacha_key: &ChaChaKey, iv: Iv) -> poly1305::Poly1305 {
    let mut key_bytes = [0u8; 32];
    let mut cha: chacha20::ChaCha20 = chacha20::ChaCha20::new(chacha_key, iv);
    poly1305:: 
}