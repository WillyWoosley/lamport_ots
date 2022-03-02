//! A Rust implementation of Leslie Lamport's one-time [signature
//! scheme].
//!
//! Intended for use with any hashing algorithm implementing RustCrypto's
//! [`digest`] trait. A list of such algorithms can be found [here].
//!
//! # Example Usage
//!
//! A [`KeyPair`] (consisting of a [`PublicKey`] and a [`PrivateKey`]) is generated using the
//! specified hashing algorithm (in the below example, Sha256). The [`KeyPair`] can then be
//! used to sign an arbitrary byte-encoded piece of data, consuming the [`KeyPair`] in the
//! process. Thereafter, the produced [`Signature`] will be able to verify whether or not a
//! passed piece of byte-encoded data is the message which it signs.
//!
//! ```
//! use lamport_ots::KeyPair;
//! use sha2::Sha256;
//!
//! // Generate a randomized Public/Private KeyPair
//! let keypair = KeyPair::<Sha256>::generate();
//!
//! // Use that KeyPair to generate a signature for passed data
//! let signature = keypair.sign(b"Hello world!");
//!
//! // That signature can now verify the signed data
//! assert!(signature.verify(b"Hello world!"));
//! assert!(!signature.verify(b"Hello moon!"));
//! ```
//!
//! It must be stressed that each [`KeyPair`] can and should only be used to generate a single
//! signature, in order to remain cryptographically secure. Signing subsequent pieces of
//! data will require the generation of a fresh [`KeyPair`].
//!
//! # An Important Note on Security:
//! While Lamport's scheme is secure, this implementation thereof has not been guaranteed
//! to be by any authority. Proceed with caution and at your own risk.
//! 
//! [signature scheme]: https://en.wikipedia.org/wiki/Lamport_signature
//! [`digest`]: https://docs.rs/digest/latest/digest/
//! [here]: https://github.com/RustCrypto/hashes

use digest::Digest;
use rand::{thread_rng, Rng};

use std::marker::PhantomData;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

/// A one-time use private key, containing random data.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct PrivateKey {
    key_options: Vec<(Vec<u8>, Vec<u8>)>,
}

impl PrivateKey {
    /// Generates a private key consisting of a vector of tuples of equally sized
    /// randomized data. The number of elements in the vector and the size of the
    /// values in the tuple are determined by `digest_bytes`, which should correspond to
    /// the hashing algorithm being utilized.
    ///
    /// In general, this function should not be called directly, but rather be called
    /// implicitly through [`KeyPair::generate()`].
    pub fn generate(digest_bytes: usize) -> Self {
        let mut rng = thread_rng();
        let mut key_options = Vec::with_capacity(digest_bytes * 8);
        
        for _ in 0..(digest_bytes * 8) {
            let key0 = (0..digest_bytes).map(|_| rng.gen()).collect();
            let key1 = (0..digest_bytes).map(|_| rng.gen()).collect();
            key_options.push((key0, key1));
        }

        PrivateKey {key_options}
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        for (priv0, priv1) in self.key_options.iter_mut() {
            for byte in priv0 {
                *byte = u8::MIN;
            }
            for byte in priv1 {
                *byte = u8::MIN;
            }
        }
    }
}

/// A one-time use public key, derived from a corresponding [`PrivateKey`].
#[derive(Debug, Clone)]
pub struct PublicKey<T> {
    key_options: Vec<(Vec<u8>, Vec<u8>)>,
    hasher: PhantomData<T>,
}

impl<T: Digest> PublicKey<T> {
    /// Generates the public key which corresponds to the passed [`PrivateKey`],
    /// consisting of tuples containing hashes of the values in `private` using the
    /// associated [`digest`]-implementing hasher.
    ///
    /// In general, this function should not be called directly, but rather be called
    /// implicitly through [`KeyPair::generate()`].
    ///
    /// [`digest`]: https://docs.rs/digest/latest/digest/
    pub fn generate(private: &PrivateKey) -> Self {
        let mut key_options = Vec::with_capacity(<T as Digest>::output_size() * 8);

        for val in &private.key_options {
            let hash0 = T::digest(&val.0).to_vec();
            let hash1 = T::digest(&val.1).to_vec();
            key_options.push((hash0, hash1));
       }

        PublicKey {
            hasher: PhantomData,
            key_options,
        }
    }
}

impl<T> PartialEq for PublicKey<T> {
    fn eq(&self, other: &Self) -> bool {
        self.key_options == other.key_options &&
        self.hasher == other.hasher
    }
}

impl<T> Eq for PublicKey<T> {}

impl<T> PartialOrd for PublicKey<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for PublicKey<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key_options.cmp(&other.key_options)
            .then(self.hasher.cmp(&other.hasher))
    }
}

impl<T> Hash for PublicKey<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key_options.hash(state);
        self.hasher.hash(state);
    }
}

/// A [`PrivateKey`]/[`PublicKey`] pair with an associated hashing algorithm.
#[derive(Debug, Clone)]
pub struct KeyPair<T> {
    private: PrivateKey,
    public: PublicKey<T>,
    hasher: PhantomData<T>, 
}

impl<T: Digest> KeyPair<T> {
    /// Provides a reference to the pair's [`PrivateKey`].
    pub fn private(&self) -> &PrivateKey {
        &self.private
    }

    /// Provides a reference to the pair's [`PublicKey`].
    pub fn public(&self) -> &PublicKey<T> {
        &self.public
    }

    /// Generates a [`PrivateKey`] and [`PublicKey`] using the associated 
    /// [`digest`]-implementing hasher, which can then be used to sign a single piece 
    /// of data.
    ///
    /// # Example
    /// ```
    /// use lamport_ots::{KeyPair, PublicKey};
    /// use sha2::Sha256;
    /// 
    /// let keypair = KeyPair::<Sha256>::generate();
    ///
    /// assert_eq!(keypair.public(), &PublicKey::generate(keypair.private()));
    /// ```
    ///
    /// [`digest`]: https://docs.rs/digest/latest/digest/
    pub fn generate() -> Self {
        let private = PrivateKey::generate(<T as Digest>::output_size());
        let public = PublicKey::<T>::generate(&private);

        KeyPair {
            hasher: PhantomData,
            private,
            public,
        }
    }
   
    /// Uses the keypair to sign the passed `msg` bytes, generating a corresponding
    /// [`Signature`] for the data.
    ///
    /// Note that this method should only ever be invoked once per keypair, as
    /// subsequent uses of the same pair can reveal enough information to potentially
    /// allow signature fabrication. Further explanation of why re-use can lead to
    /// security vulnerabilities can be found [here].
    ///
    /// # Example
    /// ```
    /// use lamport_ots::{KeyPair};
    /// use sha2::Sha256;
    ///
    /// let keypair = KeyPair::<Sha256>::generate();
    /// let sig = keypair.sign(b"Hello world!"); 
    /// ```
    ///
    /// The following would fail to compile, since it attempts to use the same pair more
    /// than once.
    /// ```compile_fail
    /// use lamport_ots::{KeyPair};
    /// use sha2::Sha256;
    ///
    /// let keypair = KeyPair::<Sha256>::generate();
    ///
    /// let sig1 = keypair.sign(b"Hello world!");
    /// let sig2 = keypair.sign(b"Hello moon!"); // keypair already moved creating sig1
    /// ```
    ///
    /// While the following would compile, it should never be done, as it completely
    /// breaks any security provided by the signature scheme.
    /// ```
    /// use lamport_ots::{KeyPair};
    /// use sha2::Sha256;
    ///
    /// let keypair1 = KeyPair::<Sha256>::generate();
    /// let keypair2 = keypair1.clone();
    ///
    /// let sig1 = keypair1.sign(b"Hello world!");
    /// let sig2 = keypair2.sign(b"Hello moon!");
    /// ```
    ///
    /// [here]: https://crypto.stackexchange.com/questions/2640/lamport-signature-how-many-signatures-are-needed-to-forge-a-signature
    pub fn sign(self, msg: &[u8]) -> Signature<T> {
        let msg_hash = T::digest(msg).to_vec();

        let mut sig = Vec::with_capacity(<T as Digest>::output_size() * 8);

        for i in 0..(<T as Digest>::output_size() * 8) {
            let (priv0, priv1) = self.private.key_options[i].clone();
            let msg_index = i / 8;
            let bit_index = 7 - (i % 8);
            
            if msg_hash[msg_index] & (1 << bit_index) != 0 {
                sig.push(priv1);
            } else {
                sig.push(priv0);
            }
        }

        Signature {
            pub_key: self.public,
            hasher: self.hasher,
            sig,
        }
    }
}

impl<T> PartialEq for KeyPair<T> {
    fn eq(&self, other: &Self) -> bool {
        self.private == other.private &&
        self.public == other.public &&
        self.hasher == other.hasher
    }
}

impl<T> Eq for KeyPair<T> {}

impl<T> PartialOrd for KeyPair<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for KeyPair<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.private.cmp(&other.private)
            .then(self.public.cmp(&other.public))
            .then(self.hasher.cmp(&other.hasher))
    }
}

impl<T> Hash for KeyPair<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.private.hash(state);
        self.public.hash(state);
        self.hasher.hash(state);
    }
}

/// A signature signing a single piece of byte-encoded data under an associated hashing
/// algorithm.
///
/// Note that since every signature comes from a different [`KeyPair`], every generated
/// signature will be unique, even if the underlying data is the same. Therefore, 
/// multiple distinct signatures can be generated for the same piece of data.
/// ```
/// use lamport_ots::{KeyPair, Signature};
/// use sha2::Sha256;
///
/// let key1 = KeyPair::<Sha256>::generate();
/// let key2 = KeyPair::<Sha256>::generate();
///
/// let sig1 = key1.sign(b"Hello world!");
/// let sig2 = key2.sign(b"Hello world!");
/// 
/// assert_ne!(sig1.pub_key(), sig2.pub_key());
/// assert_ne!(sig1.sig(), sig2.sig());
/// ```
#[derive(Debug, Clone)]
pub struct Signature<T> {
    pub_key: PublicKey<T>,
    sig: Vec<Vec<u8>>,
    hasher: PhantomData<T>,
}

impl<T:Digest> Signature<T> {
    /// Provides a reference to the [`PublicKey`] from the [`KeyPair`] which generated
    /// the signature.
    pub fn pub_key(&self) -> &PublicKey<T> {
        &self.pub_key
    }
    
    /// Provides a reference to the actual signature data.
    pub fn sig(&self) -> &Vec<Vec<u8>> {
        &self.sig
    }

    /// Verifies that the signature instance signs the passed byte-encoded `msg`.
    ///
    /// Will only return true when `msg` matches exactly the original data passed to the
    /// [`KeyPair::generate()`] function which created this signature. Otherwise returns
    /// false, indicating that either the message or the signature has been tampered
    /// with.
    ///
    /// # Example
    /// ```
    /// use lamport_ots::KeyPair;
    /// use sha2::Sha256;
    ///
    /// let keypair = KeyPair::<Sha256>::generate();
    /// let signature = keypair.sign(b"Hello world!");
    ///
    /// assert!(signature.verify(b"Hello world!"));
    /// assert!(!signature.verify(b"Hello moon!"));
    /// ```
    pub fn verify(&self, msg: &[u8]) -> bool {
        let msg_hash = T::digest(msg).to_vec();

        for (i, (pub0, pub1)) in self.pub_key.key_options.iter().enumerate() {
            let sig_hash = T::digest(&self.sig[i]).to_vec();

            let msg_index = i / 8;
            let bit_index = 7 - (i % 8);

            if msg_hash[msg_index] & (1 << bit_index) != 0 {
                if &sig_hash != pub1 {
                    return false;
                }
            } else {
                if &sig_hash != pub0 {
                    return false;
                }
            }
        }

        true       
    }
}

impl<T> PartialEq for Signature<T> {
    fn eq(&self, other: &Self) -> bool {
        self.pub_key == other.pub_key &&
        self.sig == other.sig &&
        self.hasher == other.hasher
    }
}

impl<T> Eq for Signature<T> {}

impl<T> PartialOrd for Signature<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Signature<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.pub_key.cmp(&other.pub_key)
            .then(self.sig.cmp(&other.sig))
            .then(self.hasher.cmp(&other.hasher))
    }
}

impl<T> Hash for Signature<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pub_key.hash(state);
        self.sig.hash(state);
        self.hasher.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Sha256, Sha512};
    use super::KeyPair;
    
    #[test]
    fn keypair_length_and_contents_sha256() {
        let keypair = KeyPair::<Sha256>::generate();
        assert_eq!(keypair.private.key_options.len(), 256);
        assert_eq!(keypair.public.key_options.len(), 256);

        for i in 0..256 {
            let (k0, k1) = &keypair.private.key_options[i];
            assert_eq!(k0.len(), 32);
            assert_eq!(k1.len(), 32);
        }

        for (k0, k1) in keypair.public.key_options {
            assert_eq!(k0.len(), 32);
            assert_eq!(k1.len(), 32);
        }
    }

    #[test]
    fn keypair_length_and_contents_sha512() {
        let keypair = KeyPair::<Sha512>::generate();
        assert_eq!(keypair.private.key_options.len(), 512);
        assert_eq!(keypair.public.key_options.len(), 512);
        
        for i in 0..512 {
            let (k0, k1) = &keypair.private.key_options[i];
            assert_eq!(k0.len(), 64);
            assert_eq!(k1.len(), 64);
        }

        for (k0, k1) in keypair.public.key_options {
            assert_eq!(k0.len(), 64);
            assert_eq!(k1.len(), 64);
        }
    }
}

