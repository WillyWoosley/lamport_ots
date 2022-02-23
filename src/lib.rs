use digest::Digest;
use rand::{thread_rng, Rng};

use std::marker::PhantomData;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct PrivateKey {
    key_options: Vec<(Vec<u8>, Vec<u8>)>,
}

impl PrivateKey {
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

#[derive(Debug, Clone)]
pub struct PublicKey<T> {
    key_options: Vec<(Vec<u8>, Vec<u8>)>,
    hasher: PhantomData<T>,
}

impl<T: Digest> PublicKey<T> {
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

#[derive(Debug, Clone)]
pub struct KeyPair<T> {
    private: PrivateKey,
    public: PublicKey<T>,
    hasher: PhantomData<T>, 
}

impl<T: Digest> KeyPair<T> {
    pub fn private(&self) -> &PrivateKey {
        &self.private
    }

    pub fn public(&self) -> &PublicKey<T> {
        &self.public
    }

    pub fn generate() -> Self {
        let private = PrivateKey::generate(<T as Digest>::output_size());
        let public = PublicKey::<T>::generate(&private);

        KeyPair {
            hasher: PhantomData,
            private,
            public,
        }
    }
    
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

#[derive(Debug, Clone)]
pub struct Signature<T> {
    pub_key: PublicKey<T>,
    sig: Vec<Vec<u8>>,
    hasher: PhantomData<T>,
}

impl<T:Digest> Signature<T> {
    pub fn pub_key(&self) -> &PublicKey<T> {
        &self.pub_key
    }

    pub fn sig(&self) -> &Vec<Vec<u8>> {
        &self.sig
    }

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

