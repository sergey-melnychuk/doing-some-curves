// cargo add sha2 hex
// cargo add ark-serialize --features derive

use ark_ff::{Field, PrimeField};
use ark_secp256k1::{Affine, Fr as F, Projective, G_GENERATOR_X, G_GENERATOR_Y};

mod types {
    use ark_ff::{Fp, MontBackend};
    use ark_secp256k1::FrConfig;

    pub type Number = Fp<MontBackend<FrConfig, 4>, 4>;
}

mod utils {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use std::io::Cursor;

    pub fn into_bytes<T: CanonicalSerialize>(x: &T) -> Vec<u8> {
        let mut bytes = Vec::new();
        x.serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    pub fn from_bytes<T: CanonicalDeserialize>(b: &[u8]) -> T {
        T::deserialize_compressed_unchecked(Cursor::new(b)).unwrap()
    }

    pub fn hash(msg: &[&[u8]]) -> Vec<u8> {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        for m in msg {
            hasher.update(m);
        }
        let hash = hasher.finalize();
        hash.to_vec()
    }
}

use utils::{from_bytes, hash, into_bytes};

pub fn rand() -> Vec<u8> {
    use ark_std::UniformRand;
    let mut rng = rand::thread_rng();
    let a = F::rand(&mut rng);
    into_bytes(&a)
}

pub fn get_pk(sk: &[u8]) -> Vec<u8> {
    // Derive Public Key from a Secret Key:
    //
    // SK - secret key (scalar)
    // G - generator point
    //
    // PK = G * SK

    let g = Affine::new(G_GENERATOR_X, G_GENERATOR_Y);
    let sk = F::from_be_bytes_mod_order(sk);
    let pk = g * sk;

    into_bytes(&pk)
}

pub fn get_pk_xy(sk: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Derive Public Key from a Secret Key:
    //
    // SK - secret key (scalar)
    // G - generator point
    //
    // PK = G * SK

    let g = Affine::new(G_GENERATOR_X, G_GENERATOR_Y);
    let sk = F::from_be_bytes_mod_order(sk);
    let pk = g * sk;

    (into_bytes(&pk.x), into_bytes(&pk.y))
}

pub fn sig(sk: &[u8], msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // Signing:
    //
    // SK - secret key
    // PK - public key (PK = SK * G)
    // m - message
    // H - sha256
    // (r, s) - signature
    //
    // k = H(H(SK) || H(m))
    // R = k * G
    // r = R.x
    // s = k' * (h + r * SK)

    let k = hash(&[&hash(&[sk]), &hash(&[msg])]);
    let k = F::from_be_bytes_mod_order(&k);
    let ki = k.inverse().unwrap();

    let h = hash(&[msg]);
    let h = F::from_be_bytes_mod_order(&h);

    let sk = F::from_be_bytes_mod_order(sk);

    let g = Affine::new(G_GENERATOR_X, G_GENERATOR_Y);
    let r = g * k;
    let r = Affine::from(r);
    let rx = F::from(r.x.into_bigint());

    let s = ki * (h + rx * sk);

    (into_bytes(&rx), into_bytes(&s))
}

pub fn ver(pk: &[u8], msg: &[u8], sig: (&[u8], &[u8])) -> bool {
    // Verification
    //
    // R = (h * s') * G + (r * s') * PK
    // For a valid signature: R.x == sig.r
    //
    // (h * s') * G + (r * s') * PK
    // (h * s') * G + (r * s') * SK * G
    // (h + r * SK) * s' * G
    // (h + r * SK) * (k' * (h + r * SK))' * G
    // (h + r * SK) * k * (h + r * SK)' * G
    // k * G

    let pk: Projective = from_bytes(pk);

    let (rx, s) = sig;
    let rx: types::Number = from_bytes(rx);
    let s: types::Number = from_bytes(s);
    let si = s.inverse().unwrap();

    let h = hash(&[msg]);
    let h = F::from_be_bytes_mod_order(&h);

    let g = Affine::new(G_GENERATOR_X, G_GENERATOR_Y);
    let r = g * h * si + pk * rx * si;
    let r = Affine::from(r);

    rx == F::from(r.x.into_bigint())
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_ecdsa() {
        use super::*;

        use ark_std::{rand, UniformRand};
        let mut rng = rand::thread_rng();
        let a = F::rand(&mut rng);
        let sk = into_bytes(&a);

        // let sk = "43cdf7c47a34cac01e717ad098bde292c2b3972719da38b7d38706be25706d4f";
        // let sk = hex::decode(sk).unwrap();
        let pk = get_pk(&sk);

        let msg = b"the quick brown fox jumps over the lazy dog";
        let (r, s) = sig(&sk, msg);
        assert!(ver(&pk, msg, (&r, &s)));
    }

    #[test]
    fn test_dhke() {
        use ark_secp256k1::{Affine, Fr as F, G_GENERATOR_X, G_GENERATOR_Y};
        use ark_std::{rand, UniformRand};

        let mut rng = rand::thread_rng();
        let g = Affine::new(G_GENERATOR_X, G_GENERATOR_Y);

        let a = F::rand(&mut rng);
        let ga = g * a;

        let b = F::rand(&mut rng);
        let gb = g * b;

        let one = ga + gb;
        let two = gb + ga;

        // shared secrets must match
        assert_eq!(one, two);
    }
}
