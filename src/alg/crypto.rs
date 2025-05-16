use anyhow::{anyhow, bail, Ok, Result};
use heapless::Vec;
#[cfg(feature = "crypto-psa")]
use crate::alg::bindings;

#[cfg(feature = "crypto-rs")]
use ed25519_dalek::{Signature, Signer, SigningKey as EdSigningKey};
#[cfg(feature = "crypto-rs")]
use hmac::{Hmac, Mac};
#[cfg(feature = "crypto-rs")]
use k256::{ecdsa::SigningKey as K256SigningKey, elliptic_curve::sec1::ToEncodedPoint, SecretKey};
#[cfg(feature = "crypto-rs")]
use pbkdf2::pbkdf2_hmac;
#[cfg(feature = "crypto-rs")]
use ripemd::Ripemd160;
#[cfg(feature = "crypto-rs")]
use sha2::{Digest, Sha256, Sha512};
#[cfg(feature = "crypto-rs")]
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
#[cfg(feature = "crypto-rs")]
use p256::{
    ecdsa::{
        signature::Signer as P256Signer,
        signature::Verifier as P256Verifier,
        Signature as P256Signature,
        SigningKey as P256SigningKey,
        VerifyingKey as P256VerifyingKey,
    },
    SecretKey as P256SecretKey,
};
pub struct Hash;
pub struct PBKDF2;
pub struct HMAC;
pub struct K256;
pub struct Ed25519;
pub struct X25519;
pub struct Nist256p1;

#[derive(Debug, Clone)]
pub struct K256Signature {
    pub public_key: [u8; 65],
    pub pre_hash: [u8; 32],
    pub signature: [u8; 64],
    pub recovery_id: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct Nist256p1Signature {
    pub public_key: [u8; 65],
    pub signature: Vec<u8, 72>, // DER 
}

impl Hash {
    #[cfg(feature = "crypto-psa")]
    pub fn sha256(input: &[u8]) -> Result<[u8; 32]> {
        let mut hash = [0u8; 32];
        unsafe { bindings::psa_sha256_wrapper(hash.as_mut_ptr(), input.as_ptr(), input.len()) }
            .then_some(hash)
            .ok_or_else(|| anyhow!(""))
    }

    #[cfg(feature = "crypto-rs")]
    pub fn sha256(input: &[u8]) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(input);
        Ok(hasher.finalize().into())
    }

    #[cfg(feature = "crypto-psa")]
    pub fn hash160(input: &[u8]) -> Result<[u8; 20]> {
        let result = Self::sha256(input)?;

        let mut hash = [0u8; 20];

        unsafe { bindings::psa_ripemd160_wrapper(hash.as_mut_ptr(), result.as_ptr(), result.len()) }
            .then_some(hash)
            .ok_or_else(|| anyhow!(""))
    }

    #[cfg(feature = "crypto-rs")]
    pub fn hash160(input: &[u8]) -> Result<[u8; 20]> {
        let sha256_result = Self::sha256(input)?;
        let mut hasher = Ripemd160::new();
        hasher.update(sha256_result);
        Ok(hasher.finalize().into())
    }
}

impl PBKDF2 {
    #[cfg(feature = "crypto-rs")]
    pub fn hmac_sha512(mnemonic: &str, salt: &str, rounds: u32) -> Result<[u8; 64]> {
        let mut seed = [0u8; 64];
        pbkdf2_hmac::<Sha512>(mnemonic.as_bytes(), salt.as_bytes(), rounds, &mut seed);
        Ok(seed)
    }

    #[cfg(feature = "crypto-psa")]
    pub fn hmac_sha512(mnemonic: &str, salt: &str, rounds: u32) -> Result<[u8; 64]> {
        let mut seed = [0u8; 64];
        let status = unsafe {
            bindings::psa_pbkdf2_hmac_sha512_wrapper(
                mnemonic.as_ptr(),
                mnemonic.len(),
                salt.as_ptr(),
                salt.len(),
                seed.as_mut_ptr(),
                rounds as usize,
            )
        };
        if status == 0 {
            Ok(seed)
        } else {
            anyhow::bail!("{}", status)
        }
    }
}

impl HMAC {
    #[cfg(feature = "crypto-rs")]
    pub fn hmac_sha512(secret: &[u8], message: &[u8]) -> Result<[u8; 64]> {
        let hmac = Hmac::<Sha512>::new_from_slice(secret)
            .map_err(|e| anyhow!(e))?
            .chain_update(message)
            .finalize()
            .into_bytes();
        Ok(hmac.into())
    }

    #[cfg(feature = "crypto-psa")]
    pub fn hmac_sha512(secret: &[u8], message: &[u8]) -> Result<[u8; 64]> {
        let mut seed = [0u8; 64];
        let status = unsafe {
            bindings::psa_hmac_sha512_wrapper(
                message.as_ptr(),
                message.len(),
                secret.as_ptr(),
                secret.len(),
                seed.as_mut_ptr(),
            )
        };
        if status == 0 {
            Ok(seed)
        } else {
            anyhow::bail!("{}", status)
        }
    }
}

impl K256 {
    #[cfg(feature = "crypto-rs")]
    pub fn export_pk_compressed(sk: &[u8]) -> Result<[u8; 33]> {
        if sk.len() != 32 {
            bail!("sk len not 32, current {}", sk.len())
        }
        let sk = SecretKey::from_slice(sk).map_err(|e| anyhow!(e))?;
        let pk = sk.public_key().to_encoded_point(true);
        Ok(pk.as_bytes().try_into()?)
    }

    #[cfg(feature = "crypto-psa")]
    pub fn export_pk_compressed(sk: &[u8]) -> Result<[u8; 33]> {
        if sk.len() != 32 {
            bail!("sk len not 32, current {}", sk.len())
        }
        let mut pk = [0u8; 33];
        let status = unsafe { bindings::psa_k256_derive_pk(sk.as_ptr(), pk.as_mut_ptr()) };
        if status == 0 {
            Ok(pk)
        } else {
            anyhow::bail!("{}", status)
        }
    }

    #[cfg(feature = "crypto-rs")]
    pub fn export_pk(sk: &[u8]) -> Result<[u8; 65]> {
        if sk.len() != 32 {
            bail!("sk len not 32, current {}", sk.len())
        }
        let sk = SecretKey::from_slice(sk).map_err(|e| anyhow!(e))?;
        let pk = sk.public_key().to_encoded_point(false);
        Ok(pk.as_bytes().try_into()?)
    }

    #[cfg(feature = "crypto-psa")]
    pub fn export_pk(sk: &[u8]) -> Result<[u8; 65]> {
        if sk.len() != 32 {
            bail!("sk len not 32, current {}", sk.len())
        }
        let mut pk = [0u8; 65];
        let status =
            unsafe { bindings::psa_k256_derive_pk_uncompressed(sk.as_ptr(), pk.as_mut_ptr()) };
        if status == 0 {
            Ok(pk)
        } else {
            anyhow::bail!("{}", status)
        }
    }

    #[cfg(feature = "crypto-rs")]
    pub fn add(num1: &[u8], num2: &[u8]) -> Result<[u8; 32]> {
        let sk1 = SecretKey::from_slice(num1).map_err(|e| anyhow!(e))?;
        let sk2 = SecretKey::from_slice(num2).map_err(|e| anyhow!(e))?;
        let new_secret_key = sk1
            .to_nonzero_scalar()
            .add(&sk2.to_nonzero_scalar())
            .to_bytes();
        Ok(new_secret_key.try_into()?)
    }

    #[cfg(feature = "crypto-psa")]
    pub fn add(num1: &[u8], num2: &[u8]) -> Result<[u8; 32]> {
        let mut result = [0u8; 32];
        let status = unsafe {
            bindings::psa_k256_add_num(num1.as_ptr(), num2.as_ptr(), result.as_mut_ptr())
        };
        if status == 0 {
            Ok(result)
        } else {
            anyhow::bail!("{}", status)
        }
    }

    #[cfg(feature = "crypto-rs")]
    pub fn sign(sk_bytes: &[u8], data: &[u8]) -> Result<K256Signature> {
        let sk = SecretKey::from_slice(sk_bytes).map_err(|e| anyhow!(e))?;
        let signing_key = K256SigningKey::from(sk);
        let signature = signing_key
            .sign_prehash_recoverable(data)
            .map_err(|e| anyhow!(e))?;
        let result = K256Signature {
            public_key: Self::export_pk(sk_bytes)?,
            pre_hash: data.try_into()?,
            signature: signature.0.to_bytes().try_into()?,
            recovery_id: signature.1.to_byte().try_into()?,
        };
        Ok(result)
    }
    #[cfg(feature = "crypto-psa")]
    pub fn sign(sk_bytes: &[u8], data: &[u8]) -> Result<K256Signature> {
        let mut result = [0u8; 64];
        let status = unsafe {
            bindings::psa_k256_sign_hash(
                sk_bytes.as_ptr(),
                data.as_ptr(),
                data.len(),
                result.as_mut_ptr(),
            )
        };
        if status != 0 {
            anyhow::bail!("{}", status);
        }
        let result = K256Signature {
            public_key: Self::export_pk(sk_bytes)?,
            pre_hash: data.try_into()?,
            signature: result.try_into()?,
            recovery_id: None,
        };
        Ok(result)
    }
}

impl Ed25519 {
    #[cfg(feature = "crypto-rs")]
    pub fn tweak_key(secret: &[u8], tweak: &[u8]) -> Result<[u8; 32]> {
        if secret.len() != 32 || tweak.len() != 32 {
            bail!(
                "error，secret: {}, tweak: {}",
                secret.len(),
                tweak.len()
            );
        }
        let mut child_secret = [0u8; 32];
        child_secret.copy_from_slice(secret);
        for (i, &t) in tweak.iter().enumerate() {
            child_secret[i] = child_secret[i].wrapping_add(t);
        }
        Ok(child_secret)
    }

    #[cfg(feature = "crypto-rs")]
    pub fn export_pk(sk: &[u8; 32]) -> Result<[u8; 33]> {
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(sk);
        let verifying_key = signing_key.verifying_key();
        let mut out = [0u8; 33];
        out[0] = 0x00;
        out[1..].copy_from_slice(verifying_key.as_bytes());
        Ok(out)
    }
    #[cfg(feature = "crypto-rs")]
    pub fn sign(secret: &[u8], msg: &[u8]) -> Result<[u8; 64]> {
        if secret.len() != 32 {
            bail!("lenth error: {}", secret.len());
        }
        let secret_key = EdSigningKey::from_bytes(secret.try_into()?);
        let signature: Signature = secret_key.sign(msg);
        Ok(signature.to_bytes())
    }
}

impl X25519 {
    #[cfg(feature = "crypto-rs")]
    pub fn tweak_key(secret: &[u8], tweak: &[u8]) -> Result<[u8; 32]> {
        use curve25519_dalek::scalar::Scalar;

        if secret.len() != 32 || tweak.len() != 32 {
            bail!(
                "Invalid secret or tweak length: {}, {}",
                secret.len(),
                tweak.len()
            );
        }

        let s = Scalar::from_bytes_mod_order(secret.try_into()?);
        let t = Scalar::from_bytes_mod_order(tweak.try_into()?);
        let child = s + t;

        // Convert back to bytes
        let mut bytes = child.to_bytes();

        // X25519 requires clamping
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;

        Ok(bytes)
    }

    #[cfg(feature = "crypto-rs")]
    pub fn export_pk(secret: &[u8]) -> Result<[u8; 33]> {
        if secret.len() != 32 {
            return Err(anyhow!(
                "Invalid secret length: expected 32, got {}",
                secret.len()
            ));
        }

        let mut secret_key = [0u8; 32];
        secret_key.copy_from_slice(secret);

        // X25519 clamping
        secret_key[0] &= 248;
        secret_key[31] &= 127;
        secret_key[31] |= 64;

        let x25519_secret = X25519Secret::from(secret_key);
        let public_key = X25519PublicKey::from(&x25519_secret);

        let mut out = [0u8; 33];
        out[0] = 0x00;
        out[1..].copy_from_slice(&public_key.to_bytes());
        Ok(out)
    }
}

impl Nist256p1 {
    #[cfg(feature = "crypto-rs")]
    pub fn add(sk: &[u8], tweak: &[u8]) -> Result<[u8; 32]> {
        use p256::elliptic_curve::ff::PrimeField;
        use p256::elliptic_curve::Field;
        use p256::FieldBytes;

        if sk.len() != 32 || tweak.len() != 32 {
            bail!("sk or tweak length != 32");
        }

        let sk_scalar = Option::<p256::Scalar>::from(p256::Scalar::from_repr(*FieldBytes::from_slice(sk)))
            .ok_or_else(|| anyhow!("invalid sk scalar"))?;
        let tweak_scalar = Option::<p256::Scalar>::from(p256::Scalar::from_repr(*FieldBytes::from_slice(tweak)))
            .ok_or_else(|| anyhow!("invalid tweak scalar"))?;

        let sum = sk_scalar + tweak_scalar;
        if sum.is_zero().into() {
            bail!("derived zero key");
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(&sum.to_repr());
        Ok(out)
    }

    #[cfg(feature = "crypto-rs")]
    pub fn export_pk_compressed(sk: &[u8]) -> Result<[u8; 33]> {
        if sk.len() != 32 {
            bail!("sk len not 32, current {}", sk.len())
        }
        let sk = P256SecretKey::from_slice(sk).map_err(|e| anyhow!(e))?;
        let pk = sk.public_key().to_encoded_point(true);
        Ok(pk.as_bytes().try_into()?)
    }

    #[cfg(feature = "crypto-rs")]
    pub fn export_pk(sk: &[u8]) -> Result<[u8; 33]> {
        if sk.len() != 32 {
            bail!("sk len not 32, current {}", sk.len())
        }
        let sk = P256SecretKey::from_slice(sk).map_err(|e| anyhow!(e))?;
        let pk = sk.public_key().to_encoded_point(true); // true = compressed
        Ok(pk.as_bytes().try_into()?)
    }

    #[cfg(feature = "crypto-rs")]
    pub fn sign(secret: &[u8], msg: &[u8]) -> Result<Nist256p1Signature> {
        if secret.len() != 32 {
            bail!("secret key length not 32");
        }

        let signing_key = P256SigningKey::from_bytes(secret.into()).map_err(|e| anyhow!(e))?;
        let verifying_key = signing_key.verifying_key();
        let sig: P256Signature = P256Signer::sign(&signing_key, msg);

        let pk = verifying_key.to_encoded_point(false);
        let mut out_sig = Vec::<u8, 72>::new();
        let _ = out_sig.extend_from_slice(&sig.to_vec());

        Ok(Nist256p1Signature {
            public_key: pk.as_bytes().try_into()?,
            signature: out_sig,
        })
    }

    #[cfg(feature = "crypto-rs")]
    pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool> {
        let verifying_key = P256VerifyingKey::from_sec1_bytes(pk).map_err(|e| anyhow!(e))?;
        let sig = P256Signature::from_der(sig).map_err(|e| anyhow!(e))?;
        Ok(P256Verifier::verify(&verifying_key, msg, &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::vec;
    use hex;

    #[test]
    fn test_k256_invalid_private_keys() {
        let zero_pk = vec![0u8; 32];
        assert!(K256::export_pk_compressed(&zero_pk).is_err());

        let overflow_pk =
            hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
                .unwrap();
        assert!(K256::export_pk_compressed(&overflow_pk).is_err());

        let n_pk = hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
            .unwrap();
        assert!(K256::export_pk_compressed(&n_pk).is_err());

        let short_pk = vec![1u8; 31];
        assert!(K256::export_pk_compressed(&short_pk).is_err());

        let long_pk = vec![1u8; 33];
        assert!(K256::export_pk_compressed(&long_pk).is_err());
    }

    #[test]
    fn test_k256_sign_1() {
        let hex = hex::decode("780293f5138d6713e369b0faa692d3d61ec66426c9e34461281b7ca75a5aa284")
            .unwrap();

        let sk = hex::decode("419a6c35542d94571590434e3e7824d692c9a709d635c9878684c8e4cd2bb080")
            .unwrap();

        let signature = "5dc3e1169d68315eb56afc659dacbfa024d00e47522ef41a6a044657cc7d66aa7ff3734a8c6e587559d267aa0330f0d97966f95350caa64e41403b633b1822ad";

        let result = K256::sign(&sk, &hex).unwrap();

        assert_eq!(hex::encode(result.signature), signature);
    }

    #[test]
    fn test_k256_sign_2() {
        let hex = hex::decode("deec2a84471d85e6fc4746937d39157b863d2d73a80c523977b0348f3a18a063")
            .unwrap();

        let sk = hex::decode("d7d4a7d004e5b3adbd80699456dfb9d5194cbb7b0214d3c115c0971cba27d5d0")
            .unwrap();

        let signature = "72bf1ac4f0c4f3f134d4ab462b6427af361592d364cedb8d7ace68b37f17387757cb234a59004cabbfd2f4043f35870cc9f466c4d203b989d8deca4c2134d4f3";

        let result = K256::sign(&sk, &hex).unwrap();

        assert_eq!(hex::encode(result.signature), signature);
    }

    #[test]
    fn test_k256_get_pk() {
        let sk = hex::decode("0bc0bb17546bea74ce589ce21caae32ae3302f1fdda1c370fcb381c8155d536c")
            .unwrap();

        let pk = K256::export_pk(sk.as_slice()).unwrap();

        let pk_hex = hex::decode("04401b572dd885235567e0177711e913ec1587344669936f6358c86bcc73c189be3f2340a88249509b4b9bce6f5190d4e537ec314026ee849707e28ad57a1723b2").unwrap();
        assert_eq!(pk, pk_hex.as_slice());

        let pk2 = K256::export_pk_compressed(sk.as_slice()).unwrap();

        let pk2_hex =
            hex::decode("02401b572dd885235567e0177711e913ec1587344669936f6358c86bcc73c189be")
                .unwrap();

        assert_eq!(pk2, pk2_hex.as_slice());
    }

    #[test]
    fn test_ed25519_sign() {
        let sk = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        let msg = b"test message";
        let sig = Ed25519::sign(&sk, msg).unwrap();
        let expected_sig = hex::decode("98a39ec11a0dfbbfdbd7a7e2394b2b83a16586e92100bcb9be672ddfba3e7acb861c94d6ad4cf6e3e60136ca141fc4f2f1be0c1b8ef0bea12aee76f007a4c30a").unwrap();
        assert_eq!(sig.as_slice(), expected_sig.as_slice());
    }

    #[test]
    fn test_ed25519_tweak_key() {
        let sk = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        let tweak = hex::decode("1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
        let tweaked = Ed25519::tweak_key(&sk, &tweak).unwrap();
        let expected =
            hex::decode("ae72c2ae000e6b71cb955b05a3fd3dd5555ad67a8c437a2a814cbd142dbf9071")
                .unwrap();
        assert_eq!(tweaked, expected.as_slice());
    }

    #[test]
    fn test_x25519_export_pk() {
        let sk = hex::decode("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
            .unwrap();
        let pk = X25519::export_pk(&sk).unwrap();

        let expected_pk =
            hex::decode("00bcb1a123e0742b56b07e0b06c8106bef137131ace91585f0eee4949447661c15")
                .unwrap();

        assert_eq!(pk.as_slice(), expected_pk.as_slice());
    }

    #[test]
    fn test_x25519_tweak_key() {
        let sk = hex::decode("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3")
            .unwrap();
        let tweak = hex::decode("1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
        let tweaked = X25519::tweak_key(&sk, &tweak).unwrap();
        let expected =
            hex::decode("d00b4ef8a5842c85c35ed7ebf4495090b05b30501031b18faa9f970809b48b44")
                .unwrap();
        assert_eq!(tweaked, expected.as_slice());
    }
}
