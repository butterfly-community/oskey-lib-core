use anyhow::{anyhow, bail, Ok, Result};

#[cfg(feature = "crypto-psa")]
use crate::alg::bindings;

#[cfg(feature = "crypto-rs")]
use hmac::{Hmac, Mac};
#[cfg(feature = "crypto-rs")]
use k256::{ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint, SecretKey};
#[cfg(feature = "crypto-rs")]
use pbkdf2::pbkdf2_hmac;
#[cfg(feature = "crypto-rs")]
use ripemd::Ripemd160;
#[cfg(feature = "crypto-rs")]
use sha2::{Digest, Sha256, Sha512};

pub struct Hash;

pub struct PBKDF2;

pub struct HMAC;

pub struct K256;

#[derive(Debug, Clone)]
pub struct K256Signature {
    pub public_key: [u8; 65],
    pub pre_hash: [u8; 32],
    pub signature: [u8; 64],
    pub recovery_id: Option<u8>,
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

        let signing_key = SigningKey::from(sk);

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

#[cfg(test)]
mod tests {

    extern crate alloc;

    use super::*;
    use alloc::vec;

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
}
