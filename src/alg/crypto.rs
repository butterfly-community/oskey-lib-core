use anyhow::{anyhow, bail, Ok, Result};

#[cfg(feature = "crypto-psa")]
use crate::alg::bindings;

#[cfg(feature = "crypto-rs")]
use hmac::{Hmac, Mac};
#[cfg(feature = "crypto-rs")]
use k256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::sec1::ToEncodedPoint,
    SecretKey,
};
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
    pub fn add(num1: &[u8], num2: &[u8]) -> Result<[u8; 32]> {
        let sk1 = SecretKey::from_slice(num1).map_err(|e| anyhow!(e))?;
        let sk2 = SecretKey::from_slice(num2).map_err(|e| anyhow!(e))?;

        let new_secret_key = sk1
            .to_nonzero_scalar()
            .add(&sk2.to_nonzero_scalar())
            .to_bytes();
        Ok(new_secret_key.try_into()?)
    }

    #[cfg(feature = "crypto-rs")]
    pub fn sign(sk: &[u8], data: &[u8]) -> Result<[u8; 64]> {
        let sk = SecretKey::from_slice(sk).map_err(|e| anyhow!(e))?;

        let signing_key = SigningKey::from(sk);

        let signature: Signature = signing_key.try_sign(data).map_err(|e| anyhow!(e))?;

        Ok(signature.to_bytes().into())
    }

    #[cfg(feature = "crypto-rs")]
    pub fn verify_sign(pk: &[u8], message: &[u8], signature: &[u8; 64]) -> Result<bool> {
        let verifying_key = VerifyingKey::from_sec1_bytes(pk).map_err(|e| anyhow!(e))?;

        let signature = Signature::from_bytes(signature.into()).map_err(|e| anyhow!(e))?;

        Ok(verifying_key.verify(message, &signature).is_ok())
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

    #[cfg(feature = "crypto-psa")]
    pub fn sign(sk: &[u8], message: &[u8]) -> Result<[u8; 64]> {
        let mut result = [0u8; 64];
        let status = unsafe {
            bindings::psa_k256_sign_message(
                sk.as_ptr(),
                message.as_ptr(),
                message.len(),
                result.as_mut_ptr(),
            )
        };
        if status == 0 {
            Ok(result)
        } else {
            anyhow::bail!("{}", status)
        }
    }

    #[cfg(feature = "crypto-psa")]
    pub fn verify_sign(pk: &[u8], message: &[u8], signature: &[u8; 64]) -> Result<bool> {
        let status = unsafe {
            bindings::psa_k256_verify_message(
                pk.as_ptr(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
            )
        };
        if status == 0 {
            Ok(true)
        } else {
            anyhow::bail!("{}", status)
        }
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
}
