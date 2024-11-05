#[cfg(feature = "crypto-psa")]
use crate::bindings;
use anyhow::{anyhow, Result};
#[cfg(feature = "crypto-rs")]
use sha2::{Digest, Sha256};

pub struct Hash;

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
}
