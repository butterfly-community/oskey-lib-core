use anyhow::Result;

use crate::crypto::{HMAC, K256};
use crate::path::{ChildNumber, DerivationPath};
use crate::utils::ByteVec;

#[derive(Clone, PartialEq, Hash, Eq, Debug)]
pub struct ExtendedPrivKey {
    pub secret_key: [u8; 32],
    pub chain_code: [u8; 32],
}

impl ExtendedPrivKey {
    pub fn derive(seed: &[u8], n: DerivationPath) -> Result<ExtendedPrivKey> {
        let result = HMAC::hmac_sha512(b"Bitcoin seed", seed)?;

        let (secret_key, chain_code) = result.split_at(32);

        let mut sk = ExtendedPrivKey {
            secret_key: secret_key.try_into()?,
            chain_code: chain_code.try_into()?,
        };

        for child in n.iter() {
            sk = sk.child(*child)?;
        }

        Ok(sk)
    }

    pub fn child(&self, child: ChildNumber) -> Result<ExtendedPrivKey> {
        let mut bytes = ByteVec::<128>::new();

        if child.is_normal() {
            let encoded_point = K256::export_pk_compressed(&self.secret_key)?;
            bytes.extend(&encoded_point)?;
        } else {
            bytes.push(0)?;
            bytes.extend(&self.secret_key)?;
        };

        bytes.extend(&child.to_bytes())?;

        let result = HMAC::hmac_sha512(&self.chain_code, &bytes.into_vec())?;

        let (tweak, chain_code) = result.split_at(32);

        let child_key = K256::add(&self.secret_key, tweak)?;

        Ok(ExtendedPrivKey {
            secret_key: child_key.try_into()?,
            chain_code: chain_code.try_into()?,
        })
    }
}

#[cfg(test)]
mod test {
    use super::ExtendedPrivKey;

    #[test]
    pub fn test_wallets() {
        let seed = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        let hd =
            ExtendedPrivKey::derive(&hex::decode(seed).unwrap(), "m/0".parse().unwrap()).unwrap();
        assert_eq!(
            hex::encode(hd.secret_key),
            "baa89a8bdd61c5e22b9f10601d8791c9f8fc4b2fa6df9d68d336f0eb03b06eb6"
        );

        let hd2 = ExtendedPrivKey::derive(
            &hex::decode(seed).unwrap(),
            "m/44'/60'/0'/0/0".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(hd2.secret_key),
            "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"
        );
    }
}
