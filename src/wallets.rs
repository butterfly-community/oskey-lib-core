use anyhow::{anyhow, Result};
use heapless::String;


use crate::crypto::K256;
use crate::path::DerivationPath;
use crate::{
    crypto::{Hash, HMAC},
    path::ChildNumber,
};

struct VecBuilder<const N: usize> {
    inner: heapless::Vec<u8, N>,
}

impl<const N: usize> VecBuilder<N> {
    fn new() -> Self {
        Self {
            inner: heapless::Vec::new(),
        }
    }

    fn push(&mut self, byte: u8) -> Result<(), anyhow::Error> {
        self.inner.push(byte).map_err(|e| anyhow!(e))
    }

    fn extend(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        self.inner.extend_from_slice(data).map_err(|_| anyhow!("Buffer full"))
    }

    fn build(self) -> heapless::Vec<u8, N> {
        self.inner
    }
}

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
        let mut builder = VecBuilder::<128>::new();

        if child.is_normal() {
            let encoded_point = K256::export_pk_compressed(&self.secret_key)?;
            builder.extend(&encoded_point)?;
        } else {
            builder.push(0)?;
            builder.extend(&self.secret_key)?;
        };

        builder.extend(&child.to_bytes())?;

        let result = HMAC::hmac_sha512(&self.chain_code, &builder.build())?;

        let (il, chain_code) = result.split_at(32);

        let new_secret_key = K256::add(&self.secret_key, il)?;

        Ok(ExtendedPrivKey {
            secret_key: new_secret_key.try_into()?,
            chain_code: chain_code.try_into()?,
        })
    }

    pub fn to_xprv(&self) -> String<111> {
        let mut data = [0u8; 78];

        data[0..4].copy_from_slice(&[0x04, 0x88, 0xAD, 0xE4]);
        data[4] = 0;
        // 5..9 and 9..13 already zero
        data[13..45].copy_from_slice(&self.chain_code);
        data[45] = 0;
        data[46..78].copy_from_slice(&self.secret_key);

        let hash1 = Hash::sha256(&data).unwrap();

        let hash2 = Hash::sha256(&hash1).unwrap();

        let mut final_data = [0u8; 82];
        final_data[..78].copy_from_slice(&data);
        final_data[78..].copy_from_slice(&hash2[..4]);

        let mut result: String<111> = String::new();
        let test = bs58::encode(&final_data);
        result.push_str(&test.into_string()).unwrap();
        result
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
