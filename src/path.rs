use anyhow::{anyhow, Result};
use core::str::FromStr;

const HARDENED_BIT: u32 = 1 << 31;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ChildNumber(u32);

impl ChildNumber {
    pub fn is_hardened(&self) -> bool {
        self.0 & HARDENED_BIT == HARDENED_BIT
    }

    pub fn is_normal(&self) -> bool {
        self.0 & HARDENED_BIT == 0
    }

    pub fn to_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }

    pub fn hardened_from_u32(index: u32) -> Result<Self> {
        Ok(ChildNumber(index | HARDENED_BIT))
    }

    pub fn non_hardened_from_u32(index: u32) -> Result<Self> {
        Ok(ChildNumber(index))
    }
}

impl FromStr for ChildNumber {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<ChildNumber> {
        let (num_str, hardened) = match input.strip_suffix('\'') {
            Some(n) => (n, HARDENED_BIT),
            None => (input, 0),
        };

        let index: u32 = num_str.parse()?;
        if index >= HARDENED_BIT {
            return Err(anyhow!("Index too large"));
        }

        Ok(ChildNumber(index | hardened))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DerivationPath {
    path: heapless::Vec<ChildNumber, 32>,
}

impl FromStr for DerivationPath {
    type Err = anyhow::Error;

    fn from_str(path: &str) -> Result<DerivationPath> {
        let mut parts = path.split('/');

        if parts.next() != Some("m") {
            return Err(anyhow!("Path must start with 'm'"));
        }

        let mut path_vec = heapless::Vec::new();
        for part in parts {
            path_vec
                .push(part.parse()?)
                .map_err(|_| anyhow!("Path too long"))?;
        }

        Ok(DerivationPath { path: path_vec })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heapless::Vec;

    #[test]
    fn test_derivation_path() {
        let path: DerivationPath = "m/44'/60'/0'/0".parse().unwrap();

        let expected_path = {
            let mut v = Vec::new();
            v.extend_from_slice(&[
                ChildNumber(44 | HARDENED_BIT),
                ChildNumber(60 | HARDENED_BIT),
                ChildNumber(0 | HARDENED_BIT),
                ChildNumber(0),
            ])
            .unwrap();
            DerivationPath { path: v }
        };

        assert_eq!(path, expected_path);
    }

    #[test]
    fn test_derivation_path_invalid() {
        assert!("44'/60'/0'/0".parse::<DerivationPath>().is_err());
        assert!("m/2147483648".parse::<DerivationPath>().is_err());
        assert!("m/abc".parse::<DerivationPath>().is_err());
    }
}
