use core::{str, str::FromStr};

use anyhow::{anyhow, Result};
use heapless::{String, Vec};

use crate::alg::crypto::{Ed25519, Hash, HMAC, K256, X25519};
use crate::path::{ChildNumber, DerivationPath};
use crate::utils::ByteVec;

#[derive(Clone, PartialEq, Hash, Eq, Debug, Copy)]
pub enum Curve {
    K256,
    Ed25519,
    X25519,
    P256,
}

impl Curve {
    fn seed_key(&self) -> &[u8] {
        match self {
            Curve::K256 => b"Bitcoin seed",
            Curve::Ed25519 => b"ed25519 seed",
            Curve::X25519 => b"curve25519 seed",
            Curve::P256 => b"Nist256p1 seed",
        }
    }
    fn version_bytes(&self, is_public: bool) -> [u8; 4] {
        match (self, is_public) {
            (Curve::K256, false) => [0x04, 0x88, 0xAD, 0xE4], // xprv
            (Curve::K256, true) => [0x04, 0x88, 0xB2, 0x1E],  // xpub
            (Curve::Ed25519, false) => [0x2b, 0x00, 0x00, 0x00],
            (Curve::Ed25519, true) => [0x2c, 0x00, 0x00, 0x00],
            (Curve::X25519, false) => [0x2d, 0x00, 0x00, 0x00],
            (Curve::X25519, true) => [0x2e, 0x00, 0x00, 0x00],
            (Curve::P256, false) => [0x2f, 0x00, 0x00, 0x00],
            (Curve::P256, true) => [0x30, 0x00, 0x00, 0x00],
        }
    }

    fn validate_child(&self, child: ChildNumber) -> Result<()> {
        match self {
            Curve::K256 | Curve::P256 => Ok(()),
            Curve::Ed25519 | Curve::X25519 => {
                if child.is_hardened() {
                    Ok(())
                } else {
                    Err(anyhow!("SLIP-0010 requires hardened derivation"))
                }
            }
        }
    }
}

#[derive(Clone, PartialEq, Hash, Eq, Debug)]
pub struct ExtendedPrivKey {
    pub curve: Curve,
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: ChildNumber,
    pub secret_key: [u8; 32],
    pub chain_code: [u8; 32],
}

impl ExtendedPrivKey {
    pub fn derive(seed: &[u8], path: DerivationPath, curve: Curve) -> Result<ExtendedPrivKey> {
        let (secret_key, chain_code): ([u8; 32], [u8; 32]) = match curve {
            Curve::K256 | Curve::P256 => {
                let result = HMAC::hmac_sha512(curve.seed_key(), seed)?;
                let (sk, cc) = result.split_at(32);
                (sk.try_into().unwrap(), cc.try_into().unwrap())
            }
            Curve::Ed25519 | Curve::X25519 => {
                let i = HMAC::hmac_sha512(curve.seed_key(), seed)?;
                let (sk, cc) = i.split_at(32);
                (sk.try_into().unwrap(), cc.try_into().unwrap())
            }
        };

        let mut sk = ExtendedPrivKey {
            curve,
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: ChildNumber::non_hardened_from_u32(0)?,
            secret_key,
            chain_code,
        };

        for child in path.iter() {
            sk = sk.child(*child)?;
        }

        Ok(sk)
    }

    pub fn child(&self, child: ChildNumber) -> Result<ExtendedPrivKey> {
        self.curve.validate_child(child)?;

        match self.curve {
            Curve::K256 | Curve::P256 => {
                let mut bytes = ByteVec::<128>::new();
                if child.is_normal() {
                    let encoded_point = match self.curve {
                        Curve::K256 => K256::export_pk_compressed(&self.secret_key)?,
                        _ => unreachable!(),
                    };
                    bytes.extend(&encoded_point)?;
                } else {
                    bytes.push(0)?;
                    bytes.extend(&self.secret_key)?;
                }
                bytes.extend(&child.to_bytes())?;

                let i = HMAC::hmac_sha512(&self.chain_code, &bytes.into_vec())?;
                let (il, ir) = i.split_at(32);

                let child_sk = match self.curve {
                    Curve::K256 => K256::add(&self.secret_key, il)?,
                    _ => unreachable!(),
                };
                Ok(ExtendedPrivKey {
                    curve: self.curve,
                    depth: self.depth + 1,
                    parent_fingerprint: self.fingerprint()?,
                    child_number: child,
                    secret_key: child_sk,
                    chain_code: ir.try_into().unwrap(),
                })
            }
            Curve::Ed25519 | Curve::X25519 => {
                // SLIP-0010: data = 0x00 || k_par || i_be
                let mut data = ByteVec::<128>::new();
                data.push(0)?;
                data.extend(&self.secret_key)?;
                data.extend(&child.to_bytes())?;

                let i = HMAC::hmac_sha512(&self.chain_code, &data.into_vec())?;
                let (sk, cc) = i.split_at(32);

                Ok(ExtendedPrivKey {
                    curve: self.curve,
                    depth: self.depth + 1,
                    parent_fingerprint: self.fingerprint()?,
                    child_number: child,
                    secret_key: sk.try_into().unwrap(),
                    chain_code: cc.try_into().unwrap(),
                })
            }
        }
    }

    pub fn export_pk(&self) -> Result<Vec<u8, 65>> {
        match self.curve {
            Curve::K256 => {
                let pk = K256::export_pk(&self.secret_key)?;
                Ok(Vec::from_slice(&pk).unwrap())
            }
            Curve::Ed25519 => {
                let pk = Ed25519::export_pk(&self.secret_key)?;
                Ok(Vec::from_slice(&pk).unwrap())
            }
            Curve::X25519 => {
                let pk = X25519::export_pk(&self.secret_key)?;
                Ok(Vec::from_slice(&pk).unwrap())
            }
            _ => unreachable!(),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8, 64>> {
        match self.curve {
            Curve::K256 => {
                let sig = K256::sign(&self.secret_key, msg)?;
                Ok(Vec::from_slice(&sig.signature).expect("Signature fits in Vec<u8, 64>"))
            }
            Curve::Ed25519 => {
                let sig = Ed25519::sign(&self.secret_key, msg)?;
                Ok(Vec::from_slice(&sig).expect("Signature fits in Vec<u8, 64>"))
            }
            Curve::X25519 => Err(anyhow!("X25519 keys cannot be used for signing")),
            _ => unreachable!(),
        }
    }

    pub fn fingerprint(&self) -> Result<[u8; 4]> {
        let pub_key_slice: &[u8] = match self.curve {
            Curve::K256 => &K256::export_pk_compressed(&self.secret_key)?[..],
            Curve::Ed25519 => &Ed25519::export_pk(&self.secret_key)?[..],
            Curve::X25519 => &X25519::export_pk(&self.secret_key)?[..],
            _ => unreachable!(),
        };

        let pub_key =
            Vec::<u8, 33>::from_slice(pub_key_slice).expect("Public key fits in Vec<u8, 33>");

        let hash = Hash::hash160(&pub_key)?;

        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&hash[..4]);

        Ok(fingerprint)
    }

    pub fn encode(&self, is_public: bool) -> Result<String<256>> {
        let mut data = ByteVec::<128>::new();

        // 1. version
        data.extend(&self.curve.version_bytes(is_public))?;

        // 2. depth
        data.push(self.depth)?;

        // 3. parent fingerprint
        data.extend(&self.parent_fingerprint)?;

        // 4. child number
        data.extend(&self.child_number.to_bytes())?;

        // 5. chain code
        data.extend(&self.chain_code)?;

        // 6. key data
        if is_public {
            let pub_key: &[u8] = match self.curve {
                Curve::K256 => &K256::export_pk_compressed(&self.secret_key)?[..],
                Curve::Ed25519 => &Ed25519::export_pk(&self.secret_key)?[..],
                Curve::X25519 => &X25519::export_pk(&self.secret_key)?[..],
                _ => unreachable!(),
            };
            data.extend(pub_key)?;
        } else {
            match self.curve {
                Curve::K256 | Curve::P256 => {
                    data.push(0)?;
                    data.extend(&self.secret_key)?;
                }
                Curve::Ed25519 | Curve::X25519 => {
                    data.extend(&self.secret_key)?;
                }
            }
        }

        // 7. Base58Check
        let mut base58 = [0u8; 256];
        let len = bs58::encode(&data.clone().into_vec())
            .with_check()
            .onto(&mut base58[..])
            .map_err(|e| anyhow!(e))?;

        Ok(String::from_str(str::from_utf8(&base58[..len])?).map_err(|_| anyhow!("utf8"))?)
    }
}

#[cfg(test)]
mod test {
    extern crate alloc;

    use super::*;
    use heapless::Vec;

    pub fn get_test_vector_1() -> Vec<[&'static str; 4], 16> {
        let mut test_vectors = Vec::new();
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m",
                "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
            ])
            .unwrap();
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m/0'",
                "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
            ])
            .unwrap();
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m/0'/1",
                "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
            ])
            .unwrap();
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m/0'/1/2'",
                "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
            ])
            .unwrap();
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m/0'/1/2'/2",
                "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
            ])
            .unwrap();
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m/0'/1/2'/2/1000000000",
                "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
            ])
            .unwrap();
        test_vectors
    }

    pub fn get_test_vector_2() -> Vec<[&'static str; 4], 16> {
        let mut test_vectors = Vec::new();
        test_vectors
            .push([
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "m",
                "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
            ])
            .unwrap();
        test_vectors
            .push([
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "m/0",
                "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
            ])
            .unwrap();
        test_vectors
            .push([
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "m/0/2147483647'",
                "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
            ])
            .unwrap();
        test_vectors
            .push([
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "m/0/2147483647'/1",
                "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
            ])
            .unwrap();
        test_vectors
            .push([
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "m/0/2147483647'/1/2147483646'",
                "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
            ])
            .unwrap();
        test_vectors
            .push([
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
                "m/0/2147483647'/1/2147483646'/2",
                "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
            ])
            .unwrap();
        test_vectors
    }

    pub fn get_test_vector_3() -> Vec<[&'static str; 4], 16> {
        let mut test_vectors = Vec::new();
        test_vectors
            .push([
                "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
                "m",
                "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
                "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
            ])
            .unwrap();
        test_vectors
            .push([
                "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
                "m/0'",
                "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
                "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
            ])
            .unwrap();
        test_vectors
    }

    pub fn get_test_vector_4() -> Vec<[&'static str; 4], 16> {
        let mut test_vectors = Vec::new();
        test_vectors
            .push([
                "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
                "m",
                "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
                "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
            ])
            .unwrap();
        test_vectors
            .push([
                "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
                "m/0'",
                "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
                "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
            ])
            .unwrap();
        test_vectors
            .push([
                "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
                "m/0'/1'",
                "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
                "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
            ])
            .unwrap();
        test_vectors
    }

    pub fn get_slip10_ed25519_vector() -> Vec<[&'static str; 4], 16> {
        let mut test_vectors = Vec::new();
        // Test Vector 1
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m",
                "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
                "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
            ])
            .unwrap();
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m/0'",
                "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
            ])
            .unwrap();
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m/0'/1'",
                "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
            ])
            .unwrap();
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m/0'/1'/2'",
                "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
            ])
            .unwrap();
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m/0'/1'/2'/2'",
                "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c",
            ])
            .unwrap();
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m/0'/1'/2'/2'/1000000000'",
                "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
                "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a",
            ])
            .unwrap();
        // Test Vector 2
        test_vectors.push([
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "m",
        "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
        "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a",
    ]) .unwrap();
        test_vectors.push([
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "m/0'",
        "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
        "0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037",
    ]) .unwrap();
        test_vectors.push([
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "m/0'/2147483647'",
        "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
        "005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d",
    ]) .unwrap();
        test_vectors.push([
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "m/0'/2147483647'/1'",
        "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
        "002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45",
    ]) .unwrap();
        test_vectors.push([
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "m/0'/2147483647'/1'/2147483646'",
        "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
        "00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b",
    ]) .unwrap();
        test_vectors.push([
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "m/0'/2147483647'/1'/2147483646'/2'",
        "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
        "0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0",
    ]).unwrap();
        test_vectors
    }

    pub fn get_slip10_x25519_vector() -> Vec<[&'static str; 4], 16> {
        let mut test_vectors = Vec::new();
        // Test Vector 1: Seed 000102030405060708090a0b0c0d0e0f
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m",
                "d70a59c2e68b836cc4bbe8bcae425169b9e2384f3905091e3d60b890e90cd92c",
                "005c7289dc9f7f3ea1c8c2de7323b9fb0781f69c9ecd6de4f095ac89a02dc80577",
            ])
            .unwrap();
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m/0'",
                "cd7630d7513cbe80515f7317cdb9a47ad4a56b63c3f1dc29583ab8d4cc25a9b2",
                "00cb8be6b256ce509008b43ae0dccd69960ad4f7ff2e2868c1fbc9e19ec3ad544b",
            ])
            .unwrap();
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m/0'/1'",
                "a95f97cfc1a61dd833b882c89d36a78a030ea6b2fbe3ae2a70e4f1fc9008d6b1",
                "00e9506455dce2526df42e5e4eb5585eaef712e5f9c6a28bf9fb175d96595ea872",
            ])
            .unwrap();
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m/0'/1'/2'",
                "3d6cce04a9175929da907a90b02176077b9ae050dcef9b959fed978bb2200cdc",
                "0018f008fcbc6d1cd8b4fe7a9eba00f6570a9da02a9b0005028cb2731b12ee4118",
            ])
            .unwrap();
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m/0'/1'/2'/2'",
                "7ae7437efe0a3018999e6f00d72e810ebc50578dbf6728bfa1c7fe73501081a7",
                "00512e288a8ef4d869620dc4b06bb06ad2524b350dee5a39fcfeb708dbac65c25c",
            ])
            .unwrap();
        test_vectors
            .push([
                "000102030405060708090a0b0c0d0e0f",
                "m/0'/1'/2'/2'/1000000000'",
                "7a59954d387abde3bc703f531f67d659ec2b8a12597ae82824547d7e27991e26",
                "00a077fcf5af53d210257d44a86eb2031233ac7237da220434ac01a0bebccc1919",
            ])
            .unwrap();
        // Test Vector 2: Seed fffcf9f6...
        test_vectors.push([
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            "m",
            "088491f5b4dfafbe956de471f3db10e02d784bc76050ee3b7c3f11b9706d3730",
            "0060cc3b40567729af08757e1efe62536dc864a57ec582f98b96f484201a260c7a",
        ]).unwrap();
        test_vectors.push([
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            "m/0'",
            "8e73218a1ba5c7b95e94b6e7cf7b37fb6240fb3b2ecd801402a4439da7067ee2",
            "007992b3f270ef15f266785fffb73246ad7f40d1fe8679b737fed0970d92cc5f39",
        ]).unwrap();
        test_vectors.push([
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            "m/0'/2147483647'",
            "29262b215c961bae20274588b33955c36f265c1f626df9feebb51034ce63c19d",
            "002372feac417c38b833e1aba75f2420278122d698605b995cafc2fed7bb453d41",
        ]).unwrap();
        test_vectors.push([
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            "m/0'/2147483647'/1'",
            "a4d2474bd98c5e9ff416f536697b89949627d6d2c384b81a86d29f1136f4c2d1",
            "00eca4fd0458d3f729b6218eda871b350fa8870a744caf6d30cd84dad2b9dd9c2d",
        ]).unwrap();
        test_vectors.push([
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            "m/0'/2147483647'/1'/2147483646'",
            "d3500d9b30529c51d92497eded1d68d29f60c630c45c61a481c185e574c6e5cf",
            "00edaa3d381a2b02f40a80d69b2ce7ba7c3c4a9421744808857cd48c50d29b5868",
        ]).unwrap();
        test_vectors.push([
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            "m/0'/2147483647'/1'/2147483646'/2'",
            "e20fecd59312b63b37eee27714465aae1caa1c87840abd0d685ea88b3d598fdf",
            "00aa705de68066e9534a238af35ea77c48016462a8aff358d22eaa6c7d5b034354",
        ]).unwrap();
        test_vectors
    }

    fn run_test_vector(test_vectors: Vec<[&'static str; 4], 16>, curve: Curve) -> Result<()> {
        for case in &test_vectors {
            let seed = hex::decode(&case[0]).unwrap();
            let path = case[1].parse()?;
            let child = ExtendedPrivKey::derive(&seed, path, curve)?;

            if case[2].starts_with("xprv") || case[2].starts_with("xpub") {
                assert_eq!(child.encode(false)?, case[2]);
                assert_eq!(child.encode(true)?, case[3]);
            } else {
                assert_eq!(hex::encode(child.secret_key), case[2]);
                let pk = child.export_pk()?;
                assert_eq!(hex::encode(&pk), case[3]);
            }
        }
        Ok(())
    }

    #[test]
    fn test_bip32_vector1() -> Result<()> {
        run_test_vector(get_test_vector_1(), Curve::K256)
    }

    #[test]
    fn test_bip32_vector2() -> Result<()> {
        run_test_vector(get_test_vector_2(), Curve::K256)
    }

    #[test]
    fn test_bip32_vector3() -> Result<()> {
        run_test_vector(get_test_vector_3(), Curve::K256)
    }

    #[test]
    fn test_bip32_vector4() -> Result<()> {
        run_test_vector(get_test_vector_4(), Curve::K256)
    }

    #[test]
    fn test_slip10_ed25519() -> Result<()> {
        run_test_vector(get_slip10_ed25519_vector(), Curve::Ed25519)
    }

    #[test]
    fn test_slip10_x25519() -> Result<()> {
        run_test_vector(get_slip10_x25519_vector(), Curve::X25519)
    }
}
