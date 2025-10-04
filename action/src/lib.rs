#![no_std]
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use anyhow::Result;
use oskey_bus::{proto, proto::res_data};
use oskey_wallet::mnemonic;
use oskey_wallet::wallets;

pub trait WalletCallbacks {
    fn version(&self) -> String;
    fn initialized(&self) -> bool;
    fn support_mask(&self) -> Vec<u8>;
    fn random(&self, len: usize) -> Vec<u8>;
    fn save_seed(&self, seed: &[u8], phrase_len: usize) -> Result<()>;
    fn load_seed(&self) -> Vec<u8>;
}

pub fn handle_unknown() -> res_data::Payload {
    res_data::Payload::Unknown(proto::Unknown {})
}

pub fn handle_version<C: WalletCallbacks>(callbacks: &C) -> res_data::Payload {
    res_data::Payload::VersionResponse(oskey_bus::proto::VersionResponse {
        version: callbacks.version(),
        features: oskey_bus::proto::Features {
            initialized: callbacks.initialized(),
            support_mask: callbacks.support_mask(),
        }
        .into(),
    })
}

pub fn handle_init_wallet<C: WalletCallbacks>(
    data: proto::InitWalletRequest,
    callbacks: &C,
    save_seed: bool,
) -> Result<res_data::Payload> {
    let need_len = data.length as usize * 4 / 3;
    let buffer = callbacks.random(need_len);
    let mnemonic = mnemonic::Mnemonic::from_entropy(&buffer)?;

    if save_seed {
        let seed = mnemonic.to_seed(&data.password)?;
        callbacks.save_seed(&seed, data.length as usize)?;
    }

    //TODO: only debug return mnemonic msg.
    let response = proto::InitWalletResponse {
        mnemonic: mnemonic.words.join(" ").into(),
    };

    Ok(res_data::Payload::InitWalletResponse(response))
}

pub fn handle_init_wallet_custom<C: WalletCallbacks>(
    data: proto::InitWalletCustomRequest,
    callbacks: &C,
) -> Result<res_data::Payload> {
    let mnemonic = mnemonic::Mnemonic::from_phrase(&data.words)?;
    let seed = mnemonic.to_seed(&data.password)?;

    callbacks.save_seed(&seed, mnemonic.words.len())?;

    //TODO: only debug return mnemonic msg.
    let response = proto::InitWalletResponse {
        mnemonic: mnemonic.words.join(" ").into(),
    };

    Ok(res_data::Payload::InitWalletResponse(response))
}

fn derive_extended_key<C: WalletCallbacks>(
    callbacks: &C,
    path: &str,
) -> Result<wallets::ExtendedPrivKey> {
    let buffer = callbacks.load_seed();
    wallets::ExtendedPrivKey::derive(&buffer, path.parse()?, oskey_wallet::wallets::Curve::K256)
}

pub fn handle_derive_public_key<C: WalletCallbacks>(
    data: proto::DerivePublicKeyRequest,
    callbacks: &C,
) -> Result<res_data::Payload> {
    let ex_priv_key = derive_extended_key(callbacks, &data.path)?;
    let pk = ex_priv_key.export_pk()?;

    let response = proto::DerivePublicKeyResponse {
        path: data.path,
        public_key: pk.to_vec(),
    };

    Ok(res_data::Payload::DerivePublicKeyResponse(response))
}

pub fn handle_sign_keccak256<C: WalletCallbacks>(
    id: i32,
    path: &str,
    hash: [u8; 32],
    callbacks: &C,
) -> Result<res_data::Payload> {
    let ex_priv_key = derive_extended_key(callbacks, path)?;
    let public_key = ex_priv_key.export_pk()?.to_vec();
    let sign = ex_priv_key.sign(&hash)?;

    let response = proto::SignResponse {
        id,
        message: "".into(),
        public_key,
        pre_hash: hash.to_vec(),
        signature: sign.to_vec(),
        recovery_id: None,
    };

    Ok(res_data::Payload::SignResponse(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use anyhow::{anyhow, Result};
    use oskey_bus::proto::req_data;

    struct TestCallbacks;

    impl WalletCallbacks for TestCallbacks {
        fn version(&self) -> String {
            String::from("1.0.0")
        }

        fn initialized(&self) -> bool {
            true
        }

        fn support_mask(&self) -> Vec<u8> {
            [0u8; 16].to_vec()
        }

        fn random(&self, len: usize) -> Vec<u8> {
            let random =
                hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                    .unwrap();
            random[..len].to_vec()
        }

        fn save_seed(&self, seed: &[u8], phrase_len: usize) -> Result<()> {
            if phrase_len == 12 {
                let test = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
                assert_eq!(seed, test.as_slice());
            }

            if phrase_len == 24 {
                let test2 = hex::decode("408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840").unwrap();
                assert_eq!(seed, test2.as_slice());
            }
            Ok(())
        }

        fn load_seed(&self) -> Vec<u8> {
            hex::decode("408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840").unwrap()
        }
    }

    pub fn event_hub(req: oskey_bus::proto::ReqData) -> Result<proto::ResData> {
        let callbacks = TestCallbacks;
        let payload = match req.payload.ok_or(anyhow!("Fail"))? {
            req_data::Payload::Unknown(_unknown) => handle_unknown(),
            req_data::Payload::VersionRequest(_) => handle_version(&callbacks),
            req_data::Payload::InitRequest(data) => handle_init_wallet(data, &callbacks, true)?,
            req_data::Payload::InitCustomRequest(data) => {
                handle_init_wallet_custom(data, &callbacks)?
            }
            req_data::Payload::DerivePublicKeyRequest(data) => {
                handle_derive_public_key(data, &callbacks)?
            }
            // TODO: add test case
            // req_data::Payload::SignEthRequest(data) => {
            // }
            _ => return Err(anyhow!("Not Implement")),
        };

        Ok(proto::ResData {
            payload: payload.into(),
        })
    }

    #[test]
    fn test_wallet_unknown_req_res() {
        let req = proto::ReqData {
            payload: Some(req_data::Payload::Unknown(proto::Unknown {})),
        };
        let res = handle_unknown();
        let event = event_hub(req).unwrap();
        assert_eq!(event.payload.unwrap(), res);
    }

    #[test]
    fn test_wallet_version_req_res() {
        let req = proto::ReqData {
            payload: Some(req_data::Payload::VersionRequest(proto::VersionRequest {})),
        };

        let res = res_data::Payload::VersionResponse(proto::VersionResponse {
            version: String::from("1.0.0"),
            features: proto::Features {
                initialized: true,
                support_mask: [0u8; 16].to_vec(),
            }
            .into(),
        });

        let event = event_hub(req).unwrap();

        assert_eq!(event.payload.unwrap(), res);
    }

    #[test]
    fn test_wallet_init_default_res_1() {
        let req = proto::ReqData {
            payload: Some(req_data::Payload::InitRequest(proto::InitWalletRequest {
                length: 12,
                password: "".into(),
                seed: None,
                pin: [0u8; 16].to_vec(),
            })),
        };
        let res = res_data::Payload::InitWalletResponse(proto::InitWalletResponse {
            mnemonic: Some(String::from("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")),
        });
        let event = event_hub(req).unwrap();
        assert_eq!(event.payload.unwrap(), res);
    }

    #[test]
    fn test_wallet_init_default_res_2() {
        let req = proto::ReqData {
            payload: Some(req_data::Payload::InitRequest(proto::InitWalletRequest {
                length: 24,
                password: "".into(),
                seed: None,
                pin: [0u8; 16].to_vec(),
            })),
        };
        let res = res_data::Payload::InitWalletResponse(proto::InitWalletResponse {
            mnemonic: Some(String::from("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")),
        });
        let event = event_hub(req).unwrap();
        assert_eq!(event.payload.unwrap(), res);
    }

    #[test]
    fn test_wallet_init_custom_res_1() {
        let req = proto::ReqData {
            payload: Some(req_data::Payload::InitCustomRequest(proto::InitWalletCustomRequest {
                words: String::from("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
                password: "".into(),
                pin: [0u8; 16].to_vec(),
            })),
        };
        let res = res_data::Payload::InitWalletResponse(proto::InitWalletResponse {
            mnemonic:  String::from("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").into(),
        });
        let event = event_hub(req).unwrap();
        assert_eq!(event.payload.unwrap(), res);
    }

    #[test]
    fn test_wallet_init_custom_res_2() {
        let req = proto::ReqData {
            payload: Some(req_data::Payload::InitCustomRequest(proto::InitWalletCustomRequest {
                words: String::from("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"),
                password: "".into(),
                pin: [0u8; 16].to_vec(),
            })),
        };
        let res = res_data::Payload::InitWalletResponse(proto::InitWalletResponse {
            mnemonic:  String::from("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art").into(),
        });
        let event = event_hub(req).unwrap();
        assert_eq!(event.payload.unwrap(), res);
    }

    #[test]
    fn test_wallet_drive_public_key_res() {
        let req = proto::ReqData {
            payload: Some(req_data::Payload::DerivePublicKeyRequest(
                proto::DerivePublicKeyRequest {
                    path: String::from("m/44'/60'/0'/0/0"),
                },
            )),
        };
        let res = res_data::Payload::DerivePublicKeyResponse(proto::DerivePublicKeyResponse {
            path: String::from("m/44'/60'/0'/0/0"),
            public_key: hex::decode(
                "04dc286c821c7490afbe20a79d13123b9f41f3d7ef21e4a9caacd22f5983b28eca0e4dbd5624505a2c968fec15f25990c7324736890f6d0f74241f98e4259c1d42",
            )
            .unwrap(),
        });
        let event = event_hub(req).unwrap();
        assert_eq!(event.payload.unwrap(), res);
    }

    #[test]
    #[ignore]
    fn test_wallet_sign_eth_res() {
        let req = proto::ReqData {
            payload: Some(req_data::Payload::SignEthRequest(proto::SignEthRequest {
                id: 1,
                path: String::from("m/44'/60'/0'/0/0"),
                debug_text: None,
                tx: Some(proto::sign_eth_request::Tx::Eip2930(
                    proto::AppEthTxEip2930 {
                        chain_id: 0xaa36a7,
                        nonce: 0x5,
                        gas_price: "1112408".to_string(),
                        gas_limit: 0x5208,
                        to: Some("0x00Ab1EAd740f95aDE25b78B3137fdcC333326e7d".to_string()),
                        value: "0x16345785d8a0000".to_string(),
                        input: None,
                        access_list: None,
                    },
                )),
            })),
        };

        let res = res_data::Payload::SignResponse(proto::SignResponse {
            id: 1,
            message: "".into(),
            public_key: hex::decode("04dc286c821c7490afbe20a79d13123b9f41f3d7ef21e4a9caacd22f5983b28eca0e4dbd5624505a2c968fec15f25990c7324736890f6d0f74241f98e4259c1d42").unwrap(),
            pre_hash: hex::decode("e8a4c5905197c0ebe135460219fd0f47381b17c91d1d28e51feca29980a10a69").unwrap(),
            signature: hex::decode("20d20999d1b08983bcf36bc5205643765ee9e68c22268b32d21861b71957faa45308e2d917edfbf761e4da7530f87ee012eca06e88b14d99064ad692c1cd56bb").unwrap(),
            recovery_id: None,
        });

        let event = event_hub(req).unwrap();
        assert_eq!(event.payload.unwrap(), res)
    }
}
