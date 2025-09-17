#![no_std]
extern crate alloc;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use anyhow::Result;
use core::ffi::CStr;
use oskey_bus::{proto, proto::res_data};
use oskey_wallet::mnemonic;
use oskey_wallet::wallets;

pub type VersionCallback = extern "C" fn(data: *mut u8, len: usize) -> bool;
pub type CheckInitCallback = extern "C" fn() -> bool;
pub type RandomCallback = extern "C" fn(data: *mut u8, len: usize) -> bool;
pub type InitCallback = extern "C" fn(data: *const u8, len: usize, phrase_len: usize) -> bool;
pub type GetSeedStorageCallback = extern "C" fn(data: *mut u8, len: usize) -> bool;

pub fn wallet_unknown_req() -> res_data::Payload {
    return res_data::Payload::Unknown(proto::Unknown {});
}

pub fn wallet_version_req(
    support: Vec<u8>,
    version_cb: VersionCallback,
    check_init_cb: CheckInitCallback,
) -> res_data::Payload {
    let mut buffer = vec![0u8; 10];

    version_cb(buffer.as_mut_ptr(), buffer.len());

    let init_check = check_init_cb();

    let features = oskey_bus::proto::Features {
        initialized: init_check,
        support_mask: support,
    };

    let version = oskey_bus::proto::VersionResponse {
        version: String::from(
            CStr::from_bytes_until_nul(&buffer)
                .unwrap_or(CStr::from_bytes_with_nul(b"unknown\0").unwrap())
                .to_str()
                .unwrap_or("unknown"),
        ),
        features: features.into(),
    };

    let payload = res_data::Payload::VersionResponse(version);
    return payload;
}

pub fn wallet_init_default(
    data: proto::InitWalletRequest,
    random_cb: RandomCallback,
    save_seed: bool,
    init_cb: InitCallback,
) -> Result<res_data::Payload> {
    let need_len = data.length as usize * 4 / 3;

    let mut buffer = vec![0u8; need_len];

    random_cb(buffer.as_mut_ptr(), need_len);

    let mnemonic = mnemonic::Mnemonic::from_entropy(&buffer)?;

    if save_seed {
        let seed = mnemonic.to_seed(&data.password)?;
        init_cb(seed.as_ptr(), seed.len(), data.length as usize);
    }

    //TODO: only debug return mnemonic msg.
    let init = proto::InitWalletResponse {
        mnemonic: mnemonic.words.join(" ").into(),
    };

    return Ok(res_data::Payload::InitWalletResponse(init));
}

pub fn wallet_init_custom(
    data: proto::InitWalletCustomRequest,
    init_cb: InitCallback,
) -> Result<res_data::Payload> {
    let mnemonic = mnemonic::Mnemonic::from_phrase(&data.words)?;
    let seed = mnemonic.to_seed(&data.password)?;

    init_cb(seed.as_ptr(), seed.len(), mnemonic.words.len() as usize);
    //TODO: only debug return mnemonic msg.
    let init = proto::InitWalletResponse {
        mnemonic: mnemonic.words.join(" ").into(),
    };

    let payload = res_data::Payload::InitWalletResponse(init);

    return Ok(payload);
}

pub fn wallet_drive_public_key(
    data: proto::DerivePublicKeyRequest,
    seed_storage_cb: GetSeedStorageCallback,
) -> Result<res_data::Payload> {
    let mut buffer = vec![0u8; 64];

    seed_storage_cb(buffer.as_mut_ptr(), buffer.len());

    let ex_priv_key = wallets::ExtendedPrivKey::derive(
        &buffer,
        data.path.parse()?,
        oskey_wallet::wallets::Curve::K256,
    )?;

    let pk = ex_priv_key.export_pk()?;

    let data = proto::DerivePublicKeyResponse {
        path: data.path,
        public_key: pk.to_vec(),
    };

    let payload = res_data::Payload::DerivePublicKeyResponse(data);

    return Ok(payload);
}

pub fn wallet_sign_keccak256(
    id: i32,
    path: String,
    hash: [u8; 32],
    seed_storage_cb: GetSeedStorageCallback,
) -> Result<res_data::Payload> {
    let mut buffer = vec![0u8; 64];

    seed_storage_cb(buffer.as_mut_ptr(), buffer.len());

    let ex_priv_key = wallets::ExtendedPrivKey::derive(
        &buffer,
        path.parse()?,
        oskey_wallet::wallets::Curve::K256,
    )?;

    let sign = ex_priv_key.sign(&hash)?;

    let data = proto::SignResponse {
        id: id,
        message: "".into(),
        public_key: ex_priv_key.export_pk()?.to_vec(),
        pre_hash: hash.to_vec(),
        signature: sign.to_vec(),
        recovery_id: None,
    };

    let payload = res_data::Payload::SignResponse(data);

    return Ok(payload);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use anyhow::{anyhow, Result};
    use oskey_bus::proto::req_data;

    extern "C" fn version_cb(data: *mut u8, len: usize) -> bool {
        let version = b"1.0.0";
        unsafe {
            if len >= version.len() {
                core::ptr::copy_nonoverlapping(version.as_ptr(), data, version.len());
            } else {
                return false;
            }
        }
        true
    }

    extern "C" fn check_init_cb() -> bool {
        true
    }

    extern "C" fn random_cb(data: *mut u8, len: usize) -> bool {
        let random =
            hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        if len <= random.len() {
            unsafe {
                core::ptr::copy_nonoverlapping(random.as_ptr(), data, len);
            }
            true
        } else {
            false
        }
    }

    extern "C" fn init_cb_no_password(data: *const u8, len: usize, phrase_len: usize) -> bool {
        let seed = unsafe { core::slice::from_raw_parts(data, len) };

        if phrase_len == 12 {
            let test = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
            assert_eq!(seed, test.as_slice());
        }

        if phrase_len == 24 {
            let test2 = hex::decode("408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840").unwrap();
            assert_eq!(seed, test2.as_slice());
        }
        true
    }

    extern "C" fn get_seed_storage_cb(data: *mut u8, len: usize) -> bool {
        let seed = hex::decode("408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840").unwrap();
        unsafe {
            core::ptr::copy_nonoverlapping(seed.as_ptr(), data, len);
        }
        true
    }

    pub fn event_hub(req: oskey_bus::proto::ReqData) -> Result<proto::ResData> {
        let payload = match req.payload.ok_or(anyhow!("Fail"))? {
            req_data::Payload::Unknown(_unknown) => wallet_unknown_req(),
            req_data::Payload::VersionRequest(_) => {
                wallet_version_req([0u8; 16].to_vec(), version_cb, check_init_cb)
            }
            req_data::Payload::InitRequest(data) => {
                wallet_init_default(data, random_cb, true, init_cb_no_password)?
            }
            req_data::Payload::InitCustomRequest(data) => {
                wallet_init_custom(data, init_cb_no_password)?
            }
            req_data::Payload::DerivePublicKeyRequest(data) => {
                wallet_drive_public_key(data, get_seed_storage_cb)?
            }
            // TODO: add test case
            // req_data::Payload::SignEthRequest(data) => {
            // }
            _ => return Err(anyhow!("Not Implement")),
        };

        let response = proto::ResData {
            payload: payload.into(),
        };

        Ok(response)
    }

    #[test]
    fn test_wallet_unknown_req_res() {
        let req = proto::ReqData {
            payload: Some(req_data::Payload::Unknown(proto::Unknown {})),
        };
        let res = wallet_unknown_req();
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
