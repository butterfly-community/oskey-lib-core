#![no_std]
extern crate alloc;
use alloc::string::String;
use alloc::vec;
use anyhow::Result;
use oskey_bus::{proto, proto::res_data};
use oskey_wallet::mnemonic;

pub type VersionCallback = extern "C" fn(data: *mut u8, len: *mut usize) -> bool;
pub type CheckInitCallback = extern "C" fn() -> bool;
pub type RandomCallback = extern "C" fn(data: *mut u8, len: usize) -> bool;
pub type InitCallback = extern "C" fn(data: *const u8, len: usize, phrase_len: usize) -> bool;

pub fn wallet_unknown_req() -> res_data::Payload {
    return res_data::Payload::Unknown(proto::Unknown {});
}

pub fn wallet_version_req(
    version_cb: VersionCallback,
    check_init_cb: CheckInitCallback,
) -> res_data::Payload {
    let mut buffer = vec![0u8; 10];
    let mut version_len: usize = 0;

    let _version_check = version_cb(buffer.as_mut_ptr(), &mut version_len);

    let init_check = check_init_cb();

    let features = oskey_bus::proto::Features {
        initialized: init_check,
        has_hardware_random: true,
    };

    let version = oskey_bus::proto::VersionResponse {
        version: String::from(core::str::from_utf8(&buffer[..version_len]).unwrap_or("unknown")),
        features: features.into(),
    };

    let payload = res_data::Payload::VersionResponse(version);
    return payload;
}

pub fn wallet_init_default(
    data: proto::InitWalletRequest,
    random_cb: RandomCallback,
    init_cb: InitCallback,
) -> Result<res_data::Payload> {
    let need_len = data.length as usize * 4 / 3;

    let mut buffer = vec![0u8; need_len];
    random_cb(buffer.as_mut_ptr(), need_len);

    let mnemonic = mnemonic::Mnemonic::from_entropy(&buffer)?;
    let seed = mnemonic.to_seed("")?;

    init_cb(seed.as_ptr(), seed.len(), data.length as usize);

    //TODO: only debug return mnemonic msg.
    let init = proto::InitWalletResponse {
        mnemonic: mnemonic.words.join(" ").into(),
    };

    return Ok(res_data::Payload::InitWalletResponse(init));
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Result};
    use oskey_bus::proto::req_data;

    extern "C" fn version_cb(data: *mut u8, len: *mut usize) -> bool {
        let version = b"1.0.0";
        unsafe {
            core::ptr::copy_nonoverlapping(version.as_ptr(), data, version.len());
            *len = version.len();
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

    // fn event_bytes_handle(bytes: *mut u8, len: usize) -> Result<oskey_bus::proto::ReqData> {
    //     let bytes = unsafe { core::slice::from_raw_parts(bytes, len) };
    //     let parser = oskey_bus::FrameParser::unpack(bytes)?.ok_or(anyhow!("Waiting"))?;
    //     let req_data =
    //         oskey_bus::proto::ReqData::decode(parser.as_slice()).map_err(|e| anyhow!(e))?;
    //     Ok(req_data)
    // }

    pub fn event_hub(req: oskey_bus::proto::ReqData) -> Result<proto::ResData> {
        let payload = match req.payload.ok_or(anyhow!("Fail"))? {
            req_data::Payload::Unknown(_unknown) => wallet_unknown_req(),
            req_data::Payload::VersionRequest(_) => wallet_version_req(version_cb, check_init_cb),
            req_data::Payload::InitRequest(data) => {
                wallet_init_default(data, random_cb, init_cb_no_password)?
            }
            req_data::Payload::InitCustomRequest(_data) => wallet_unknown_req(),
            req_data::Payload::DerivePublicKeyRequest(_data) => wallet_unknown_req(),
            req_data::Payload::SignRequest(_data) => wallet_unknown_req(),
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
                has_hardware_random: true,
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
}
