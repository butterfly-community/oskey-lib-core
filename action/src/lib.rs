#![no_std]
extern crate alloc;
use alloc::string::String;
use alloc::vec;
use oskey_bus::{proto, proto::res_data};

pub type VersionCallback = extern "C" fn(data: *mut u8, len: *mut usize) -> bool;
pub type CheckInitCallback = extern "C" fn() -> bool;

pub fn wallet_unknown_req() -> res_data::Payload {
    return res_data::Payload::Unknown(proto::Unknown {});
}

pub fn wallet_version_req(
    version_cb: VersionCallback,
    init_cb: CheckInitCallback,
) -> res_data::Payload {
    let mut buffer = vec![0u8; 20];
    let mut version_len: usize = 0;

    let _version_check = version_cb(buffer.as_mut_ptr(), &mut version_len);

    let init_check = init_cb();

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

    extern "C" fn init_cb() -> bool {
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
            req_data::Payload::VersionRequest(_) => wallet_version_req(version_cb, init_cb),
            req_data::Payload::InitRequest(_data) => wallet_unknown_req(),
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
}
