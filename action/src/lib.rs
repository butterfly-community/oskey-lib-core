#![no_std]
extern crate alloc;
use alloc::vec::Vec;
use anyhow::{anyhow, Result};
use oskey_bus::proto;
use oskey_bus::proto::{req_data, res_data};
use oskey_bus::Message;

pub type EventCallback = extern "C" fn(data: *const u8, len: usize);

#[no_mangle]
extern "C" fn event_bytes_handle(bytes: *mut u8, len: usize, callback: EventCallback) {
    let bytes = unsafe { core::slice::from_raw_parts(bytes, len) };
    let event = event_parser(bytes);

    if let Ok(e) = event {
        callback(e.as_ptr(), e.len());
    }
    return;
}

pub fn event_parser(bytes: &[u8]) -> Result<Vec<u8>> {
    let parser = oskey_bus::FrameParser::unpack(bytes)?;

    let payload_bytes = parser.ok_or(anyhow!("Waiting"))?;

    let req_data =
        oskey_bus::proto::ReqData::decode(payload_bytes.as_slice()).map_err(|e| anyhow!(e))?;

    Ok(event_hub(req_data)?)
}

pub fn event_hub(req: oskey_bus::proto::ReqData) -> Result<Vec<u8>> {
    let payload = match req.payload.ok_or(anyhow!("Fail"))? {
        req_data::Payload::Unknown(_unknown) => wallet_unknown_req(),
        req_data::Payload::VersionRequest(_) => wallet_unknown_req(),
        req_data::Payload::InitRequest(_data) => wallet_unknown_req(),
        req_data::Payload::InitCustomRequest(_data) => wallet_unknown_req(),
        req_data::Payload::DerivePublicKeyRequest(_data) => wallet_unknown_req(),
        req_data::Payload::SignRequest(_data) => wallet_unknown_req(),
    };

    let response = oskey_bus::proto::ResData {
        payload: payload.into(),
    };

    let pack = oskey_bus::FrameParser::pack(&response.encode_to_vec());

    Ok(pack)
}

pub fn wallet_unknown_req() -> res_data::Payload {
    return res_data::Payload::Unknown(proto::Unknown {});
}

#[cfg(test)]
mod tests {
    use core::ffi::{c_char, c_int};

    pub type CCallback = extern "C" fn(c_int, *const c_char) -> bool;

    #[no_mangle]
    pub extern "C" fn rust_c_callback(data: c_int, callback: CCallback) {
        callback(data * 2, "Hello World!\0".as_ptr() as *const c_char);
    }

    extern "C" fn test_callback(data: c_int, msg: *const c_char) -> bool {
        let c_str = unsafe { core::ffi::CStr::from_ptr(msg) };
        let str_slice = c_str.to_str().unwrap();
        assert_eq!(data, 20);
        assert_eq!(str_slice, "Hello World!");
        return true;
    }

    #[test]
    fn test_rust_c_callback() {
        rust_c_callback(10, test_callback);
    }
}
