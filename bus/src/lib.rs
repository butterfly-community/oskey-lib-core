#![no_std]
#![allow(static_mut_refs)]
extern crate alloc;
use crate::proto::ReqData;
use alloc::vec::Vec;
use anyhow::anyhow;
use anyhow::Result;
pub use prost::Message;

pub mod proto {
    include!("proto/ohw.rs");
}

pub struct FrameParser {
    pub buffer: Vec<u8>,
}

impl FrameParser {
    const MAGIC: &'static [u8] = "₿".as_bytes();
    const HEADER_LEN: usize = Self::MAGIC.len() + 2;

    pub const fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn add(&mut self, data: &[u8]) -> Option<Result<ReqData>> {
        self.buffer.extend_from_slice(data);
        if self.check() == false {
            return None;
        }
        return self.unpack();
    }

    pub fn check(&mut self) -> bool {
        if self.buffer.len() < Self::HEADER_LEN {
            return false;
        }

        if !self.buffer.starts_with(Self::MAGIC) && !self.buffer.is_empty() {
            if let Some(pos) = self
                .buffer
                .windows(Self::MAGIC.len())
                .position(|window| window == Self::MAGIC)
            {
                self.buffer.drain(..pos);
            } else {
                if self.buffer.len() > 64 {
                    self.clear();
                }
            }
        }

        if self.buffer.len() < Self::HEADER_LEN || !self.buffer.starts_with(Self::MAGIC) {
            return false;
        }
        return true;
    }

    pub fn unpack(&mut self) -> Option<Result<ReqData>> {
        let payload_len = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;

        if self.buffer.len() < Self::HEADER_LEN + payload_len {
            return None;
        }

        let frame_len = Self::HEADER_LEN + payload_len;

        let decoded = proto::ReqData::decode(&self.buffer[Self::HEADER_LEN..frame_len]);

        self.buffer.drain(..frame_len);

        if self.buffer.is_empty() {
            self.clear();
        }
        Some(decoded.map_err(|e| anyhow!(e)))
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
        self.buffer.shrink_to_fit();
    }

    pub fn pack(data: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(Self::HEADER_LEN + data.len());
        frame.extend_from_slice(Self::MAGIC);
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        frame
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use crate::proto::VersionRequest;

    use super::*;
    use anyhow::{anyhow, Ok, Result};
    use prost::Message;
    use proto::{
        req_data::Payload as ReqPayload, res_data::Payload as ResPayload, Features, ReqData,
        ResData, VersionResponse,
    };

    fn get_test_res_payload_bytes() -> Vec<u8> {
        let payload = ResPayload::VersionResponse(VersionResponse {
            version: "1.0.0".into(),
            features: { Features::default() }.into(),
        });

        let response = ResData {
            payload: payload.into(),
        };

        let bytes = response.encode_to_vec();

        return bytes;
    }

    fn get_test_req_payload_bytes() -> Vec<u8> {
        let payload = ReqPayload::VersionRequest(VersionRequest {});

        let response = ReqData {
            payload: payload.into(),
        };

        let bytes = response.encode_to_vec();

        return bytes;
    }

    #[test]
    fn test_version() -> Result<()> {
        let bytes = get_test_res_payload_bytes();

        let decoded_response = proto::ResData::decode(bytes.as_slice()).map_err(|e| anyhow!(e))?;

        if let ResPayload::VersionResponse(resp) =
            decoded_response.payload.ok_or(anyhow!("Decode Error"))?
        {
            assert_eq!(resp.version, "1.0.0");
        } else {
            panic!("Expected VersionResponse");
        }

        Ok(())
    }

    #[test]
    fn test_frame() -> Result<()> {
        let bytes = get_test_req_payload_bytes();

        let frame = FrameParser::pack(&bytes);

        let payload = FrameParser::new()
            .add(&frame)
            .ok_or(anyhow!("No frame"))?
            .map_err(|e| anyhow!(e))?;

        assert_eq!(payload.encode_to_vec(), bytes);

        Ok(())
    }

    #[test]
    fn test_invalid_frame() -> Result<()> {
        let bytes = get_test_req_payload_bytes();

        let frame = FrameParser::pack(&bytes);

        let mut invalid_header = frame.clone();
        invalid_header[0] = b'x';
        let mut parser_1 = FrameParser::new();
        parser_1.add(&invalid_header);
        assert_eq!(parser_1.buffer.len(), frame.len());
        let test = parser_1.add(&frame);
        assert!(test.is_some());

        let short_frame = &frame.clone()[..frame.len() - 1];
        let mut parser_2 = FrameParser::new();
        let req_2 = parser_2.add(short_frame);
        assert!(req_2.is_none());
        assert_eq!(parser_2.buffer.len(), frame.len() - 1);
        Ok(())
    }
}
