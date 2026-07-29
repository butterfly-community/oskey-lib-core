#![no_std]

extern crate alloc;

use crate::proto::ReqData;
use alloc::vec::Vec;
use anyhow::anyhow;
use anyhow::Result;
pub use prost::Message;

pub mod proto {
    include!("proto/oskey.rs");
}

pub struct FrameParser {
    buffer: Vec<u8>,
}

impl Default for FrameParser {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameParser {
    const MAGIC: &'static [u8] = "₿".as_bytes();
    const HEADER_LEN: usize = Self::MAGIC.len() + 2;

    pub const fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn push(&mut self, data: &[u8]) {
        // TODO: Add a bounded or streaming parser without rejecting large wallet messages.
        self.buffer.extend_from_slice(data);
    }

    fn check(&mut self) -> bool {
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
            } else if self.buffer.len() > 64 {
                self.buffer.clear();
            }
        }

        if self.buffer.len() < Self::HEADER_LEN || !self.buffer.starts_with(Self::MAGIC) {
            return false;
        }

        let payload_len = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;

        self.buffer.len() >= Self::HEADER_LEN + payload_len
    }

    pub fn unpack(&mut self) -> Option<Result<ReqData>> {
        if !self.check() {
            return None;
        }

        let payload_len = u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize;
        let frame_len = Self::HEADER_LEN + payload_len;

        let decoded = proto::ReqData::decode(&self.buffer[Self::HEADER_LEN..frame_len]);

        self.buffer.drain(..frame_len);
        Some(decoded.map_err(|e| anyhow!(e)))
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
            sn: "XXXXXXXX".into(),
        });

        let response = ResData {
            payload: payload.into(),
        };

        response.encode_to_vec()
    }

    fn get_test_req_payload_bytes() -> Vec<u8> {
        let payload = ReqPayload::VersionRequest(VersionRequest {});

        let response = ReqData {
            payload: payload.into(),
        };

        response.encode_to_vec()
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

        let mut parser = FrameParser::new();
        parser.push(&frame);
        let payload = parser
            .unpack()
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
        parser_1.push(&invalid_header);
        assert!(parser_1.unpack().is_none());
        assert_eq!(parser_1.buffer.len(), frame.len());
        parser_1.push(&frame);
        let test = parser_1.unpack();
        assert!(test.is_some());

        let short_frame = &frame.clone()[..frame.len() - 1];
        let mut parser_2 = FrameParser::new();
        parser_2.push(short_frame);
        let req_2 = parser_2.unpack();
        assert!(req_2.is_none());
        assert_eq!(parser_2.buffer.len(), frame.len() - 1);
        Ok(())
    }

    #[test]
    fn test_partial_frame() -> Result<()> {
        let bytes = get_test_req_payload_bytes();
        let frame = FrameParser::pack(&bytes);

        let mut parser = FrameParser::new();

        let mid = frame.len() / 2;
        let part1 = &frame[..mid];
        let part2 = &frame[mid..];

        parser.push(part1);
        let req_1 = parser.unpack();
        assert!(req_1.is_none());
        assert_eq!(parser.buffer.len(), part1.len());

        parser.push(part2);
        let req_2 = parser.unpack();
        assert!(req_2.is_some());
        assert_eq!(parser.buffer.len(), 0);

        let payload = req_2.unwrap().map_err(|e| anyhow!(e))?;
        assert_eq!(payload.encode_to_vec(), bytes);
        Ok(())
    }

    #[test]
    fn test_unpack_after_partial() -> Result<()> {
        let bytes = get_test_req_payload_bytes();
        let frame = FrameParser::pack(&bytes);

        let mut parser = FrameParser::new();

        let mid = frame.len() / 2;
        let part1 = &frame[..mid];
        let part2 = &frame[mid..];

        parser.push(part1);
        assert!(parser.unpack().is_none());
        assert_eq!(parser.buffer.len(), part1.len());

        parser.push(part2);
        assert_eq!(parser.buffer.len(), frame.len());

        let req = parser.unpack();
        assert!(req.is_some());
        let payload = req.unwrap().map_err(|e| anyhow!(e))?;
        assert_eq!(payload.encode_to_vec(), bytes);
        Ok(())
    }
}
