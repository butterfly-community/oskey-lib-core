#![no_std]

extern crate alloc;

use crate::proto::ReqData;
use alloc::vec::Vec;
use anyhow::anyhow;
use anyhow::Result;
pub use prost::Message;
use zeroize::Zeroize;

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
    // Allows an 8 KiB request body plus its protobuf envelope.
    const MAX_PAYLOAD_LEN: usize = 9 * 1024;
    const MAX_RETAINED_FRAME_CAPACITY: usize = 1024;

    pub const fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn clear(&mut self) {
        self.buffer.zeroize();
        self.buffer = Vec::new();
    }

    fn discard(&mut self, len: usize) {
        let remaining = self.buffer.len() - len;
        self.buffer.copy_within(len.., 0);
        self.buffer[remaining..].zeroize();
        self.buffer.truncate(remaining);
    }

    fn payload_len(&mut self) -> Option<usize> {
        if self.buffer.len() < Self::HEADER_LEN {
            return None;
        }

        if !self.buffer.starts_with(Self::MAGIC) && !self.buffer.is_empty() {
            if let Some(pos) = self
                .buffer
                .windows(Self::MAGIC.len())
                .position(|window| window == Self::MAGIC)
            {
                self.discard(pos);
            } else if self.buffer.len() > 64 {
                self.clear();
            }
        }

        if self.buffer.len() < Self::HEADER_LEN || !self.buffer.starts_with(Self::MAGIC) {
            return None;
        }

        Some(u16::from_be_bytes([self.buffer[3], self.buffer[4]]) as usize)
    }

    pub fn unpack(&mut self) -> Option<Result<ReqData>> {
        let payload_len = self.payload_len()?;
        if payload_len > Self::MAX_PAYLOAD_LEN {
            self.clear();
            return Some(Err(anyhow!("Frame exceeds maximum payload size")));
        }
        if self.buffer.len() < Self::HEADER_LEN + payload_len {
            return None;
        }

        let frame_len = Self::HEADER_LEN + payload_len;

        let decoded = proto::ReqData::decode(&self.buffer[Self::HEADER_LEN..frame_len]);

        if frame_len == self.buffer.len()
            && self.buffer.capacity() > Self::MAX_RETAINED_FRAME_CAPACITY
        {
            self.clear();
        } else {
            self.discard(frame_len);
        }
        Some(decoded.map_err(|e| anyhow!(e)))
    }

    pub fn pack(data: &[u8]) -> Vec<u8> {
        let len = u16::try_from(data.len()).expect("frame payload exceeds u16 length field");

        let mut frame = Vec::with_capacity(Self::HEADER_LEN + data.len());
        frame.extend_from_slice(Self::MAGIC);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(data);
        frame
    }

    pub fn pack_message(message: &impl Message) -> Vec<u8> {
        let len = message.encoded_len();
        let frame_len = u16::try_from(len).expect("encoded message exceeds u16 length field");

        let mut frame = Vec::with_capacity(Self::HEADER_LEN + len);
        frame.extend_from_slice(Self::MAGIC);
        frame.extend_from_slice(&frame_len.to_be_bytes());
        message
            .encode(&mut frame)
            .expect("encoding into Vec cannot fail");
        frame
    }
}

impl Drop for FrameParser {
    fn drop(&mut self) {
        self.clear();
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
    fn test_pack_message() {
        let request = ReqData {
            payload: Some(ReqPayload::VersionRequest(VersionRequest {})),
        };
        assert_eq!(
            FrameParser::pack_message(&request),
            FrameParser::pack(&request.encode_to_vec())
        );
    }

    #[test]
    #[should_panic(expected = "frame payload exceeds u16 length field")]
    fn test_oversized_frame_is_rejected() {
        let payload = alloc::vec![0; u16::MAX as usize + 1];
        FrameParser::pack(&payload);
    }

    #[test]
    #[should_panic(expected = "encoded message exceeds u16 length field")]
    fn test_oversized_message_is_rejected() {
        let response = proto::ResData {
            payload: Some(ResPayload::SignResponse(proto::SignResponse {
                message: alloc::vec![0; u16::MAX as usize + 1],
                ..Default::default()
            })),
        };
        FrameParser::pack_message(&response);
    }

    #[test]
    fn test_large_consumed_buffer_is_released() {
        let frame = FrameParser::pack(&get_test_req_payload_bytes());
        let mut parser = FrameParser::new();
        parser.buffer.reserve(8192);
        parser.push(&frame);

        assert!(parser.unpack().unwrap().is_ok());
        assert_eq!(parser.buffer.capacity(), 0);
    }

    #[test]
    fn test_oversized_frame_is_rejected_from_its_header() {
        let mut parser = FrameParser::new();
        parser.push(FrameParser::MAGIC);
        parser.push(&u16::MAX.to_be_bytes());

        assert!(parser.unpack().unwrap().is_err());
        assert!(parser.buffer.is_empty());

        parser.push(&FrameParser::pack(&get_test_req_payload_bytes()));
        assert!(parser.unpack().unwrap().is_ok());
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
    fn clear_releases_large_frame_buffer() {
        let mut parser = FrameParser::new();
        parser.push(&[0; 4096]);
        assert!(parser.buffer.capacity() >= 4096);

        parser.clear();

        assert!(parser.buffer.is_empty());
        assert_eq!(parser.buffer.capacity(), 0);
    }

    #[test]
    fn invalid_input_releases_large_frame_buffer() {
        let mut parser = FrameParser::new();
        parser.push(&[0; 4096]);

        assert!(parser.unpack().is_none());
        assert!(parser.buffer.is_empty());
        assert_eq!(parser.buffer.capacity(), 0);
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
