extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use alloy_consensus::private::alloy_primitives::{eip191_hash_message, keccak256, TxKind};
use alloy_consensus::SignableTransaction;
use alloy_consensus::TxEip2930;
use anyhow::{anyhow, Result};
use oskey_bus::proto;

const MESSAGE_PREVIEW_BYTES: usize = 256;

pub struct OSKeyTxEip191;

impl OSKeyTxEip191 {
    pub fn hash_message(message: &[u8]) -> [u8; 32] {
        eip191_hash_message(message).into()
    }

    pub fn confirmation_text(message: &str, hash: &[u8; 32]) -> String {
        let mut preview_end = message.len().min(MESSAGE_PREVIEW_BYTES);
        while !message.is_char_boundary(preview_end) {
            preview_end -= 1;
        }

        let preview = &message[..preview_end];
        let suffix = if preview_end < message.len() {
            "..."
        } else {
            ""
        };

        format!(
            "message:\n{preview}{suffix}\n\nmessage_length:\n{}\n\nhash:\n0x{}",
            message.len(),
            hex::encode(hash)
        )
    }
}

#[derive(Debug)]
pub struct OSKeyTxEip2930 {
    pub tx: TxEip2930,
}

impl OSKeyTxEip2930 {
    pub fn from_proto(proto: proto::AppEthTxEip2930) -> Result<Self> {
        if proto
            .access_list
            .as_ref()
            .is_some_and(|access_list| !access_list.is_empty())
        {
            return Err(anyhow!("EIP-2930 access lists are unsupported"));
        }

        let tx = TxEip2930 {
            chain_id: proto.chain_id,
            nonce: proto.nonce,
            gas_price: proto.gas_price.parse()?,
            gas_limit: proto.gas_limit,
            to: match proto.to {
                Some(to) => TxKind::Call(to.parse()?),
                None => TxKind::Create,
            },
            value: proto
                .value
                .parse()
                .map_err(|_| anyhow!("u256 parse error"))?,
            input: proto.input.unwrap_or_default().into(),
            access_list: Default::default(),
        };
        Ok(Self { tx })
    }

    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut rlp_buffer = Vec::with_capacity(self.tx.payload_len_for_signature());
        self.tx.encode_for_signing(&mut rlp_buffer);
        rlp_buffer
    }

    pub fn hash(&self) -> [u8; 32] {
        self.tx.signature_hash().into()
    }

    pub fn confirmation_text(&self, hash: &[u8; 32]) -> String {
        let to = match &self.tx.to {
            TxKind::Call(address) => format!("0x{}", hex::encode(address.as_slice())),
            TxKind::Create => "contract creation".into(),
        };
        let selector = self.tx.input.get(..4).map_or_else(String::new, |input| {
            format!("selector:\n0x{}\n\n", hex::encode(input))
        });

        format!(
            "chain_id:\n{}\n\nnonce:\n{}\n\ngas_price:\n{}\n\ngas_limit:\n{}\n\nto:\n{}\n\nvalue:\n{}\n\ninput_length:\n{}\n\n{}input_hash:\n0x{}\n\nhash:\n0x{}",
            self.tx.chain_id,
            self.tx.nonce,
            self.tx.gas_price,
            self.tx.gas_limit,
            to,
            self.tx.value,
            self.tx.input.len(),
            selector,
            hex::encode(keccak256(&self.tx.input)),
            hex::encode(hash),
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    #[test]
    fn test_eth_eip2930_transaction() {
        let source = proto::AppEthTxEip2930 {
            chain_id: 0xaa36a7,
            nonce: 0x5,
            gas_price: "1112408".to_string(),
            gas_limit: 0x5208,
            to: Some("0x00Ab1EAd740f95aDE25b78B3137fdcC333326e7d".to_string()),
            value: "0x16345785d8a0000".to_string(),
            input: None,
            access_list: None,
        };

        let tx = OSKeyTxEip2930::from_proto(source).unwrap();

        assert_eq!(tx.rlp_encode(), hex::decode("01ec83aa36a7058310f9588252089400ab1ead740f95ade25b78b3137fdcc333326e7d88016345785d8a000080c0").unwrap().as_slice());

        let tx_hash = tx.hash();

        assert_eq!(
            tx_hash,
            hex::decode("e8a4c5905197c0ebe135460219fd0f47381b17c91d1d28e51feca29980a10a69")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_confirmation_text() {
        let source = proto::AppEthTxEip2930 {
            chain_id: 0xaa36a7,
            nonce: 0x5,
            gas_price: "1112408".to_string(),
            gas_limit: 0x5208,
            to: Some("0x00Ab1EAd740f95aDE25b78B3137fdcC333326e7d".to_string()),
            value: "0x16345785d8a0000".to_string(),
            input: Some([0xa9, 0x05, 0x9c, 0xbb].repeat(512)),
            access_list: None,
        };

        let tx = OSKeyTxEip2930::from_proto(source).unwrap();
        let hash = tx.hash();
        let text = tx.confirmation_text(&hash);

        assert!(text.contains("chain_id:\n11155111"));
        assert!(text.contains("nonce:\n5"));
        assert!(text.contains("gas_price:\n1112408"));
        assert!(text.contains("gas_limit:\n21000"));
        assert!(text.contains("to:\n0x00ab1ead740f95ade25b78b3137fdcc333326e7d"));
        assert!(text.contains("input_length:\n2048"));
        assert!(text.contains("selector:\n0xa9059cbb"));
        assert!(text.contains(&hex::encode(hash)));
        assert!(text.len() < 512);
    }

    #[test]
    fn test_rejects_nonempty_access_list() {
        let source = proto::AppEthTxEip2930 {
            chain_id: 1,
            nonce: 0,
            gas_price: "1".to_string(),
            gas_limit: 21000,
            to: None,
            value: "0".to_string(),
            input: None,
            access_list: Some(vec![0xc0]),
        };

        assert!(OSKeyTxEip2930::from_proto(source).is_err());
    }

    #[test]
    fn test_hash_message() {
        let empty_hash = OSKeyTxEip191::hash_message(b"");
        assert_eq!(
            hex::encode(empty_hash),
            "5f35dce98ba4fba25530a026ed80b2cecdaa31091ba4958b99b52ea1d068adad"
        );

        let hello_hash = OSKeyTxEip191::hash_message("hello world".as_bytes());
        assert_eq!(
            hex::encode(hello_hash),
            "d9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68"
        );

        let hello_bytes = b"hello world";
        let hello_bytes_hash = OSKeyTxEip191::hash_message(hello_bytes);
        assert_eq!(hello_hash, hello_bytes_hash);
    }

    #[test]
    fn test_message_confirmation_is_bounded() {
        let message = "测".repeat(4096);
        let hash = OSKeyTxEip191::hash_message(message.as_bytes());
        let text = OSKeyTxEip191::confirmation_text(&message, &hash);

        assert!(text.contains("...\n\nmessage_length:\n12288"));
        assert!(text.contains(&hex::encode(hash)));
        assert!(text.len() < 512);
    }
}
