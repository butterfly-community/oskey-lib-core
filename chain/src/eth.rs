extern crate alloc;
use alloc::string::ToString;
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

    pub fn confirmation(message: &str, hash: &[u8; 32]) -> proto::EthMessageConfirmation {
        let mut preview_end = message.len().min(MESSAGE_PREVIEW_BYTES);
        while !message.is_char_boundary(preview_end) {
            preview_end -= 1;
        }

        proto::EthMessageConfirmation {
            preview: message[..preview_end].into(),
            byte_length: message.len() as u64,
            signing_hash: hash.to_vec(),
            truncated: preview_end < message.len(),
        }
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

    pub fn confirmation(&self, hash: &[u8; 32]) -> proto::EthTransactionConfirmation {
        let (to, contract_creation) = match &self.tx.to {
            TxKind::Call(address) => (address.as_slice().to_vec(), false),
            TxKind::Create => (Vec::new(), true),
        };

        proto::EthTransactionConfirmation {
            chain_id: self.tx.chain_id,
            nonce: self.tx.nonce,
            gas_price: self.tx.gas_price.to_string(),
            gas_limit: self.tx.gas_limit,
            to,
            contract_creation,
            value: self.tx.value.to_string(),
            input_length: self.tx.input.len() as u64,
            selector: self.tx.input.get(..4).unwrap_or_default().to_vec(),
            input_hash: keccak256(&self.tx.input).to_vec(),
            signing_hash: hash.to_vec(),
        }
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
    fn test_transaction_confirmation() {
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
        let confirmation = tx.confirmation(&hash);

        assert_eq!(confirmation.chain_id, 11155111);
        assert_eq!(confirmation.nonce, 5);
        assert_eq!(confirmation.gas_price, "1112408");
        assert_eq!(confirmation.gas_limit, 21000);
        assert_eq!(
            confirmation.to,
            hex::decode("00ab1ead740f95ade25b78b3137fdcc333326e7d").unwrap()
        );
        assert!(!confirmation.contract_creation);
        assert_eq!(confirmation.input_length, 2048);
        assert_eq!(confirmation.selector, [0xa9, 0x05, 0x9c, 0xbb]);
        assert_eq!(confirmation.signing_hash, hash);
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
        let confirmation = OSKeyTxEip191::confirmation(&message, &hash);

        assert!(confirmation.truncated);
        assert_eq!(confirmation.byte_length, 12288);
        assert_eq!(confirmation.signing_hash, hash);
        assert!(confirmation.preview.len() <= MESSAGE_PREVIEW_BYTES);
        assert!(confirmation
            .preview
            .is_char_boundary(confirmation.preview.len()));
    }
}
