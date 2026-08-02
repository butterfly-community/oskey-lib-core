extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloy_consensus::private::alloy_primitives::{eip191_hash_message, keccak256, TxKind};
use alloy_consensus::SignableTransaction;
use alloy_consensus::TxEip2930;
use anyhow::{anyhow, bail, Result};

use crate::{EthMessageConfirmation, EthTransactionConfirmation};

const MESSAGE_PREVIEW_BYTES: usize = 256;

pub struct OSKeyTxEip191;

impl OSKeyTxEip191 {
    pub fn hash_message(message: &[u8]) -> [u8; 32] {
        eip191_hash_message(message).into()
    }

    pub fn confirmation(
        message: &str,
        hash: &[u8; 32],
        from: [u8; 20],
    ) -> Result<EthMessageConfirmation> {
        if !message
            .bytes()
            .all(|byte| byte == b'\n' || (b' '..=b'~').contains(&byte))
        {
            bail!("Ethereum message cannot be displayed safely");
        }
        let preview_end = message.len().min(MESSAGE_PREVIEW_BYTES);

        Ok(EthMessageConfirmation {
            from,
            preview: message[..preview_end].into(),
            byte_length: message.len() as u64,
            signing_hash: *hash,
            truncated: preview_end < message.len(),
        })
    }

    pub fn address(public_key: &[u8]) -> Result<[u8; 20]> {
        if public_key.len() != 65 || public_key[0] != 4 {
            bail!("Invalid Ethereum public key");
        }
        Ok(keccak256(&public_key[1..])[12..].try_into()?)
    }
}

#[derive(Debug)]
pub struct OSKeyTxEip2930 {
    pub tx: TxEip2930,
}

pub struct Eip2930Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: String,
    pub gas_limit: u64,
    pub to: Option<String>,
    pub value: String,
    pub input: Vec<u8>,
}

impl OSKeyTxEip2930 {
    pub fn new(transaction: Eip2930Transaction) -> Result<Self> {
        let tx = TxEip2930 {
            chain_id: transaction.chain_id,
            nonce: transaction.nonce,
            gas_price: transaction.gas_price.parse()?,
            gas_limit: transaction.gas_limit,
            to: match transaction.to {
                Some(to) => TxKind::Call(to.parse()?),
                None => TxKind::Create,
            },
            value: transaction
                .value
                .parse()
                .map_err(|_| anyhow!("u256 parse error"))?,
            input: transaction.input.into(),
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

    pub fn confirmation(&self, hash: &[u8; 32], from: [u8; 20]) -> EthTransactionConfirmation {
        let (to, contract_creation) = match &self.tx.to {
            TxKind::Call(address) => (address.as_slice().to_vec(), false),
            TxKind::Create => (Vec::new(), true),
        };

        EthTransactionConfirmation {
            from,
            chain_id: self.tx.chain_id,
            nonce: self.tx.nonce,
            gas_price: self.tx.gas_price.to_string(),
            gas_limit: self.tx.gas_limit,
            to,
            contract_creation,
            value: self.tx.value.to_string(),
            input_length: self.tx.input.len() as u64,
            selector: self.tx.input.get(..4).unwrap_or_default().to_vec(),
            input_hash: keccak256(&self.tx.input).into(),
            signing_hash: *hash,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_eth_eip2930_transaction() {
        let source = Eip2930Transaction {
            chain_id: 0xaa36a7,
            nonce: 0x5,
            gas_price: "1112408".to_string(),
            gas_limit: 0x5208,
            to: Some("0x00Ab1EAd740f95aDE25b78B3137fdcC333326e7d".to_string()),
            value: "0x16345785d8a0000".to_string(),
            input: Vec::new(),
        };

        let tx = OSKeyTxEip2930::new(source).unwrap();

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
        let source = Eip2930Transaction {
            chain_id: 0xaa36a7,
            nonce: 0x5,
            gas_price: "1112408".to_string(),
            gas_limit: 0x5208,
            to: Some("0x00Ab1EAd740f95aDE25b78B3137fdcC333326e7d".to_string()),
            value: "0x16345785d8a0000".to_string(),
            input: [0xa9, 0x05, 0x9c, 0xbb].repeat(512),
        };

        let tx = OSKeyTxEip2930::new(source).unwrap();
        let hash = tx.hash();
        let confirmation = tx.confirmation(&hash, [1; 20]);

        assert_eq!(confirmation.from, [1; 20]);
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
        let message = "a".repeat(4096);
        let hash = OSKeyTxEip191::hash_message(message.as_bytes());
        let confirmation = OSKeyTxEip191::confirmation(&message, &hash, [2; 20]).unwrap();

        assert_eq!(confirmation.from, [2; 20]);
        assert!(confirmation.truncated);
        assert_eq!(confirmation.byte_length, 4096);
        assert_eq!(confirmation.signing_hash, hash);
        assert!(confirmation.preview.len() <= MESSAGE_PREVIEW_BYTES);
        assert_eq!(confirmation.preview.len(), MESSAGE_PREVIEW_BYTES);
    }

    #[test]
    fn message_confirmation_rejects_hidden_suffix() {
        let message = "approve\0hidden";
        let hash = OSKeyTxEip191::hash_message(message.as_bytes());

        assert!(OSKeyTxEip191::confirmation(message, &hash, [0; 20]).is_err());
    }

    #[test]
    fn message_confirmation_accepts_multiline_text() {
        let message = "example.com wants you to sign in\nURI: https://example.com";
        let hash = OSKeyTxEip191::hash_message(message.as_bytes());
        let confirmation = OSKeyTxEip191::confirmation(message, &hash, [0; 20]).unwrap();

        assert_eq!(confirmation.preview, message);
    }

    #[test]
    fn message_confirmation_rejects_unrenderable_text() {
        let message = "批准";
        let hash = OSKeyTxEip191::hash_message(message.as_bytes());
        assert!(OSKeyTxEip191::confirmation(message, &hash, [0; 20]).is_err());
    }

    #[test]
    fn derives_ethereum_address_from_public_key() {
        let public_key = hex::decode("04401b572dd885235567e0177711e913ec1587344669936f6358c86bcc73c189be3f2340a88249509b4b9bce6f5190d4e537ec314026ee849707e28ad57a1723b2").unwrap();
        assert_eq!(
            hex::encode(OSKeyTxEip191::address(&public_key).unwrap()),
            "938247a9b8a889a18637d1e769ac721655f3aa1a"
        );
        assert!(OSKeyTxEip191::address(&public_key[1..]).is_err());
    }
}
