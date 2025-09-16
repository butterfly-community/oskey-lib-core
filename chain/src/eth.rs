extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use alloy_consensus::private::alloy_primitives::{keccak256, TxKind};
use alloy_consensus::SignableTransaction;
use alloy_consensus::TxEip2930;
use anyhow::{anyhow, Result};
use oskey_bus::proto;
use core::fmt;

pub struct OSKeyMsgSignEip191;

impl OSKeyMsgSignEip191 {
    const MESSAGE_PREFIX: &'static str = "\x19Ethereum Signed Message:\n";

    pub fn hash_message(message: &[u8]) -> [u8; 32] {
        let len = message.len().to_string();
        let mut data = Vec::new();
        data.extend_from_slice(Self::MESSAGE_PREFIX.as_bytes());
        data.extend_from_slice(len.as_bytes());
        data.extend_from_slice(message);
        keccak256(&data).into()
    }
}

#[derive(Debug, Clone)]
pub struct OSKeyTxEip2930 {
    pub tx: TxEip2930,
}

impl OSKeyTxEip2930 {
    pub fn from_proto(proto: proto::AppEthTxEip2930) -> Result<Self> {
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
            input: proto.input.unwrap_or(vec![]).into(),
            access_list: vec![].into(),
        };
        Ok(Self { tx })
    }

    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut rlp_buffer = Vec::new();
        self.tx.encode_for_signing(&mut rlp_buffer);
        rlp_buffer
    }

    pub fn hash(&self) -> [u8; 32] {
        let rlp = self.rlp_encode();
        keccak256(&rlp).into()
    }

    pub fn fields(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();

        let to_address = match &self.tx.to {
            TxKind::Call(addr) => "0x".to_string() + &hex::encode(addr.as_slice()),
            TxKind::Create => "0x".to_string(),
        };

        let input_data = "0x".to_string() + &hex::encode(&self.tx.input);

        insert_field!(map, self.tx, chain_id);
        insert_field!(map, self.tx, nonce);
        insert_field!(map, self.tx, gas_price);
        insert_field!(map, self.tx, gas_limit);
        insert_field!(map, self.tx, to, to_address);
        insert_field!(map, self.tx, value);
        insert_field!(map, self.tx, input, input_data);
        map.insert(
            "hash".to_string(),
            "0x".to_string() + &hex::encode(self.hash()),
        );

        map
    }
}

impl fmt::Display for OSKeyTxEip2930 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (key, value) in self.fields() {
            f.write_str("\n")?;
            f.write_str(&key)?;
            f.write_str(":\n")?;
            f.write_str(&value)?;
            f.write_str("\n\n")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::string::ToString;

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
    fn test_display_methods() {
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

        let display_map = tx.fields();

        assert_eq!(display_map.get("chain_id").unwrap(), "11155111");
        assert_eq!(display_map.get("nonce").unwrap(), "5");
        assert_eq!(display_map.get("gas_price").unwrap(), "1112408");
        assert_eq!(display_map.get("gas_limit").unwrap(), "21000");
        assert_eq!(
            display_map.get("to").unwrap(),
            "0x00ab1ead740f95ade25b78b3137fdcc333326e7d"
        );
        assert_eq!(display_map.get("input").unwrap(), "0x");

        std::println!("{}", tx);
    }

    #[test]
    fn test_hash_message() {
        let empty_hash = OSKeyMsgSignEip191::hash_message(b"");
        assert_eq!(
            hex::encode(empty_hash),
            "5f35dce98ba4fba25530a026ed80b2cecdaa31091ba4958b99b52ea1d068adad"
        );

        let hello_hash = OSKeyMsgSignEip191::hash_message("hello world".as_bytes());
        assert_eq!(
            hex::encode(hello_hash),
            "d9eba16ed0ecae432b71fe008c98cc872bb4cc214d3220a36f365326cf807d68"
        );

        let hello_bytes = b"hello world";
        let hello_bytes_hash = OSKeyMsgSignEip191::hash_message(hello_bytes);
        assert_eq!(hello_hash, hello_bytes_hash);
    }
}
