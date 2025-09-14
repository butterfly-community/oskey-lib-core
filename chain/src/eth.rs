extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use alloy_consensus::private::alloy_primitives::{keccak256, TxKind};
use alloy_consensus::SignableTransaction;
use alloy_consensus::TxEip2930;
use anyhow::{anyhow, Result};
use oskey_bus::proto;

pub struct OSKeyTxEip2930 {
    pub tx: TxEip2930,
}

impl OSKeyTxEip2930 {
    pub fn from_proto(proto: proto::AppEthLegacyTx) -> Result<Self> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use oskey_bus::proto;

    #[test]
    fn test_eth_legacy_transaction() {
        let source = proto::AppEthLegacyTx {
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
}
