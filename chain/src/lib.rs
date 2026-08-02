#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub mod eth;
pub mod fido;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FidoOperation {
    Register = 1,
    Authenticate = 2,
    Select = 3,
    Authorize = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthMessageConfirmation {
    pub from: [u8; 20],
    pub preview: String,
    pub byte_length: u64,
    pub signing_hash: [u8; 32],
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthTransactionConfirmation {
    pub from: [u8; 20],
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: String,
    pub gas_limit: u64,
    pub to: Vec<u8>,
    pub contract_creation: bool,
    pub value: String,
    pub input_length: u64,
    pub selector: Vec<u8>,
    pub input_hash: [u8; 32],
    pub signing_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FidoConfirmation {
    pub operation: FidoOperation,
    pub rp_id: String,
    pub account: Vec<u8>,
    pub account_is_text: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfirmationDetails {
    EthMessage(EthMessageConfirmation),
    EthTransaction(EthTransactionConfirmation),
    Fido(FidoConfirmation),
}
