#![no_std]
#![allow(dead_code)]

#[cfg(feature = "zephyr-rtos")]
pub extern crate zephyr;

pub mod mnemonic;

pub mod path;

pub mod alg;

pub mod wallets;

mod utils;
