#![no_std]
#![allow(dead_code)]

#[cfg(feature = "zephyr-rtos")]
pub use zephyr_wrapper::zephyr;

pub mod mnemonic;

pub mod path;

pub mod alg;

pub mod wallets;

mod utils;
