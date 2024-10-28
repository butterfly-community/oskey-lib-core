#![no_std]

extern crate alloc;

#[allow(warnings)]
mod bindings {
    include!("bindings.rs");
}

pub use bindings::mnemonic_from_data;

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Result};
    use core::ffi::CStr;

    #[test]
    fn test() -> Result<()> {
        let mut bytes = [0u8; 16];

        hex::decode_to_slice("d93d7512a47fd913fda5ba2453b4f345", &mut bytes)
            .map_err(|e| anyhow!(e))?;

        let test = unsafe { mnemonic_from_data(bytes.as_mut_ptr(), 128) };

        let result = unsafe { CStr::from_ptr(test).to_str()? };

        let mnemonic = "summer two dwarf employ work measure walk resemble cattle oval devote melt";

        assert!(result.eq(mnemonic));

        Ok(())
    }
}
