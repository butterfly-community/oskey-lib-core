#[allow(warnings)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub use bindings::mnemonic_from_data;

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test() {
        let hex = "d93d7512a47fd913fda5ba2453b4f345";
        let mut data = [0u8; 16];

        for i in 0..16 {
            let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
            data[i] = byte;
        }

        let test = unsafe { mnemonic_from_data(data.as_ptr(), 128) };
        let result = unsafe {
            core::ffi::CStr::from_ptr(test)
                .to_str()
                .unwrap()
                .to_string()
        };
        println!("Mnemonic: {:#?}", result);
    }
}
