#![no_std]
extern crate alloc;



#[cfg(test)]
mod tests {
    use core::ffi::{c_char, c_int};

    pub type CCallback = extern "C" fn(c_int, *const c_char) -> bool;

    #[no_mangle]
    pub extern "C" fn rust_c_callback(data: c_int, callback: CCallback) {
        callback(data * 2, "Hello World!\0".as_ptr() as *const c_char);
    }

    extern "C" fn test_callback(data: c_int, msg: *const c_char) -> bool {
        let c_str = unsafe { core::ffi::CStr::from_ptr(msg) };
        let str_slice = c_str.to_str().unwrap();
        assert_eq!(data, 20);
        assert_eq!(str_slice, "Hello World!");
        return true;
    }

    #[test]
    fn test_rust_c_callback() {
        rust_c_callback(10, test_callback);
    }
}
