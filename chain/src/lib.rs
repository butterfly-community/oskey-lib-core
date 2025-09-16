#![no_std]
#![allow(dead_code)]

#[macro_export]
macro_rules! insert_field {
    ($map:expr, $obj:expr, $field:ident) => {
        $map.insert(stringify!($field).to_string(), $obj.$field.to_string());
    };
    ($map:expr, $obj:expr, $field:ident, $value:expr) => {
        $map.insert(stringify!($field).to_string(), $value);
    };
}

pub mod eth;
