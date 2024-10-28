#[cfg(not(feature = "builtin"))]
use cmake::Config;

#[cfg(not(feature = "builtin"))]
fn main() {
    let dst = Config::new("./")
        .define("MBEDTLS_USE_STATIC_LIBS", "ON")
        .define("BUILD_SHARED_LIBS", "OFF")
        .build();

    println!("cargo:rustc-link-search=native={}", dst.display());
    println!(
        "cargo:rustc-link-search=native={}",
        "/home/linuxbrew/.linuxbrew/lib"
    );
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=mbedtls");
    println!("cargo:rustc-link-lib=static=mbedcrypto");

    bindgen::Builder::default()
        .headers(["crypto/wrapper.h"])
        .use_core()
        .derive_debug(true)
        .generate_comments(true)
        .generate()
        .unwrap()
        .write_to_file("src/bindings.rs")
        .unwrap();
}

#[cfg(feature = "builtin")]
fn main() {}
