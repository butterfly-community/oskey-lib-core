#[cfg(feature = "build")]
use cmake::Config;

#[cfg(feature = "build")]
fn main() {
    // println!("cargo:rerun-if-changed=psa/");

    let dst = Config::new("./").build();

    println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:rustc-link-lib=static=crypto");
    pkg_config::Config::new()
        .probe("mbedcrypto")
        .expect("failed to find Mbed Crypto with pkg-config");

    let target = std::env::var("TARGET").expect("Cargo did not provide TARGET");

    bindgen::Builder::default()
        .headers(["psa/wrapper.h"])
        .clang_arg(format!("--target={}", target))
        .use_core()
        .derive_debug(true)
        .generate_comments(true)
        .generate()
        .expect("failed to generate PSA bindings")
        .write_to_file("src/alg/bindings.rs")
        .expect("failed to write PSA bindings");
}

#[cfg(not(feature = "build"))]
fn main() {}
