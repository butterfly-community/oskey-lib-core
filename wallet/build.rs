#[cfg(feature = "build")]
use cmake::Config;

#[cfg(feature = "build")]
fn main() {
    println!("cargo:rerun-if-changed=psa/");

    let dst = Config::new("./")
        .define("MBEDTLS_USE_STATIC_LIBS", "ON")
        .define("BUILD_SHARED_LIBS", "OFF")
        .build();

    println!("cargo:rustc-link-search=native={}", dst.display());
    println!(
        "cargo:rustc-link-search=native={}",
        "/home/linuxbrew/.linuxbrew/lib"
    );
    println!("cargo:rustc-link-search=native=/usr/local/lib/");
    println!("cargo:rustc-link-lib=static=crypto");
    println!("cargo:rustc-link-lib=static=mbedtls");
    println!("cargo:rustc-link-lib=static=mbedcrypto");
    println!("cargo:rustc-link-lib=static=mbedx509");

    let target = std::env::var("TARGET").unwrap();

    bindgen::Builder::default()
        .headers(["psa/wrapper.h"])
        .clang_arg(format!("--target={}", target))
        .use_core()
        .derive_debug(true)
        .generate_comments(true)
        .generate()
        .unwrap()
        .write_to_file("src/alg/bindings.rs")
        .unwrap();
}

#[cfg(not(feature = "build"))]
fn main() {}
