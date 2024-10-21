# ohw-algorithm

## Overview

ohw-algorithm is an embedded systems-focused library that implements some cryptographic algorithms, with goals including `no_std` compatibility, gas optimization, optimization for resource-constrained environments, and support for common algorithms and operations.

## Installation

To use `ohw-algorithm` in your project, add the following dependency to your `Cargo.toml` file:

```toml
[dependencies]
ohw-algorithm = { git = "https://github.com/butterfly-communtiy/ohw-algorithm.git" }
```

This crate supports the following features:

- `full`: Enables all features. (default)
- `bip32`: Hierarchical deterministic wallets.
- `bip39`: Mnemonic phrase generation and recovery.
- `bip44`: Multi-currency support for hierarchical deterministic wallets.

## Usage Example

Here is a simple example of how to use `ohw-algorithm` to generate a new mnemonic in English:

```rust
use ohw_algorithm::bip39::Mnemonic;

fn main() {
    let mnemonic = Mnemonic::generate(24).unwrap();
    for (i, word) in mnemonic.words().enumerate() {
        println!("{}. {}", i, word);
    }
}
```

## License

Licensed under the Mozilla Public License Version 2.0. For more details, please see the [LICENSE](LICENSE) file.
