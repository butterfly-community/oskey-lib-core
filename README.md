# OSKey Wallets

A secure, embedded-friendly cryptocurrency wallet library for hardware wallets.

## Packages

- **wallet** - BIP-32/39/44 and SLIP-0010 compliant HD wallet implementation with multi-curve support (secp256k1, Ed25519, Curve25519, P256)
- **bus** - Protocol Buffers communication with custom framing for hardware-software interaction
- **chain** - Blockchain-specific transaction encoding and signing, currently implements Ethereum (EIP-2930/EIP-191)
- **action** - High-level wallet operations with trait-based callbacks for platform abstraction
- **bridge** - Client-device communication bridge layer

## References

- [BIP-32: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP-39: Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP-44: Multi-Account Hierarchy](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [SLIP-0010: Universal private key derivation](https://github.com/satoshilabs/slips/blob/master/slip-0010.md)
- [EIP-2930: Optional access lists](https://eips.ethereum.org/EIPS/eip-2930)
- [EIP-191: Signed Data Standard](https://eips.ethereum.org/EIPS/eip-191)

## Links

- [English Documentation](https://deepwiki.com/butterfly-community/oskey-lib-wallets)
- [中文文档](https://zread.ai/butterfly-community/oskey-lib-wallets)

## License

Mozilla Public License 2.0 (MPL-2.0)
