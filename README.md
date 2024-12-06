Test This:

```
println!("\n1.Generate Hardware secure random number:\n");
println!("128 Bit - 256 Bit, Add checksum to 11 bit split. Supports 12, 15, 21, and 24 mnemonics. This use 128 Bit.");

let random = rust_cs_random_vec(16);
println!("\nRandom: {} \n\n", ohw_wallets::alg::hex::encode(random.clone()));

println!("\n2.Use random entropy generate mnemonic:");
let mnemonic = ohw_wallets::mnemonic::Mnemonic::from_entropy(&random).unwrap();
println!("\nMnemonic: {} \n\n", mnemonic.words.join(" ").as_str());

println!("\n3.Mnemonic to seed. Supports mnemonic passwords, here the password is ohw.\n");
println!("Key: {} \n\n", ohw_wallets::alg::hex::encode(mnemonic.clone().to_seed("ohw").unwrap()));

println!("\n4.BIP32 Root Key:\n");
let root = ohw_wallets::wallets::ExtendedPrivKey::derive(&mnemonic.to_seed("ohw").unwrap(), "m".parse().unwrap()).unwrap();
println!("Key: {} \n\n", root.encode(false).unwrap());

println!("\n5.BIP44 ETH Extended Private Key, m/44'/60'/0'/0 Derivation Path:\n");
let root = ohw_wallets::wallets::ExtendedPrivKey::derive(&mnemonic.to_seed("ohw").unwrap(), "m/44'/60'/0'/0".parse().unwrap()).unwrap();
println!("Key: {} \n\n", root.encode(false).unwrap());

println!("\n6.ETH Account 0, m/44'/60'/0'/0/0 Derivation Path:\n");
let root = ohw_wallets::wallets::ExtendedPrivKey::derive(&mnemonic.to_seed("ohw").unwrap(), "m/44'/60'/0'/0/0".parse().unwrap()).unwrap();
println!("Key: {} \n\n", ohw_wallets::alg::hex::encode(root.secret_key));
```
