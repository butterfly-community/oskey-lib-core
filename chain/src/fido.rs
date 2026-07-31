use anyhow::{bail, Result};
use oskey_wallet::alg::crypto::{Hash, HMAC, P256};
use oskey_wallet::path::{ChildNumber, DerivationPath};
use oskey_wallet::wallets::{Curve, ExtendedPrivKey};

pub const CREDENTIAL_ID_SIZE: usize = 64;
pub const NONCE_SIZE: usize = 16;

const VERSION: u8 = 2;
const NONCE_OFFSET: usize = 1;
const RP_ID_HASH_OFFSET: usize = NONCE_OFFSET + NONCE_SIZE;
const TAG_OFFSET: usize = RP_ID_HASH_OFFSET + 32;
const FIDO_NAMESPACE: u32 = u32::from_be_bytes(*b"FIDO");

pub struct Credential {
    pub id: [u8; CREDENTIAL_ID_SIZE],
    pub public_key: [u8; 65],
}

pub fn create(seed: &[u8], rp_id: &str, nonce: &[u8; NONCE_SIZE]) -> Result<Credential> {
    let rp_id_hash = Hash::sha256(rp_id.as_bytes())?;

    let mut id = [0; CREDENTIAL_ID_SIZE];
    id[0] = VERSION;
    id[NONCE_OFFSET..RP_ID_HASH_OFFSET].copy_from_slice(nonce);
    id[RP_ID_HASH_OFFSET..TAG_OFFSET].copy_from_slice(&rp_id_hash);

    let namespace = namespace_key(seed)?;
    let handle_key = namespace.child(ChildNumber::hardened_from_u32(0)?)?;
    let tag = HMAC::hmac_sha512(&handle_key.secret_key, &id[..TAG_OFFSET])?;
    id[TAG_OFFSET..].copy_from_slice(&tag[..CREDENTIAL_ID_SIZE - TAG_OFFSET]);

    let key_root = namespace.child(ChildNumber::hardened_from_u32(1)?)?;
    let key = derive_identity(key_root, &identity(nonce, &rp_id_hash)?)?;

    Ok(Credential {
        id,
        public_key: P256::export_pk(&key.secret_key)?,
    })
}

pub fn sign(
    seed: &[u8],
    credential_id: &[u8],
    rp_id_hash: &[u8],
    hash: &[u8],
) -> Result<heapless::Vec<u8, 72>> {
    let key_root = authenticate(seed, credential_id, rp_id_hash)?;
    let key = derive_identity(
        key_root,
        &identity(
            credential_id[NONCE_OFFSET..RP_ID_HASH_OFFSET].try_into()?,
            rp_id_hash.try_into()?,
        )?,
    )?;
    if hash.len() != 32 {
        bail!("Invalid FIDO2 signing hash");
    }
    P256::sign(&key.secret_key, hash)
}

pub fn validate(seed: &[u8], credential_id: &[u8], rp_id_hash: &[u8]) -> Result<()> {
    authenticate(seed, credential_id, rp_id_hash).map(|_| ())
}

fn authenticate(seed: &[u8], credential_id: &[u8], rp_id_hash: &[u8]) -> Result<ExtendedPrivKey> {
    if credential_id.len() != CREDENTIAL_ID_SIZE
        || rp_id_hash.len() != 32
        || credential_id[0] != VERSION
        || credential_id[RP_ID_HASH_OFFSET..TAG_OFFSET] != *rp_id_hash
    {
        bail!("Invalid FIDO2 credential");
    }

    let namespace = namespace_key(seed)?;
    let handle_key = namespace.child(ChildNumber::hardened_from_u32(0)?)?;
    let expected = HMAC::hmac_sha512(&handle_key.secret_key, &credential_id[..TAG_OFFSET])?;
    let valid = expected[..CREDENTIAL_ID_SIZE - TAG_OFFSET]
        .iter()
        .zip(&credential_id[TAG_OFFSET..])
        .fold(0, |difference, (a, b)| difference | (a ^ b))
        == 0;
    if !valid {
        bail!("Invalid FIDO2 credential tag");
    }

    namespace.child(ChildNumber::hardened_from_u32(1)?)
}

fn namespace_key(seed: &[u8]) -> Result<ExtendedPrivKey> {
    ExtendedPrivKey::derive(seed, "m/13'".parse::<DerivationPath>()?, Curve::P256)?
        .child(ChildNumber::hardened_from_u32(FIDO_NAMESPACE)?)
}

fn identity(nonce: &[u8; NONCE_SIZE], rp_id_hash: &[u8; 32]) -> Result<[u8; 32]> {
    let mut data = [0; NONCE_SIZE + 32];
    data[..NONCE_SIZE].copy_from_slice(nonce);
    data[NONCE_SIZE..].copy_from_slice(rp_id_hash);
    Hash::sha256(&data)
}

fn derive_identity(mut key: ExtendedPrivKey, identity: &[u8; 32]) -> Result<ExtendedPrivKey> {
    for component in identity[..16].chunks_exact(4) {
        key = key.child(ChildNumber::hardened_from_u32(
            u32::from_le_bytes(component.try_into()?) & 0x7fff_ffff,
        )?)?;
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 64] = [7; 64];
    const NONCE: [u8; NONCE_SIZE] = [11; NONCE_SIZE];

    #[test]
    fn credential_matches_recovery_vector() {
        let credential = create(&SEED, "ssh:", &NONCE).unwrap();

        assert_eq!(
            hex::encode(credential.id),
            "020b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0be30610e8a162115960fe1ec223e652\
             9c9f4b6e80200dcb5e5c321c8af1e2b1bf0318a6710fc1996476851578977613"
        );
        assert_eq!(
            hex::encode(credential.public_key),
            "04cf46efbc23425ea0d4d9ea62ae572f50e28fa6b3c36f56e33cb99f71299c046\
             dd6f314c1212464347340d961bc2c7c53b1e8f97ae9266efdb8056fd712afc3dd"
        );
    }

    #[test]
    fn credential_is_bound_to_relying_party() {
        let mut credential = create(&SEED, "ssh:", &NONCE).unwrap();
        let hash = [3; 32];

        assert!(sign(
            &SEED,
            &credential.id,
            &Hash::sha256(b"ssh:").unwrap(),
            &hash
        )
        .is_ok());
        assert!(sign(
            &SEED,
            &credential.id,
            &Hash::sha256(b"example.com").unwrap(),
            &hash
        )
        .is_err());

        let mut altered_nonce = credential.id;
        altered_nonce[NONCE_OFFSET] ^= 1;
        assert!(validate(&SEED, &altered_nonce, &Hash::sha256(b"ssh:").unwrap()).is_err());

        credential.id[CREDENTIAL_ID_SIZE - 1] ^= 1;
        assert!(sign(
            &SEED,
            &credential.id,
            &Hash::sha256(b"ssh:").unwrap(),
            &hash
        )
        .is_err());
    }

    #[test]
    fn each_registration_creates_a_new_key() {
        let first = create(&SEED, "ssh:", &[1; NONCE_SIZE]).unwrap();
        let second = create(&SEED, "ssh:", &[2; NONCE_SIZE]).unwrap();

        assert_ne!(first.id, second.id);
        assert_ne!(first.public_key, second.public_key);
    }

    #[test]
    fn credential_is_bound_to_seed() {
        let credential = create(&SEED, "ssh:", &NONCE).unwrap();
        let mut other_seed = SEED;
        other_seed[0] ^= 1;

        assert!(validate(&other_seed, &credential.id, &Hash::sha256(b"ssh:").unwrap()).is_err());
    }
}
