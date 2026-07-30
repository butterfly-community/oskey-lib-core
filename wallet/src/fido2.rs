use crate::alg::crypto::{Hash, HMAC, P256};
use crate::path::{ChildNumber, DerivationPath};
use crate::wallets::{Curve, ExtendedPrivKey};
use anyhow::{bail, Result};

pub const CREDENTIAL_ID_SIZE: usize = 64;

const VERSION: u8 = 1;
const IDENTITY_OFFSET: usize = 1;
const IDENTITY_SIZE: usize = 16;
const RP_ID_HASH_OFFSET: usize = IDENTITY_OFFSET + IDENTITY_SIZE;
const TAG_OFFSET: usize = RP_ID_HASH_OFFSET + 32;

pub struct Credential {
    pub id: [u8; CREDENTIAL_ID_SIZE],
    pub public_key: [u8; 65],
}

pub fn create(seed: &[u8], rp_id: &str, user_id: &[u8]) -> Result<Credential> {
    let user_hash = Hash::sha256(user_id)?;
    let rp_id_hash = Hash::sha256(rp_id.as_bytes())?;
    let mut identity = [0; 64];
    identity[..32].copy_from_slice(&rp_id_hash);
    identity[32..].copy_from_slice(&user_hash);
    let identity = Hash::sha256(&identity)?;

    let mut id = [0; CREDENTIAL_ID_SIZE];
    id[0] = VERSION;
    id[IDENTITY_OFFSET..RP_ID_HASH_OFFSET].copy_from_slice(&identity[..IDENTITY_SIZE]);
    id[RP_ID_HASH_OFFSET..TAG_OFFSET].copy_from_slice(&rp_id_hash);

    let purpose = purpose_key(seed)?;
    let tag = HMAC::hmac_sha512(&purpose.chain_code, &id[..TAG_OFFSET])?;
    id[TAG_OFFSET..].copy_from_slice(&tag[..CREDENTIAL_ID_SIZE - TAG_OFFSET]);
    let key = derive_identity(purpose, &identity[..IDENTITY_SIZE])?;

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
    let purpose = authenticate(seed, credential_id, rp_id_hash)?;
    let key = derive_identity(purpose, &credential_id[IDENTITY_OFFSET..RP_ID_HASH_OFFSET])?;
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

    let purpose = purpose_key(seed)?;
    let expected = HMAC::hmac_sha512(&purpose.chain_code, &credential_id[..TAG_OFFSET])?;
    let valid = expected[..CREDENTIAL_ID_SIZE - TAG_OFFSET]
        .iter()
        .zip(&credential_id[TAG_OFFSET..])
        .fold(0, |difference, (a, b)| difference | (a ^ b))
        == 0;
    if !valid {
        bail!("Invalid FIDO2 credential tag");
    }

    Ok(purpose)
}

fn purpose_key(seed: &[u8]) -> Result<ExtendedPrivKey> {
    ExtendedPrivKey::derive(seed, "m/13'".parse::<DerivationPath>()?, Curve::P256)
}

fn derive_identity(mut key: ExtendedPrivKey, identity: &[u8]) -> Result<ExtendedPrivKey> {
    for component in identity.chunks_exact(2) {
        key = key.child(ChildNumber::hardened_from_u32(
            u16::from_le_bytes(component.try_into()?) as u32,
        )?)?;
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 64] = [7; 64];

    #[test]
    fn credential_matches_recovery_vector() {
        let credential = create(&SEED, "ssh:", b"oskey").unwrap();

        assert_eq!(
            hex::encode(credential.id),
            "0199a9c544bc6953a0b3088807cd9c8500e30610e8a162115960fe1ec223e652\
             9c9f4b6e80200dcb5e5c321c8af1e2b1bf62c28d79735a5dd54f0e86112d2e80"
        );
        assert_eq!(
            hex::encode(credential.public_key),
            "042486df6e38f74ccf55afd17bae161fef549101821476961064d8360df6fe110\
             d8482e77bc45b2b902884c419758921164716b9c3e12221eca5acc6d829e63e82"
        );
    }

    #[test]
    fn credential_is_bound_to_relying_party() {
        let mut credential = create(&SEED, "ssh:", b"oskey").unwrap();
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
    fn credential_path_changes_with_user() {
        let first = create(&SEED, "ssh:", b"first").unwrap();
        let second = create(&SEED, "ssh:", b"second").unwrap();

        assert_ne!(first.id, second.id);
        assert_ne!(first.public_key, second.public_key);
    }

    #[test]
    fn credential_uses_more_than_the_user_hash_prefix() {
        let first = create(&SEED, "ssh:", b"user-20491").unwrap();
        let second = create(&SEED, "ssh:", b"user-32057").unwrap();

        assert_eq!(
            &Hash::sha256(b"user-20491").unwrap()[..4],
            &Hash::sha256(b"user-32057").unwrap()[..4]
        );
        assert_ne!(first.id, second.id);
        assert_ne!(first.public_key, second.public_key);
    }
}
