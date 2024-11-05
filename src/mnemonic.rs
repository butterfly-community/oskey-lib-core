use anyhow::{anyhow, bail, Result};
use bitvec::{field::BitField, order::Msb0, vec::BitVec};
use core::fmt::Write;
use heapless::{String, Vec};

use crate::crypto::{Hash, PBKDF2};
use crate::data::ENGLISH_WORDS;

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mnemonic {
    entropy: BitVec<u8, Msb0>,
    words: Vec<&'static str, 24>,
}

impl Mnemonic {
    pub fn from(entropy: &[u8]) -> Result<Self, anyhow::Error> {
        // Calculate entropy length in bits
        // 1 byte = 8 bits
        let entropy_len = entropy.len() * 8;
        if !(128..=256).contains(&entropy_len) || entropy_len % 32 != 0 {
            bail!("Invalid entropy length")
        }

        // Convert entropy bytes to bits sequence
        let mut entropy_bits = BitVec::new();
        entropy_bits.extend_from_raw_slice(entropy);

        // Calculate SHA256 hash of entropy
        let hash = Hash::sha256(entropy)?;
        // ENT / 32, where ENT is entropy length in bits
        let checksum_len = entropy_len / 32;

        // Combine entropy bits with checksum
        let mut full_bits = entropy_bits.clone();
        // Add first byte of hash as checksum
        full_bits.extend_from_raw_slice(&hash[..1]);
        // Truncate to required length
        full_bits.truncate(entropy_len + checksum_len);

        // Generate mnemonic words
        let mut mnemonic = Vec::new();
        // Split bits into 11-bit chunks
        // Each 11-bit chunk maps to one word
        for index_bits in full_bits.chunks(11) {
            let index = index_bits.load_be::<u16>() as usize;
            // Get word from words
            mnemonic
                .push(ENGLISH_WORDS[index])
                .map_err(|e| anyhow!(e))?;
        }

        // Return mnemonic structure
        Ok(Self {
            entropy: entropy_bits,
            words: mnemonic,
        })
    }

    pub fn verify(phrase: &str) -> Result<Self> {
        // Split the phrase into words and collect
        let words: Vec<&str, 24> = phrase.trim().split_whitespace().collect();

        // Check if word count is valid
        let word_count = words.len();
        if !(12..=24).contains(&word_count) || word_count % 3 != 0 {
            bail!("Invalid entropy length")
        }

        // Create a bit vector to store binary representation of indices
        let mut bits: BitVec<u8, Msb0> = BitVec::new();
        // Convert each word to its index in the wordlist
        for word in words.iter() {
            // Find the word's index in ENGLISH_WORDS
            let idx = ENGLISH_WORDS
                .iter()
                .position(|&w| w == *word)
                .ok_or_else(|| anyhow!("Invalid word"))?;

            // Convert index to 11 bits (big-endian) and add to bit vector
            for i in (0..11).rev() {
                bits.push(idx & (1 << i) != 0);
            }
        }

        // Calculate entropy bits (total bits minus checksum bits)
        let entropy_bits = word_count * 11 - word_count / 3;
        // Create vector to store entropy bytes
        let mut entropy_bytes: Vec<u8, 32> = Vec::new();

        // Convert bits to bytes
        for chunk in bits[..entropy_bits].chunks(8) {
            entropy_bytes
                .push(chunk.load_be())
                .map_err(|_| anyhow!("Entropy conversion failed"))?;
        }

        // Generate mnemonic from entropy and verify it matches input
        let mnemonic = Self::from(&entropy_bytes)?;
        if mnemonic.words.as_slice() != words.as_slice() {
            bail!("Checksum mismatch");
        }
        Ok(mnemonic)
    }

    pub fn to_seed(&self, salt: &str) -> Result<[u8; 64]> {
        let mut new_salt = String::<256>::new();
        write!(new_salt, "mnemonic{}", salt)?;

        PBKDF2::hmac_sha512(self.words.join(" ").as_str(), new_salt.as_str(), 2048)
    }
}

#[cfg(test)]
mod test {
    extern crate alloc;
    use super::*;
    use alloc::{vec, vec::Vec};

    pub fn get_test_case() -> Vec<[&'static str; 3]> {
        let test_vectors = vec![
            [
                "00000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "770e09af824d04ad3d583c8868b67ae4ca116f830c72b7e12f0b5c6767c06dca97f46950720b223ab1fef5ba7a2bcb4e9a0e8e796f355ae53fdef5fc7a68b03c"
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                "260f8ffc086847cbb43961f2a890834d7245dd161a807645e319558c16ded1955832604f5e75fedf4ffc9be939aae5308cba8a857c3d54bb62c5355321dc1970"
            ],
            [
                "80808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
                "00990dad85a86ede6f9e89bf6fd376aa8e64be972a42640a5e63aeada6a1068bab4b0149995470417a9360702e1fc10e5643698e9ccbcebce8f5bb813a6b2569"
            ],
            [
                "ffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
                "f7ad4c3373f8af293426dbccc1ccf3bb3c8f1d32d13ca0001c018a00df4e00be77a5df53ab4775e174fe134396a7209a6d0e67f4839be64e1f9956a2d97dfb64"
            ],
            [
                "000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
                "d10feed113c1b43b95a97a3b9231dc00860e55a30ee34c6f4c109a80ecfad689892b63502740575c564d356aba87b0b1117674291c4277b8aa40a29d7f5f8599"
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
                "0fc98604818138badd49f58135e3168ea612f756844eed15619b920de1037250554166e8bb39c27afa1956c4599557dc68f7dfa7821111308824a72ccd6a0084"
            ],
            [
                "808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
                "5fcc074349e39e1cf6d84e1717994d279c7c400a4db3fc1489aeeed343f5374d9319dae1c01093181cc2d8330eb174246e1ccd462840861ad83c1fa4a5cd47ec"
            ],
            [
                "ffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
                "a857e4fd702a64fd713768c41785ce33815deba5fbdbe85da8f86dc15159870d796c06146bf5b2bb291f041da9422f21b7475cb74d7547ef874c688d6cb7c373"
            ],
            [
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
                "cfead91a10563da552a21b93a729c4aa3e87a0f627d01f2fcd54e4661b421ba6c63d6c21f01237a51385ded1ad86dd28d4d102dba8acd6fa169e6638e8323b11"
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
                "8d99b66bd7e2dcce42866803aa22f91268d6bb4ca6d97061e4822e9b32cfa57c8ba8c8ae49e7df687885169ea8ccb976ba5bd9fc8f20105addc8753763303e40"
            ],
            [
                "8080808080808080808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
                "33515e664acd79a8a239a3dae48743cde7e31195f8aa6cf5e1aa377747530cfacee3c33f6d5f852df257b0cb619425f98d80b10ce2fd6c93ed944cef8637bd86"
            ],
            [
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
                "ed8072be6fd242988b77a315485bfde849929560754b63ed49e68ffd5435aeece0abb300f0c99fa4a06a05c2a9fb987846695fb4f00254e0d6d47ccd6fdec99b"
            ],
            [
                "9e885d952ad362caeb4efe34a8e91bd2",
                "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
                "34f4012d3ac6eea08ea53cc7ba1da6aeb52680ea30f341a978568706ccb46f3b49e9fb4d456b87f05529fb39e78157c2f7d053d4652a0fceaa8a003451e2a854"
            ],
            [
                "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
                "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
                "273ed5b264d3b7b84bf3acb2ebab77e80b23cd9a504bb26560b9a52e86c3ae6f7252d06a24716a8273fc1f7aa06a63e66821824a897ac4dedbb0b0111b1ad99d"
            ],
            [
                "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
                "9b1c768f800a57fbad3a4fc88b57695b80531edc9843558fa7c50f9f4ac5062818591b4fbb0e85c8ea792b4c4c5719e98ff3e3c86c529b5d895bd84e2ab56f3a"
            ],
            [
                "c0ba5a8e914111210f2bd131f3d5e08d",
                "scheme spot photo card baby mountain device kick cradle pact join borrow",
                "7f2cda929cc57046b2b1e7255d4a2505b09e97c9c1b2a1bf6c798abab7f66c421a14ac71c4941f545ab8636f41ed4dae857f019d1efc468b7d4d2acfef993ad0"
            ],
            [
                "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
                "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
                "59021201a4df583ce172d7d2db4604d19615d59e9c8de93b601ec682151b5c7d0018dbbc157f9a9ed40b14c0dd8cbb11764de6a2a7c0cc39e931fcf2e3185a11"
            ],
            [
                "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
                "763e829277008971f6b8dbcde544c09490ef058b7c97eee390cee27c4a675e1bf55908a78edb4daa9dcf5aafe38578f6ffdf3850ea475aed4abd798cbb03fd4d"
            ],
            [
                "23db8160a31d3e0dca3688ed941adbf3",
                "cat swing flag economy stadium alone churn speed unique patch report train",
                "038bb8daef865058f805967d54be4f0592e564a16f21fcdf6ba181f7ddc7c6cd5e5f7de5506cc7ef50db16779304e261f36ae6333f9a937b78391aab4e3bcc77"
            ],
            [
                "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
                "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
                "86c1e02718af391cdfdf7ad147742102d894d78a8a01cf176bb9862e45bf81abb369b0c5f4ed194d04d0aee6e172f588687e527e087b504e2f13e1eebbbad330"
            ],
            [
                "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
                "629a0f2b8bbd8b832ce21a03be3793885d1b56b62d34414a8223687a3b6ae661d72e681028169b8703ec6ba323add78c6f258672bc62ea8f30887363bcf36818"
            ],
            [
                "f30f8c1da665478f49b001d94c5fc452",
                "vessel ladder alter error federal sibling chat ability sun glass valve picture",
                "d8984bc70aab5ec99552d14d5518ae8620cbd52e50e4a1311453a70113cab8882bb58c20189751e452530ffea1547c2e64e1655f71ce565980b195cbc303a055"
            ],
            [
                "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
                "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
                "18766d857a5f020712b6f6b22db219acbd8cdaa706f5149610a604b093d6b539e71cbf5df7667ae50864d1d89b8c415dbd4f495acae4da1e10ee257a79712764"
            ],
            [
                "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
                "ad341aaf2d13773021d07f9f755a54c87a13569058a070979e58c17c090ecc2f8152227ae75a0a9f50766f030c84d5c7a860d64b421bafeeba36a6c572c1aeb0"
            ]
        ];
        return test_vectors;
    }

    #[test]
    pub fn test_mnemonic_from() {
        let test_vectors = get_test_case();

        for case in &test_vectors {
            let entropy = hex::decode(case[0]).unwrap();
            let mnemonic = Mnemonic::from(&entropy).unwrap();
            assert!(mnemonic.words.join(" ").as_str().eq(case[1]));
        }
    }

    #[test]
    pub fn test_mnemonic_verify() {
        let test_vectors = get_test_case();

        for case in &test_vectors {
            let mnemonic = Mnemonic::verify(case[1]).unwrap();
            assert!(mnemonic.words.join(" ").as_str().eq(case[1]));
            assert_eq!(hex::encode(mnemonic.entropy.as_raw_slice()), case[0]);
        }
    }

    #[test]
    pub fn test_mnemonic_to_seed() {
        let test_vectors = get_test_case();

        for case in &test_vectors {
            let mnemonic = Mnemonic::verify(case[1]).unwrap();
            let seed = mnemonic.to_seed("OHW").unwrap();
            assert_eq!(hex::encode(seed), case[2])
        }
    }
}
