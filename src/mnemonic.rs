use anyhow::{anyhow, bail, Result};
use bitvec::{field::BitField, order::Msb0, vec::BitVec};
use core::fmt::Write;
use heapless::{String, Vec};

use crate::alg::crypto::{Hash, PBKDF2};
use crate::alg::ENGLISH_WORDS;

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mnemonic {
    pub words: Vec<&'static str, 24>,
}

impl Mnemonic {
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let original_words: Vec<&str, 24> = phrase.trim().split_whitespace().collect();
        let original_bits = Self::words_to_bits(&original_words)?;

        let entropy = Self::bits_to_entropy(&original_bits)?;
        let rebuilt_bits = Self::entropy_with_checksum(&entropy)?;

        if original_bits != rebuilt_bits {
            bail!("Checksum mismatch")
        }

        let mnemonic = Self::bits_to_words(&original_bits)?;

        Ok(Self { words: mnemonic })
    }

    pub fn from_entropy(entropy: &[u8]) -> Result<Self, anyhow::Error> {
        let full_bits = Self::entropy_with_checksum(entropy)?;
        let mnemonic = Self::bits_to_words(&full_bits)?;

        Ok(Self { words: mnemonic })
    }

    pub fn to_seed(&self, salt: &str) -> Result<[u8; 64]> {
        let mut new_salt = String::<256>::new();
        write!(new_salt, "mnemonic{}", salt)?;

        PBKDF2::hmac_sha512(self.words.join(" ").as_str(), new_salt.as_str(), 2048)
    }

    fn entropy_with_checksum(entropy: &[u8]) -> Result<BitVec<u8, Msb0>> {
        let entropy_len = entropy.len() * 8;

        if !(128..=256).contains(&entropy_len) || entropy_len % 32 != 0 {
            bail!("Invalid entropy length")
        }

        let entropy_len = entropy.len() * 8;
        let checksum_len = entropy_len / 32;

        let mut full_bits = BitVec::new();
        full_bits.extend_from_raw_slice(entropy);

        let hash = Hash::sha256(entropy)?;
        full_bits.extend_from_raw_slice(&hash[..1]);
        full_bits.truncate(entropy_len + checksum_len);

        Ok(full_bits)
    }

    fn bits_to_words(bits: &BitVec<u8, Msb0>) -> Result<Vec<&'static str, 24>> {
        let mut words = Vec::new();

        for index_bits in bits.chunks(11) {
            let index = index_bits.load_be::<u16>() as usize;
            words.push(ENGLISH_WORDS[index]).map_err(|e| anyhow!(e))?;
        }

        Ok(words)
    }

    fn words_to_bits(words: &[&str]) -> Result<BitVec<u8, Msb0>> {
        let word_count = words.len();

        if !(12..=24).contains(&word_count) || word_count % 3 != 0 {
            bail!("Invalid entropy length")
        }

        let mut bits: BitVec<u8, Msb0> = BitVec::new();

        for word in words.iter() {
            let idx = ENGLISH_WORDS
                .iter()
                .position(|&w| w == *word)
                .ok_or_else(|| anyhow!("Invalid word"))?;

            for i in (0..11).rev() {
                bits.push(idx & (1 << i) != 0);
            }
        }

        Ok(bits)
    }

    fn bits_to_entropy(full_bits: &BitVec<u8, Msb0>) -> Result<Vec<u8, 32>> {
        let entropy_len = full_bits.len() * 32 / 33;
        let mut entropy_bytes = Vec::new();

        for chunk in full_bits[..entropy_len].chunks(8) {
            entropy_bytes
                .push(chunk.load_be())
                .map_err(|_| anyhow!("Entropy conversion failed"))?;
        }

        Ok(entropy_bytes)
    }
}

#[cfg(test)]
mod test {
    extern crate alloc;

    use super::*;
    use alloc::{vec, vec::Vec};

    pub fn get_test_vector() -> Vec<[&'static str; 4]> {
        let test_vectors = vec![
            [
                "00000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "770e09af824d04ad3d583c8868b67ae4ca116f830c72b7e12f0b5c6767c06dca97f46950720b223ab1fef5ba7a2bcb4e9a0e8e796f355ae53fdef5fc7a68b03c",
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                "260f8ffc086847cbb43961f2a890834d7245dd161a807645e319558c16ded1955832604f5e75fedf4ffc9be939aae5308cba8a857c3d54bb62c5355321dc1970",
                "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
            ],
            [
                "80808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
                "00990dad85a86ede6f9e89bf6fd376aa8e64be972a42640a5e63aeada6a1068bab4b0149995470417a9360702e1fc10e5643698e9ccbcebce8f5bb813a6b2569",
                "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
            ],
            [
                "ffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
                "f7ad4c3373f8af293426dbccc1ccf3bb3c8f1d32d13ca0001c018a00df4e00be77a5df53ab4775e174fe134396a7209a6d0e67f4839be64e1f9956a2d97dfb64",
                "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
            ],
            [
                "000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
                "d10feed113c1b43b95a97a3b9231dc00860e55a30ee34c6f4c109a80ecfad689892b63502740575c564d356aba87b0b1117674291c4277b8aa40a29d7f5f8599",
                "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
                "0fc98604818138badd49f58135e3168ea612f756844eed15619b920de1037250554166e8bb39c27afa1956c4599557dc68f7dfa7821111308824a72ccd6a0084",
                "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
            ],
            [
                "808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
                "5fcc074349e39e1cf6d84e1717994d279c7c400a4db3fc1489aeeed343f5374d9319dae1c01093181cc2d8330eb174246e1ccd462840861ad83c1fa4a5cd47ec",
                "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
            ],
            [
                "ffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
                "a857e4fd702a64fd713768c41785ce33815deba5fbdbe85da8f86dc15159870d796c06146bf5b2bb291f041da9422f21b7475cb74d7547ef874c688d6cb7c373",
                "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",

            ],
            [
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
                "cfead91a10563da552a21b93a729c4aa3e87a0f627d01f2fcd54e4661b421ba6c63d6c21f01237a51385ded1ad86dd28d4d102dba8acd6fa169e6638e8323b11",
                "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
                "8d99b66bd7e2dcce42866803aa22f91268d6bb4ca6d97061e4822e9b32cfa57c8ba8c8ae49e7df687885169ea8ccb976ba5bd9fc8f20105addc8753763303e40",
                "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",

            ],
            [
                "8080808080808080808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
                "33515e664acd79a8a239a3dae48743cde7e31195f8aa6cf5e1aa377747530cfacee3c33f6d5f852df257b0cb619425f98d80b10ce2fd6c93ed944cef8637bd86",
                "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
            ],
            [
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
                "ed8072be6fd242988b77a315485bfde849929560754b63ed49e68ffd5435aeece0abb300f0c99fa4a06a05c2a9fb987846695fb4f00254e0d6d47ccd6fdec99b",
                "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
            ],
            [
                "9e885d952ad362caeb4efe34a8e91bd2",
                "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
                "34f4012d3ac6eea08ea53cc7ba1da6aeb52680ea30f341a978568706ccb46f3b49e9fb4d456b87f05529fb39e78157c2f7d053d4652a0fceaa8a003451e2a854",
                "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
            ],
            [
                "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
                "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
                "273ed5b264d3b7b84bf3acb2ebab77e80b23cd9a504bb26560b9a52e86c3ae6f7252d06a24716a8273fc1f7aa06a63e66821824a897ac4dedbb0b0111b1ad99d",
                "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
            ],
            [
                "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
                "9b1c768f800a57fbad3a4fc88b57695b80531edc9843558fa7c50f9f4ac5062818591b4fbb0e85c8ea792b4c4c5719e98ff3e3c86c529b5d895bd84e2ab56f3a",
                "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
            ],
            [
                "c0ba5a8e914111210f2bd131f3d5e08d",
                "scheme spot photo card baby mountain device kick cradle pact join borrow",
                "7f2cda929cc57046b2b1e7255d4a2505b09e97c9c1b2a1bf6c798abab7f66c421a14ac71c4941f545ab8636f41ed4dae857f019d1efc468b7d4d2acfef993ad0",
                "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
            ],
            [
                "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
                "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
                "59021201a4df583ce172d7d2db4604d19615d59e9c8de93b601ec682151b5c7d0018dbbc157f9a9ed40b14c0dd8cbb11764de6a2a7c0cc39e931fcf2e3185a11",
                "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
            ],
            [
                "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
                "763e829277008971f6b8dbcde544c09490ef058b7c97eee390cee27c4a675e1bf55908a78edb4daa9dcf5aafe38578f6ffdf3850ea475aed4abd798cbb03fd4d",
                "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
            ],
            [
                "23db8160a31d3e0dca3688ed941adbf3",
                "cat swing flag economy stadium alone churn speed unique patch report train",
                "038bb8daef865058f805967d54be4f0592e564a16f21fcdf6ba181f7ddc7c6cd5e5f7de5506cc7ef50db16779304e261f36ae6333f9a937b78391aab4e3bcc77",
                "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
            ],
            [
                "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
                "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
                "86c1e02718af391cdfdf7ad147742102d894d78a8a01cf176bb9862e45bf81abb369b0c5f4ed194d04d0aee6e172f588687e527e087b504e2f13e1eebbbad330",
                "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
            ],
            [
                "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
                "629a0f2b8bbd8b832ce21a03be3793885d1b56b62d34414a8223687a3b6ae661d72e681028169b8703ec6ba323add78c6f258672bc62ea8f30887363bcf36818",
                "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
            ],
            [
                "f30f8c1da665478f49b001d94c5fc452",
                "vessel ladder alter error federal sibling chat ability sun glass valve picture",
                "d8984bc70aab5ec99552d14d5518ae8620cbd52e50e4a1311453a70113cab8882bb58c20189751e452530ffea1547c2e64e1655f71ce565980b195cbc303a055",
                "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
            ],
            [
                "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
                "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
                "18766d857a5f020712b6f6b22db219acbd8cdaa706f5149610a604b093d6b539e71cbf5df7667ae50864d1d89b8c415dbd4f495acae4da1e10ee257a79712764",
                "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
            ],
            [
                "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
                "ad341aaf2d13773021d07f9f755a54c87a13569058a070979e58c17c090ecc2f8152227ae75a0a9f50766f030c84d5c7a860d64b421bafeeba36a6c572c1aeb0",
                "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
            ]
        ];
        return test_vectors;
    }

    #[test]
    pub fn test_mnemonic_from_entropy() {
        let test_vectors = get_test_vector();

        for case in &test_vectors {
            let entropy = hex::decode(case[0]).unwrap();
            let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
            assert!(mnemonic.words.join(" ").as_str().eq(case[1]));
        }
    }

    #[test]
    pub fn test_mnemonic_from_phrase() {
        let test_vectors = get_test_vector();

        for case in &test_vectors {
            let mnemonic = Mnemonic::from_phrase(case[1]).unwrap();
            assert!(mnemonic.words.join(" ").as_str().eq(case[1]));
        }
    }

    #[test]
    pub fn test_mnemonic_to_seed() {
        let test_vectors = get_test_vector();

        for case in &test_vectors {
            let mnemonic = Mnemonic::from_phrase(case[1]).unwrap();
            let seed = mnemonic.to_seed("OHW").unwrap();
            assert_eq!(hex::encode(seed.clone()), case[2]);

            let mnemonic = Mnemonic::from_phrase(case[1]).unwrap();
            let seed = mnemonic.to_seed("TREZOR").unwrap();
            assert_eq!(hex::encode(seed), case[3]);
        }
    }

    #[test]
    pub fn test_mnemonic_verify_invalid() {
        let test_invalid_vectors = vec![
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about abandon",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
        ];

        for case in &test_invalid_vectors {
            let mnemonic = Mnemonic::from_phrase(case);
            assert!(mnemonic.is_err());
        }
    }
}
