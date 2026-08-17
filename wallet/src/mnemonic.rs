use alloc::vec::Vec;
use anyhow::{anyhow, bail, Result};
use bit_vec::BitVec;
use zeroize::Zeroizing;

use crate::alg::crypto::{Hash, PBKDF2};
use crate::alg::word_list::ENGLISH_WORDS;

pub struct Mnemonic {
    pub words: Vec<&'static str>,
}

impl Mnemonic {
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let mut original_words = Vec::with_capacity(24);
        for word in phrase.split_whitespace() {
            if original_words.len() == 24 {
                bail!("Invalid entropy length");
            }
            original_words.push(word);
        }
        let original_bits = Self::words_to_bits(&original_words)?;

        let entropy = Self::bits_to_entropy(&original_bits)?;
        let rebuilt_bits = Self::entropy_to_bits(&entropy)?;

        if original_bits != rebuilt_bits {
            bail!("Checksum mismatch")
        }

        let mnemonic = Self::bits_to_words(&original_bits)?;

        Ok(Self { words: mnemonic })
    }

    pub fn from_entropy(entropy: &[u8]) -> Result<Self, anyhow::Error> {
        let full_bits = Self::entropy_to_bits(entropy)?;
        let mnemonic = Self::bits_to_words(&full_bits)?;

        Ok(Self { words: mnemonic })
    }

    pub fn to_seed(&self, salt: &str) -> Result<[u8; 64]> {
        const PREFIX: &[u8] = b"mnemonic";
        if PREFIX.len() + salt.len() > 256 {
            bail!("Mnemonic salt is too long")
        }

        let mut salt_bytes = Zeroizing::new([0; 256]);
        salt_bytes[..PREFIX.len()].copy_from_slice(PREFIX);
        salt_bytes[PREFIX.len()..PREFIX.len() + salt.len()].copy_from_slice(salt.as_bytes());
        let new_salt = core::str::from_utf8(&salt_bytes[..PREFIX.len() + salt.len()])?;
        let phrase = Zeroizing::new(self.words.join(" "));

        PBKDF2::hmac_sha512(phrase.as_str(), new_salt, 2048)
    }

    fn entropy_to_bits(entropy: &[u8]) -> Result<BitVec> {
        let entropy_len = entropy.len() * 8;

        if !(128..=256).contains(&entropy_len) || !entropy_len.is_multiple_of(32) {
            bail!("Invalid entropy length")
        }

        let checksum_len = entropy_len / 32;

        let mut full_bits = BitVec::with_capacity(entropy_len + checksum_len);

        for byte in entropy {
            for i in (0..8).rev() {
                full_bits.push((byte & (1 << i)) != 0);
            }
        }

        let hash = Hash::sha256(entropy)?;
        let checksum_byte = hash[0];
        for i in 0..checksum_len {
            full_bits.push((checksum_byte & (1 << (7 - i))) != 0);
        }

        Ok(full_bits)
    }

    fn bits_to_words(bits: &BitVec) -> Result<Vec<&'static str>> {
        let total_bits = bits.len();
        let word_count = total_bits.div_ceil(11);
        if word_count > 24 {
            bail!("Invalid entropy length");
        }
        let mut words = Vec::with_capacity(word_count);

        for word_idx in (0..total_bits).step_by(11) {
            let index = Self::load_bits_be(bits, word_idx, 11);
            words.push(ENGLISH_WORDS[index as usize]);
        }

        Ok(words)
    }

    fn words_to_bits(words: &[&str]) -> Result<BitVec> {
        let word_count = words.len();

        if !(12..=24).contains(&word_count) || !word_count.is_multiple_of(3) {
            bail!("Invalid entropy length")
        }
        let mut bits = BitVec::with_capacity(word_count * 11);

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

    fn bits_to_entropy(full_bits: &BitVec) -> Result<Vec<u8>> {
        let entropy_len = full_bits.len() * 32 / 33;
        if entropy_len > 256 {
            bail!("Invalid entropy length");
        }
        let mut entropy_bytes = Vec::with_capacity(entropy_len.div_ceil(8));

        for byte_idx in (0..entropy_len).step_by(8) {
            let byte = Self::load_bits_be(full_bits, byte_idx, 8) as u8;
            entropy_bytes.push(byte);
        }

        Ok(entropy_bytes)
    }

    fn load_bits_be(bits: &BitVec, start: usize, bit_count: usize) -> u16 {
        let mut value = 0u16;
        for i in 0..bit_count {
            if start + i >= bits.len() {
                break;
            }
            if bits[start + i] {
                value |= 1 << (bit_count - 1 - i);
            }
        }
        value
    }
}

#[cfg(test)]
mod test {
    extern crate alloc;

    use super::*;
    use alloc::{string::ToString, vec, vec::Vec};

    pub fn get_test_vector() -> Vec<[&'static str; 4]> {
        let test_vectors = vec![
            [
                "00000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "1088aeb07659767fe3b96ec9826c8288d17fd6475e1f131f0bcfc082bcf02cf8df29e49e527cb8bd8cbfbc859fd16eb10a99d78511b870a2b87379e32a08b6fe",
                "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
                "5e7aeb17c993cf484e4016a10df4d5de16d53602eddfeea1bb3c591e86d5c85a666ed02f95e4d0208c2bcc494b73e58f6f5934feff90dbe360484bf62f8d63c8",
                "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
            ],
            [
                "80808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
                "65ffe8e89342c31852ad73c59df6b8aef40e7935dffd887189d2565413a9defd2d7b3de8efb508eab61836b7e8a7fc291f0b41ff1f27dc5f7abc4a96ec01ba09",
                "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
            ],
            [
                "ffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
                "311b41cdbddf9685d235fe0b41c2fe799bf7bbdc267e1db70760bb35cfa95279fd9e1f2c43ea240a5c922f5640d3876ad22ba3cb0df1647305ce47952c54f5ca",
                "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
            ],
            [
                "000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
                "f0bed05c18e2c05838160c61de58db4d968e37d53e32d07a3cea29fc26f99352076d9b8c882ef295b8ba6c54da59fb6a34eaaeee9ed5bb1a8c4650d9cbd067eb",
                "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
                "8c02acc083d57dd6026aacbefa6f709fcbc3fe94d2468aad80d3aadc4f6bc1d49c3134e04314b9d1d9d0f2a69bf0736e983ab59fc5356b8c8079acf331320b02",
                "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
            ],
            [
                "808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
                "2b45a6d9360edf5edf507b439293274e356bac8763843f1943a0b3053f297a149857aa8348426d8e01504e2e5f6a44d48df2ef1fb4c5c857fadf48e08b960f83",
                "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
            ],
            [
                "ffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
                "04966195a052fc2dc49ec4912352a3236977ab13fb92bb94ebb806448df937ca92e097d42234c062926c3843ecac804e8a9dd08cc6ed0758515252ee91ca74ea",
                "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",

            ],
            [
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
                "ae2ca9636e9e1e6428ce341dcca9f1495226076fecf15e7e0dd3125a7e31694ec4ea59a82dd75ab9eedb7235f98f55069006aaefe46168ec4d4392f6897f03e0",
                "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
            ],
            [
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
                "ec16d0d1438cd29f0f2e695e8f1ef4b14bf5bfb04a304b4fe309672f16cbd2dbe5c765d1408c490c6888513a7e30a8067981628e04da6ad3e28240eb89615d62",
                "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",

            ],
            [
                "8080808080808080808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
                "08d3be4c96345f6fc5f8eb5d0784e4f4674df82d38268f86f848046c589d3254cd0e4f814dbab6c9103d20c761b8884a7d3bc64537323b5752096606ba084b48",
                "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
            ],
            [
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
                "6e0981bf28b3f0e007ddf0fbf4a7293a37478c4577d1911aa795b2dec520a79e326a04afcdd7d9bf8c6a6c33681d9e875b7bb7ccf9776895282d46450a1245ac",
                "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
            ],
            [
                "9e885d952ad362caeb4efe34a8e91bd2",
                "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
                "9deeba9b00e8d0aebac37081e041d13e0627b98d5c4c0f85febbf96f263ccb3b22d1ca79ff4cd9f562eef1f11910f41c440f3c7d745e2cd11caf122f4988c3f6",
                "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
            ],
            [
                "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
                "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
                "9bec2d18083d603d12edb40a30ece26e0c328f76bb63a7595d6392e267c951c181934632ddca69884173eef4825406932a82842d22dcc91ae5ee0016acfc3f18",
                "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
            ],
            [
                "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
                "d86d022bec7f95dc2579d5d6b966aa11f7d85a93c2348722720dd9de9aef10176585a2c12e721528353a58a5fd081e16099fea110ed08a579d47ad23901eea63",
                "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
            ],
            [
                "c0ba5a8e914111210f2bd131f3d5e08d",
                "scheme spot photo card baby mountain device kick cradle pact join borrow",
                "d16c72574d57e973cdc4d3a36df49cab3b2f9d1a3129024aa054eb01bddc59a6422353c506be9bc9f72e56f2ce58f4f15448f4b16b7f5560a88629cf8c03414f",
                "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
            ],
            [
                "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
                "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
                "cfba4eeb3a9c289bd0c19872614a525fb54ceb60a9ad68fbd28b998d80bce63c3cfb804d5f4cf2f0c8be78dcc3855eb691ee47aac409a36a14e5867ee71f4b61",
                "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
            ],
            [
                "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
                "6a2c4b292d8dfdec056eb59a0888dd9970e4547976406c109965723833a6fbef23cc949b3f67190673aec19075d8b22bc880a7694b650441485a2e1e1b80ad04",
                "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
            ],
            [
                "23db8160a31d3e0dca3688ed941adbf3",
                "cat swing flag economy stadium alone churn speed unique patch report train",
                "218d132a547a003aadec84842fe024167baf17613948a017d056680381e095b7c16d8d292b83ebeb6962d11261d2d3f5d4f999f0f1f87d97279cdb3ff8f42237",
                "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
            ],
            [
                "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
                "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
                "75296032794577562751729ba2293ec15ffb95ffb6cee8b9cdac8b21037089d18622526707d3e6288add17bca9d9d8fde3c26b9638e1459d8afcdaba2580ba1e",
                "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
            ],
            [
                "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
                "d07bc4fd38ff8018b9603a419743e03429f7aef4a1762dbe1eb24bde1ddc14158133bee6a2eec7e801721f624114452fe2331617786eff31782f28f1483437ac",
                "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
            ],
            [
                "f30f8c1da665478f49b001d94c5fc452",
                "vessel ladder alter error federal sibling chat ability sun glass valve picture",
                "6055cea2b5ef8a0fcfcb84ee7ce7d6b8258a4a637ff1b404b734963709f557b995aff8faa79799353d85bd1907c7ce0b2faa9f21e2ed5ececb057a5bae123432",
                "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
            ],
            [
                "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
                "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
                "bab783d77151da26cea1c5aa0a8ae15eee5bf32f69345937030b340a1727168baa3addc3799fd3de398cbf5866ec047829f183b986006f60d6e1698ae03c3b77",
                "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
            ],
            [
                "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
                "059edd46250629b5819c15a702ec24a8e2aa5af484bce18a9ba111a6226271083dea4a63213d5e7d48179236aa037030df654c16b6d1221571cc35c5959cf75a",
                "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
            ]
        ];
        test_vectors
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
            let seed = mnemonic.to_seed("OSKey").unwrap();
            assert_eq!(hex::encode(seed), case[2]);

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

    #[test]
    pub fn test_mnemonic_rejects_more_than_24_words() {
        let phrase = ["abandon"; 25].join(" ");
        let error = Mnemonic::from_phrase(&phrase).err().unwrap();

        assert_eq!(error.to_string(), "Invalid entropy length");
    }
}
