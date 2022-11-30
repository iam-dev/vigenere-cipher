// REF FROM https://github.com/fbielejec/CryptographyEngineering/blob/master/study-group-hw/vigenere/src/lib.rs
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

pub mod vignere {

    #[derive(Clone, Debug)]
    pub struct Vignere {
        key: String,
    }

    /// Encodes a character to a u32 by subtracting by 97 to normalize to range of 0 - 25.
    /// Source: https://www.asciitable.com/
    fn encode_char(c: char) -> u32 {
        (c as u32)
            .checked_sub(97)
            .expect("Error encoding char to u32!")
    }

    /// Encodes a u32 to a char by adding 97 to undo normalization of the chosen range of 0 - 25.
    /// Source: https://www.asciitable.com/
    fn decode_u32(n: u32) -> char {
        std::char::from_u32(n + 97).expect("Error decoding u32 to char!")
    }

    // Check if a character is a letter
    // lowercase a..z
    fn check_alphabetic(s: &str) -> anyhow::Result<()> {
        let copy: &str = &s.clone().to_lowercase();
        for c in copy.chars() {
            match c {
                'a'..='z' => (),
                _ => {
                    return Err(anyhow::anyhow!(
                        "Invalid character in key, must be lowercase a-z: {c}"
                    ))
                }
            }
        }
        Ok(())
    }

    // This function generates the key in
    // a cyclic manner until it's length is
    // equal to the length of original text
    fn generate_key(keyword: &str, length: usize) -> String {
        let keyword = keyword.to_ascii_lowercase();
        (0..length)
            .map(|index| keyword.chars().nth(index % keyword.len()).unwrap())
            .collect()
    }

    impl Vignere {
        pub fn new(key: &str) -> anyhow::Result<Self> {
            check_alphabetic(&key)?;
            Ok(Self {
                key: key.to_string(),
            })
        }

        // This function returns the encrypted text
        // Ci = (Ki + Pi) % 26
        pub fn encrypt(&self, plaintext: &str) -> anyhow::Result<String> {
            check_alphabetic(&plaintext);
            let keysteam = generate_key(&self.key, plaintext.len());
            let keysteam = keysteam.to_lowercase();
            let plaintext = plaintext.to_lowercase();
            let keysteam = keysteam.as_bytes();

            let mut cipher_vec: Vec<char> = vec![];
            for (i, p_i) in plaintext.chars().enumerate() {
                let k_i: u32 = encode_char(keysteam[i % keysteam.len()] as char);
                let p_i: u32 = encode_char(p_i);
                let c_i = (k_i + p_i) % 26;

                cipher_vec.push(decode_u32(c_i));
            }

            return Ok(cipher_vec.into_iter().collect());
        }

        // This function returns the original text
        // Pi = (Ci - Ki) % 26
        pub fn decrypt(&self, ciphertext: &str) -> anyhow::Result<String> {
            check_alphabetic(&ciphertext);
            let keysteam = generate_key(&self.key, ciphertext.len());
            let keysteam = keysteam.to_lowercase();
            let ciphertext = ciphertext.to_lowercase();

            let keysteam = keysteam.as_bytes();

            let mut plaintext_vec: Vec<char> = vec![];
            for (i, c_i) in ciphertext.chars().enumerate() {
                let k_i: u32 = encode_char(keysteam[i % keysteam.len()] as char);
                let c_i: u32 = encode_char(c_i);
                // rem_euclid acts as a modulus operator when we have negative results.
                let p_i = (c_i as i32 - k_i as i32).rem_euclid(26) as u32;

                plaintext_vec.push(decode_u32(p_i));
            }

            return Ok(plaintext_vec.into_iter().collect());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vignere::Vignere;

    #[test]
    // Key = cryptocryp
    // Plaintext = helloworld
    // Ciphertext = jvjahkqijs
    // +-----+------+------+------+------+------+------+------+------+------+------+
    // | Key | c=2  | r=17 | y=24 | p=15 | t=19 | o=14 | c=2  | r=17 | y=24 | p=15 |
    // | PT  | h=7  | e=4  | l=11 | l=11 | o=14 | w=22 | o=14 | r=17 | l=11 | d=3  |
    // | CT  | 9=j  | 21=v | 9=j  | 0=a  | 7=h  | 10=k | 16=q | 8=i  | 9=j  | 18=s |
    // +-----+------+------+------+------+------+------+------+------+------+------+
    // 2 + 7 mod 26 = 9
    // 17 + 4 mod 26 = 21
    // 24 + 11 mod 26 = 9
    // 15 + 11 mod 26 = 0
    // 19 + 14 mod 26 = 7
    // 14 + 22 mod 26 = 10
    // 2 + 14 mod 26 = 16
    // 17 + 17 mod 26 = 8
    // 24 + 11 mod 26 = 9
    // 15 + 3 mod 26 = 18
    fn hello_world() {
        let key = "CRYPTO";
        let msg = "HELLOWORLD";
        let v = Vignere::new(&key).unwrap();
        let ciphertext = v.encrypt(&msg).unwrap();
        assert_eq!(ciphertext, "jvjahkqijs");
        let plaintext = v.decrypt(&ciphertext).unwrap();
        assert_eq!(msg.to_lowercase(), plaintext);
    }

    #[test]
    fn attack_at_dawn() {
        let key = "LEMON";
        let msg = "ATTACKATDAWN";
        let v = Vignere::new(&key).unwrap();
        let ciphertext = v.encrypt(&msg).unwrap();
        assert_eq!(ciphertext, "lxfopvefrnhr");
        let plaintext = v.decrypt(&ciphertext).unwrap();
        assert_eq!(msg.to_lowercase(), plaintext);
    }

    #[test]
    fn dont_tell_anyone() {
        let key = "cat";
        let msg = "donttellanyone";
        let v = Vignere::new(&key).unwrap();
        let ciphertext = v.encrypt(&msg).unwrap();
        let plaintext = v.decrypt(&ciphertext).unwrap();
        assert_eq!(msg, plaintext);
    }

    #[test]
    fn really_long_text() {
        let key = "secrets";
        let msg = String::from("LoremipsumdolorsitametconsecteturadipiscingelitseddoeiusmodtemporincididuntutlaboreetdoloremagnaaliquaUtenimadminimveniamquisnostrudexercitationullamcolaborisnisiutaliquipexeacommodoconsequatDuisauteiruredolorinreprehenderitinvoluptatevelitessecillumdoloreeufugiatnullapariaturExcepteursintoccaecatcupidatatnonproidentsuntinculpaquiofficiadeseruntmollitanimidestlaborum").to_uppercase();
        let v = Vignere::new(&key).unwrap();
        let ciphertext = v.encrypt(&msg).unwrap();
        let plaintext = v.decrypt(&ciphertext).unwrap();
        assert_eq!(msg.to_lowercase(), plaintext);
    }

    #[test]
    fn really_long_key() {
        let key = "LoremipsummetconsecteturadipiscingelitseddoeiusmodtemporincididuntutlaboreetdoloremagnaaliquaUtenimadminimveniamquisnostrudexercitationullamcolaborisnisiutaliquipexeacommodoconsequatDuisauteiruredolorinreprehenderitinvoluptatevelitessecillumdoloreeufugiatnullapariaturExcepteursintoccaecatcupidatatnonproidentsuntinculpaquiofficiadeseruntmollitanimidestlaboru";
        let msg = String::from("jpokmssrwjlazz").to_uppercase();
        let v = Vignere::new(&key).unwrap();
        let ciphertext = v.encrypt(&msg).unwrap();
        let plaintext = v.decrypt(&ciphertext).unwrap();
        assert_eq!(msg.to_lowercase(), plaintext);
    }

    #[test]
    fn really_long_text_and_key() {
        let key = "LoremipsumdolorsitametconsecteturadipiscingelitseddoeiusmodtemporincididuntutlaboreetdoloremagnaaliquaUtenimadminimveniamquisnostrudexercitationullamcolaborisnisiutaliquipexeacommodoconsequatDuisauteiruredolorinreprehenderitinvoluptatevelitessecillumdoloreeufugiatnullapariaturExcepteursintoccaecatcupidatatnonproidentsuntinculpaquiofficiadeseruntmollitanimidestlaborum";
        let msg = String::from("rxfqgfmijapvfrahyvjbkrvrlngwdrqqsjzilbfdwhuhphtlphrbqsxaxsdivxmbhknvridnlxxvgorbhjaabdxcjridczqsumctefntukkvsjvmbikplirqtresjtyvhtkytcjzmcvcwbyufbmnwmrxzviyyjjxvecqpqkrzxnigycqjjvbxdmeqdjpipvdzcgeyenopfpnzsxzkhtdnlctonqlellwdhpsijfrukoqcrkxmwjpokmssrwjlazz").to_uppercase();
        let v = Vignere::new(&key).unwrap();
        let ciphertext = v.encrypt(&msg).unwrap();
        let decipher_text = v.decrypt(&ciphertext).unwrap();
        assert_eq!(msg.to_lowercase(), decipher_text);
    }
}
