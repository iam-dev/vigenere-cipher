// REF FROM https://github.com/fbielejec/CryptographyEngineering/blob/master/study-group-hw/vigenere/src/lib.rs
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

pub mod vignere {

    #[derive(Clone, Debug)]
    pub struct Vignere {
        key: String,
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

    // Get the position of a character in the alphabet
    // a = 0, b = 1, c = 2, ..., z = 25
    fn get_position(c: char) -> u8 {
        let copy: char = c.clone().to_ascii_lowercase();
        match copy {
            'a' => 0,
            'b' => 1,
            'c' => 2,
            'd' => 3,
            'e' => 4,
            'f' => 5,
            'g' => 6,
            'h' => 7,
            'i' => 8,
            'j' => 9,
            'k' => 10,
            'l' => 11,
            'm' => 12,
            'n' => 13,
            'o' => 14,
            'p' => 15,
            'q' => 16,
            'r' => 17,
            's' => 18,
            't' => 19,
            'u' => 20,
            'v' => 21,
            'w' => 22,
            'x' => 23,
            'y' => 24,
            'z' => 25,
            _ => panic!("Invalid character"),
        }
    }

    // Get the character at a position in the alphabet
    fn alphabet_position_to_char(pos: u8) -> char {
        match pos {
            0 => 'a',
            1 => 'b',
            2 => 'c',
            3 => 'd',
            4 => 'e',
            5 => 'f',
            6 => 'g',
            7 => 'h',
            8 => 'i',
            9 => 'j',
            10 => 'k',
            11 => 'l',
            12 => 'm',
            13 => 'n',
            14 => 'o',
            15 => 'p',
            16 => 'q',
            17 => 'r',
            18 => 's',
            19 => 't',
            20 => 'u',
            21 => 'v',
            22 => 'w',
            23 => 'x',
            24 => 'y',
            25 => 'z',
            _ => panic!("Invalid position"),
        }
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
        pub fn encrypt(&self, plaintext: &str) -> String {
            check_alphabetic(&plaintext);
            let key = generate_key(&self.key, plaintext.len());
            (0..plaintext.len())
                .map(|index| {
                    let c = (get_position(key.chars().nth(index).unwrap())
                        + get_position(plaintext.chars().nth(index).unwrap()))
                        % 26;

                    alphabet_position_to_char(c as u8)
                })
                .collect()
        }

        // This function returns the original text
        // Pi = (Ci - Ki + 26) % 26
        pub fn decrypt(&self, ciphertext: &str) -> String {
            check_alphabetic(&ciphertext);
            let key = generate_key(&self.key, ciphertext.len());
            (0..ciphertext.len())
                .map(|index| {
                    let c = (get_position(ciphertext.chars().nth(index).unwrap()) + 26
                        - get_position(key.chars().nth(index).unwrap()))
                        % 26;

                    alphabet_position_to_char(c as u8)
                })
                .collect()
        }
    }
}

use vignere::Vignere;

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
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vignere_cipher() {
        let key = "CRYPTO";
        let msg = "HELLOWORLD";
        let v = Vignere::new(&key).unwrap();
        let ciphertext = v.encrypt(&msg);
        let plaintext = v.decrypt(&ciphertext);
        assert_eq!(msg.to_lowercase(), plaintext);
    }
}
