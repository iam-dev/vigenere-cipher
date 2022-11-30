// Check if a character is a letter
// lowercase a..z
fn check_alphabetic(s: &str) -> anyhow::Result<bool> {
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
    Ok(true)
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

// This function returns the encrypted text
// Ci = (Ki + Pi) % 26
fn encrypt(message: &str, key: &str) -> String {
    check_alphabetic(&message).unwrap();
    check_alphabetic(&key).unwrap();

    (0..message.len())
        .map(|index| {
            let c = (get_position(key.chars().nth(index).unwrap())
                + get_position(message.chars().nth(index).unwrap()))
                % 26;

            alphabet_position_to_char(c as u8)
        })
        .collect()
}

// This function returns the original text
// Pi = (Ci - Ki + 26) % 26
fn decrypt(message: &str, key: &str) -> String {
    check_alphabetic(&message).unwrap();
    check_alphabetic(&key).unwrap();

    (0..message.len())
        .map(|index| {
            let c = (get_position(message.chars().nth(index).unwrap()) + 26
                - get_position(key.chars().nth(index).unwrap()))
                % 26;

            alphabet_position_to_char(c as u8)
        })
        .collect()
}

// Key = cryptocryp
// Plaintext = helloworld
// Ciphertext = jvjahkqijs
// +-----+------+------+------+------+------+------+------+------+------+------+
// | Key | c=2  | r=17 | y=24 | p=15 | t=19 | o=14 | c=2  | r=17 | y=24 | p=15 |
// | PT  | h=7  | e=4  | l=11 | l=11 | o=14 | w=22 | o=14 | r=17 | l=11 | d=3  |
// | CT  | 9= j | 21=v | 9=j  | 0=a  | 7=h  | 10=k | 16=q | 8=i  | 9=j  | 18=s |
// +-----+------+------+------+------+------+------+------+------+------+------+
fn main() {
    let keyword = "CRYPTO";
    let message = "HELLOWORLD";

    let key = generate_key(keyword, message.len());
    assert!(check_alphabetic(&key).unwrap());

    let key_positions: Vec<u8> = key.chars().map(|c| get_position(c)).collect();
    assert_eq!(key_positions, vec![2, 17, 24, 15, 19, 14, 2, 17, 24, 15]);

    assert!(check_alphabetic(&message).unwrap());
    let message_positions: Vec<u8> = message.chars().map(|c| get_position(c)).collect();
    assert_eq!(message_positions, vec![7, 4, 11, 11, 14, 22, 14, 17, 11, 3]);

    let encrypted = encrypt(message, &key);
    assert_eq!(encrypted, "jvjahkqijs");

    let decrypted = decrypt(&encrypted, &key);
    assert_eq!(decrypted, message.to_ascii_lowercase());
}
