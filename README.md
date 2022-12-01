# Vigenere Cipher Rust Implementation

This is a very basic implementation of the vigenere cipher for the session 1 of [Open Rust Cryptography Engineering Study Group](https://hackmd.io/@thor314/ryEWRY6Qs).


## How to use vignere
```ignore
use vigenere_cipher::vignere::Vignere;

let key = "CRYPTO";
let msg = "HELLOWORLD";
let v = Vignere::new(&key).unwrap();
let ciphertext = v.encrypt(&msg).unwrap();
let plaintext = v.decrypt(&ciphertext).unwrap();
```

## Run test

```ignore
cargo test
```

to test the cipher.


## Performance test
```ignore
cargo bench
```

to test the performance of vignere

