//! Benches. To use, import functions of interest, and `cargo bench`.
//!
//! https://bheisler.github.io/criterion.rs/book/iai/iai.html
#![allow(unused_imports)]
use std::{thread, time};

use criterion::{black_box as bb, criterion_group, criterion_main, Criterion};
use vigenere_cipher::vignere::Vignere;

// 24.131 µs on my machine
fn bench_en(c: &mut Criterion) {
    let key = "LoremipsumdolorsitametconsecteturadipiscingelitseddoeiusmodtemporincididuntutlaboreetdoloremagnaaliquaUtenimadminimveniamquisnostrudexercitationullamcolaborisnisiutaliquipexeacommodoconsequatDuisauteiruredolorinreprehenderitinvoluptatevelitessecillumdoloreeufugiatnullapariaturExcepteursintoccaecatcupidatatnonproidentsuntinculpaquiofficiadeseruntmollitanimidestlaborum";
    let msg = String::from("rxfqgfmijapvfrahyvjbkrvrlngwdrqqsjzilbfdwhuhphtlphrbqsxaxsdivxmbhknvridnlxxvgorbhjaabdxcjridczqsumctefntukkvsjvmbikplirqtresjtyvhtkytcjzmcvcwbyufbmnwmrxzviyyjjxvecqpqkrzxnigycqjjvbxdmeqdjpipvdzcgeyenopfpnzsxzkhtdnlctonqlellwdhpsijfrukoqcrkxmwjpokmssrwjlazz").to_uppercase();
    let v = Vignere::new(&key).unwrap();

    c.bench_function("encrypt", |f| f.iter(|| v.encrypt(&msg).unwrap()));
}

//  24.319 µs on my machine
fn bench_de(c: &mut Criterion) {
    let key = "LoremipsumdolorsitametconsecteturadipiscingelitseddoeiusmodtemporincididuntutlaboreetdoloremagnaaliquaUtenimadminimveniamquisnostrudexercitationullamcolaborisnisiutaliquipexeacommodoconsequatDuisauteiruredolorinreprehenderitinvoluptatevelitessecillumdoloreeufugiatnullapariaturExcepteursintoccaecatcupidatatnonproidentsuntinculpaquiofficiadeseruntmollitanimidestlaborum";
    let msg = String::from("rxfqgfmijapvfrahyvjbkrvrlngwdrqqsjzilbfdwhuhphtlphrbqsxaxsdivxmbhknvridnlxxvgorbhjaabdxcjridczqsumctefntukkvsjvmbikplirqtresjtyvhtkytcjzmcvcwbyufbmnwmrxzviyyjjxvecqpqkrzxnigycqjjvbxdmeqdjpipvdzcgeyenopfpnzsxzkhtdnlctonqlellwdhpsijfrukoqcrkxmwjpokmssrwjlazz").to_uppercase();
    let v = Vignere::new(&key).unwrap();
    let ciphertext = v.encrypt(&msg).unwrap();
    c.bench_function("decrypt", |f| f.iter(|| v.decrypt(&ciphertext).unwrap()));
}

criterion_group!(benches, bench_en, bench_de);
criterion_main!(benches);
