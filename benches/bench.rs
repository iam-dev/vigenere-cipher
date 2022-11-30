//! Benches. To use, import functions of interest, and `cargo bench`.
//!
//! https://bheisler.github.io/criterion.rs/book/iai/iai.html
#![allow(unused_imports)]
use std::{thread, time};

use criterion::{black_box as bb, criterion_group, criterion_main, Criterion};
use vigenere_cipher::vignere::Vignere;

// 1.0525 µs on my machine
fn bench_en(c: &mut Criterion) {
    let key = "LEMON";
    let msg = "ATTACKATDAWN";
    let v = Vignere::new(&key).unwrap();

    c.bench_function("encrypt", |f| f.iter(|| v.encrypt(&msg).unwrap()));
}

//  1.0668 µs on my machine
fn bench_de(c: &mut Criterion) {
    let key = "LEMON";
    let msg = "ATTACKATDAWN";
    let v = Vignere::new(&key).unwrap();
    let ciphertext = v.encrypt(&msg).unwrap();
    c.bench_function("decrypt", |f| f.iter(|| v.decrypt(&ciphertext).unwrap()));
}

criterion_group!(benches, bench_en, bench_de);
criterion_main!(benches);
