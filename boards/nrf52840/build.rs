use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mut memory_x = File::create(out.join("memory.x")).unwrap();
    if env::var("CARGO_FEATURE_NICENANO").is_ok() {
        memory_x
            .write_all(include_bytes!("memory-nicenano.x"))
            .unwrap();
    } else {
        memory_x.write_all(include_bytes!("memory.x")).unwrap();
    }
    println!("cargo:rustc-link-search={}", out.display());

    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=memory-nicenano.x");
    println!("cargo:rerun-if-changed=Cargo.toml");

    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rustc-link-arg-bins=-Tdefmt.x");
}
