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

    // Stamp the build so a running board can say which firmware it carries. Without this the only
    // way to tell whether a node had a given change was to remember when it was flashed, which is
    // not evidence. Falls back to "unknown" outside a git checkout rather than failing the build.
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    let hash = git(&["rev-parse", "--short=7", "HEAD"]).unwrap_or_else(|| "unknown".into());
    // A trailing `+` means the tree had uncommitted changes when this was built, so the hash alone
    // does not describe what is running.
    let dirty = git(&["status", "--porcelain"]).is_some_and(|o| !o.is_empty());
    println!(
        "cargo:rustc-env=MR_BUILD={hash}{}",
        if dirty { "+" } else { "" }
    );
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");

    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
    println!("cargo:rustc-link-arg-bins=-Tdefmt.x");
}
