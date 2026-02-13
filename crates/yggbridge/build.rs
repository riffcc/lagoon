use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let go_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("go");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let lib_path = out_dir.join("libyggbridge.a");

    let status = Command::new("go")
        .args([
            "build",
            "-buildmode=c-archive",
            "-o",
            lib_path.to_str().unwrap(),
            ".",
        ])
        .current_dir(&go_dir)
        .env("CGO_ENABLED", "1")
        .status()
        .expect("failed to run `go build` — is Go installed?");

    assert!(
        status.success(),
        "go build -buildmode=c-archive failed with status {status}"
    );

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=yggbridge");
    // Go's c-archive runtime needs pthreads and resolv
    println!("cargo:rustc-link-lib=dylib=resolv");
    println!("cargo:rerun-if-changed=go/yggbridge.go");
    println!("cargo:rerun-if-changed=go/go.mod");
    println!("cargo:rerun-if-changed=go/go.sum");
}
