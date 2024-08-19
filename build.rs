use std::env;
use std::fs;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/trace.bpf.c";

fn main() {
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("trace.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-I"),
            OsStr::new(&format!("/usr/include/aarch64-linux-gnu")),
            OsStr::new("-I"),
            OsStr::new(&format!("/usr/src/linux-headers-6.1.0-23-common/include")),
        ])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}