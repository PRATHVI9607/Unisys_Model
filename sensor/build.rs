use libbpf_cargo::SkeletonBuilder;
use std::{env, path::PathBuf};

const SRC: &str = "src/bpf/sensor.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("sensor.skel.rs");
    // no vmlinux.h: the program reads only stable tracepoint/syscall ABI, see sensor.bpf.c
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(["-I/usr/include", "-D__TARGET_ARCH_x86"])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}
