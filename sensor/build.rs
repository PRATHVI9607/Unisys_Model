use libbpf_cargo::SkeletonBuilder;
use std::{env, path::PathBuf};

const SRC: &str = "src/bpf/sensor.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("sensor.skel.rs");
    // no vmlinux.h: sensor.bpf.c declares the few kernel structs it reads locally (CO-RE relocated)
    SkeletonBuilder::new()
        .source(SRC)
        // -mcpu=v3: atomic xchg (per-CPU walk pool); older clang defaults to v1
        .clang_args(["-I/usr/include", "-D__TARGET_ARCH_x86", "-mcpu=v3"])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}
