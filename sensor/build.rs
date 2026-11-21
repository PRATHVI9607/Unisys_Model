use libbpf_cargo::SkeletonBuilder;
use std::{env, path::PathBuf};

const SRC: &str = "src/bpf/sensor.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("sensor.skel.rs");
    // The bpf target is arch-neutral; the arch only selects the pt_regs layout (syscall number) and the
    // asm/ headers directory (Debian multiarch: libelf-dev:<arch> brings linux-libc-dev:<arch>).
    let (bpf_arch, triple) = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "x86_64" => ("x86", "x86_64-linux-gnu"),
        "aarch64" => ("arm64", "aarch64-linux-gnu"),
        a => panic!("unsupported target arch {a}"),
    };
    // no vmlinux.h: sensor.bpf.c declares the few kernel structs it reads locally (CO-RE relocated)
    SkeletonBuilder::new()
        .source(SRC)
        // -mcpu=v3: atomic xchg (per-CPU walk pool); older clang defaults to v1
        .clang_args(["-I/usr/include".to_string(), format!("-I/usr/include/{triple}"), format!("-D__TARGET_ARCH_{bpf_arch}"), "-mcpu=v3".into()])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}
