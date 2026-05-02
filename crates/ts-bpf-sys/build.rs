//! Compile every `bpf/*.bpf.c` in the repo and emit a libbpf-cargo
//! skeleton into OUT_DIR/<name>.skel.rs. The library entry point
//! re-exports those modules.

use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

/// Each entry: (BPF source filename, generated skeleton filename).
/// Add new probes here as they're written.
const PROGRAMS: &[(&str, &str)] = &[("sched_exec.bpf.c", "sched_exec.skel.rs")];

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir.join("..").join("..");
    let bpf_dir = repo_root.join("bpf");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed={}", bpf_dir.display());

    for (src_name, skel_name) in PROGRAMS {
        let src = bpf_dir.join(src_name);
        let skel = out_dir.join(skel_name);

        println!("cargo:rerun-if-changed={}", src.display());

        SkeletonBuilder::new()
            .source(&src)
            .clang_args(["-I", bpf_dir.to_str().unwrap()])
            .build_and_generate(&skel)
            .unwrap_or_else(|e| {
                panic!("failed to build BPF skeleton for {}: {e}", src.display());
            });
    }
}
