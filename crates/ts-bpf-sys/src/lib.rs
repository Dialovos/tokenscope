//! Generated BPF skeletons.
//!
//! Each `pub mod X` corresponds to a `bpf/X.bpf.c` source and exposes
//! - `XSkelBuilder` (open the program)
//! - `XSkel`        (the loaded skeleton with `maps()` and `progs()`)
//! - `XOpenSkel`    (intermediate stage between open and load)
//!
//! See libbpf-rs docs: https://docs.rs/libbpf-rs

#![allow(clippy::all)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub mod sched_exec {
    include!(concat!(env!("OUT_DIR"), "/sched_exec.skel.rs"));
}

pub mod net {
    include!(concat!(env!("OUT_DIR"), "/net.skel.rs"));
}

pub use libbpf_rs;
