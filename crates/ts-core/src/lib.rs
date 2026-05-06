//! Shared types and helpers for TokenScope.
//!
//! This crate has no I/O, no async, no platform deps — pure data layout
//! plus tiny helpers. It must compile to `no_std` in the future (currently
//! uses `std` for the `thiserror` derives).

pub mod event;

pub use event::{
    decode_header, decode_net_connect, DecodeError, TsEventHdr, TsEventType, TsNetConnectPayload,
};
