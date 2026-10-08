//! CWA parsing, metadata, resampling and CSV over Rust readers and writers.
//! This crate has no Python or JavaScript runtime dependency.
pub mod data;
pub mod errors;
pub mod header;
mod locate;
mod packet;
pub mod reader;

pub mod batch;
