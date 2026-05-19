#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

//! `fortibackup` — Automated configuration backup for FortiGate devices.
//!
//! This library exposes all of the building blocks used by the `fortibackup`
//! binary, so integration tests and downstream consumers can exercise the
//! same pipeline.

pub mod backup;
pub mod cli;
pub mod config;
pub mod error;
pub mod metrics;
pub mod normalize;
pub mod notify;
pub mod scheduler;
pub mod storage;
pub mod storage_s3;
pub mod transport;
pub mod webui;
