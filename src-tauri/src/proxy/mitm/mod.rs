//! MITM Forward Proxy (Plan v7)
//!
//! Intercepts ALL outbound HTTPS traffic from the IDE process,
//! inspects requests inside TLS tunnels, and selectively drops
//! native telemetry that would conflict with our synthetic metrics.

#![allow(dead_code)]
pub mod ca;
pub mod forward_proxy;
pub mod rules;

use std::sync::atomic::{AtomicU16, Ordering};

static MITM_PORT: AtomicU16 = AtomicU16::new(0);

/// Set the MITM forward proxy port (called on startup).
pub fn set_mitm_port(port: u16) {
    MITM_PORT.store(port, Ordering::Relaxed);
}

/// Get the MITM forward proxy port (0 = not running).
pub fn get_mitm_port() -> Option<u16> {
    let port = MITM_PORT.load(Ordering::Relaxed);
    if port > 0 {
        Some(port)
    } else {
        None
    }
}

/// Get the path to the MITM CA certificate PEM file.
pub fn get_ca_cert_path() -> Option<String> {
    ca::get_ca_cert_path_string()
}
