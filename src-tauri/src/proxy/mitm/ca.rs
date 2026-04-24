#![allow(dead_code)]
//! MITM Certificate Authority
//!
//! Generates a self-signed root CA certificate on first run and persists it.
//! For each intercepted HTTPS host, generates a dynamic server certificate
//! signed by our CA. Certs are cached in memory.

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use std::path::PathBuf;
use std::sync::Arc;
use tokio_rustls::rustls::{self, pki_types::PrivateKeyDer};

/// In-memory cache of generated TLS server configs per hostname.
type CertCache = dashmap::DashMap<String, Arc<rustls::ServerConfig>>;

/// Manages the MITM CA certificate and generates per-host server certificates.
pub struct CertificateAuthority {
    /// The CA certificate object (for use in signed_by)
    ca_cert: rcgen::Certificate,
    /// CA key pair (for signing host certs)
    ca_key_pair: KeyPair,
    /// DER bytes of the CA cert (for PEM export)
    ca_cert_der: Vec<u8>,
    /// Per-host cert cache
    cert_cache: CertCache,
}

/// Build CA CertificateParams.
fn build_ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Development Proxy CA");
    dn.push(DnType::OrganizationName, "Local Development");
    params.distinguished_name = dn;
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2034, 12, 31);
    params
}

impl CertificateAuthority {
    /// Load an existing CA key from disk (regenerating the cert), or generate a new one.
    pub fn load_or_generate() -> Result<Self, String> {
        let (cert_path, key_path) = get_ca_paths();

        let mut is_new = false;
        let ca = if key_path.exists() {
            tracing::info!("[MITM-CA] Loading existing CA key from {:?}", key_path);
            let ca = Self::load_key_and_regenerate(&key_path)?;
            ca.save_cert_to_file(&cert_path)?;
            ca
        } else {
            tracing::info!("[MITM-CA] Generating new CA certificate");
            let ca = Self::generate_new()?;
            ca.save_to_files(&cert_path, &key_path)?;
            is_new = true;
            ca
        };

        // On Windows, Go doesn't respect SSL_CERT_FILE. We must inject it into the OS trust store.
        #[cfg(target_os = "windows")]
        if let Err(e) = ca.install_to_system_store(&cert_path, is_new) {
            tracing::warn!("[MITM-CA] Failed to install CA to system store: {}", e);
        }

        Ok(ca)
    }

    /// Install the CA certificate into the Windows CurrentUser Root store.
    #[cfg(target_os = "windows")]
    fn install_to_system_store(&self, cert_path: &PathBuf, is_new: bool) -> Result<(), String> {
        // If it's not new, check if it's already installed to avoid popping up UI or running certutil on every startup
        if !is_new {
            // Note: certutil -verifystore doesn't always have a clean fast check, so we just install it once
            // Actually, adding it again is usually a no-op, but we'll try to only do it if it's new.
            // Wait, what if the user deleted it from the store? We should probably just run it.
            // But running it might trigger a Windows Security prompt (even for CurrentUser).
            // Let's only do it if the cert is freshly generated to minimize prompts.
        }

        if is_new || std::env::var("FORCE_CA_INSTALL").is_ok() {
            tracing::info!("[MITM-CA] Installing MITM CA to Windows CurrentUser Root store...");
            let output = std::process::Command::new("certutil")
                .args(["-addstore", "-user", "Root"])
                .arg(cert_path)
                .output()
                .map_err(|e| format!("certutil failed: {}", e))?;

            if !output.status.success() {
                return Err(String::from_utf8_lossy(&output.stderr).into_owned());
            }
            tracing::info!("[MITM-CA] Successfully installed CA to system store.");
        }
        Ok(())
    }

    /// Generate a new self-signed CA.
    fn generate_new() -> Result<Self, String> {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("CA key generation failed: {}", e))?;

        let params = build_ca_params();
        let ca_cert = params
            .self_signed(&key_pair)
            .map_err(|e| format!("CA self-sign failed: {}", e))?;

        let ca_cert_der = ca_cert.der().to_vec();

        Ok(Self {
            ca_cert,
            ca_key_pair: key_pair,
            ca_cert_der,
            cert_cache: CertCache::new(),
        })
    }

    /// Load CA key from PEM file, regenerate the CA cert from it.
    /// This produces a valid `rcgen::Certificate` that can be used in `signed_by`.
    fn load_key_and_regenerate(key_path: &PathBuf) -> Result<Self, String> {
        let key_pem =
            std::fs::read_to_string(key_path).map_err(|e| format!("Read CA key: {}", e))?;
        let key_pair = KeyPair::from_pem(&key_pem).map_err(|e| format!("Parse CA key: {}", e))?;

        // Regenerate the CA cert using the loaded key pair
        // (same key pair = same public key = trust chain works)
        let params = build_ca_params();
        let ca_cert = params
            .self_signed(&key_pair)
            .map_err(|e| format!("CA re-self-sign failed: {}", e))?;

        let ca_cert_der = ca_cert.der().to_vec();

        Ok(Self {
            ca_cert,
            ca_key_pair: key_pair,
            ca_cert_der,
            cert_cache: CertCache::new(),
        })
    }

    /// Save both CA certificate and key to PEM files.
    fn save_to_files(&self, cert_path: &PathBuf, key_path: &PathBuf) -> Result<(), String> {
        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("Create CA dir: {}", e))?;
        }

        self.save_cert_to_file(cert_path)?;

        let key_pem = self.ca_key_pair.serialize_pem();
        std::fs::write(key_path, &key_pem).map_err(|e| format!("Write CA key: {}", e))?;

        tracing::info!("[MITM-CA] CA saved to {:?}", cert_path);
        Ok(())
    }

    /// Save just the cert PEM to file.
    fn save_cert_to_file(&self, cert_path: &PathBuf) -> Result<(), String> {
        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("Create CA dir: {}", e))?;
        }
        let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", self.ca_cert_der.clone()));
        std::fs::write(cert_path, &cert_pem).map_err(|e| format!("Write CA cert: {}", e))?;
        Ok(())
    }

    /// Get or generate a TLS ServerConfig for the given hostname.
    pub fn get_server_config(&self, hostname: &str) -> Arc<rustls::ServerConfig> {
        if let Some(cached) = self.cert_cache.get(hostname) {
            return cached.clone();
        }

        let config = self.generate_host_config(hostname).unwrap_or_else(|e| {
            tracing::error!("[MITM-CA] Failed to generate cert for {}: {}", hostname, e);
            self.generate_host_config("localhost").unwrap()
        });

        let config = Arc::new(config);
        self.cert_cache.insert(hostname.to_string(), config.clone());
        config
    }

    /// Generate a ServerConfig with a certificate valid for the given hostname.
    fn generate_host_config(&self, hostname: &str) -> Result<rustls::ServerConfig, String> {
        let host_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("Host key gen: {}", e))?;

        let mut host_params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        host_params.distinguished_name = dn;
        host_params.subject_alt_names =
            vec![SanType::DnsName(hostname.try_into().map_err(
                |e: rcgen::Error| format!("Invalid hostname: {}", e),
            )?)];
        host_params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        host_params.not_after = rcgen::date_time_ymd(2026, 12, 31);

        // Sign the host cert with our CA cert + CA key
        let ca_params = build_ca_params();
        let issuer = rcgen::Issuer::new(ca_params, &self.ca_key_pair);
        let host_cert = host_params
            .signed_by(&host_key, &issuer)
            .map_err(|e| format!("Host cert sign: {}", e))?;

        // Build rustls ServerConfig
        let cert_der = rustls::pki_types::CertificateDer::from(host_cert.der().as_ref().to_vec());
        let cert_chain = vec![cert_der];
        let private_key = PrivateKeyDer::Pkcs8(host_key.serialize_der().into());

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| format!("ServerConfig build: {}", e))?;

        Ok(config)
    }

    /// Get the CA certificate as PEM string.
    #[allow(dead_code)]
    pub fn ca_cert_pem(&self) -> String {
        pem::encode(&pem::Pem::new("CERTIFICATE", self.ca_cert_der.clone()))
    }
}

/// Get the directory for storing MITM CA files.
fn get_ca_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("dev-proxy")
        .join("mitm")
}

/// Get paths for CA cert and key files.
fn get_ca_paths() -> (PathBuf, PathBuf) {
    let dir = get_ca_dir();
    (dir.join("mitm-ca-v3.pem"), dir.join("mitm-ca-key-v3.pem"))
}

/// Get the CA cert path as a String (for env vars).
pub fn get_ca_cert_path_string() -> Option<String> {
    let (cert_path, _) = get_ca_paths();
    if cert_path.exists() {
        Some(cert_path.to_string_lossy().to_string())
    } else {
        None
    }
}
