//! OpenSSH certificate parsing and verification.
//!
//! The certificate format and its checks live in `neotales-x509`. This module
//! re-exports that API for SSH callers.

pub use neotales_x509::ssh_cert::{
    CERTIFICATE_TYPE_HOST, CERTIFICATE_TYPE_USER, CRITICAL_OPTION_FORCE_COMMAND,
    CRITICAL_OPTION_SOURCE_ADDRESS, Certificate, CertificateError, CertificateOption,
    CertificateType, ED25519_PUBLIC_KEY_LENGTH, ED25519_SIGNATURE_LENGTH, SSH_ECDSA_SHA2_NISTP256,
    SSH_ECDSA_SHA2_NISTP256_CERT_V01, SSH_ECDSA_SHA2_NISTP384, SSH_ECDSA_SHA2_NISTP384_CERT_V01,
    SSH_ECDSA_SHA2_NISTP521, SSH_ECDSA_SHA2_NISTP521_CERT_V01, SSH_ED25519, SSH_ED25519_CERT_V01,
    SSH_MLDSA44_CERT_V01, SSH_MLDSA65_CERT_V01, SSH_MLDSA87_CERT_V01, SSH_RSA, SSH_RSA_CERT_V01,
    SUPPORTED_CERTIFICATE_ALGORITHMS, VerifiedCertificate, WireError, parse_certificate,
    verify_certificate,
};

/// Verifies a host certificate against the CA marker for this host and port.
/// Time is explicit Unix seconds. All critical options, including source-address
/// and force-command, are rejected because this layer cannot enforce them.
///
/// # Errors
/// Rejects an untrusted/revoked CA, wrong role/principal/time, invalid signature,
/// or any critical option. No prompt or trust-store mutation occurs.
pub fn verify_host_certificate(
    blob: &[u8],
    hosts: &crate::known_hosts::KnownHosts,
    host: &str,
    port: u16,
    now: u64,
) -> Result<VerifiedCertificate, CertificateError> {
    let certificate = parse_certificate(blob)?;
    if hosts.check(host, port, blob) == crate::known_hosts::KnownHostsStatus::Revoked
        || hosts.check(host, port, certificate.subject_public_key_blob())
            == crate::known_hosts::KnownHostsStatus::Revoked
    {
        return Err(CertificateError::SignatureKeyMismatch);
    }
    if hosts.check(host, port, certificate.signature_key_blob())
        != crate::known_hosts::KnownHostsStatus::CertificateAuthority
    {
        return Err(CertificateError::SignatureKeyMismatch);
    }
    verify_certificate(
        blob,
        CertificateType::Host,
        host,
        now,
        &[],
        certificate.signature_key_blob(),
    )
}

type PrincipalPolicy = dyn Fn(&str, &Certificate) -> Option<String>;
/// Explicit user-certificate CA, clock, and account-to-principal policy.
/// All critical options are rejected, not silently allowed. No issuance or
/// disk access is provided. Debug never delegates to supplied callbacks.
pub struct UserCertificateTrust {
    ca: Vec<u8>,
    now: Box<dyn Fn() -> u64>,
    principal: Box<PrincipalPolicy>,
}
impl std::fmt::Debug for UserCertificateTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserCertificateTrust")
            .finish_non_exhaustive()
    }
}
impl UserCertificateTrust {
    /// Configures one trusted public CA and explicit time/principal providers.
    /// The principal callback must return a concrete authorized principal for
    /// the requested account, or None to deny. Invalid CA bytes fail at verify.
    #[must_use]
    pub fn new(
        ca: &[u8],
        now: impl Fn() -> u64 + 'static,
        principal: impl Fn(&str, &Certificate) -> Option<String> + 'static,
    ) -> Self {
        Self {
            ca: ca.to_vec(),
            now: Box::new(now),
            principal: Box::new(principal),
        }
    }
    /// Checks the CA signature, role, account principal and current validity.
    ///
    /// # Errors
    /// Rejects invalid certificates, critical options, or denied principals.
    /// Panicking application callbacks fail closed without leaking their data.
    pub fn verify(
        &self,
        username: &str,
        blob: &[u8],
    ) -> Result<VerifiedCertificate, CertificateError> {
        let certificate = parse_certificate(blob)?;
        let (now, principal) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ((self.now)(), (self.principal)(username, &certificate))
        }))
        .map_err(|_| CertificateError::InvalidPrincipal)?;
        let principal = principal.ok_or(CertificateError::PrincipalMismatch)?;
        verify_certificate(blob, CertificateType::User, &principal, now, &[], &self.ca)
    }
}
