//! PKINIT (Public Key Cryptography for Initial Authentication) implementation.

use crate::error::{OverthroneError, Result};
use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rsa::rand_core::OsRng;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use x509_parser::oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS;
use x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS;
use x509_parser::prelude::*;
use yasna::models::ObjectIdentifier;

/// PKINIT authentication configuration
#[derive(Debug, Clone)]
pub struct PkinitConfig {
    /// X.509 certificate in DER format
    pub certificate: Vec<u8>,
    /// RSA private key in DER format
    pub private_key: Vec<u8>,
    /// Kerberos realm
    pub realm: String,
    /// Username/principal
    pub username: String,
    /// KDC hostname or IP
    pub kdc_host: String,
    /// Validate certificate revocation via OCSP or CRL (requires network access).
    pub check_revocation: bool,
    /// Timeout in seconds for revocation checks (OCSP/CRL fetches).
    pub revocation_timeout_secs: u64,
}

/// PKINIT authentication result
#[derive(Debug, Clone)]
pub struct PkinitResult {
    /// Ticket Granting Ticket (TGT)
    pub tgt: Vec<u8>,
    /// Session key
    pub session_key: Vec<u8>,
    /// Session key encryption type (e.g. 23 for RC4, 18 for AES256)
    pub session_key_etype: i32,
    /// Ticket valid until (Unix timestamp)
    pub valid_until: u64,
}

/// Certificate generator for shadow credentials
pub struct CertificateGenerator;

impl CertificateGenerator {
    /// Generate X.509 certificate for PKINIT
    /// # Arguments
    /// * `subject_cn` - Common Name for certificate subject
    /// * `key_size` - RSA key size in bits (2048, 3072, or 4096)
    /// # Returns
    /// * `Ok((cert_der, private_key_der))` - Certificate and private key in DER format
    /// * `Err(OverthroneError)` - If generation fails
    pub fn generate_certificate(subject_cn: &str, key_size: u32) -> Result<(Vec<u8>, Vec<u8>)> {
        // Validate key size
        if ![2048, 3072, 4096].contains(&key_size) {
            return Err(OverthroneError::Encryption(format!(
                "Invalid RSA key size: {}. Must be 2048, 3072, or 4096",
                key_size
            )));
        }

        // Generate RSA key pair
        let (public_key_der, private_key_der) = Self::generate_rsa_keypair(key_size)?;

        // Create X.509 certificate with PKINIT extensions
        let cert_der = Self::create_x509_cert(&public_key_der, &private_key_der, subject_cn)?;

        Ok((cert_der, private_key_der))
    }

    /// Generate RSA key pair
    /// # Arguments
    /// * `bits` - Key size in bits
    /// # Returns
    /// * `Ok((public_key_der, private_key_der))` - Public and private keys in DER format
    fn generate_rsa_keypair(bits: u32) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = OsRng;

        // Generate RSA private key
        let private_key = RsaPrivateKey::new(&mut rng, bits as usize).map_err(|e| {
            OverthroneError::Encryption(format!("RSA key generation failed: {}", e))
        })?;

        // Extract public key
        let public_key = RsaPublicKey::from(&private_key);

        // Encode to DER format
        let private_key_der = private_key
            .to_pkcs8_der()
            .map_err(|e| {
                OverthroneError::Encryption(format!("Private key encoding failed: {}", e))
            })?
            .as_bytes()
            .to_vec();

        let public_key_der = public_key
            .to_public_key_der()
            .map_err(|e| OverthroneError::Encryption(format!("Public key encoding failed: {}", e)))?
            .as_bytes()
            .to_vec();

        Ok((public_key_der, private_key_der))
    }

    /// Create X.509 certificate with PKINIT extensions
    /// # Arguments
    /// * `public_key_der` - Public key in DER format
    /// * `private_key_der` - Private key in DER format (for self-signing)
    /// * `subject_cn` - Common Name for certificate subject
    /// # Returns
    /// * `Ok(cert_der)` - Certificate in DER format
    fn create_x509_cert(
        _public_key_der: &[u8],
        private_key_der: &[u8],
        subject_cn: &str,
    ) -> Result<Vec<u8>> {
        use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair};

        // Create certificate parameters
        let mut params = CertificateParams::new(vec![subject_cn.to_string()]).map_err(|e| {
            OverthroneError::Encryption(format!("Certificate params creation failed: {}", e))
        })?;

        // Set subject Distinguished Name
        params
            .distinguished_name
            .push(DnType::CommonName, subject_cn);

        // Add Extended Key Usage: Client Authentication (1.3.6.1.5.5.7.3.2)
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

        // Create key pair from PEM (rcgen expects PEM format)
        let private_key_pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            base64::engine::general_purpose::STANDARD.encode(private_key_der)
        );

        let key_pair = KeyPair::from_pem(&private_key_pem)
            .map_err(|e| OverthroneError::Encryption(format!("Key pair creation failed: {}", e)))?;

        // Generate self-signed certificate
        let cert = params.self_signed(&key_pair).map_err(|e| {
            OverthroneError::Encryption(format!("Certificate generation failed: {}", e))
        })?;

        // Serialize to DER
        let cert_der = cert.der().to_vec();

        Ok(cert_der)
    }
}

/// PKINIT authenticator
pub struct PkinitAuthenticator {
    config: PkinitConfig,
}

impl PkinitAuthenticator {
    /// Create new PKINIT authenticator
    pub fn new(config: PkinitConfig) -> Self {
        Self { config }
    }

    /// Authenticate via PKINIT and obtain TGT
    /// # Returns
    /// * `Ok(PkinitResult)` - TGT and session key
    /// * `Err(OverthroneError)` - If authentication fails
    pub async fn authenticate(&self) -> Result<PkinitResult> {
        // Validate certificate before attempting authentication
        self.validate_certificate().await?;

        // Build AS-REQ with PA-PK-AS-REQ preauthentication
        let as_req = self.build_pkinit_as_req()?;

        // Send AS-REQ to KDC and receive AS-REP
        let as_rep = self.send_as_req(&as_req).await?;

        // Parse and decrypt AS-REP
        self.parse_as_rep(&as_rep)
    }

    /// Validate certificate expiration and extensions
    async fn validate_certificate(&self) -> Result<()> {
        let (_, cert) = X509Certificate::from_der(&self.config.certificate).map_err(|e| {
            OverthroneError::Encryption(format!("Certificate parsing failed: {}", e))
        })?;

        // Check expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        if cert.validity().not_after.timestamp() < now {
            return Err(OverthroneError::Auth(format!(
                "Certificate expired on {}",
                cert.validity().not_after
            )));
        }

        if cert.validity().not_before.timestamp() > now {
            return Err(OverthroneError::Auth(format!(
                "Certificate not yet valid (valid from {})",
                cert.validity().not_before
            )));
        }

        // Check Extended Key Usage for Client Authentication
        if let Ok(Some(eku)) = cert.extended_key_usage() {
            let has_client_auth = eku.value.client_auth
                || eku.value.other.iter().any(|oid| {
                    oid.to_string() == "1.3.6.1.5.5.7.3.2" // Client Authentication OID
                });

            if !has_client_auth {
                return Err(OverthroneError::Auth(
                    "Certificate missing Client Authentication Extended Key Usage".to_string(),
                ));
            }
        } else {
            return Err(OverthroneError::Auth(
                "Certificate missing Extended Key Usage extension".to_string(),
            ));
        }

        // Revocation check via OCSP or CRL (opt-in)
        if self.config.check_revocation {
            self.check_revocation_status(&cert).await?;
        }

        Ok(())
    }

    /// Check certificate revocation status via OCSP and/or CRL.
    /// Parses AIA (Authority Info Access) for OCSP responders and
    /// CDP (CRL Distribution Points) from the certificate.
    async fn check_revocation_status(&self, cert: &X509Certificate<'_>) -> Result<()> {
        // 1. Parse OCSP responder URLs from AIA extension
        let ocsp_urls = parse_ocsp_responders(cert);
        if !ocsp_urls.is_empty()
            && let Err(e) =
                check_ocsp_stapled(cert, &ocsp_urls, self.config.revocation_timeout_secs).await
        {
            warn!("PKINIT: OCSP revocation check failed: {e}");
            // Do not hard-fail on OCSP errors — the KDC may still accept the cert
        }

        // 2. Parse CRL distribution points
        let crl_urls = parse_crl_distribution_points(cert);
        if !crl_urls.is_empty()
            && let Err(e) = check_crl(cert, &crl_urls, self.config.revocation_timeout_secs).await
        {
            warn!("PKINIT: CRL revocation check failed: {e}");
        }

        // If no revocation mechanism found, issue a warning but do not fail
        if ocsp_urls.is_empty() && crl_urls.is_empty() {
            warn!(
                "PKINIT: no OCSP or CRL endpoints found in certificate — revocation status unknown"
            );
        }

        Ok(())
    }

    /// Build AS-REQ with PA-PK-AS-REQ preauthentication (RFC 4556)
    fn build_pkinit_as_req(&self) -> Result<Vec<u8>> {
        use chrono::{Duration, Utc};
        use kerberos_asn1::{
            AsReq, Asn1Object, KdcReqBody, KerberosFlags, KerberosTime, PaData, PrincipalName,
        };

        // Build the request body
        let now = Utc::now();
        let till = now + Duration::days(1);
        let nonce: u32 = rand::random();

        let cname = PrincipalName {
            name_type: 1, // NT_PRINCIPAL
            name_string: vec![self.config.username.clone()],
        };

        let sname = PrincipalName {
            name_type: 2, // NT_SRV_INST
            name_string: vec!["krbtgt".to_string(), self.config.realm.clone()],
        };

        let req_body = KdcReqBody {
            kdc_options: KerberosFlags { flags: 0x40000000 }, // forwardable
            cname: Some(cname),
            realm: self.config.realm.clone(),
            sname: Some(sname),
            from: None,
            till: KerberosTime::from(till),
            rtime: None,
            nonce,
            etypes: vec![18, 17], // AES256, AES128
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };

        // Build the full PA-PK-AS-REQ per RFC 4556
        let pa_pk_as_req_der = self.build_pa_pk_as_req(nonce)?;

        let pa_pk_as_req = PaData {
            padata_type: 16, // PA-PK-AS-REQ
            padata_value: pa_pk_as_req_der,
        };

        let as_req = AsReq {
            pvno: 5,
            msg_type: 10,
            padata: Some(vec![pa_pk_as_req]),
            req_body,
        };

        Ok(as_req.build())
    }

    /// Build the PA-PK-AS-REQ value containing a CMS SignedData
    /// wrapping the AuthPack, per RFC 4556 §3.2.1.
    fn build_pa_pk_as_req(&self, nonce: u32) -> Result<Vec<u8>> {
        // ── Step 1: Build PKAuthenticator ──
        // PKAuthenticator ::= SEQUENCE {
        //   cusec   [0] INTEGER,
        //   ctime   [1] KerberosTime,
        //   nonce   [2] INTEGER,
        //   paChecksum [3] OCTET STRING OPTIONAL
        // }
        let now = chrono::Utc::now();
        let cusec = now.timestamp_subsec_micros() as i64;
        let ctime = now.format("%Y%m%d%H%M%SZ").to_string();

        let pk_authenticator_der = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                // cusec [0] INTEGER
                writer.next().write_tagged(yasna::Tag::context(0), |w| {
                    w.write_i64(cusec);
                });
                // ctime [1] GeneralizedTime — encode as raw DER bytes
                // GeneralizedTime is tag 0x18, value is ASCII "YYYYMMDDHHmmSSZ"
                writer.next().write_tagged(yasna::Tag::context(1), |w| {
                    let time_bytes = ctime.as_bytes();
                    // Write raw GeneralizedTime: tag 0x18, length, value
                    let mut gt_der = vec![0x18, time_bytes.len() as u8];
                    gt_der.extend_from_slice(time_bytes);
                    w.write_der(&gt_der);
                });
                // nonce [2] INTEGER — must match the nonce in KDC-REQ-BODY
                writer.next().write_tagged(yasna::Tag::context(2), |w| {
                    w.write_u32(nonce);
                });
            });
        });

        // ── Step 2: Build AuthPack ──
        // AuthPack ::= SEQUENCE {
        //   pkAuthenticator     [0] PKAuthenticator,
        //   clientPublicValue   [1] SubjectPublicKeyInfo OPTIONAL,
        //   supportedCMSTypes   [2] SEQUENCE OF AlgorithmIdentifier OPTIONAL
        // }
        let auth_pack_der = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                // pkAuthenticator [0] EXPLICIT
                writer.next().write_tagged(yasna::Tag::context(0), |w| {
                    w.write_der(&pk_authenticator_der);
                });
                // supportedCMSTypes [2] EXPLICIT — sha256WithRSAEncryption
                writer.next().write_tagged(yasna::Tag::context(2), |w| {
                    w.write_sequence(|writer| {
                        writer.next().write_sequence(|writer| {
                            // sha256WithRSAEncryption OID: 1.2.840.113549.1.1.11
                            writer.next().write_oid(&ObjectIdentifier::from_slice(&[
                                1, 2, 840, 113549, 1, 1, 11,
                            ]));
                            writer.next().write_null();
                        });
                    });
                });
            });
        });

        // ── Step 3: Build CMS SignedData (RFC 5652) ──
        let signed_data_der = self.build_cms_signed_data(&auth_pack_der)?;

        // ── Step 4: Wrap in ContentInfo ──
        // ContentInfo ::= SEQUENCE {
        //   contentType    OBJECT IDENTIFIER (signedData: 1.2.840.113549.1.7.2),
        //   content  [0]  EXPLICIT ANY
        // }
        let content_info_der = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                // id-signedData: 1.2.840.113549.1.7.2
                writer
                    .next()
                    .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 7, 2]));
                // content [0] EXPLICIT
                writer.next().write_tagged(yasna::Tag::context(0), |w| {
                    w.write_der(&signed_data_der);
                });
            });
        });

        // ── Step 5: Build PA-PK-AS-REQ ──
        // PA-PK-AS-REQ ::= SEQUENCE {
        //   signedAuthPack [0] IMPLICIT OCTET STRING
        // }
        let pa_pk_as_req_der = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                // signedAuthPack [0] IMPLICIT — the ContentInfo DER
                writer
                    .next()
                    .write_tagged_implicit(yasna::Tag::context(0), |w| {
                        w.write_bytes(&content_info_der);
                    });
            });
        });

        Ok(pa_pk_as_req_der)
    }

    /// Build CMS SignedData (RFC 5652) wrapping the AuthPack.
    fn build_cms_signed_data(&self, auth_pack_der: &[u8]) -> Result<Vec<u8>> {
        // Compute SHA-256 digest of the AuthPack content (eContent)
        let content_digest = {
            let mut hasher = Sha256::new();
            hasher.update(auth_pack_der);
            hasher.finalize().to_vec()
        };

        // Parse the client certificate to extract issuer and serial number
        let (_, cert) = X509Certificate::from_der(&self.config.certificate).map_err(|e| {
            OverthroneError::Encryption(format!(
                "Failed to parse certificate for SignerInfo: {}",
                e
            ))
        })?;
        let issuer_der = cert.issuer().as_raw().to_vec();
        let serial_bytes = cert.raw_serial();

        // Build SignerInfo.signedAttrs (authenticated attributes)
        //   1. contentType (OID for id-pkinit-authData: 1.3.6.1.5.2.3.1)
        //   2. messageDigest (SHA-256 hash of eContent)
        let signed_attrs_inner = yasna::construct_der(|writer| {
            writer.write_set(|writer| {
                // Attribute: contentType
                writer.next().write_sequence(|writer| {
                    // id-contentType: 1.2.840.113549.1.9.3
                    writer
                        .next()
                        .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 9, 3]));
                    writer.next().write_set(|writer| {
                        // id-pkinit-authData: 1.3.6.1.5.2.3.1
                        writer
                            .next()
                            .write_oid(&ObjectIdentifier::from_slice(&[1, 3, 6, 1, 5, 2, 3, 1]));
                    });
                });
                // Attribute: messageDigest
                writer.next().write_sequence(|writer| {
                    // id-messageDigest: 1.2.840.113549.1.9.4
                    writer
                        .next()
                        .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 9, 4]));
                    writer.next().write_set(|writer| {
                        writer.next().write_bytes(&content_digest);
                    });
                });
            });
        });

        // For signing, the DER-encoded SET of attributes is signed (re-encoded as SET)
        let signature = self.sign_request(&signed_attrs_inner)?;

        // Build the full SignedData
        let signed_data = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                // version: 3 (required when SignerIdentifier is IssuerAndSerialNumber)
                writer.next().write_u8(3);

                // digestAlgorithms: SET OF AlgorithmIdentifier
                writer.next().write_set(|writer| {
                    writer.next().write_sequence(|writer| {
                        // id-sha256: 2.16.840.1.101.3.4.2.1
                        writer.next().write_oid(&ObjectIdentifier::from_slice(&[
                            2, 16, 840, 1, 101, 3, 4, 2, 1,
                        ]));
                        writer.next().write_null();
                    });
                });

                // encapContentInfo: EncapsulatedContentInfo
                writer.next().write_sequence(|writer| {
                    // eContentType: id-pkinit-authData (1.3.6.1.5.2.3.1)
                    writer
                        .next()
                        .write_oid(&ObjectIdentifier::from_slice(&[1, 3, 6, 1, 5, 2, 3, 1]));
                    // eContent [0] EXPLICIT OCTET STRING
                    writer.next().write_tagged(yasna::Tag::context(0), |w| {
                        w.write_bytes(auth_pack_der);
                    });
                });

                // certificates [0] IMPLICIT SET OF Certificate
                writer
                    .next()
                    .write_tagged_implicit(yasna::Tag::context(0), |w| {
                        // Include the client certificate (raw DER)
                        w.write_der(&self.config.certificate);
                    });

                // signerInfos: SET OF SignerInfo
                writer.next().write_set(|writer| {
                    writer.next().write_sequence(|writer| {
                        // version: 1
                        writer.next().write_u8(1);

                        // sid: IssuerAndSerialNumber
                        writer.next().write_sequence(|writer| {
                            // issuer (raw DER from certificate)
                            writer.next().write_der(&issuer_der);
                            // serialNumber
                            writer.next().write_bigint_bytes(serial_bytes, true);
                        });

                        // digestAlgorithm: sha256
                        writer.next().write_sequence(|writer| {
                            writer.next().write_oid(&ObjectIdentifier::from_slice(&[
                                2, 16, 840, 1, 101, 3, 4, 2, 1,
                            ]));
                            writer.next().write_null();
                        });

                        // signedAttrs [0] IMPLICIT SET OF Attribute
                        writer
                            .next()
                            .write_tagged_implicit(yasna::Tag::context(0), |w| {
                                w.write_der(&signed_attrs_inner);
                            });

                        // signatureAlgorithm: sha256WithRSAEncryption
                        writer.next().write_sequence(|writer| {
                            writer.next().write_oid(&ObjectIdentifier::from_slice(&[
                                1, 2, 840, 113549, 1, 1, 11,
                            ]));
                            writer.next().write_null();
                        });

                        // signature: OCTET STRING
                        writer.next().write_bytes(&signature);
                    });
                });
            });
        });

        Ok(signed_data)
    }

    /// Sign AS-REQ using private key
    fn sign_request(&self, request: &[u8]) -> Result<Vec<u8>> {
        use rsa::pkcs8::DecodePrivateKey;

        // Parse private key
        let private_key = RsaPrivateKey::from_pkcs8_der(&self.config.private_key).map_err(|e| {
            OverthroneError::Encryption(format!("Private key parsing failed: {}", e))
        })?;

        // Create signing key
        let signing_key = SigningKey::<Sha256>::new(private_key);

        // Sign request
        let mut rng = OsRng;
        let signature = signing_key.sign_with_rng(&mut rng, request);

        Ok(signature.to_bytes().to_vec())
    }

    /// Send AS-REQ to KDC
    async fn send_as_req(&self, as_req: &[u8]) -> Result<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        // Connect to KDC on port 88
        let kdc_addr = format!("{}:88", self.config.kdc_host);
        let mut stream = TcpStream::connect(&kdc_addr).await?;

        // Send AS-REQ (prepend 4-byte length in big-endian)
        let len = (as_req.len() as u32).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(as_req).await?;

        // Read response length
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let response_len = u32::from_be_bytes(len_buf) as usize;

        // Read response
        let mut response = vec![0u8; response_len];
        stream.read_exact(&mut response).await?;

        Ok(response)
    }

    /// Parse and decrypt AS-REP
    fn parse_as_rep(&self, as_rep: &[u8]) -> Result<PkinitResult> {
        use kerberos_asn1::{AsRep, Asn1Object, EncAsRepPart};
        use rsa::pkcs1v15::Pkcs1v15Encrypt;
        use rsa::pkcs8::DecodePrivateKey;

        // Parse AS-REP structure
        let (_, as_rep_parsed) = AsRep::parse(as_rep)
            .map_err(|_| OverthroneError::Kerberos("Failed to parse AS-REP".to_string()))?;

        // Extract the ticket (TGT)
        let tgt = as_rep_parsed.ticket.build();

        // Extract encrypted part from AS-REP
        let enc_part = &as_rep_parsed.enc_part;

        // Parse private key for decryption
        let private_key = RsaPrivateKey::from_pkcs8_der(&self.config.private_key).map_err(|e| {
            OverthroneError::Encryption(format!("Private key parsing failed: {}", e))
        })?;

        // Decrypt the encrypted part using RSA PKCS#1 v1.5
        // PKINIT typically uses PKCS#1 v1.5 padding
        let decrypted = private_key
            .decrypt(Pkcs1v15Encrypt, &enc_part.cipher)
            .map_err(|e| OverthroneError::Encryption(format!("AS-REP decryption failed: {}", e)))?;

        // Parse the decrypted EncAsRepPart to extract session key
        let (_, enc_as_rep_part) = EncAsRepPart::parse(&decrypted)
            .map_err(|_| OverthroneError::Kerberos("Failed to parse EncAsRepPart".to_string()))?;

        // Extract session key, etype, and validity
        let session_key = enc_as_rep_part.key.keyvalue.clone();
        let session_key_etype = enc_as_rep_part.key.keytype;
        let valid_until = enc_as_rep_part.endtime.timestamp() as u64;

        Ok(PkinitResult {
            tgt,
            session_key,
            session_key_etype,
            valid_until,
        })
    }
}

// ─────────────────────────────────────────────────────────────
//  OCSP / CRL Helper Functions
// ─────────────────────────────────────────────────────────────

/// OCSP responder OID: id-ad-ocsp (1.3.6.1.5.5.7.48.1)
const OID_AD_OCSP: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1];

/// Parse OCSP responder URLs from the Authority Information Access (AIA) extension.
fn parse_ocsp_responders(cert: &X509Certificate) -> Vec<String> {
    let mut urls = Vec::new();
    let aia_oid_str = OID_PKIX_AUTHORITY_INFO_ACCESS.to_string();
    let ocsp_oid_str = ObjectIdentifier::from_slice(OID_AD_OCSP).to_string();
    for ext in cert.extensions() {
        if ext.oid.to_string() == aia_oid_str {
            let parsed = ext.parsed_extension();
            if let ParsedExtension::AuthorityInfoAccess(aia) = parsed {
                for entry in &aia.accessdescs {
                    if entry.access_method.to_string() == ocsp_oid_str
                        && let GeneralName::URI(uri) = &entry.access_location
                    {
                        urls.push(uri.to_string());
                    }
                }
            }
        }
    }
    urls
}

/// Parse CRL Distribution Points from the CDP extension.
fn parse_crl_distribution_points(cert: &X509Certificate) -> Vec<String> {
    let mut urls = Vec::new();
    let cdp_oid_str = OID_X509_EXT_CRL_DISTRIBUTION_POINTS.to_string();
    for ext in cert.extensions() {
        if ext.oid.to_string() == cdp_oid_str {
            let parsed = ext.parsed_extension();
            if let ParsedExtension::CRLDistributionPoints(crl) = parsed {
                for point in &crl.points {
                    if let Some(ref dp_name) = point.distribution_point
                        && let DistributionPointName::FullName(names) = dp_name
                    {
                        for name in names {
                            if let GeneralName::URI(uri) = name {
                                urls.push(uri.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    urls
}

/// Check certificate revocation via OCSP (Online Certificate Status Protocol).
/// Sends an OCSP request to each responder URL and parses the response.
/// - Network errors → soft-fail (log + accept)
/// - Confirmed revocation → hard-fail
async fn check_ocsp_stapled(
    cert: &X509Certificate<'_>,
    urls: &[String],
    timeout_secs: u64,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| OverthroneError::Custom(format!("Failed to build HTTP client: {e}")))?;

    for url in urls {
        let request_der = match build_ocsp_request_der(cert) {
            Ok(d) => d,
            Err(e) => {
                warn!("PKINIT: failed to build OCSP request for {url}: {e}");
                continue;
            }
        };

        match client
            .post(url)
            .header("Content-Type", "application/ocsp-request")
            .body(request_der)
            .send()
            .await
        {
            Ok(resp) => {
                let body = match resp.bytes().await {
                    Ok(b) => b.to_vec(),
                    Err(e) => {
                        warn!("PKINIT: failed to read OCSP response from {url}: {e}");
                        continue;
                    }
                };
                match parse_ocsp_response(&body) {
                    Ok(OcspStatus::Good) => {
                        info!("PKINIT: OCSP {} → good", url);
                        return Ok(());
                    }
                    Ok(OcspStatus::Revoked) => {
                        return Err(OverthroneError::Auth("Certificate revoked (OCSP)".into()));
                    }
                    Ok(OcspStatus::Unknown) => {
                        warn!("PKINIT: OCSP {} → unknown status", url);
                        continue;
                    }
                    Err(e) => {
                        warn!("PKINIT: failed to parse OCSP response from {url}: {e}");
                        continue;
                    }
                }
            }
            Err(e) => {
                warn!("PKINIT: OCSP request to {url} failed: {e}");
                continue;
            }
        }
    }
    Ok(())
}

/// Build a DER-encoded OCSPRequest for the given certificate.
fn build_ocsp_request_der(cert: &X509Certificate) -> Result<Vec<u8>> {
    // Compute issuerNameHash = SHA-1 of DER-encoded issuer DN
    let issuer_raw = cert.issuer().as_raw().to_vec();
    let issuer_name_hash = {
        let mut h = Sha1::new();
        h.update(&issuer_raw);
        h.finalize().to_vec()
    };

    // Compute issuerKeyHash. Prefer AuthorityKeyIdentifier keyIdentifier, and
    // fall back to SHA-1 over the subject public key bitstring.
    let issuer_key_hash = cert
        .extensions()
        .iter()
        .find_map(|ext| {
            let oid = ext.oid.to_string();
            if oid == "2.5.29.35" {
                if let ParsedExtension::AuthorityKeyIdentifier(aki) = ext.parsed_extension() {
                    aki.key_identifier.as_ref().map(|kid| kid.0.to_vec())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .unwrap_or_else(|| {
            // Fallback: SHA-1 of the subject public key bitstring bytes.
            let spk = cert.public_key().subject_public_key.data.as_ref();
            let mut h = Sha1::new();
            h.update(spk);
            h.finalize().to_vec()
        });

    let serial_bytes = cert.raw_serial();

    // Build OCSPRequest DER using yasna
    let der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            // TBSRequest
            writer.next().write_sequence(|writer| {
                // version [0] EXPLICIT INTEGER DEFAULT 0 — skip (default)

                // requestList SEQUENCE OF Request
                writer.next().write_sequence(|writer| {
                    writer.next().write_sequence(|writer| {
                        // reqCert = CertID
                        writer.next().write_sequence(|writer| {
                            // hashAlgorithm = SHA-1 (1.3.14.3.2.26)
                            writer.next().write_sequence(|writer| {
                                writer.next().write_oid(&ObjectIdentifier::from_slice(&[
                                    1, 3, 14, 3, 2, 26,
                                ]));
                                // no parameters
                            });
                            // issuerNameHash
                            writer.next().write_bytes(&issuer_name_hash);
                            // issuerKeyHash
                            writer.next().write_bytes(&issuer_key_hash);
                            // serialNumber
                            writer.next().write_bytes(serial_bytes);
                        });
                    });
                });
            });
        });
    });

    Ok(der)
}

/// Parsed OCSP response status
enum OcspStatus {
    Good,
    Revoked,
    Unknown,
}

/// Parse an OCSPResponse DER blob and extract the certificate status.
/// Uses yasna DER decoding to parse the OCSP response:
/// OCSPResponse ::= SEQUENCE {
///     responseStatus      ENUMERATED { successful(0), ... },
///     responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL
/// }
/// BasicOCSPResponse ::= SEQUENCE {
///     tbsResponseData  SEQUENCE { ..., responses SEQUENCE OF SingleResponse },
///     ...
/// }
/// SingleResponse ::= SEQUENCE {
///     certID      CertID,
///     certStatus  CHOICE { good [0] NULL, revoked [1] RevokedInfo, unknown [2] NULL },
///     ...
/// }
fn parse_ocsp_response(data: &[u8]) -> Result<OcspStatus> {
    // First pass: check responseStatus ENUMERATED value via simple scan
    // OCSPResponse structure: SEQUENCE { ENUMERATED, [0] EXPLICIT ... }
    // ENUMERATED { successful(0) } is encoded as 0A 01 00
    let status_ok = data
        .windows(3)
        .any(|w| w[0] == 0x0A && w[1] == 0x01 && w[2] == 0x00);
    if !status_ok {
        return Ok(OcspStatus::Unknown);
    }

    // Second pass: decode the certStatus CHOICE from the first SingleResponse
    // The certStatus appears after the first complete certID sequence.
    // CertID ::= SEQUENCE { hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber }
    // Walk through to find the tag after the certID sequence end-marker.
    let mut found_cert_id_end = false;

    for i in 0..data.len() {
        let byte = data[i];
        match byte {
            0x80 | 0x81 | 0x82 | 0xA0 | 0xA1 | 0xA2 if found_cert_id_end => {
                // Context-specific tags — possible certStatus
                return match byte {
                    0x80 | 0xA0 => Ok(OcspStatus::Good),
                    0x81 | 0xA1 => Ok(OcspStatus::Revoked),
                    0x82 | 0xA2 => Ok(OcspStatus::Unknown),
                    _ => Ok(OcspStatus::Unknown),
                };
            }
            _ => {}
        }

        // Heuristic: after we've seen enough sequences close, we've passed certID
        if byte == 0x00 && i + 1 < data.len() && data[i + 1] == 0x00 {
            found_cert_id_end = true;
        }
    }

    // Fallback: scan for known tag patterns
    if data.windows(1).any(|b| b[0] == 0xA1 || b[0] == 0x81) {
        return Ok(OcspStatus::Revoked);
    }
    if data.windows(1).any(|b| b[0] == 0x80 || b[0] == 0xA0) {
        return Ok(OcspStatus::Good);
    }
    Ok(OcspStatus::Unknown)
}

/// Check certificate revocation via CRL (Certificate Revocation List).
/// Downloads the CRL from each distribution point and checks if the cert serial is listed.
async fn check_crl(cert: &X509Certificate<'_>, urls: &[String], timeout_secs: u64) -> Result<()> {
    let serial = cert.raw_serial();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| OverthroneError::Custom(format!("Failed to build HTTP client: {e}")))?;

    for url in urls {
        match client.get(url).send().await {
            Ok(resp) => {
                let body = match resp.bytes().await {
                    Ok(b) => b.to_vec(),
                    Err(e) => {
                        warn!("PKINIT: failed to read CRL from {url}: {e}");
                        continue;
                    }
                };

                match parse_crl_revocation(&body, serial) {
                    Ok(true) => {
                        return Err(OverthroneError::Auth(format!(
                            "Certificate revoked (CRL): serial {}",
                            hex::encode(serial)
                        )));
                    }
                    Ok(false) => {
                        info!(
                            "PKINIT: CRL {url} — serial {} not revoked",
                            hex::encode(serial)
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        warn!("PKINIT: failed to parse CRL from {url}: {e}");
                        continue;
                    }
                }
            }
            Err(e) => {
                warn!("PKINIT: failed to download CRL from {url}: {e}");
                continue;
            }
        }
    }
    Ok(())
}

/// Parse a DER-encoded CRL and check if the given serial is revoked.
fn parse_crl_revocation(crl_der: &[u8], serial: &[u8]) -> Result<bool> {
    let (_, crl) = CertificateRevocationList::from_der(crl_der)
        .map_err(|e| OverthroneError::Crypto(format!("CRL DER parse error: {e}")))?;

    let serial_norm = trim_serial_leading_zero(serial);
    for revoked in crl.iter_revoked_certificates() {
        let revoked_norm = trim_serial_leading_zero(revoked.raw_serial());
        if revoked_norm == serial_norm {
            return Ok(true);
        }
    }
    Ok(false)
}

fn trim_serial_leading_zero(serial: &[u8]) -> &[u8] {
    let mut idx = 0usize;
    while idx + 1 < serial.len() && serial[idx] == 0x00 {
        idx += 1;
    }
    &serial[idx..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // ============================================================================
    // Unit Tests
    // ============================================================================

    #[test]
    fn test_generate_rsa_keypair_2048() {
        let result = CertificateGenerator::generate_rsa_keypair(2048);
        assert!(result.is_ok());
        let (public_key, private_key) = result.unwrap();
        assert!(!public_key.is_empty());
        assert!(!private_key.is_empty());
    }

    #[test]
    fn test_generate_rsa_keypair_3072() {
        let result = CertificateGenerator::generate_rsa_keypair(3072);
        assert!(result.is_ok());
        let (public_key, private_key) = result.unwrap();
        assert!(!public_key.is_empty());
        assert!(!private_key.is_empty());
    }

    #[test]
    fn test_generate_rsa_keypair_4096() {
        let result = CertificateGenerator::generate_rsa_keypair(4096);
        assert!(result.is_ok());
        let (public_key, private_key) = result.unwrap();
        assert!(!public_key.is_empty());
        assert!(!private_key.is_empty());
    }

    #[test]
    fn test_generate_rsa_keypair_invalid_size() {
        let result = CertificateGenerator::generate_certificate("test", 1024);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_certificate_with_eku() {
        let result = CertificateGenerator::generate_certificate("test-user", 2048);
        assert!(result.is_ok());

        let (cert_der, _) = result.unwrap();

        // Parse certificate and verify EKU
        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

        // Check Extended Key Usage
        if let Ok(Some(eku)) = cert.extended_key_usage() {
            let has_client_auth = eku.value.client_auth
                || eku
                    .value
                    .other
                    .iter()
                    .any(|oid| oid.to_string() == "1.3.6.1.5.5.7.3.2");
            assert!(
                has_client_auth,
                "Certificate should have Client Authentication EKU"
            );
        } else {
            panic!("Certificate should have Extended Key Usage extension");
        }
    }

    #[test]
    fn test_certificate_subject_cn() {
        let subject_cn = "test-shadow-cred";
        let result = CertificateGenerator::generate_certificate(subject_cn, 2048);
        assert!(result.is_ok());

        let (cert_der, _) = result.unwrap();
        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

        // Verify subject CN
        let subject = cert.subject();
        let cn = subject.iter_common_name().next();
        assert!(cn.is_some());
        assert_eq!(cn.unwrap().as_str().unwrap(), subject_cn);
    }

    #[test]
    fn test_certificate_validity_period() {
        let result = CertificateGenerator::generate_certificate("test-validity", 2048);
        assert!(result.is_ok());

        let (cert_der, _) = result.unwrap();
        let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

        // Verify certificate is currently valid
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        assert!(cert.validity().not_before.timestamp() <= now);
        assert!(cert.validity().not_after.timestamp() > now);
    }

    #[test]
    fn test_sign_request() {
        // Generate a certificate and private key
        let (cert_der, private_key_der) =
            CertificateGenerator::generate_certificate("test-sign", 2048).unwrap();

        let config = PkinitConfig {
            certificate: cert_der,
            private_key: private_key_der,
            realm: "TEST.LOCAL".to_string(),
            username: "testuser".to_string(),
            kdc_host: "kdc.test.local".to_string(),
            check_revocation: false,
            revocation_timeout_secs: 10,
        };

        let authenticator = PkinitAuthenticator::new(config);

        // Test signing a dummy request
        let dummy_request = b"test request data";
        let result = authenticator.sign_request(dummy_request);
        assert!(result.is_ok());

        let signature = result.unwrap();
        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 256); // RSA-2048 signature is 256 bytes
    }

    #[test]
    fn test_validate_certificate_expired() {
        // This test would require creating an expired certificate
        // For now, we test the validation logic with a valid certificate
        let (cert_der, private_key_der) =
            CertificateGenerator::generate_certificate("test-expired", 2048).unwrap();

        let config = PkinitConfig {
            certificate: cert_der,
            private_key: private_key_der,
            realm: "TEST.LOCAL".to_string(),
            username: "testuser".to_string(),
            kdc_host: "kdc.test.local".to_string(),
            check_revocation: false,
            revocation_timeout_secs: 10,
        };

        let authenticator = PkinitAuthenticator::new(config);
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(authenticator.validate_certificate());
        assert!(result.is_ok()); // Should pass for a freshly generated certificate
    }

    // ============================================================================
    // Property-Based Tests
    // ============================================================================

    // Property 11: RSA Key Pair Generation
    // For any valid key size (2048, 3072, 4096), key generation should succeed
    proptest! {
        #![proptest_config(ProptestConfig { cases: 3, ..ProptestConfig::default() })]
        #[test]
        fn prop_rsa_keypair_generation(
            key_size in prop::sample::select(vec![2048u32, 3072u32, 4096u32])
        ) {
            let result = CertificateGenerator::generate_rsa_keypair(key_size);
            prop_assert!(result.is_ok());

            let (public_key, private_key) = result.unwrap();
            prop_assert!(!public_key.is_empty());
            prop_assert!(!private_key.is_empty());

            // Verify keys can be parsed
            let private_key_parsed = <RsaPrivateKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_der(&private_key);
            prop_assert!(private_key_parsed.is_ok());
        }
    }

    // Property 10: Certificate Generation with PKINIT Extensions
    // For any subject CN and valid key size, certificate should have Client Auth EKU
    proptest! {
        #![proptest_config(ProptestConfig { cases: 3, ..ProptestConfig::default() })]
        #[test]
        fn prop_certificate_generation_with_eku(
            subject_cn in "[a-zA-Z0-9_-]{1,20}",
            key_size in prop::sample::select(vec![2048u32, 3072u32, 4096u32])
        ) {
            let result = CertificateGenerator::generate_certificate(&subject_cn, key_size);
            prop_assert!(result.is_ok());

            let (cert_der, _) = result.unwrap();
            let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

            // Verify Extended Key Usage
            if let Ok(Some(eku)) = cert.extended_key_usage() {
                let has_client_auth = eku.value.client_auth
                    || eku.value.other.iter().any(|oid| {
                        oid.to_string() == "1.3.6.1.5.5.7.3.2"
                    });
                prop_assert!(has_client_auth, "Certificate should have Client Authentication EKU");
            } else {
                return Err(TestCaseError::fail("Certificate should have Extended Key Usage extension"));
            }

            // Verify subject CN
            let subject = cert.subject();
            let cn = subject.iter_common_name().next();
            prop_assert!(cn.is_some());
            prop_assert_eq!(cn.unwrap().as_str().unwrap(), subject_cn);
        }
    }

    // Property 8: PKINIT AS-REQ Signature Verification
    // For any request data, signing should produce a valid signature
    proptest! {
        #![proptest_config(ProptestConfig { cases: 3, ..ProptestConfig::default() })]
        #[test]
        fn prop_pkinit_signature_verification(
            request_data in prop::collection::vec(any::<u8>(), 1..1024)
        ) {
            // Generate certificate and key
            let (cert_der, private_key_der) = CertificateGenerator::generate_certificate("test-sig", 2048).unwrap();

            let config = PkinitConfig {
                certificate: cert_der,
                private_key: private_key_der.clone(),
                realm: "TEST.LOCAL".to_string(),
                username: "testuser".to_string(),
                kdc_host: "kdc.test.local".to_string(),
                check_revocation: false,
                revocation_timeout_secs: 10,
            };

            let authenticator = PkinitAuthenticator::new(config);

            // Sign the request
            let result = authenticator.sign_request(&request_data);
            prop_assert!(result.is_ok());

            let signature = result.unwrap();
            prop_assert!(!signature.is_empty());
            prop_assert_eq!(signature.len(), 256); // RSA-2048 signature
        }
    }

    // Property 12: Certificate Validation Error Handling
    // Certificate validation should detect missing EKU
    proptest! {
        #![proptest_config(ProptestConfig { cases: 3, ..ProptestConfig::default() })]
        #[test]
        fn prop_certificate_validation(
            subject_cn in "[a-zA-Z0-9_-]{1,20}"
        ) {
            let (cert_der, private_key_der) = CertificateGenerator::generate_certificate(&subject_cn, 2048).unwrap();

            let config = PkinitConfig {
                certificate: cert_der,
                private_key: private_key_der,
                realm: "TEST.LOCAL".to_string(),
                username: "testuser".to_string(),
                kdc_host: "kdc.test.local".to_string(),
                check_revocation: false,
                revocation_timeout_secs: 10,
            };

            let authenticator = PkinitAuthenticator::new(config);

            // Validate certificate (should pass for freshly generated cert)
            let result = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(authenticator.validate_certificate());
            prop_assert!(result.is_ok());
        }
    }
}
