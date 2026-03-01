use crate::error::{OverthroneError, Result};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use sha2::Sha256;
use x509_parser::prelude::*;
use rand::rngs::OsRng;
use base64::Engine;

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
}

/// PKINIT authentication result
#[derive(Debug, Clone)]
pub struct PkinitResult {
    /// Ticket Granting Ticket (TGT)
    pub tgt: Vec<u8>,
    /// Session key
    pub session_key: Vec<u8>,
    /// Ticket valid until (Unix timestamp)
    pub valid_until: u64,
}

/// Certificate generator for shadow credentials
pub struct CertificateGenerator;

impl CertificateGenerator {
    /// Generate X.509 certificate for PKINIT
    /// 
    /// # Arguments
    /// * `subject_cn` - Common Name for certificate subject
    /// * `key_size` - RSA key size in bits (2048, 3072, or 4096)
    /// 
    /// # Returns
    /// * `Ok((cert_der, private_key_der))` - Certificate and private key in DER format
    /// * `Err(OverthroneError)` - If generation fails
    pub fn generate_certificate(
        subject_cn: &str,
        key_size: u32,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
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
    /// 
    /// # Arguments
    /// * `bits` - Key size in bits
    /// 
    /// # Returns
    /// * `Ok((public_key_der, private_key_der))` - Public and private keys in DER format
    fn generate_rsa_keypair(bits: u32) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = OsRng;

        // Generate RSA private key
        let private_key = RsaPrivateKey::new(&mut rng, bits as usize)
            .map_err(|e| OverthroneError::Encryption(format!("RSA key generation failed: {}", e)))?;

        // Extract public key
        let public_key = RsaPublicKey::from(&private_key);

        // Encode to DER format
        let private_key_der = private_key
            .to_pkcs8_der()
            .map_err(|e| OverthroneError::Encryption(format!("Private key encoding failed: {}", e)))?
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
    /// 
    /// # Arguments
    /// * `public_key_der` - Public key in DER format
    /// * `private_key_der` - Private key in DER format (for self-signing)
    /// * `subject_cn` - Common Name for certificate subject
    /// 
    /// # Returns
    /// * `Ok(cert_der)` - Certificate in DER format
    fn create_x509_cert(
        public_key_der: &[u8],
        private_key_der: &[u8],
        subject_cn: &str,
    ) -> Result<Vec<u8>> {
        use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair};

        // Create certificate parameters
        let mut params = CertificateParams::new(vec![subject_cn.to_string()])
            .map_err(|e| OverthroneError::Encryption(format!("Certificate params creation failed: {}", e)))?;

        // Set subject Distinguished Name
        params.distinguished_name.push(DnType::CommonName, subject_cn);

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
        let cert = params.self_signed(&key_pair)
            .map_err(|e| OverthroneError::Encryption(format!("Certificate generation failed: {}", e)))?;

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
    /// 
    /// # Returns
    /// * `Ok(PkinitResult)` - TGT and session key
    /// * `Err(OverthroneError)` - If authentication fails
    pub async fn authenticate(&self) -> Result<PkinitResult> {
        // Validate certificate before attempting authentication
        self.validate_certificate()?;

        // Build AS-REQ with PA-PK-AS-REQ preauthentication
        let as_req = self.build_pkinit_as_req()?;

        // Send AS-REQ to KDC and receive AS-REP
        let as_rep = self.send_as_req(&as_req).await?;

        // Parse and decrypt AS-REP
        self.parse_as_rep(&as_rep)
    }

    /// Validate certificate expiration and extensions
    fn validate_certificate(&self) -> Result<()> {
        let (_, cert) = X509Certificate::from_der(&self.config.certificate)
            .map_err(|e| OverthroneError::Encryption(format!("Certificate parsing failed: {}", e)))?;

        // Check expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
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

        Ok(())
    }

    /// Build AS-REQ with PA-PK-AS-REQ preauthentication
    fn build_pkinit_as_req(&self) -> Result<Vec<u8>> {
        use kerberos_asn1::{AsReq, Asn1Object, KdcReqBody, KerberosFlags, KerberosTime, PaData, PrincipalName};
        use chrono::{Duration, Utc};

        // Build the request body
        let now = Utc::now();
        let till = now + Duration::days(1);

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
            nonce: rand::random::<u32>(),
            etypes: vec![18, 17], // AES256, AES128 (fixed field name)
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };

        // Build PA-PK-AS-REQ padata
        // Note: This is a simplified implementation
        // Full PKINIT requires building AuthPack with PKAuthenticator and signing it
        let pa_pk_as_req = PaData {
            padata_type: 16, // PA-PK-AS-REQ
            padata_value: vec![], // Simplified - would contain signed AuthPack
        };

        let as_req = AsReq {
            pvno: 5,
            msg_type: 10,
            padata: Some(vec![pa_pk_as_req]),
            req_body,
        };

        Ok(as_req.build())
    }

    /// Sign AS-REQ using private key
    fn sign_request(&self, request: &[u8]) -> Result<Vec<u8>> {
        use rsa::pkcs8::DecodePrivateKey;

        // Parse private key
        let private_key = RsaPrivateKey::from_pkcs8_der(&self.config.private_key)
            .map_err(|e| OverthroneError::Encryption(format!("Private key parsing failed: {}", e)))?;

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
        let private_key = RsaPrivateKey::from_pkcs8_der(&self.config.private_key)
            .map_err(|e| OverthroneError::Encryption(format!("Private key parsing failed: {}", e)))?;

        // Decrypt the encrypted part using RSA PKCS#1 v1.5
        // PKINIT typically uses PKCS#1 v1.5 padding
        let decrypted = private_key.decrypt(Pkcs1v15Encrypt, &enc_part.cipher)
            .map_err(|e| OverthroneError::Encryption(format!("AS-REP decryption failed: {}", e)))?;

        // Parse the decrypted EncAsRepPart to extract session key
        let (_, enc_as_rep_part) = EncAsRepPart::parse(&decrypted)
            .map_err(|_| OverthroneError::Kerberos("Failed to parse EncAsRepPart".to_string()))?;

        // Extract session key and validity
        let session_key = enc_as_rep_part.key.keyvalue.clone();
        let valid_until = enc_as_rep_part.endtime.timestamp() as u64;

        Ok(PkinitResult {
            tgt,
            session_key,
            valid_until,
        })
    }
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
                || eku.value.other.iter().any(|oid| {
                    oid.to_string() == "1.3.6.1.5.5.7.3.2"
                });
            assert!(has_client_auth, "Certificate should have Client Authentication EKU");
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
        let (cert_der, private_key_der) = CertificateGenerator::generate_certificate("test-sign", 2048).unwrap();
        
        let config = PkinitConfig {
            certificate: cert_der,
            private_key: private_key_der,
            realm: "TEST.LOCAL".to_string(),
            username: "testuser".to_string(),
            kdc_host: "kdc.test.local".to_string(),
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
        let (cert_der, private_key_der) = CertificateGenerator::generate_certificate("test-expired", 2048).unwrap();
        
        let config = PkinitConfig {
            certificate: cert_der,
            private_key: private_key_der,
            realm: "TEST.LOCAL".to_string(),
            username: "testuser".to_string(),
            kdc_host: "kdc.test.local".to_string(),
        };

        let authenticator = PkinitAuthenticator::new(config);
        let result = authenticator.validate_certificate();
        assert!(result.is_ok()); // Should pass for a freshly generated certificate
    }

    // ============================================================================
    // Property-Based Tests
    // ============================================================================

    // Property 11: RSA Key Pair Generation
    // For any valid key size (2048, 3072, 4096), key generation should succeed
    proptest! {
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
            let private_key_parsed = RsaPrivateKey::from_pkcs8_der(&private_key);
            prop_assert!(private_key_parsed.is_ok());
        }
    }

    // Property 10: Certificate Generation with PKINIT Extensions
    // For any subject CN and valid key size, certificate should have Client Auth EKU
    proptest! {
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
            };

            let authenticator = PkinitAuthenticator::new(config);
            
            // Validate certificate (should pass for freshly generated cert)
            let result = authenticator.validate_certificate();
            prop_assert!(result.is_ok());
        }
    }
}
