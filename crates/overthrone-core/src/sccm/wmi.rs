//! SCCM WMI Enumeration Helpers
//!
//! Enumerates SCCM collections, applications, and managed devices from a site
//! server via WMI (`root\sms\site_<SITECODE>`).
//!
//! On **Windows** the WMI queries run natively via the `wmi` crate.
//! On **non-Windows** systems, equivalent PowerShell commands are generated for
//! the operator to run on a Windows pivot.

use super::SccmSite;
#[cfg(windows)]
use crate::error::OverthroneError;
use crate::error::Result;
use tracing::info;
#[cfg(not(windows))]
use tracing::warn;

#[cfg(windows)]
use {
    ::wmi::{COMLibrary, WMIConnection},
    serde::Deserialize,
};

// ─────────────────────────────────────────────────────────────
// Collection enumeration
// ─────────────────────────────────────────────────────────────

/// An SCCM collection (device or user).
#[derive(Debug, Clone)]
pub struct SccmCollection {
    pub collection_id: String,
    pub name: String,
    pub member_count: u32,
    pub collection_type: CollectionType,
    pub is_built_in: bool,
}

/// SCCM collection type: 1 = User, 2 = Device.
#[derive(Debug, Clone, PartialEq)]
pub enum CollectionType {
    User,
    Device,
    Unknown(u32),
}

impl CollectionType {
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::User,
            2 => Self::Device,
            n => Self::Unknown(n),
        }
    }
}

impl std::fmt::Display for CollectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => write!(f, "User"),
            Self::Device => write!(f, "Device"),
            Self::Unknown(n) => write!(f, "Unknown({n})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Application enumeration
// ─────────────────────────────────────────────────────────────

/// An SCCM application / package.
#[derive(Debug, Clone)]
pub struct SccmApplication {
    pub app_id: String,
    pub local_id: u32,
    pub name: String,
    pub software_version: String,
    pub is_deployed: bool,
    pub deployment_types: Vec<String>,
}

// ─────────────────────────────────────────────────────────────
// SCCM managed device
// ─────────────────────────────────────────────────────────────

/// An SCCM-managed computer.
#[derive(Debug, Clone)]
pub struct SccmDevice {
    pub resource_id: u32,
    pub name: String,
    pub dns_name: String,
    pub os_name: String,
    pub last_logon_user: String,
    pub client_version: String,
    pub client_activity: u32,
    pub is_active: bool,
}

// ─────────────────────────────────────────────────────────────
// Cross-platform enumerate functions
// ─────────────────────────────────────────────────────────────

/// Enumerate all SCCM collections from the site server.
///
/// On Windows: queries `SMS_Collection` via native WMI.
/// On other platforms: returns a stub and logs the equivalent PowerShell.
pub async fn enumerate_collections(site: &SccmSite) -> Result<Vec<SccmCollection>> {
    info!(
        "[SCCM/wmi] Enumerating collections from site {} ({})",
        site.site_code, site.site_server
    );

    #[cfg(windows)]
    {
        enumerate_collections_native(site).await
    }

    #[cfg(not(windows))]
    {
        let cmd = gen_enum_collections_cmd(site);
        warn!(
            "[SCCM/wmi] Non-Windows host — run the following on a Windows machine with SCCM access:\n{}",
            cmd
        );
        Err(crate::error::OverthroneError::Custom(
            "SCCM WMI enumeration requires Windows (native COM/WMI). Run on a Windows host or use the printed PowerShell command.".to_string()
        ))
    }
}

/// Enumerate all deployed SCCM applications / packages.
pub async fn enumerate_applications(site: &SccmSite) -> Result<Vec<SccmApplication>> {
    info!(
        "[SCCM/wmi] Enumerating applications from site {} ({})",
        site.site_code, site.site_server
    );

    #[cfg(windows)]
    {
        enumerate_applications_native(site).await
    }

    #[cfg(not(windows))]
    {
        let cmd = gen_enum_applications_cmd(site);
        warn!(
            "[SCCM/wmi] Non-Windows host — run the following on a Windows machine:\n{}",
            cmd
        );
        Err(crate::error::OverthroneError::Custom(
            "SCCM WMI enumeration requires Windows (native COM/WMI). Run on a Windows host or use the printed PowerShell command.".to_string()
        ))
    }
}

/// Enumerate SCCM-managed devices (computers with SCCM client installed).
pub async fn enumerate_devices(site: &SccmSite) -> Result<Vec<SccmDevice>> {
    info!(
        "[SCCM/wmi] Enumerating devices from site {} ({})",
        site.site_code, site.site_server
    );

    #[cfg(windows)]
    {
        enumerate_devices_native(site).await
    }

    #[cfg(not(windows))]
    {
        let cmd = gen_enum_devices_cmd(site);
        warn!(
            "[SCCM/wmi] Non-Windows host — run the following on a Windows machine:\n{}",
            cmd
        );
        Err(crate::error::OverthroneError::Custom(
            "SCCM WMI enumeration requires Windows (native COM/WMI). Run on a Windows host or use the printed PowerShell command.".to_string()
        ))
    }
}

// ─────────────────────────────────────────────────────────────
// Windows-native WMI implementations
// ─────────────────────────────────────────────────────────────

#[cfg(windows)]
async fn enumerate_collections_native(site: &SccmSite) -> Result<Vec<SccmCollection>> {
    let server = site.site_server.clone();
    let sc = site.site_code.clone();

    tokio::task::spawn_blocking(move || -> Result<Vec<SccmCollection>> {
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

        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "PascalCase")]
        struct RawCollection {
            collection_id: String,
            name: String,
            member_count: u32,
            collection_type: u32,
            is_built_in: bool,
        }

        let rows: Vec<RawCollection> = wmi
            .raw_query(
                "SELECT CollectionID,Name,MemberCount,CollectionType,IsBuiltIn FROM SMS_Collection",
            )
            .map_err(|e| OverthroneError::Protocol {
                protocol: "SCCM".into(),
                reason: format!("WMI query failed: {e}"),
            })?;

        Ok(rows
            .into_iter()
            .map(|r| SccmCollection {
                collection_id: r.collection_id,
                name: r.name,
                member_count: r.member_count,
                collection_type: CollectionType::from_u32(r.collection_type),
                is_built_in: r.is_built_in,
            })
            .collect())
    })
    .await
    .map_err(|e| OverthroneError::Protocol {
        protocol: "SCCM".into(),
        reason: format!("WMI thread panic: {e}"),
    })?
}

#[cfg(windows)]
async fn enumerate_applications_native(site: &SccmSite) -> Result<Vec<SccmApplication>> {
    let server = site.site_server.clone();
    let sc = site.site_code.clone();

    tokio::task::spawn_blocking(move || -> Result<Vec<SccmApplication>> {
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

        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "PascalCase")]
        struct RawApp {
            model_id: Option<String>,
            local_id: u32,
            local_name: String,
            software_version: Option<String>,
            is_deployed: bool,
        }

        let rows: Vec<RawApp> = wmi
            .raw_query(
                "SELECT ModelID,LocalID,LocalizedDisplayName,SoftwareVersion,IsDeployed \
                 FROM SMS_Application",
            )
            .map_err(|e| OverthroneError::Protocol {
                protocol: "SCCM".into(),
                reason: format!("WMI query failed: {e}"),
            })?;

        Ok(rows
            .into_iter()
            .map(|r| SccmApplication {
                app_id: r.model_id.unwrap_or_default(),
                local_id: r.local_id,
                name: r.local_name,
                software_version: r.software_version.unwrap_or_default(),
                is_deployed: r.is_deployed,
                deployment_types: Vec::new(),
            })
            .collect())
    })
    .await
    .map_err(|e| OverthroneError::Protocol {
        protocol: "SCCM".into(),
        reason: format!("WMI thread panic: {e}"),
    })?
}

#[cfg(windows)]
async fn enumerate_devices_native(site: &SccmSite) -> Result<Vec<SccmDevice>> {
    let server = site.site_server.clone();
    let sc = site.site_code.clone();

    tokio::task::spawn_blocking(move || -> Result<Vec<SccmDevice>> {
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

        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "PascalCase")]
        struct RawDevice {
            resource_id: u32,
            name: String,
            dns_name: Option<String>,
            os_name: Option<String>,
            user_name: Option<String>,
            client_version: Option<String>,
            client_activity: Option<u32>,
        }

        let rows: Vec<RawDevice> = wmi
            .raw_query(
                "SELECT ResourceID,Name,DNSName,OperatingSystemNameandVersion,\
                 LastLogonUserName,ClientVersion,ClientActivity \
                 FROM SMS_R_System",
            )
            .map_err(|e| OverthroneError::Protocol {
                protocol: "SCCM".into(),
                reason: format!("WMI query failed: {e}"),
            })?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let active = r.client_activity.unwrap_or(0);
                SccmDevice {
                    resource_id: r.resource_id,
                    name: r.name,
                    dns_name: r.dns_name.unwrap_or_default(),
                    os_name: r.os_name.unwrap_or_default(),
                    last_logon_user: r.user_name.unwrap_or_default(),
                    client_version: r.client_version.unwrap_or_default(),
                    client_activity: active,
                    is_active: active > 0,
                }
            })
            .collect())
    })
    .await
    .map_err(|e| OverthroneError::Protocol {
        protocol: "SCCM".into(),
        reason: format!("WMI thread panic: {e}"),
    })?
}

// ─────────────────────────────────────────────────────────────
// PowerShell command generators (non-Windows fallback)
// ─────────────────────────────────────────────────────────────

pub fn gen_enum_collections_cmd(site: &SccmSite) -> String {
    format!(
        r#"$sc = '{sc}'
$srv = '{srv}'
Get-WmiObject -ComputerName $srv -Namespace "root\sms\site_$sc" `
  -Class SMS_Collection `
  -Property CollectionID,Name,MemberCount,CollectionType,IsBuiltIn |
  Select-Object CollectionID,Name,MemberCount,CollectionType,IsBuiltIn |
  Format-Table -AutoSize"#,
        sc = site.site_code,
        srv = site.site_server,
    )
}

pub fn gen_enum_applications_cmd(site: &SccmSite) -> String {
    format!(
        r#"$sc = '{sc}'
$srv = '{srv}'
Get-WmiObject -ComputerName $srv -Namespace "root\sms\site_$sc" `
  -Class SMS_Application `
  -Property ModelID,LocalID,LocalizedDisplayName,SoftwareVersion,IsDeployed |
  Select-Object ModelID,LocalID,LocalizedDisplayName,SoftwareVersion,IsDeployed |
  Format-Table -AutoSize"#,
        sc = site.site_code,
        srv = site.site_server,
    )
}

pub fn gen_enum_devices_cmd(site: &SccmSite) -> String {
    format!(
        r#"$sc = '{sc}'
$srv = '{srv}'
Get-WmiObject -ComputerName $srv -Namespace "root\sms\site_$sc" `
  -Class SMS_R_System `
  -Property ResourceID,Name,DNSName,OperatingSystemNameandVersion,LastLogonUserName,ClientVersion,ClientActivity |
  Select-Object ResourceID,Name,DNSName,OperatingSystemNameandVersion,LastLogonUserName,ClientVersion,ClientActivity |
  Format-Table -AutoSize"#,
        sc = site.site_code,
        srv = site.site_server,
    )
}
