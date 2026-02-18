//! Export reaper results to JSON, CSV, or BloodHound-compatible formats.

use overthrone_core::error::{OverthroneError, Result};
use crate::runner::ReaperResult;
use std::ffi::OsStr;
use std::path::Path;
use tracing::info;

#[derive(Debug, Clone)]
pub enum ExportFormat {
    Json,
    JsonPretty,
    Csv,
    BloodHoundV4,
}

pub async fn export_results(
    result: &ReaperResult,
    path: &Path,
    format: ExportFormat,
) -> Result<()> {
    info!("[export] Writing results to {}", path.display());

    match format {
        ExportFormat::Json => {
            let json = serde_json::to_string(result)?;
            tokio::fs::write(path, json).await?;
        }
        ExportFormat::JsonPretty => {
            let json = serde_json::to_string_pretty(result)?;
            tokio::fs::write(path, json).await?;
        }
        ExportFormat::Csv => {
            export_csv(result, path).await?;
        }
        ExportFormat::BloodHoundV4 => {
            return Err(OverthroneError::NotImplemented {
                module: "reaper::export::bloodhound_v4".into(),
            });
        }
    }

    info!("[export] Done → {}", path.display());
    Ok(())
}

async fn export_csv(result: &ReaperResult, base: &Path) -> Result<()> {
    let dir = base.parent().unwrap_or(Path::new("."));
    let stem = base.file_stem().unwrap_or(OsStr::new("reaper")).to_string_lossy();

    if !result.users.is_empty() {
        let path = dir.join(format!("{stem}_users.csv"));
        let mut lines = vec![
            "sAMAccountName,enabled,adminCount,kerberoastable,asrepRoastable,memberOf_count".to_string()
        ];
        for u in &result.users {
            lines.push(format!("{},{},{},{},{},{}",
                u.sam_account_name, u.enabled, u.admin_count,
                u.is_kerberoastable(), u.is_asrep_roastable(),
                u.member_of.len(),
            ));
        }
        tokio::fs::write(&path, lines.join("\n")).await?;
        info!("[export] → {}", path.display());
    }

    if !result.computers.is_empty() {
        let path = dir.join(format!("{stem}_computers.csv"));
        let mut lines = vec![
            "sAMAccountName,dnsHostname,os,enabled,unconstrainedDeleg,isDC".to_string()
        ];
        for c in &result.computers {
            lines.push(format!("{},{},{},{},{},{}",
                c.sam_account_name,
                c.dns_hostname.as_deref().unwrap_or(""),
                c.operating_system.as_deref().unwrap_or(""),
                c.enabled, c.unconstrained_delegation, c.is_domain_controller,
            ));
        }
        tokio::fs::write(&path, lines.join("\n")).await?;
        info!("[export] → {}", path.display());
    }

    Ok(())
}
