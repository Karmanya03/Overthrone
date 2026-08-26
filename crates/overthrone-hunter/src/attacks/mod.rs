//! CVE exploit modules for Active Directory attack chains.
//!
//! Each module covers a specific CVE with detection, assessment, and
//! exploitation capabilities targeting specific vulnerabilities.

pub mod ad_ds_eop;
pub mod ad_rce;
pub mod adcs_uaf;
pub mod cba_bypass;
pub mod checksum_bypass;
pub mod ipv6_rce;
pub mod krb_bypass;
pub mod netcfg_ops;
pub mod netlogon_rce;
pub mod resetnightmare;
pub mod sssd_linux;
pub mod wac_compromise;

pub use ad_ds_eop::{AdDsEopResult, exploit_ad_ds_eop};
pub use ad_rce::{AdRceConfig, AdRceExploitMode, AdRceResult, exploit_ad_rce};
pub use adcs_uaf::{AdcsUafConfig, AdcsUafResult, exploit_adcs_uaf};
pub use cba_bypass::{CbaBypassResult, assess_cba_bypass};
pub use checksum_bypass::{
    ChecksumBypassConfig, ChecksumBypassResult, ChecksumTechnique, exploit_all_checksum_techniques,
    exploit_checksum_bypass,
};
pub use ipv6_rce::{
    Ipv6Payload, Ipv6RceConfig, Ipv6RceResult, exploit_ipv6_rce, scan_vulnerable_hosts,
};
pub use krb_bypass::{KrbBypassConfig, KrbBypassResult, PacHandling, exploit_krb_pac_bypass};
pub use netcfg_ops::{NetCfgOpsResult, exploit_netcfg_ops};
pub use netlogon_rce::{ExploitMode, NetlogonRceConfig, NetlogonRceResult, exploit_netlogon_rce};
pub use resetnightmare::{ResetNightmareConfig, ResetNightmareResult, exploit_resetnightmare};
pub use sssd_linux::{
    SssdLinuxConfig, SssdLinuxResult, SssdTechnique, discover_linux_hosts, exploit_sssd_linux,
};
pub use wac_compromise::{WacAuthMethod, WacCompromiseConfig, WacCompromiseResult, compromise_wac};
