//! ldapsearch-style LDAP operations.
//!
//! `ovt ldap <action>` performs raw LDAP operations similar to ldapsearch, etc.

use colored::Colorize;
use overthrone_core::proto::ldap::LdapSession;

use crate::auth::{AuthData, Credentials};

#[derive(Debug, Clone, clap::Subcommand)]
pub enum LdapAction {
    /// Query the RootDSE for domain info (no creds needed)
    Rootdse {
        /// Target DC hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// Use LDAPS (port 636) instead of LDAP
        #[arg(long)]
        ldaps: bool,
    },
    /// Perform a raw LDAP search
    Search {
        /// Target DC hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// Base DN for the search (default: domain root from RootDSE)
        #[arg(short, long)]
        base: Option<String>,
        /// LDAP filter (e.g. "(objectClass=user)")
        #[arg(short, long, default_value = "(objectClass=*)")]
        filter: String,
        /// Attributes to return (comma-separated, default: all)
        #[arg(short, long)]
        attrs: Option<String>,
        /// Use LDAPS (port 636) instead of LDAP
        #[arg(long)]
        ldaps: bool,
        /// Verbose: show each attribute on its own line
        #[arg(long)]
        detailed: bool,
    },
    /// Whoami: report the current LDAP binding state
    Whoami {
        /// Target DC hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// Use LDAPS (port 636)
        #[arg(long)]
        ldaps: bool,
    },
    /// Enumerate users via LDAP
    EnumUsers {
        /// Target DC hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// Use LDAPS
        #[arg(long)]
        ldaps: bool,
    },
    /// Enumerate computers via LDAP
    EnumComputers {
        /// Target DC hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// Use LDAPS
        #[arg(long)]
        ldaps: bool,
    },
    /// Enumerate groups via LDAP
    EnumGroups {
        /// Target DC hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// Use LDAPS
        #[arg(long)]
        ldaps: bool,
    },
    /// Enumerate domain trusts via LDAP
    EnumTrusts {
        /// Target DC hostname or IP
        #[arg(short, long, required = true)]
        target: String,
        /// Use LDAPS
        #[arg(long)]
        ldaps: bool,
    },
}

async fn connect(
    action_target: &str,
    creds: Option<&Credentials>,
    ldaps: bool,
) -> Result<LdapSession, String> {
    let Some(c) = creds else {
        return LdapSession::connect_anonymous(action_target, "local", ldaps)
            .await
            .map_err(|e| e.to_string());
    };
    match &c.auth {
        AuthData::Password(p) => {
            LdapSession::connect(action_target, &c.domain, &c.username, p, ldaps)
                .await
                .map_err(|e| e.to_string())
        }
        AuthData::NtlmHash(h) => {
            LdapSession::connect_with_hash(action_target, &c.domain, &c.username, h, ldaps)
                .await
                .map_err(|e| e.to_string())
        }
        AuthData::KerberosTicket(_) => Err(
            "Kerberos LDAP bind not yet supported via this CLI path; use --ticket with KRB5CCNAME"
                .to_string(),
        ),
    }
}

pub async fn cmd_ldap(cli: &crate::Cli, action: LdapAction) -> i32 {
    crate::banner::print_module_banner("LDAP");

    let creds = crate::resolve_credentials_from_cli(cli)
        .ok()
        .and_then(|mut v| {
            if v.is_empty() {
                None
            } else {
                Some(v.remove(0))
            }
        });

    match action {
        LdapAction::Rootdse { target, ldaps } => {
            match overthrone_core::proto::ldap::probe_rootdse_raw(&target, ldaps).await {
                Ok(root) => {
                    println!("{}", format!("\\\\{target}").cyan().bold());
                    if let Some(name) = &root.dns_host_name {
                        println!(
                            "  {:<24} {}",
                            "dnsHostName:".dimmed(),
                            name.bright_white().bold()
                        );
                    }
                    if let Some(nc) = &root.default_naming_context {
                        println!("  {:<24} {}", "defaultNamingContext:".dimmed(), nc);
                    }
                    if let Some(dn) = &root.dns_domain_name {
                        println!("  {:<24} {}", "dnsDomainName:".dimmed(), dn);
                    }
                    if let Some(fl) = &root.domain_functionality {
                        println!("  {:<24} {}", "domainFunctionality:".dimmed(), fl);
                    }
                    if !root.naming_contexts.is_empty() {
                        for nc in &root.naming_contexts {
                            println!("  {:<24} {}", "namingContext:".dimmed(), nc);
                        }
                    }
                    if !root.supported_sasl_mechanisms.is_empty() {
                        println!(
                            "  {:<24} {}",
                            "saslMechanisms:".dimmed(),
                            root.supported_sasl_mechanisms.join(", ")
                        );
                    }
                    crate::banner::print_success("RootDSE probe completed");
                    0
                }
                Err(e) => {
                    crate::banner::print_fail(&format!("RootDSE probe failed: {e}"));
                    1
                }
            }
        }
        LdapAction::Search {
            target,
            base,
            filter,
            attrs,
            ldaps,
            detailed,
        } => {
            let mut session = match connect(&target, creds.as_ref(), ldaps).await {
                Ok(s) => s,
                Err(e) => {
                    crate::banner::print_fail(&format!("LDAP connect to {target}: {e}"));
                    return 1;
                }
            };
            let base_dn = match base {
                Some(b) => b,
                None => {
                    match overthrone_core::proto::ldap::probe_rootdse_raw(&target, ldaps).await {
                        Ok(root) => root.default_naming_context.unwrap_or_default(),
                        Err(_) => {
                            crate::banner::print_fail("Cannot determine base DN; use --base");
                            return 1;
                        }
                    }
                }
            };
            let attr_list: Vec<String> = attrs
                .map(|a| a.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();

            match session
                .custom_search_with_base(
                    &base_dn,
                    &filter,
                    &attr_list.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                )
                .await
            {
                Ok(entries) => {
                    if entries.is_empty() {
                        crate::banner::print_warn("No entries returned");
                        return 1;
                    }
                    for entry in &entries {
                        println!("{}", entry.dn.bright_white().bold());
                        if detailed {
                            for (attr, values) in &entry.attrs {
                                for val in values {
                                    println!("  {}: {}", attr.dimmed(), val);
                                }
                            }
                        } else {
                            for (attr, values) in &entry.attrs {
                                if values.len() == 1 {
                                    println!("  {}: {}", attr.dimmed(), values[0]);
                                } else if !values.is_empty() {
                                    println!("  {}: [{} values]", attr.dimmed(), values.len());
                                }
                            }
                        }
                        println!();
                    }
                    crate::banner::print_success(&format!("# {} search result(s)", entries.len()));
                    0
                }
                Err(e) => {
                    crate::banner::print_fail(&format!("LDAP search failed: {e}"));
                    1
                }
            }
        }
        LdapAction::Whoami { target, ldaps } => {
            let session = match connect(&target, creds.as_ref(), ldaps).await {
                Ok(s) => s,
                Err(e) => {
                    crate::banner::print_fail(&format!("LDAP connect to {target}: {e}"));
                    return 1;
                }
            };
            let signed = session.is_signed();
            let sealed = session.is_sealed();
            println!("{}", format!("\\\\{target}").cyan().bold());
            println!(
                "  {:<20} {}",
                "Auth type:".dimmed(),
                if creds.is_some() {
                    "authenticated (SASL/GSS-SPNEGO)".bright_white()
                } else {
                    "anonymous".bright_white()
                }
            );
            println!("  {:<20} {}", "Signing:".dimmed(), signed);
            println!("  {:<20} {}", "Sealing:".dimmed(), sealed);
            crate::banner::print_success("LDAP WhoAmI completed");
            0
        }
        LdapAction::EnumUsers { target, ldaps } => {
            let mut session = match connect(&target, creds.as_ref(), ldaps).await {
                Ok(s) => s,
                Err(e) => {
                    crate::banner::print_fail(&format!("LDAP connect to {target}: {e}"));
                    return 1;
                }
            };
            match session.enumerate_users().await {
                Ok(users) => {
                    for u in &users {
                        let status = if u.enabled { "" } else { " [DISABLED]" };
                        let admin = if u.admin_count { " [ADMIN]" } else { "" };
                        println!(
                            "{}{}{} sam={}",
                            u.sam_account_name.bright_white().bold(),
                            admin.red(),
                            status.yellow(),
                            u.sam_account_name
                        );
                    }
                    crate::banner::print_success(&format!("{} users enumerated", users.len()));
                    0
                }
                Err(e) => {
                    crate::banner::print_fail(&format!("User enumeration failed: {e}"));
                    1
                }
            }
        }
        LdapAction::EnumComputers { target, ldaps } => {
            let mut session = match connect(&target, creds.as_ref(), ldaps).await {
                Ok(s) => s,
                Err(e) => {
                    crate::banner::print_fail(&format!("LDAP connect to {target}: {e}"));
                    return 1;
                }
            };
            match session.enumerate_computers().await {
                Ok(computers) => {
                    for c in &computers {
                        let os = c.operating_system.as_deref().unwrap_or("unknown");
                        println!(
                            "{} os={} dn={}",
                            c.sam_account_name.bright_white().bold(),
                            os.dimmed(),
                            c.distinguished_name
                        );
                    }
                    crate::banner::print_success(&format!(
                        "{} computers enumerated",
                        computers.len()
                    ));
                    0
                }
                Err(e) => {
                    crate::banner::print_fail(&format!("Computer enumeration failed: {e}"));
                    1
                }
            }
        }
        LdapAction::EnumGroups { target, ldaps } => {
            let mut session = match connect(&target, creds.as_ref(), ldaps).await {
                Ok(s) => s,
                Err(e) => {
                    crate::banner::print_fail(&format!("LDAP connect to {target}: {e}"));
                    return 1;
                }
            };
            match session.enumerate_groups().await {
                Ok(groups) => {
                    for g in &groups {
                        let admin = if g.admin_count { " [ADMIN]" } else { "" };
                        println!(
                            "{} members={}{} dn={}",
                            g.sam_account_name.bright_white().bold(),
                            g.members.len(),
                            admin.red(),
                            g.distinguished_name
                        );
                    }
                    crate::banner::print_success(&format!("{} groups enumerated", groups.len()));
                    0
                }
                Err(e) => {
                    crate::banner::print_fail(&format!("Group enumeration failed: {e}"));
                    1
                }
            }
        }
        LdapAction::EnumTrusts { target, ldaps } => {
            let mut session = match connect(&target, creds.as_ref(), ldaps).await {
                Ok(s) => s,
                Err(e) => {
                    crate::banner::print_fail(&format!("LDAP connect to {target}: {e}"));
                    return 1;
                }
            };
            match session.enumerate_trusts().await {
                Ok(trusts) => {
                    for t in &trusts {
                        println!(
                            "Trust: {} -> {} (direction:{:?} type:{:?} attrs:{:#x})",
                            t.flat_name.as_deref().unwrap_or("?").bright_white().bold(),
                            t.trust_partner,
                            t.trust_direction,
                            t.trust_type,
                            t.trust_attributes,
                        );
                    }
                    crate::banner::print_success(&format!("{} trusts enumerated", trusts.len()));
                    0
                }
                Err(e) => {
                    crate::banner::print_fail(&format!("Trust enumeration failed: {e}"));
                    1
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ldap_action_debug_clone() {
        let action = LdapAction::Rootdse {
            target: "10.0.0.1".into(),
            ldaps: false,
        };
        let cloned = action.clone();
        assert!(format!("{cloned:?}").contains("Rootdse"));
    }

    #[test]
    fn ldap_search_action_defaults() {
        let action = LdapAction::Search {
            target: "10.0.0.1".into(),
            base: None,
            filter: "(objectClass=*)".into(),
            attrs: None,
            ldaps: false,
            detailed: false,
        };
        let s = format!("{action:?}");
        assert!(s.contains("Search"));
        assert!(s.contains("(objectClass=*)"));
    }

    #[test]
    fn ldap_enum_variants_all_debuggable() {
        let variants = vec![
            LdapAction::Rootdse {
                target: "t".into(),
                ldaps: false,
            },
            LdapAction::Whoami {
                target: "t".into(),
                ldaps: false,
            },
            LdapAction::EnumUsers {
                target: "t".into(),
                ldaps: false,
            },
            LdapAction::EnumComputers {
                target: "t".into(),
                ldaps: false,
            },
            LdapAction::EnumGroups {
                target: "t".into(),
                ldaps: false,
            },
            LdapAction::EnumTrusts {
                target: "t".into(),
                ldaps: false,
            },
        ];
        for v in variants {
            assert!(!format!("{v:?}").is_empty());
        }
    }
}
