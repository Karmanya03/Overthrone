//! ADWS (port 9389) enumeration over WS-Trust NTLM — hardened-DC
//! enumeration channel that bypasses LDAP hardening (unsigned-bind
//! enforcement, LDAPS-only policies, filter-blocking firewalls).

use colored::Colorize;
use overthrone_core::proto::adws::{AdObject, AdwsConfig, PULL_MAX_ELEMENTS};

#[derive(Debug, Clone, clap::Subcommand)]
pub enum AdwsAction {
    /// Enumerate users through ADWS
    Enum {
        /// Target DC hostname or IP (ADWS on TCP 9389)
        #[arg(short = 't', long, required = true)]
        target: String,
        /// NetBIOS/FQDN domain
        #[arg(short = 'D', long, required = true)]
        domain: String,
        /// Username
        #[arg(long, required = true)]
        user: String,
        /// NT hash (32-hex, or LM:NT format)
        #[arg(long, required = true)]
        hash: String,
        /// LDAP-style filter for wsen:Filter
        #[arg(short = 'f', long, default_value = "(&(objectClass=user))")]
        filter: String,
        /// Max elements per Pull page
        #[arg(long, default_value_t = PULL_MAX_ELEMENTS)]
        max_elements: usize,
        /// Emit JSON instead of a table
        #[arg(long)]
        json: bool,
    },
    /// Raw ADWS search with an arbitrary filter (computers, groups, ACLs)
    Search {
        /// Target DC hostname or IP
        #[arg(short = 't', long, required = true)]
        target: String,
        /// NetBIOS/FQDN domain
        #[arg(short = 'D', long, required = true)]
        domain: String,
        /// Username
        #[arg(long, required = true)]
        user: String,
        /// NT hash
        #[arg(long, required = true)]
        hash: String,
        /// LDAP-style filter (e.g. "(objectClass=computer)")
        #[arg(short = 'f', long, default_value = "(objectClass=*)")]
        filter: String,
        /// Max elements per Pull page
        #[arg(long, default_value_t = PULL_MAX_ELEMENTS)]
        max_elements: usize,
        /// Emit JSON instead of a table
        #[arg(long)]
        json: bool,
    },
}

/// Parts extracted from either action variant: (dc, domain, user,
/// hash, filter, max_elements, json).
pub type AdwsParts = (String, String, String, String, String, usize, bool);

impl AdwsAction {
    pub fn into_parts(self) -> AdwsParts {
        match self {
            AdwsAction::Enum {
                target,
                domain,
                user,
                hash,
                filter,
                max_elements,
                json,
            }
            | AdwsAction::Search {
                target,
                domain,
                user,
                hash,
                filter,
                max_elements,
                json,
            } => (target, domain, user, hash, filter, max_elements, json),
        }
    }
}

/// Render one object in the default (human) format.
pub fn render_object(obj: &AdObject) -> String {
    let mut out = String::new();
    out.push_str(&format!("  {}\n", obj.dn.bright_white().bold()));
    for (k, vals) in &obj.attrs {
        out.push_str(&format!(
            "    {:<28} {}\n",
            format!("{k}:").dimmed(),
            vals.join(", ")
        ));
    }
    out
}

fn render_table(objects: &[AdObject]) {
    if objects.is_empty() {
        crate::banner::print_info(
            "No objects returned (auth may have succeeded but the filter matched nothing)",
        );
        return;
    }
    for obj in objects {
        print!("{}", render_object(obj));
    }
}

pub async fn cmd_adws(_cli: &crate::Cli, action: AdwsAction) -> i32 {
    crate::banner::print_module_banner("ADWS (WS-Trust / port 9389)");
    let (dc, domain, username, hash, filter, max_elements, json) = action.into_parts();

    let cfg = AdwsConfig {
        domain,
        username,
        nt_hash_hex: hash,
        timeout_secs: 30,
    };

    match overthrone_core::proto::adws::connect_tcp(&dc, &cfg) {
        Ok(mut client) => match client.enumerate(&filter, max_elements) {
            Ok(objects) => {
                if json {
                    match serde_json::to_string_pretty(&objects) {
                        Ok(s) => {
                            println!("{s}");
                            0
                        }
                        Err(e) => {
                            crate::banner::print_fail(&format!("JSON serialize: {e}"));
                            1
                        }
                    }
                } else {
                    render_table(&objects);
                    crate::banner::print_success(&format!(
                        "ADWS enumeration completed: {} objects",
                        objects.len()
                    ));
                    0
                }
            }
            Err(e) => {
                crate::banner::print_fail(&format!("ADWS enumerate: {e}"));
                1
            }
        },
        Err(e) => {
            crate::banner::print_fail(&format!("ADWS connect: {e}"));
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_into_parts_covers_both_variants() {
        let (dc, domain, user, hash, filter, max_elements, json) = AdwsAction::Search {
            target: "dc01".into(),
            domain: "CORP".into(),
            user: "a".into(),
            hash: "31d6cfe0d16ae931b73c59d7e0c089c0".into(),
            filter: "(objectClass=computer)".into(),
            max_elements: 50,
            json: true,
        }
        .into_parts();
        assert_eq!(dc, "dc01");
        assert_eq!(domain, "CORP");
        assert_eq!(user, "a");
        assert_eq!(filter, "(objectClass=computer)");
        assert_eq!(max_elements, 50);
        assert!(json);

        let (_, _, _, _, filter, max_elements, json) = AdwsAction::Enum {
            target: "dc02".into(),
            domain: "LAN".into(),
            user: "b".into(),
            hash: "x".into(),
            filter: String::new(),
            max_elements: PULL_MAX_ELEMENTS,
            json: false,
        }
        .into_parts();
        assert_eq!(max_elements, PULL_MAX_ELEMENTS);
        assert!(!json);
        assert!(filter.is_empty());

        let (_, _, _, _, default_filter, ..) = (
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            "(&(objectClass=user))".to_string(),
            PULL_MAX_ELEMENTS,
            false,
        );
        assert_eq!(
            default_filter, "(&(objectClass=user))",
            "enum default filter"
        );
    }

    #[test]
    fn test_render_object_shape() {
        let obj = AdObject {
            dn: "CN=alice,CN=Users,DC=corp,DC=local".into(),
            attrs: std::collections::BTreeMap::from([
                ("samaccountname".to_string(), vec!["alice".to_string()]),
                (
                    "memberof".to_string(),
                    vec!["CN=Admins".to_string(), "CN=Users".to_string()],
                ),
            ]),
        };
        let out = render_object(&obj);
        assert!(out.contains("CN=alice,CN=Users,DC=corp,DC=local"));
        assert!(out.contains("samaccountname"));
        assert!(out.contains("alice"));
        assert!(
            out.contains("CN=Admins, CN=Users"),
            "multi-valued joined: {out}"
        );
    }

    #[test]
    fn test_render_table_empty_no_crash() {
        render_table(&[]);
        // empty input never panics; output goes to stdout only
    }
}
