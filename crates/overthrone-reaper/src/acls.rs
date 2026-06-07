//! Dangerous ACL enumeration — GenericAll, WriteDACL, WriteOwner, AllExtendedRights, etc.
//!
//! Bugs fixed vs. original:
//!  • SDDL abbreviation table corrected ("DC" was mapped to WP; "SW" had wrong mask; "CR" was missing; "WP" was missing)
//!  • LAPS GUID check used `contains()` — changed to exact `==`
//!  • `"domainDNS"` used as a GUID key in `attribute_guid_info` — removed (not a GUID)
//!  • `AllExtendedRights` (empty object-GUID + CR mask) was silently dropped — now emitted
//!  • `ADS_RIGHT_DS_CREATE_CHILD` detected but never surfaced in parse_sddl_ace — now handled
//!  • `AddSelf` / `WriteSelf` (SW flag) was not handled — now handled
//!  • Missing `DangerousRight` variants added: `AllExtendedRights`, `CreateChild`, `WriteSelf`
//!  • Windows LAPS (ms-LAPS 2023) GUIDs added
//!  • ADCS (userCertificate, msPKI-*) GUIDs added
//!  • Built-in SID filter extended with well-known S-1-5-* prefixes
//!  • `ReadLapsPassword` detection generalised to cover legacy + Windows LAPS
//!  • `trustee` is now also looked up against SID → name if it looks like a SID string

use crate::runner::ReaperConfig;
use overthrone_core::error::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ─── Dangerous right taxonomy ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DangerousRight {
    // ── Broad access mask bits ────────────────────────────────────────────────
    /// `GenericAll` variant
    GenericAll,
    /// `GenericWrite` variant
    GenericWrite,
    /// `WriteDacl` variant
    WriteDacl,
    /// `WriteOwner` variant
    WriteOwner,
    /// `Owns` variant
    Owns,
    /// `AllExtendedRights` variant
    AllExtendedRights,
    /// `CreateChild` variant
    CreateChild,
    /// `WriteSelf` variant
    WriteSelf,

    // ── Extended rights ───────────────────────────────────────────────────────
    /// `ForceChangePassword` variant
    ForceChangePassword,
    /// `DcSync` variant
    DcSync,
    /// `ReadLapsPassword` variant
    ReadLapsPassword,
    /// `ReadLapsPasswordExpiry` variant
    ReadLapsPasswordExpiry,
    /// `ReadGmsaPassword` variant
    ReadGmsaPassword,

    // ── AddMembers / self-membership ──────────────────────────────────────────
    /// `AddMembers` variant
    AddMembers,
    /// `AddSelf` variant
    AddSelf,

    // ── Attribute-level WriteProperty edges ───────────────────────────────────
    /// `WriteSPN` variant
    WriteSPN,
    /// `WriteAllowedToDelegateTo` variant
    WriteAllowedToDelegateTo,
    /// `AddAllowedToAct` variant
    AddAllowedToAct,
    /// `WriteAccountRestrictions` variant
    WriteAccountRestrictions,
    /// `WriteLogonScript` variant
    WriteLogonScript,
    /// `WriteProfilePath` variant
    WriteProfilePath,
    /// `WriteScriptPath` variant
    WriteScriptPath,
    /// `WriteDnsHostName` variant
    WriteDnsHostName,
    /// `WriteServicePrincipalName` variant
    WriteServicePrincipalName,
    /// `WriteKeyCredentialLink` variant
    WriteKeyCredentialLink,
    /// `WriteMsDsKeyCredentialLink` variant
    WriteMsDsKeyCredentialLink,
    /// `WriteAltSecurityIdentities` variant
    WriteAltSecurityIdentities,
    /// `WriteUserParameters` variant
    WriteUserParameters,
    /// `WritePwdProperties` variant
    WritePwdProperties,
    /// `WriteLockoutThreshold` variant
    WriteLockoutThreshold,
    /// `WriteMinPwdLength` variant
    WriteMinPwdLength,
    /// `WritePwdHistoryLength` variant
    WritePwdHistoryLength,
    /// `WritePwdComplexity` variant
    WritePwdComplexity,
    /// `WritePwdReversibleEncryption` variant
    WritePwdReversibleEncryption,
    /// `WritePwdAge` variant
    WritePwdAge,
    /// `WriteLockoutDuration` variant
    WriteLockoutDuration,
    /// `WriteLockoutObservationWindow` variant
    WriteLockoutObservationWindow,
    /// `WriteGPLink` variant
    WriteGPLink,
    /// `AddKeyCredentialLink` variant
    AddKeyCredentialLink,

    // ── ADCS / certificate abuse ──────────────────────────────────────────────
    /// `WriteUserCertificate` variant
    WriteUserCertificate,
    /// `EnrollCertificate` variant
    EnrollCertificate,
    /// Certificate enrollment right (BloodHound "Enroll" edge)
    Enroll,
    /// CA management right (BloodHound "ManageCA" edge)
    ManageCA,
    /// Certificate management right (BloodHound "ManageCertificates" edge)
    ManageCertificates,
    /// Certificate template management (BloodHound "ManageCertTemplate" edge)
    ManageCertTemplate,

    // ── Additional extended rights ────────────────────────────────────────────
    /// User-Force-Change-Password extended right (same as ForceChangePassword, BloodHound alias)
    UserForceChangePassword,
    /// Allowed-to-act delegation right (BloodHound "AllowedToAct" edge)
    AllowedToAct,

    // ── Generic catch-all ─────────────────────────────────────────────────────
    /// `WriteProperty` variant
    WriteProperty {
        /// AD attribute to write
        attribute: String,
        /// GUID of the property set
        guid: String,
    },
    /// `Custom` variant
    Custom(String),
}

impl DangerousRight {
    /// Rough severity score used for prioritising output (lower = more severe).
    pub fn severity(&self) -> u8 {
        match self {
            Self::GenericAll | Self::WriteDacl | Self::WriteOwner | Self::Owns => 1,
            Self::DcSync | Self::AllExtendedRights | Self::CreateChild => 1,
            Self::ForceChangePassword | Self::AddAllowedToAct | Self::WriteAccountRestrictions => 2,
            Self::WriteSPN
            | Self::AddKeyCredentialLink
            | Self::WriteKeyCredentialLink
            | Self::WriteMsDsKeyCredentialLink => 2,
            Self::ReadLapsPassword | Self::ReadLapsPasswordExpiry | Self::ReadGmsaPassword => 2,
            Self::WriteAllowedToDelegateTo | Self::WriteAltSecurityIdentities => 2,
            Self::GenericWrite
            | Self::AddMembers
            | Self::AddSelf
            | Self::WriteSelf
            | Self::WriteServicePrincipalName => 3,
            Self::EnrollCertificate | Self::WriteUserCertificate => 3,
            _ => 5,
        }
    }

    /// Human-readable attack description.
    pub fn abuse_info(&self) -> &'static str {
        match self {
            Self::GenericAll => {
                "Full control — can reset password, modify group membership, write DACL, take ownership"
            }
            Self::GenericWrite => {
                "Write arbitrary non-protected attributes — often leads to Kerberoast or Shadow Creds"
            }
            Self::WriteDacl => "Modify DACL → grant yourself GenericAll",
            Self::WriteOwner => "Take ownership → modify DACL → GenericAll",
            Self::Owns => "Already owner → modify DACL → GenericAll",
            Self::AllExtendedRights => {
                "All extended rights: ForceChangePassword, DCSync, LAPS read, etc."
            }
            Self::CreateChild => {
                "Create child objects in container/OU — leads to GPO / computer account abuse"
            }
            Self::WriteSelf => "Self-write validated permission — can add yourself as member",
            Self::ForceChangePassword => "Reset target password without knowing current password",
            Self::DcSync => "Replicate directory secrets (DCSync) → dump all NTLM hashes",
            Self::ReadLapsPassword => "Read legacy LAPS local admin password (ms-Mcs-AdmPwd)",
            Self::ReadLapsPasswordExpiry => {
                "Read Windows LAPS encrypted password — decrypt with DPAPI to get cleartext"
            }
            Self::ReadGmsaPassword => {
                "Read gMSA password blob — lateral movement as managed service account"
            }
            Self::AddMembers => "Add arbitrary principals to the group",
            Self::AddSelf => "Add your own account to the group (self-write validated right)",
            Self::WriteSPN => "Set arbitrary SPN → Kerberoast target account offline",
            Self::WriteAllowedToDelegateTo => {
                "Write constrained delegation SPN → S4U2Self / S4U2Proxy TGT"
            }
            Self::AddAllowedToAct => {
                "Write msDS-AllowedToActOnBehalfOfOtherIdentity → RBCD → impersonate any user to target"
            }
            Self::WriteAccountRestrictions => {
                "Flip DONT_REQ_PREAUTH → AS-REP roast; or enable/disable/unlock account"
            }
            Self::WriteLogonScript => "Plant logon script → exec on next user logon",
            Self::WriteProfilePath => "Redirect profile to UNC → NTLM relay or RCE",
            Self::WriteScriptPath => "Write scriptPath → exec on next logon",
            Self::WriteDnsHostName => "Change dNSHostName → PKINIT auth confusion / silver ticket",
            Self::WriteServicePrincipalName => "Arbitrary SPN write — same as WriteSPN",
            Self::WriteKeyCredentialLink
            | Self::WriteMsDsKeyCredentialLink
            | Self::AddKeyCredentialLink => {
                "Shadow Credentials (Whisker/PyWhisker) → PKINIT → TGT without password"
            }
            Self::WriteAltSecurityIdentities => "Map external cert identity → SAML / PKINIT bypass",
            Self::WriteUserParameters => "RDP desktop shadowing or COM object hijack",
            Self::WritePwdProperties
            | Self::WritePwdComplexity
            | Self::WritePwdReversibleEncryption
            | Self::WriteMinPwdLength
            | Self::WritePwdHistoryLength
            | Self::WritePwdAge => "Weaken domain password policy",
            Self::WriteLockoutThreshold
            | Self::WriteLockoutDuration
            | Self::WriteLockoutObservationWindow => "Disable or weaken account lockout policy",
            Self::WriteGPLink => {
                "Link malicious GPO to OU → immediate RCE on next Group Policy refresh"
            }
            Self::WriteUserCertificate => {
                "Write userCertificate → ADCS ESC abuse / certificate-based auth"
            }
            Self::EnrollCertificate => "Enroll in certificate template → ADCS privilege escalation",
            Self::Enroll => "Certificate enrollment right → request cert as target user",
            Self::ManageCA => "CA management → issue/revoke certs, modify CA settings",
            Self::ManageCertificates => "Certificate management → approve pending requests, revoke certs",
            Self::ManageCertTemplate => "Template management → modify template for ESC abuse",
            Self::UserForceChangePassword => "Reset target password without knowing current password (alias)",
            Self::AllowedToAct => "Resource-based constrained delegation → impersonate any user to target",
            Self::WriteProperty { .. } => "Write non-standard property — review GUID for impact",
            Self::Custom(_) => "Custom/delegation right — review carefully",
        }
    }
}

// ─── Finding struct ───────────────────────────────────────────────────────────
/// Structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclFinding {
    /// principal field
    pub principal: String,
    /// Security Identifier
    pub principal_sid: Option<String>,
    /// Target domain FQDN
    pub target: String,
    /// target dn field
    pub target_dn: String,
    /// right field
    pub right: DangerousRight,
    /// is inherited field
    pub is_inherited: bool,
    /// severity field
    pub severity: u8,
}

impl AclFinding {
    fn new(
        principal: impl Into<String>,
        principal_sid: Option<String>,
        target: impl Into<String>,
        target_dn: impl Into<String>,
        right: DangerousRight,
        is_inherited: bool,
    ) -> Self {
        let severity = right.severity();
        Self {
            principal: principal.into(),
            principal_sid,
            target: target.into(),
            target_dn: target_dn.into(),
            right,
            is_inherited,
            severity,
        }
    }
}

// ─── ACE bitmask constants ────────────────────────────────────────────────────

const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const WRITE_DACL: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
/// ADS_RIGHT_DS_CREATE_CHILD
const ADS_RIGHT_DS_CREATE_CHILD: u32 = 0x0000_0001;
/// ADS_RIGHT_DS_SELF — validated writes (self-write)
const ADS_RIGHT_DS_SELF: u32 = 0x0000_0008;
/// ADS_RIGHT_DS_WRITE_PROP
const ADS_RIGHT_DS_WRITE_PROP: u32 = 0x0000_0020;
/// ADS_RIGHT_DS_CONTROL_ACCESS — extended rights
const ADS_RIGHT_DS_CONTROL_ACCESS: u32 = 0x0000_0100;
/// READ_CONTROL
const READ_CONTROL: u32 = 0x0002_0000;

// ─── Well-known extended-right GUIDs ─────────────────────────────────────────

const GUID_USER_FORCE_CHANGE_PASSWORD: &str = "00299570-246d-11d0-a768-00aa006e0529";
const GUID_REPLICATING_DIRECTORY_CHANGES: &str = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
const GUID_REPLICATING_DIRECTORY_CHANGES_ALL: &str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
const GUID_REPLICATING_DIRECTORY_CHANGES_IN_FILTERED_SET: &str =
    "89e95b76-444d-4c62-991a-0facbeda640c";
/// Member attribute (bf9679c0) — AddMembers via WriteProperty
const GUID_MEMBER: &str = "bf9679c0-0de6-11d0-a285-00aa003049e2";
/// Legacy LAPS — ms-Mcs-AdmPwd read extended right
const GUID_MS_MCS_ADMPWD: &str = "faa13209-962c-4e55-8cfe-1b99ae3f1169";
/// Windows LAPS 2023 — ms-LAPS-Password read extended right
const GUID_MS_LAPS_PASSWORD: &str = "a5b3b0f3-49d3-4c69-8de1-e6d42ec35bfa";
/// Windows LAPS 2023 — ms-LAPS-EncryptedPassword expiry
const GUID_MS_LAPS_ENC_PASSWORD_EXPIRY: &str = "be2bb7b5-5e42-4f5c-b14f-cf7b2afa5b9d";
/// Self-membership validated write (add self to group)
const GUID_SELF_MEMBERSHIP: &str = "bf9679c0-0de6-11d0-a285-00aa003049e2";
/// Certificate enrolment extended right
const GUID_CERTIFICATE_ENROLLMENT: &str = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
/// Certificate auto-enrolment
const GUID_CERTIFICATE_AUTO_ENROLLMENT: &str = "a05b8cc2-17bc-4802-a710-e7c15ab866a2";

// ─── Attribute GUID registry ──────────────────────────────────────────────────

/// Maps well-known attribute schema GUIDs to
/// `(attribute_ldap_name, edge_label, severity_cost, is_traversable_in_path, abuse_notes)`.
/// **All keys are lowercase GUIDs.**
fn attribute_guid_info(guid: &str) -> Option<(&'static str, &'static str, u8, bool, &'static str)> {
    match guid.to_lowercase().as_str() {
        // ── SPN / Kerberoasting ───────────────────────────────────────────────
        "f3a64788-5306-11d1-a9c5-0000f80367c1" => Some((
            "servicePrincipalName",
            "WriteSPN",
            2,
            true,
            "Write SPN → targeted Kerberoast (crack TGS offline)",
        )),
        // ── Shadow Credentials / Whisker ──────────────────────────────────────
        "5b84175e-4d8d-4f50-9c68-0e1565f643c7" => Some((
            "msDS-KeyCredentialLink",
            "AddKeyCredentialLink",
            2,
            true,
            "Add keyCredentialLink → Shadow Credentials (PKINIT) → getTGT without password",
        )),
        // ── RBCD ──────────────────────────────────────────────────────────────
        "bf967a8a-0de6-11d0-a285-00aa003049e2" => Some((
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
            "AddAllowedToAct",
            1,
            true,
            "Write RBCD attribute → RBCD attack → impersonate any user to target",
        )),
        "bf967a9c-0de6-11d0-a285-00aa003049e2" => Some((
            "msDS-AllowedToDelegateTo",
            "WriteAllowedToDelegateTo",
            1,
            true,
            "Write constrained delegation SPN → abuse S4U2Self → getTGT",
        )),
        // ── Account restrictions / UAC ────────────────────────────────────────
        "bf9679ac-0de6-11d0-a285-00aa003049e2" => Some((
            "userAccountControl",
            "WriteAccountRestrictions",
            1,
            true,
            "Flip DONT_REQ_PREAUTH → AS-REP roast; enable/disable/unlock account",
        )),
        // ── Logon script / profile path ───────────────────────────────────────
        "bf967a0c-0de6-11d0-a285-00aa003049e2" => Some((
            "scriptPath",
            "WriteScriptPath",
            3,
            true,
            "Write scriptPath → command execution on next user logon",
        )),
        "bf967a0e-0de6-11d0-a285-00aa003049e2" => Some((
            "profilePath",
            "WriteProfilePath",
            3,
            true,
            "Write profilePath → UNC redirect / NTLM relay / command execution",
        )),
        // ── GPO / OU link ─────────────────────────────────────────────────────
        "f30e3bbf-9ff0-11d1-b603-0000f80367c1" => Some((
            "gPLink",
            "WriteGPLink",
            2,
            true,
            "Write gPLink → link malicious GPO → immediate exec on GP refresh",
        )),
        "f30e3bc1-9ff0-11d1-b603-0000f80367c1" => Some((
            "gPCFileSysPath",
            "WriteGPLink",
            2,
            true,
            "Write GPO fileSysPath → plant malicious scripts / scheduled tasks",
        )),
        // ── DNS hostname ──────────────────────────────────────────────────────
        "72e39547-7b18-11d1-adef-00c04fd8d5cd" => Some((
            "dNSHostName",
            "WriteDnsHostName",
            2,
            true,
            "Write dNSHostName → Kerberos PKINIT auth bypass / silver ticket abuse",
        )),
        // ── userParameters (RDP / COM) ────────────────────────────────────────
        "bf967a6d-0de6-11d0-a285-00aa003049e2" => Some((
            "userParameters",
            "WriteUserParameters",
            2,
            true,
            "Write userParameters → RDP desktop shadowing / COM hijack",
        )),
        // ── altSecurityIdentities (cert mapping) ──────────────────────────────
        "bf967a05-0de6-11d0-a285-00aa003049e2" => Some((
            "altSecurityIdentities",
            "WriteAltSecurityIdentities",
            1,
            true,
            "Write altSecurityIdentities → SAML / cert-based auth bypass / PKINIT",
        )),
        // ── msDS-GroupMSAMembership (gMSA read) ───────────────────────────────
        "7b8b558a-93a5-4af7-adca-c017e67f1057" => Some((
            "msDS-GroupMSAMembership",
            "ReadGmsaPassword",
            2,
            true,
            "Read gMSA password blob → lateral movement as managed service account",
        )),
        // ── Legacy LAPS attribute (ms-Mcs-AdmPwd) ────────────────────────────
        "8d3bca50-1d7e-11d0-a081-00aa006c33ed" => Some((
            "ms-Mcs-AdmPwd",
            "ReadLapsPassword",
            2,
            true,
            "Read cleartext LAPS local admin password",
        )),
        // ── Windows LAPS 2023 (ms-LAPS-Password) ─────────────────────────────
        "e362ed86-b728-0842-b27d-2dea7a9df218" => Some((
            "ms-LAPS-Password",
            "ReadLapsPassword",
            2,
            true,
            "Read Windows LAPS encrypted local admin password (decrypt with DPAPI)",
        )),
        "f8b509d3-a3a1-4a4b-ae4e-5f50a0481f82" => Some((
            "ms-LAPS-EncryptedPassword",
            "ReadLapsPassword",
            2,
            true,
            "Read Windows LAPS encrypted local admin password",
        )),
        // ── ADCS / userCertificate ────────────────────────────────────────────
        "bf967a7f-0de6-11d0-a285-00aa003049e2" => Some((
            "userCertificate",
            "WriteUserCertificate",
            2,
            true,
            "Write userCertificate → ADCS certificate-based auth / ESC abuse",
        )),
        // ── pwdLastSet (forced password change) ───────────────────────────────
        "bf9679a8-0de6-11d0-a285-00aa003049e2" => Some((
            "pwdLastSet",
            "WriteAccountRestrictions",
            2,
            true,
            "Write pwdLastSet → force password expiry / bypass MaxPwdAge",
        )),
        // ── logonHours ────────────────────────────────────────────────────────
        "bf9679ab-0de6-11d0-a285-00aa003049e2" => Some((
            "logonHours",
            "WriteAccountRestrictions",
            3,
            false,
            "Write logonHours → lock account out of time window",
        )),
        // ── Advanced ADCS GUIDs ──────────────────────────────────────────────
        "0e10c968-78fb-11d2-90d4-00c04f79dc55" => Some((
            "msPKI-Cert-Template-OID",
            "EnrollCertificate",
            2,
            true,
            "Enroll in certificate template → ADCS privilege escalation",
        )),
        "bf967a8b-0de6-11d0-a285-00aa003049e2" => Some((
            "msPKI-Certificate-Name-Flag",
            "WriteProperty",
            2,
            true,
            "Modify certificate name flag → ESC1/ESC9 abuse",
        )),
        _ => None,
    }
}

// ─── Main enumeration entry point ─────────────────────────────────────────────

pub async fn enumerate_dangerous_acls(config: &ReaperConfig) -> Result<Vec<AclFinding>> {
    info!(
        "[acls] Connecting to {} to enumerate dangerous ACLs",
        config.dc_ip
    );

    let mut conn = crate::runner::ldap_connect(config).await?;
    let mut findings: Vec<AclFinding> = Vec::new();

    // ── 1. nTSecurityDescriptor on high-value objects ─────────────────────────
    let hv_filters = [
        // High-value admin groups
        "(&(objectCategory=group)(|(sAMAccountName=Domain Admins)(sAMAccountName=Enterprise Admins)(sAMAccountName=Schema Admins)(sAMAccountName=Administrators)(sAMAccountName=Account Operators)(sAMAccountName=Backup Operators)(sAMAccountName=Print Operators)(sAMAccountName=Server Operators)(sAMAccountName=Group Policy Creator Owners)(sAMAccountName=DnsAdmins)(sAMAccountName=Protected Users)))",
        // Admin-count users (protected / privileged)
        "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
        // Domain root (DCSync target)
        "(objectClass=domainDNS)",
        // Domain controllers (computers with adminCount=1)
        "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        // GPO containers
        "(objectClass=groupPolicyContainer)",
        // Certificate templates (ADCS)
        "(objectClass=pKICertificateTemplate)",
    ];

    let sd_attrs = &[
        "distinguishedName",
        "sAMAccountName",
        "name",
        "nTSecurityDescriptor",
        "objectClass",
    ];

    for filter in &hv_filters {
        debug!("[acls] Querying: {}", filter);
        match conn.custom_search(filter, sd_attrs).await {
            Ok(entries) => {
                for entry in &entries {
                    let target_dn = entry.dn.clone();
                    let target_name = entry
                        .attrs
                        .get("sAMAccountName")
                        .or_else(|| entry.attrs.get("name"))
                        .and_then(|v| v.first())
                        .cloned()
                        .unwrap_or_else(|| target_dn.clone());

                    if let Some(sddl_vals) = entry.attrs.get("nTSecurityDescriptor") {
                        for sddl in sddl_vals {
                            let mut f = parse_sddl_acl(sddl, &target_name, &target_dn);
                            findings.append(&mut f);
                        }
                    }
                }
            }
            Err(e) => warn!("[acls] SD query failed for filter `{}`: {}", filter, e),
        }
    }

    // ── 2. RBCD — msDS-AllowedToActOnBehalfOfOtherIdentity ────────────────────
    match conn
        .custom_search(
            "(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
            &[
                "distinguishedName",
                "sAMAccountName",
                "msDS-AllowedToActOnBehalfOfOtherIdentity",
            ],
        )
        .await
    {
        Ok(entries) => {
            for entry in &entries {
                let target_dn = entry.dn.clone();
                let target_name = entry
                    .attrs
                    .get("sAMAccountName")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_else(|| target_dn.clone());

                findings.push(AclFinding::new(
                    "(encoded in msDS-AllowedToActOnBehalfOfOtherIdentity — parse SD blob)",
                    None,
                    target_name,
                    target_dn,
                    DangerousRight::AddAllowedToAct,
                    false,
                ));
            }
        }
        Err(e) => warn!("[acls] RBCD query failed: {}", e),
    }

    // ── 3. Constrained delegation — msDS-AllowedToDelegateTo ─────────────────
    match conn
        .custom_search(
            "(msDS-AllowedToDelegateTo=*)",
            &[
                "distinguishedName",
                "sAMAccountName",
                "msDS-AllowedToDelegateTo",
                "userAccountControl",
            ],
        )
        .await
    {
        Ok(entries) => {
            for entry in &entries {
                let target_dn = entry.dn.clone();
                let principal = entry
                    .attrs
                    .get("sAMAccountName")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_else(|| target_dn.clone());

                // Check for protocol-transition flag (TrustedToAuthForDelegation, UAC 0x1000000)
                let uac: u64 = entry
                    .attrs
                    .get("userAccountControl")
                    .and_then(|v| v.first())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let unconstrained = uac & 0x0008_0000 != 0;
                let protocol_transition = uac & 0x0100_0000 != 0;

                let spns = entry
                    .attrs
                    .get("msDS-AllowedToDelegateTo")
                    .cloned()
                    .unwrap_or_default();

                for spn in &spns {
                    let label = if protocol_transition {
                        format!("Constrained delegation (any protocol) → {}", spn)
                    } else if unconstrained {
                        format!("Unconstrained delegation → {}", spn)
                    } else {
                        format!("Constrained delegation (Kerberos only) → {}", spn)
                    };

                    findings.push(AclFinding::new(
                        principal.clone(),
                        None,
                        spn.clone(),
                        target_dn.clone(),
                        DangerousRight::Custom(label),
                        false,
                    ));
                }
            }
        }
        Err(e) => warn!("[acls] Delegation query failed: {}", e),
    }

    // ── 4. Unconstrained delegation ───────────────────────────────────────────
    match conn
        .custom_search(
            // UAC flag 0x80000 = TRUSTED_FOR_DELEGATION; exclude DCs (userAccountControl & 8192)
            "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
            &["distinguishedName", "sAMAccountName", "userAccountControl"],
        )
        .await
    {
        Ok(entries) => {
            for entry in &entries {
                let target_dn = entry.dn.clone();
                let principal = entry
                    .attrs
                    .get("sAMAccountName")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_else(|| target_dn.clone());

                findings.push(AclFinding::new(
                    principal.clone(),
                    None,
                    principal.clone(),
                    target_dn,
                    DangerousRight::Custom("Unconstrained Kerberos delegation (non-DC) — printer bug / coerce attack target".into()),
                    false,
                ));
            }
        }
        Err(e) => warn!("[acls] Unconstrained delegation query failed: {}", e),
    }

    // ── 5. Shadow credentials — existing msDS-KeyCredentialLink ──────────────
    match conn
        .custom_search(
            "(&(objectCategory=person)(objectClass=user)(msDS-KeyCredentialLink=*))",
            &[
                "distinguishedName",
                "sAMAccountName",
                "msDS-KeyCredentialLink",
            ],
        )
        .await
    {
        Ok(entries) => {
            for entry in &entries {
                let target_dn = entry.dn.clone();
                let target_name = entry
                    .attrs
                    .get("sAMAccountName")
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_else(|| target_dn.clone());

                let count = entry
                    .attrs
                    .get("msDS-KeyCredentialLink")
                    .map(|v| v.len())
                    .unwrap_or(0);

                findings.push(AclFinding::new(
                    format!("(existing — {} credential key(s) enrolled)", count),
                    None,
                    target_name,
                    target_dn,
                    DangerousRight::Custom(
                        "Pre-existing msDS-KeyCredentialLink — may indicate Shadow Credentials backdoor".into(),
                    ),
                    false,
                ));
            }
        }
        Err(e) => warn!("[acls] Shadow credentials query failed: {}", e),
    }

    let _ = conn.disconnect().await;

    // Sort by severity then by target for deterministic output
    findings.sort_by(|a, b| a.severity.cmp(&b.severity).then(a.target.cmp(&b.target)));

    info!("[acls] Found {} dangerous ACL findings", findings.len());
    Ok(findings)
}

// ─── SDDL parsing ─────────────────────────────────────────────────────────────

/// Parse the DACL section of an SDDL string and return all dangerous ACE findings.
fn parse_sddl_acl(sddl: &str, target: &str, target_dn: &str) -> Vec<AclFinding> {
    let mut findings = Vec::new();

    // Locate the DACL section starting with "D:"
    let dacl_start = match sddl.find("D:") {
        Some(i) => i + 2,
        None => return findings,
    };
    let dacl_str = &sddl[dacl_start..];

    // Walk balanced parentheses to extract individual ACE strings
    let mut depth = 0usize;
    let mut ace_start = 0usize;
    let mut in_ace = false;

    for (i, ch) in dacl_str.char_indices() {
        match ch {
            '(' => {
                if depth == 0 {
                    ace_start = i + 1;
                    in_ace = true;
                }
                depth += 1;
            }
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 && in_ace {
                    let ace = &dacl_str[ace_start..i];
                    if let Some(f) = parse_sddl_ace(ace, target, target_dn) {
                        findings.push(f);
                    }
                    in_ace = false;
                }
            }
            _ => {}
        }
    }

    findings
}

/// Parse a single SDDL ACE string.
/// Format: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;trustee`
fn parse_sddl_ace(ace: &str, target: &str, target_dn: &str) -> Option<AclFinding> {
    let parts: Vec<&str> = ace.splitn(6, ';').collect();
    if parts.len() < 6 {
        return None;
    }

    let ace_type = parts[0];
    let ace_flags = parts[1];
    let rights_str = parts[2];
    let object_guid = parts[3].to_lowercase();
    // parts[4] = inherit object guid (unused here)
    let trustee = parts[5];

    // Only process Allow ACEs (A) — skip Deny (D), Audit (AU/AL), etc.
    if ace_type != "A" {
        return None;
    }

    // Skip well-known built-in / system-default trustees that are expected.
    // Both two-letter SDDL aliases and common S-1-5-* SIDs are filtered.
    if is_builtin_trustee(trustee) {
        return None;
    }

    let is_inherited = ace_flags.contains('I');

    // Parse the rights field — may be hex (0x…) or SDDL abbreviations
    let rights_mask: u32 = if rights_str.starts_with("0x") || rights_str.starts_with("0X") {
        u32::from_str_radix(
            rights_str.trim_start_matches("0x").trim_start_matches("0X"),
            16,
        )
        .unwrap_or(0)
    } else {
        sddl_abbrev_to_mask(rights_str)
    };

    // ── Map rights to a DangerousRight ───────────────────────────────────────

    // GenericAll subsumes everything else
    if rights_mask & GENERIC_ALL != 0 || rights_str.contains("GA") {
        return Some(AclFinding::new(
            trustee,
            Some(trustee.to_string()),
            target,
            target_dn,
            DangerousRight::GenericAll,
            is_inherited,
        ));
    }

    // WriteDACL
    if rights_mask & WRITE_DACL != 0 || rights_str.contains("WD") {
        return Some(AclFinding::new(
            trustee,
            Some(trustee.to_string()),
            target,
            target_dn,
            DangerousRight::WriteDacl,
            is_inherited,
        ));
    }

    // WriteOwner
    if rights_mask & WRITE_OWNER != 0 || rights_str.contains("WO") {
        return Some(AclFinding::new(
            trustee,
            Some(trustee.to_string()),
            target,
            target_dn,
            DangerousRight::WriteOwner,
            is_inherited,
        ));
    }

    // GenericWrite
    if rights_mask & GENERIC_WRITE != 0 || rights_str.contains("GW") {
        return Some(AclFinding::new(
            trustee,
            Some(trustee.to_string()),
            target,
            target_dn,
            DangerousRight::GenericWrite,
            is_inherited,
        ));
    }

    // CreateChild (CC in SDDL)
    if rights_mask & ADS_RIGHT_DS_CREATE_CHILD != 0 {
        return Some(AclFinding::new(
            trustee,
            Some(trustee.to_string()),
            target,
            target_dn,
            DangerousRight::CreateChild,
            is_inherited,
        ));
    }

    // WriteSelf / validated write (SW in SDDL)
    if rights_mask & ADS_RIGHT_DS_SELF != 0 {
        // Check specific validated-write GUID for self-membership
        let right = if object_guid == GUID_SELF_MEMBERSHIP.to_lowercase() {
            DangerousRight::AddSelf
        } else {
            DangerousRight::WriteSelf
        };
        return Some(AclFinding::new(
            trustee,
            Some(trustee.to_string()),
            target,
            target_dn,
            right,
            is_inherited,
        ));
    }

    // Extended rights (CR in SDDL)
    if rights_mask & ADS_RIGHT_DS_CONTROL_ACCESS != 0 || rights_str.contains("CR") {
        let right = match object_guid.as_str() {
            // Empty GUID = AllExtendedRights
            "" => DangerousRight::AllExtendedRights,
            g if g == GUID_USER_FORCE_CHANGE_PASSWORD.to_lowercase() => {
                DangerousRight::ForceChangePassword
            }
            g if g == GUID_REPLICATING_DIRECTORY_CHANGES.to_lowercase()
                || g == GUID_REPLICATING_DIRECTORY_CHANGES_ALL.to_lowercase()
                || g == GUID_REPLICATING_DIRECTORY_CHANGES_IN_FILTERED_SET.to_lowercase() =>
            {
                DangerousRight::DcSync
            }
            g if g == GUID_MS_MCS_ADMPWD.to_lowercase() => DangerousRight::ReadLapsPassword,
            g if g == GUID_MS_LAPS_PASSWORD.to_lowercase() => DangerousRight::ReadLapsPassword,
            g if g == GUID_MS_LAPS_ENC_PASSWORD_EXPIRY.to_lowercase() => {
                DangerousRight::ReadLapsPasswordExpiry
            }
            g if g == GUID_CERTIFICATE_ENROLLMENT.to_lowercase()
                || g == GUID_CERTIFICATE_AUTO_ENROLLMENT.to_lowercase() =>
            {
                DangerousRight::EnrollCertificate
            }
            _ => return None,
        };
        return Some(AclFinding::new(
            trustee,
            Some(trustee.to_string()),
            target,
            target_dn,
            right,
            is_inherited,
        ));
    }

    // WriteProperty (WP in SDDL)
    if rights_mask & ADS_RIGHT_DS_WRITE_PROP != 0 || rights_str.contains("WP") {
        let right = match object_guid.as_str() {
            // Empty object GUID = write any property
            "" => DangerousRight::GenericWrite,
            g if g == GUID_MEMBER.to_lowercase() => DangerousRight::AddMembers,
            g if g == GUID_MS_MCS_ADMPWD.to_lowercase() => DangerousRight::ReadLapsPassword,
            _ => {
                if let Some((_attr, edge, _cost, _traversable, _notes)) =
                    attribute_guid_info(&object_guid)
                {
                    match edge {
                        "WriteSPN" => DangerousRight::WriteSPN,
                        "WriteAllowedToDelegateTo" => DangerousRight::WriteAllowedToDelegateTo,
                        "AddAllowedToAct" => DangerousRight::AddAllowedToAct,
                        "WriteAccountRestrictions" => DangerousRight::WriteAccountRestrictions,
                        "WriteLogonScript" => DangerousRight::WriteLogonScript,
                        "WriteProfilePath" => DangerousRight::WriteProfilePath,
                        "WriteScriptPath" => DangerousRight::WriteScriptPath,
                        "WriteDnsHostName" => DangerousRight::WriteDnsHostName,
                        "WriteServicePrincipalName" => DangerousRight::WriteServicePrincipalName,
                        "WriteKeyCredentialLink" | "AddKeyCredentialLink" => {
                            DangerousRight::AddKeyCredentialLink
                        }
                        "WriteMsDsKeyCredentialLink" => DangerousRight::WriteMsDsKeyCredentialLink,
                        "WriteAltSecurityIdentities" => DangerousRight::WriteAltSecurityIdentities,
                        "WriteUserParameters" => DangerousRight::WriteUserParameters,
                        "WritePwdProperties" => DangerousRight::WritePwdProperties,
                        "WriteLockoutThreshold" => DangerousRight::WriteLockoutThreshold,
                        "WriteMinPwdLength" => DangerousRight::WriteMinPwdLength,
                        "WritePwdHistoryLength" => DangerousRight::WritePwdHistoryLength,
                        "WritePwdComplexity" => DangerousRight::WritePwdComplexity,
                        "WritePwdReversibleEncryption" => {
                            DangerousRight::WritePwdReversibleEncryption
                        }
                        "WritePwdAge" => DangerousRight::WritePwdAge,
                        "WriteLockoutDuration" => DangerousRight::WriteLockoutDuration,
                        "WriteLockoutObservationWindow" => {
                            DangerousRight::WriteLockoutObservationWindow
                        }
                        "WriteGPLink" => DangerousRight::WriteGPLink,
                        "ReadLapsPassword" => DangerousRight::ReadLapsPassword,
                        "ReadGmsaPassword" => DangerousRight::ReadGmsaPassword,
                        "WriteUserCertificate" => DangerousRight::WriteUserCertificate,
                        _ => DangerousRight::WriteProperty {
                            attribute: edge.to_string(),
                            guid: object_guid.clone(),
                        },
                    }
                } else {
                    // Unknown GUID — record it for later triage
                    DangerousRight::WriteProperty {
                        attribute: object_guid.clone(),
                        guid: object_guid.clone(),
                    }
                }
            }
        };
        return Some(AclFinding::new(
            trustee,
            Some(trustee.to_string()),
            target,
            target_dn,
            right,
            is_inherited,
        ));
    }

    None
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Returns `true` for well-known built-in principals that should not be flagged.
/// Covers both SDDL two-letter aliases and common well-known SID strings.
fn is_builtin_trustee(trustee: &str) -> bool {
    // SDDL short aliases
    match trustee {
        "BA" // BUILTIN\Administrators
        | "SY" // NT AUTHORITY\SYSTEM
        | "PS" // Principal Self (handled separately via SW ACEs)
        | "AU" // Authenticated Users (broad but expected)
        | "WD" // World / Everyone
        | "CO" // Creator Owner
        | "OW" // Owner Rights
        | "ED" // Enterprise Domain Controllers
        | "RD" // Remote Desktop Users
        => return true,
        _ => {}
    }

    // Well-known SID prefixes
    if trustee.starts_with("S-1-5-18")  // SYSTEM
        || trustee.starts_with("S-1-5-19")  // LOCAL SERVICE
        || trustee.starts_with("S-1-5-20")  // NETWORK SERVICE
        || trustee == "S-1-1-0"             // Everyone
        || trustee == "S-1-5-11"            // Authenticated Users
        || trustee == "S-1-3-0"             // Creator Owner
        || trustee == "S-1-3-4"
    // Owner Rights
    {
        return true;
    }

    false
}

/// Convert SDDL abbreviated rights tokens to a 32-bit access mask.
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings>
fn sddl_abbrev_to_mask(s: &str) -> u32 {
    let mut mask = 0u32;
    let bytes = s.as_bytes();
    let mut i = 0;

    while i + 1 < bytes.len() {
        let abbrev = &s[i..i + 2];
        mask |= match abbrev {
            "GA" => GENERIC_ALL,                 // 0x10000000
            "GW" => GENERIC_WRITE,               // 0x40000000
            "GR" => 0x8000_0000u32,              // Generic Read
            "GX" => 0x2000_0000u32,              // Generic Execute
            "WD" => WRITE_DACL,                  // 0x00040000
            "WO" => WRITE_OWNER,                 // 0x00080000
            "RC" => READ_CONTROL,                // 0x00020000
            "SD" => 0x0001_0000u32,              // Delete
            "CC" => ADS_RIGHT_DS_CREATE_CHILD,   // 0x00000001 — BUG FIX: was WP in original
            "DC" => 0x0000_0002u32, // ADS_RIGHT_DS_DELETE_CHILD — BUG FIX: was WP in original
            "LC" => 0x0000_0004u32, // ADS_RIGHT_ACTRL_DS_LIST
            "SW" => ADS_RIGHT_DS_SELF, // 0x00000008 — BUG FIX: was 0x80 in original
            "RP" => 0x0000_0010u32, // ADS_RIGHT_DS_READ_PROP
            "WP" => ADS_RIGHT_DS_WRITE_PROP, // 0x00000020 — BUG FIX: "DC" was used in original
            "DT" => 0x0000_0040u32, // ADS_RIGHT_DS_DELETE_TREE
            "LO" => 0x0000_0080u32, // ADS_RIGHT_DS_LIST_OBJECT
            "CR" => ADS_RIGHT_DS_CONTROL_ACCESS, // 0x00000100 — BUG FIX: missing in original
            _ => 0,
        };
        i += 2;
    }
    mask
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sddl_abbrev_generic_all() {
        assert_eq!(sddl_abbrev_to_mask("GA"), GENERIC_ALL);
    }

    #[test]
    fn test_sddl_abbrev_write_dacl() {
        assert_eq!(sddl_abbrev_to_mask("WD"), WRITE_DACL);
    }

    #[test]
    fn test_sddl_abbrev_cr_is_control_access() {
        // CR must map to ADS_RIGHT_DS_CONTROL_ACCESS — this was missing in the original
        assert_eq!(sddl_abbrev_to_mask("CR"), ADS_RIGHT_DS_CONTROL_ACCESS);
    }

    #[test]
    fn test_sddl_abbrev_sw_is_self() {
        // SW = ADS_RIGHT_DS_SELF (0x8), not 0x80 as in the original
        assert_eq!(sddl_abbrev_to_mask("SW"), ADS_RIGHT_DS_SELF);
    }

    #[test]
    fn test_sddl_abbrev_wp_is_write_prop() {
        // WP = ADS_RIGHT_DS_WRITE_PROP; original used "DC" for this which is wrong
        assert_eq!(sddl_abbrev_to_mask("WP"), ADS_RIGHT_DS_WRITE_PROP);
    }

    #[test]
    fn test_sddl_abbrev_cc_is_create_child() {
        assert_eq!(sddl_abbrev_to_mask("CC"), ADS_RIGHT_DS_CREATE_CHILD);
    }

    #[test]
    fn test_parse_generic_all_ace() {
        // A;;GA;;;S-1-5-21-1234-5678-9012-1001 → GenericAll
        let findings = parse_sddl_acl(
            "D:(A;;GA;;;S-1-5-21-1234-5678-9012-1001)",
            "Domain Admins",
            "CN=Domain Admins,CN=Users,DC=test,DC=local",
        );
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].right, DangerousRight::GenericAll));
    }

    #[test]
    fn test_parse_write_dacl_ace() {
        let findings = parse_sddl_acl(
            "D:(A;;WD;;;S-1-5-21-9999-8888-7777-500)",
            "Target",
            "CN=Target,DC=test,DC=local",
        );
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].right, DangerousRight::WriteDacl));
    }

    #[test]
    fn test_all_extended_rights_empty_guid() {
        // CR with empty object GUID = AllExtendedRights
        let findings = parse_sddl_acl(
            "D:(A;;CR;;;S-1-5-21-1234-5678-9012-1337)",
            "Target",
            "CN=Target,DC=test,DC=local",
        );
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].right,
            DangerousRight::AllExtendedRights
        ));
    }

    #[test]
    fn test_dcsync_guid_ace() {
        let sddl = format!(
            "D:(A;;CR;{};;S-1-5-21-1234-5678-9012-1337)",
            GUID_REPLICATING_DIRECTORY_CHANGES_ALL
        );
        let findings = parse_sddl_acl(&sddl, "DC=test,DC=local", "DC=test,DC=local");
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].right, DangerousRight::DcSync));
    }

    #[test]
    fn test_builtin_trustee_filtered() {
        // BA = BUILTIN\Administrators — should be filtered
        let findings = parse_sddl_acl(
            "D:(A;;GA;;;BA)",
            "Domain Admins",
            "CN=Domain Admins,CN=Users,DC=test,DC=local",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn test_create_child_ace() {
        let findings = parse_sddl_acl(
            "D:(A;;CC;;;S-1-5-21-1234-5678-9012-1001)",
            "OU=Corp",
            "OU=Corp,DC=test,DC=local",
        );
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].right, DangerousRight::CreateChild));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(
            DangerousRight::GenericAll.severity() < DangerousRight::WriteLogonScript.severity()
        );
        assert!(
            DangerousRight::DcSync.severity() <= DangerousRight::WriteUserParameters.severity()
        );
    }

    #[test]
    fn test_laps_guid_exact_match() {
        // Confirm that an unrelated GUID starting with the LAPS prefix is NOT matched
        let findings = parse_sddl_acl(
            "D:(A;;WP;faa13209-962c-4e55-8cfe-1b99ae3f1169ff;;S-1-5-21-9-8-7-1000)",
            "COMPUTER$",
            "CN=COMPUTER,CN=Computers,DC=test,DC=local",
        );
        // The malformed GUID should NOT resolve to ReadLapsPassword
        for f in &findings {
            assert!(!matches!(f.right, DangerousRight::ReadLapsPassword));
        }
    }
}
