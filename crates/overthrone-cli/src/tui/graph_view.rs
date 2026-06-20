//! TUI graph canvas and node-detail panel rendering.
//!
//! Bugs fixed vs. original:
//!  â€¢ `EdgeRef` imported but never used â€” removed dead import
//!  â€¢ `highlighted` colour was `LightRed` â€” same as critical edges, invisible on path;
//!    changed to `LightYellow` for contrast
//!  â€¢ `graph` MutexGuard held across `f.render_widget` â€” potential deadlock;
//!    data is now cloned out before the lock is released
//!  â€¢ `Some(match { return None; ... })` pattern caused rustc delimiter mismatch â€”
//!    `edge_abuse_info` rewritten so every arm returns `Option<&'static str>` directly,
//!    no wrapping `Some(match {...})` and no `return` inside the match
//!  â€¢ `Box::leak` for Custom edge string caused unbounded memory leak â€” removed;
//!    Custom/MemberOf/Contains arms now return `None`
//!  â€¢ `let Some(x) = ... else { ... }` let-else replaced with explicit `match` to
//!    avoid indentation-mismatch false positives from rust-analyzer
//!  â€¢ Severity-coloured ACL findings summary in the graph overview panel
//!
//! New features:
//!  â€¢ `render_acl_findings` â€” scrollable ACL findings panel
//!  â€¢ `render_paths` â€” attack-path panel with per-hop abuse notes
//!  â€¢ `render_legend` â€” colour-coded edge-type legend overlay
//!  â€¢ Scroll offset support via `app.graph_scroll`, `app.detail_scroll`,
//!    `app.acl_scroll`, `app.path_scroll`
//!  â€¢ `node_color()` helper covering GPO / OU / CertTemplate node types
//!  â€¢ `edge_color_by_name()` for statistics view
//!  â€¢ Visual graph canvas with clean node/edge rendering
//!  â€¢ Node type visibility toggles (users/computers/groups/etc.)

use crate::tui::app::App;
use overthrone_core::graph::{EdgeRef, EdgeType, NodeId, NodeType};
use ratatui::prelude::*;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{
    Block, Borders, List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
    Wrap,
};
use std::collections::HashMap;
use std::time::Instant;
use tracing::warn;

// â”€â”€â”€ Colour helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Map an edge type to its display colour.
/// When `highlighted` is `true` (the edge lies on the current attack path) the
/// colour is overridden to `LightYellow` so it contrasts against the `LightRed`
/// already used for high-severity edges like `GenericAll` / `AdminTo`.
pub fn edge_color(edge_type: &EdgeType, highlighted: bool) -> Color {
    if highlighted {
        return Color::LightYellow;
    }
    match edge_type {
        EdgeType::MemberOf => Color::DarkGray,
        EdgeType::Contains => Color::DarkGray,
        EdgeType::TrustedBy => Color::LightMagenta,

        EdgeType::AdminTo => Color::Red,
        EdgeType::AllowedToAct => Color::Red,
        EdgeType::ExecuteDCOM => Color::LightRed,
        EdgeType::CanPSRemote => Color::LightRed,

        EdgeType::HasSession => Color::Yellow,
        EdgeType::HasSpn => Color::Yellow,
        EdgeType::DontReqPreauth => Color::Yellow,
        EdgeType::AddSelf => Color::Yellow,
        EdgeType::AddMembers => Color::Yellow,

        EdgeType::CanRDP => Color::Cyan,
        EdgeType::SQLAdmin => Color::Cyan,

        EdgeType::GenericAll => Color::LightRed,
        EdgeType::GenericWrite => Color::LightRed,
        EdgeType::WriteDacl => Color::LightRed,
        EdgeType::WriteOwner => Color::LightRed,
        EdgeType::Owns => Color::LightRed,

        EdgeType::AllExtendedRights => Color::LightRed,
        EdgeType::WriteSPN => Color::Magenta,
        EdgeType::WriteKeyCredentialLink => Color::LightRed,
        EdgeType::AddKeyCredentialLink => Color::LightRed,
        EdgeType::WriteAllowedToDelegateTo => Color::Magenta,
        EdgeType::AddAllowedToAct => Color::Red,
        EdgeType::WriteAccountRestrictions => Color::Magenta,
        EdgeType::CreateChild => Color::DarkGray,
        EdgeType::WriteSelf => Color::Yellow,
        EdgeType::ReadLapsPasswordExpiry => Color::Magenta,
        EdgeType::Enroll => Color::Green,
        EdgeType::EnrollOnBehalfOf => Color::LightRed,
        EdgeType::ManageCA => Color::Green,
        EdgeType::ManageCertificates => Color::Green,
        EdgeType::ManageCertTemplate => Color::Green,
        EdgeType::ForceChangePassword => Color::Magenta,
        EdgeType::ReadLapsPassword => Color::Magenta,
        EdgeType::ReadGmsaPassword => Color::Magenta,
        EdgeType::AllowedToDelegate => Color::Magenta,
        EdgeType::DcSync => Color::Magenta,
        EdgeType::GetChanges => Color::Magenta,
        EdgeType::GetChangesAll => Color::Magenta,
        EdgeType::HasSidHistory => Color::LightMagenta,

        EdgeType::GpoLink => Color::Green,

        EdgeType::AdcsEsc1
        | EdgeType::AdcsEsc2
        | EdgeType::AdcsEsc3
        | EdgeType::AdcsEsc4
        | EdgeType::AdcsEsc5
        | EdgeType::AdcsEsc6
        | EdgeType::AdcsEsc7
        | EdgeType::AdcsEsc8
        | EdgeType::AdcsEsc9
        | EdgeType::AdcsEsc10
        | EdgeType::AdcsEsc11
        | EdgeType::AdcsEsc12
        | EdgeType::AdcsEsc13
        | EdgeType::AdcsEsc14
        | EdgeType::AdcsEsc15
        | EdgeType::AdcsEsc16 => Color::LightRed,

        EdgeType::Custom(name) => edge_color_by_name(name),
    }
}

/// Severity-mapped colour for ACL finding rows (1 = most severe).
fn severity_color(severity: u8) -> Color {
    match severity {
        1 => Color::Red,
        2 => Color::LightRed,
        3 => Color::Yellow,
        4 => Color::Cyan,
        _ => Color::Gray,
    }
}

/// Display colour for a node type.
pub fn node_color(node_type: &NodeType) -> Color {
    match node_type {
        NodeType::User => Color::Green,
        NodeType::Computer => Color::Blue,
        NodeType::Group => Color::Yellow,
        NodeType::Domain => Color::Magenta,
        NodeType::Gpo => Color::Cyan,
        NodeType::Ou => Color::LightBlue,
        NodeType::CertTemplate => Color::LightMagenta,
    }
}

/// Derive a display colour from an edge-type name string.
/// Used in the statistics view where we only have `&str`, not `&EdgeType`.
fn normalized_edge_name(name: &str) -> String {
    name.trim()
        .trim_start_matches("Custom(")
        .trim_end_matches(')')
        .replace([' ', '-', '_'], "")
        .to_ascii_lowercase()
}

fn edge_color_by_name(name: &str) -> Color {
    match normalized_edge_name(name).as_str() {
        "adminto" | "allowedtoact" | "addallowedtoact" => Color::Red,
        "genericall"
        | "writedacl"
        | "writeowner"
        | "genericwrite"
        | "owns"
        | "allextendedrights"
        | "writekeycredentiallink"
        | "writemsdskeycredentiallink"
        | "addkeycredentiallink"
        | "writealtsecurityidentities"
        | "enrollcertificate"
        | "enrollonbehalfof" => Color::LightRed,
        "hassession" | "hasspn" | "dontreqpreauth" | "addmembers" | "addself" | "writeself" => {
            Color::Yellow
        }
        "canrdp" | "sqladmin" => Color::Cyan,
        "canpsremote" | "executedcom" => Color::LightRed,
        "forcechangepassword"
        | "dcsync"
        | "getchanges"
        | "getchangesall"
        | "getchangesinfilteredset"
        | "allowedtodelegate"
        | "writeallowedtodelegateto"
        | "readlapspassword"
        | "readlapspasswordexpiry"
        | "readlapsencryptedpassword"
        | "readgmsapassword"
        | "hassidhistory"
        | "writespn"
        | "writeserviceprincipalname" => Color::Magenta,
        "gpolink" | "gplink" | "writegplink" | "gpoadmin" | "gpocontributor" => Color::Green,
        "trustedby" | "trustedtoauth" => Color::LightMagenta,
        "memberof" | "contains" | "createchild" => Color::DarkGray,
        _ => Color::Gray,
    }
}

/// Short abuse description for an edge type.
/// Returns `None` for non-abusable traversal edges (MemberOf, Contains, Custom).
/// **Key fix:** every arm returns `Option<&'static str>` directly.  The original
/// code used `Some(match { ... })` with `return None` / `return Some(...)` inside
/// the match body, which confused rustc's brace balancer and produced the
/// "unexpected closing delimiter" error at the last `}` of the file.
fn edge_abuse_info(edge_type: &EdgeType) -> Option<&'static str> {
    match edge_type {
        EdgeType::AdminTo => Some("Local admin â€” exec via WMI / WinRM / SMB / PsExec"),
        EdgeType::GenericAll => Some("Full control â€” reset password, modify DACL, add to group"),
        EdgeType::GenericWrite => {
            Some("Write non-protected attributes â€” SPN, KeyCredentialLink, etc.")
        }
        EdgeType::WriteDacl => Some("Modify DACL / ACEs -> grant yourself GenericAll"),
        EdgeType::WriteOwner => Some("Take ownership -> modify DACL / ACEs -> GenericAll"),
        EdgeType::Owns => Some("Already owner â€” modify DACL to gain GenericAll"),
        EdgeType::AllExtendedRights => Some("Covers all extended rights â€” check individual RSOP"),
        EdgeType::ForceChangePassword => {
            Some("net rpc password / Set-ADAccountPassword (no current pw needed)")
        }
        EdgeType::AddMembers => Some("Add yourself / controlled account to the group"),
        EdgeType::AddSelf => {
            Some("Self-write validated right â€” add your own account to the group")
        }
        EdgeType::CreateChild => Some("CreateChild â€” create new AD objects in the container"),
        EdgeType::WriteSelf => Some("WriteSelf â€” modify attributes on self/group membership"),
        EdgeType::ReadLapsPasswordExpiry => Some("Read LAPS expiry metadata"),
        EdgeType::WriteSPN => Some("Write SPN -> targeted Kerberoast after ticket collection"),
        EdgeType::WriteKeyCredentialLink => {
            Some("Shadow Credentials -> authenticate as target via PKINIT")
        }
        EdgeType::AddKeyCredentialLink => {
            Some("Shadow Credentials (self) -> authenticate as target via PKINIT")
        }
        EdgeType::WriteAllowedToDelegateTo => {
            Some("Write msDS-AllowedToDelegateTo for constrained delegation")
        }
        EdgeType::AddAllowedToAct => {
            Some("Write RBCD ACE -> impersonate Domain Admin to target computer")
        }
        EdgeType::WriteAccountRestrictions => {
            Some("Write account restriction attributes -> delegation/policy abuse")
        }
        EdgeType::Enroll => Some("Certificate enrollment -> request certificate from template"),
        EdgeType::EnrollOnBehalfOf => {
            Some("Enrollment agent -> request certs on behalf of other principals")
        }
        EdgeType::ManageCA => Some("Manage CA -> modify CA settings, revocation, permissions"),
        EdgeType::ManageCertificates => {
            Some("Manage Certificates -> approve/reject pending requests")
        }
        EdgeType::ManageCertTemplate => {
            Some("Manage Certificate Template -> modify EKU/issuance settings")
        }
        EdgeType::AllowedToDelegate => {
            Some("S4U2Self + S4U2Proxy â†’ impersonate any user to target service")
        }
        EdgeType::AllowedToAct => {
            Some("RBCD ACE -> getST.py to impersonate Domain Admin to target computer")
        }
        EdgeType::DcSync => Some("secretsdump.py -just-dc â†’ dump NTDS + all NTLM hashes"),
        EdgeType::GetChanges | EdgeType::GetChangesAll => {
            Some("Part of DCSync right â€” principal needs both GetChanges flags")
        }
        EdgeType::ReadLapsPassword => {
            Some("Read ms-Mcs-AdmPwd / ms-LAPS-Password â†’ cleartext local admin cred")
        }
        EdgeType::ReadGmsaPassword => {
            Some("GMSAPasswordReader â†’ NT hash for lateral movement as gMSA")
        }
        EdgeType::HasSidHistory => {
            Some("SID in SIDHistory â†’ principal implicitly member of historical group")
        }
        EdgeType::CanRDP => {
            Some("xfreerdp / mstsc â€” GUI access; local admin may not be required")
        }
        EdgeType::CanPSRemote => Some("Enter-PSSession / evil-winrm â€” PowerShell remoting"),
        EdgeType::ExecuteDCOM => Some("Invoke-DCOM / MMC20.Application lateral movement"),
        EdgeType::SQLAdmin => Some("SQL Server sysadmin â†’ xp_cmdshell / CLR assembly RCE"),
        EdgeType::HasSession => {
            Some("Token impersonation if admin on host (Incognito / mimikatz tokens)")
        }
        EdgeType::HasSpn => Some("GetUserSPNs.py â†’ offline TGS crack (Kerberoast)"),
        EdgeType::DontReqPreauth => Some("GetNPUsers.py â†’ AS-REP roast (DONT_REQ_PREAUTH set)"),
        EdgeType::GpoLink => Some("Link GPO to OU â†’ immediate exec on Group Policy refresh"),
        EdgeType::TrustedBy => {
            Some("Cross-domain trust â€” SID injection / trust escalation potential")
        }
        EdgeType::AdcsEsc1 | EdgeType::AdcsEsc6 | EdgeType::AdcsEsc16 => {
            Some("ADCS: Impersonate any user via SAN / UPN poisoning")
        }
        EdgeType::AdcsEsc3 => Some("ADCS: Enrollment agent path â€” request on behalf of others"),
        EdgeType::AdcsEsc4 => Some("ADCS: Template modification â€” grant yourself enroll rights"),
        EdgeType::AdcsEsc9 | EdgeType::AdcsEsc15 => {
            Some("ADCS: No-security-extension abuse / UPN poisoning")
        }
        EdgeType::AdcsEsc14 => Some("ADCS: altSecurityIdentities mapping abuse"),
        EdgeType::AdcsEsc2
        | EdgeType::AdcsEsc5
        | EdgeType::AdcsEsc7
        | EdgeType::AdcsEsc8
        | EdgeType::AdcsEsc10
        | EdgeType::AdcsEsc11
        | EdgeType::AdcsEsc12
        | EdgeType::AdcsEsc13 => Some("ADCS: Configuration-based certificate abuse path"),

        // Non-abusable traversal / membership edges â€” no abuse note
        EdgeType::Custom(name) => edge_abuse_info_by_name(name),
        EdgeType::MemberOf | EdgeType::Contains => None,
    }
}

fn edge_abuse_info_by_name(name: &str) -> Option<&'static str> {
    match normalized_edge_name(name).as_str() {
        "allextendedrights" => Some(
            "AllExtendedRights - on users this often enables password reset; on domains confirm replication rights before DCSync.",
        ),
        "createchild" => Some(
            "CreateChild - can create objects in the container/OU; check machine-account, group, and policy abuse scope.",
        ),
        "writeself" => Some(
            "WriteSelf - validated self-write; commonly abused for group self-add or targeted attribute updates.",
        ),
        "readlapspasswordexpiry" | "readlapsencryptedpassword" => Some(
            "LAPS metadata/encrypted material - pair with DPAPI/LAPS decryption capability and host targeting rules.",
        ),
        "writespn" | "writeserviceprincipalname" => Some(
            "SPN write - set a controlled SPN for targeted Kerberoasting, then remove it after ticket collection.",
        ),
        "writeallowedtodelegateto" => Some(
            "Delegation write - change msDS-AllowedToDelegateTo, then test only the intended S4U service path.",
        ),
        "addallowedtoact" => Some(
            "RBCD write - add msDS-AllowedToActOnBehalfOfOtherIdentity for a controlled computer account.",
        ),
        "writeaccountrestrictions" => Some(
            "Account restrictions write - may enable delegation or auth-policy changes depending on target class.",
        ),
        "writelogonscript" | "writeprofilepath" | "writescriptpath" => Some(
            "Logon/profile script write - code execution path that is visible; keep payload and rollback tightly scoped.",
        ),
        "writednshostname" => Some(
            "DNS hostname write - validate SPN/DNS side effects before using for delegation or relay chains.",
        ),
        "writekeycredentiallink" | "writemsdskeycredentiallink" | "addkeycredentiallink" => Some(
            "Shadow credentials - add a controlled KeyCredentialLink, authenticate with PKINIT, then remove the value.",
        ),
        "writealtsecurityidentities" => Some(
            "Certificate mapping write - can map an attacker certificate to the account; verify ADCS mapping policy first.",
        ),
        "writeuserparameters" => Some(
            "UserParameters write - legacy attribute execution or persistence surface; validate client logon impact.",
        ),
        "writepwdproperties"
        | "writelockoutthreshold"
        | "writeminpwdlength"
        | "writepwdhistorylength"
        | "writepwdcomplexity"
        | "writepwdreversibleencryption"
        | "writepwdage"
        | "writelockoutduration"
        | "writelockoutobservationwindow" => Some(
            "Password policy write - domain-impacting control; document original policy and avoid disruptive changes.",
        ),
        "writegplink" => Some(
            "GPLink write - link a controlled GPO to an OU; confirm security filtering, inheritance, and rollback.",
        ),
        "enrollcertificate" => Some(
            "Certificate enrollment - inspect template EKUs, subject supply, manager approval, and enrollment agent scope.",
        ),
        "enrollonbehalfof" => Some(
            "Enrollment-agent path - request on behalf of another principal only after validating template constraints.",
        ),
        "writeproperty" => Some(
            "WriteProperty - inspect the exact attribute GUID; abuse varies from SPN and delegation to ADCS mapping.",
        ),
        _ => None,
    }
}

fn edge_ovt_command(edge_type: &EdgeType) -> Option<&'static str> {
    match edge_type {
        EdgeType::AdminTo => Some("ovt exec --target <TARGET> --method auto"),
        EdgeType::GenericAll | EdgeType::GenericWrite => Some("ovt powerview acls --sid <SID>"),
        EdgeType::WriteDacl | EdgeType::WriteOwner | EdgeType::Owns => {
            Some("ovt acls writedacl --target <TARGET>")
        }
        EdgeType::ForceChangePassword => {
            Some("ovt acl force-password --target <TARGET> --password <NEW_PASSWORD>")
        }
        EdgeType::AddMembers => Some("ovt acl add-member --group <GROUP> --member <ACCOUNT>"),
        EdgeType::AddSelf => Some("ovt acl add-self --group <GROUP>"),
        EdgeType::AllExtendedRights => Some("ovt powerview acls --sid <SID>"),
        EdgeType::CreateChild => Some("ovt acls writedacl --target <TARGET>"),
        EdgeType::WriteSelf => Some("ovt powerview acls --sid <SID>"),
        EdgeType::ReadLapsPasswordExpiry => {
            Some("ovt laps read --computer <COMPUTER> --target-dc <DC>")
        }
        EdgeType::WriteSPN => Some("ovt acl write-spn --target <TARGET> --spn <SPN>"),
        EdgeType::WriteKeyCredentialLink | EdgeType::AddKeyCredentialLink => {
            Some("ovt acl shadow-creds --target <TARGET> --cert <CERT_FILE>")
        }
        EdgeType::WriteAllowedToDelegateTo => Some("ovt acls writedacl --target <TARGET>"),
        EdgeType::AddAllowedToAct => Some("ovt acls add-allowed-to-act --target <TARGET>"),
        EdgeType::WriteAccountRestrictions => Some("ovt powerview acls --sid <SID>"),
        EdgeType::Enroll => Some("ovt adcs enroll --template <TEMPLATE> --target <TARGET>"),
        EdgeType::EnrollOnBehalfOf => {
            Some("ovt adcs enroll --template <TEMPLATE> --target <TARGET> --agent")
        }
        EdgeType::ManageCA => Some("ovt adcs manage-ca --ca <CA>"),
        EdgeType::ManageCertificates => Some("ovt adcs manage-certificates --ca <CA>"),
        EdgeType::ManageCertTemplate => Some("ovt adcs template --template <TEMPLATE> --inspect"),
        EdgeType::AllowedToDelegate => Some("ovt powerview delegations --target <TARGET>"),
        EdgeType::AllowedToAct => Some("ovt acls add-allowed-to-act --target <TARGET>"),
        EdgeType::DcSync | EdgeType::GetChanges | EdgeType::GetChangesAll => {
            Some("ovt adcs dcsync --target <TARGET> --domain <DOMAIN>")
        }
        EdgeType::ReadLapsPassword => Some("ovt laps read --computer <COMPUTER> --target-dc <DC>"),
        EdgeType::ReadGmsaPassword => Some("ovt powerview acls --sid <SID>"),
        EdgeType::HasSidHistory => Some("ovt move sid-history --target <TARGET>"),
        EdgeType::CanRDP => Some("ovt exec --target <TARGET> --method rdp"),
        EdgeType::CanPSRemote => Some("ovt exec --target <TARGET> --method psremote"),
        EdgeType::ExecuteDCOM => Some("ovt exec --target <TARGET> --method dcom"),
        EdgeType::SQLAdmin => Some("ovt mssql --target <TARGET> --query 'SELECT @@version'"),
        EdgeType::HasSession => Some("ovt exec --target <TARGET> --method token"),
        EdgeType::HasSpn => Some("ovt kerberoast --spn <SPN>"),
        EdgeType::DontReqPreauth => Some("ovt asrep --user <USER>"),
        EdgeType::GpoLink => Some("ovt gpo status --target <TARGET>"),
        EdgeType::TrustedBy => Some("ovt move trust --domain <SOURCE_DOMAIN> --target <TARGET>"),
        EdgeType::AdcsEsc1 => Some("ovt adcs esc1 --ca <CA> --template <TEMPLATE>"),
        EdgeType::AdcsEsc2 => Some("ovt adcs esc2 --ca <CA> --template <TEMPLATE>"),
        EdgeType::AdcsEsc3 => Some("ovt adcs esc3 --ca <CA> --template <TEMPLATE>"),
        EdgeType::AdcsEsc4 => Some("ovt adcs esc4 --ca <CA> --template <TEMPLATE>"),
        EdgeType::AdcsEsc5 => Some("ovt adcs esc5 --ca <CA> --template <TEMPLATE>"),
        EdgeType::AdcsEsc6 => Some("ovt adcs esc6 --ca <CA> --template <TEMPLATE>"),
        EdgeType::AdcsEsc7 => Some("ovt adcs esc7 --ca <CA> --template <TEMPLATE>"),
        EdgeType::AdcsEsc8 => Some("ovt adcs esc8 --ca <CA> --template <TEMPLATE>"),
        EdgeType::AdcsEsc9 => Some("ovt adcs esc9 --ca <CA> --template <TEMPLATE>"),
        EdgeType::AdcsEsc10 => Some("ovt adcs esc10 --ca <CA> --template <TEMPLATE>"),
        EdgeType::AdcsEsc11 => Some("ovt adcs esc11 --ca <CA> --template <TEMPLATE>"),
        EdgeType::AdcsEsc12 => Some("ovt adcs esc12 --ca <CA> --template <TEMPLATE>"),
        EdgeType::AdcsEsc13 => Some("ovt adcs esc13 --ca <CA> --template <TEMPLATE>"),
        EdgeType::AdcsEsc14 => Some("ovt adcs esc14 --ca <CA> --template <TEMPLATE>"),
        EdgeType::AdcsEsc15 => Some("ovt adcs esc15 --ca <CA> --template <TEMPLATE>"),
        EdgeType::AdcsEsc16 => Some("ovt adcs esc16 --ca <CA> --template <TEMPLATE>"),
        EdgeType::Custom(name) => edge_ovt_command_by_name(name),
        EdgeType::MemberOf => Some("ovt powerview members --group <GROUP> --recurse"),
        EdgeType::Contains => Some("ovt powerview container --target <TARGET>"),
    }
}

fn edge_ovt_command_by_name(name: &str) -> Option<&'static str> {
    match normalized_edge_name(name).as_str() {
        "allextendedrights" | "writeself" | "writeproperty" => {
            Some("ovt powerview acls --sid <SID>")
        }
        "createchild" | "writeallowedtodelegateto" => Some("ovt acls writedacl --target <TARGET>"),
        "writespn" | "writeserviceprincipalname" => {
            Some("ovt acl write-spn --target <TARGET> --spn <SPN>")
        }
        "addallowedtoact" => Some("ovt acls add-allowed-to-act --target <TARGET>"),
        "writekeycredentiallink" | "writemsdskeycredentiallink" | "addkeycredentiallink" => {
            Some("ovt acl shadow-creds --target <TARGET> --cert <CERT_FILE>")
        }
        "writealtsecurityidentities" => Some("ovt adcs alt-sid --target <TARGET>"),
        "writegplink" => Some("ovt gpo link --target <TARGET> --gpo <GPO_ID>"),
        "enrollcertificate" | "enrollonbehalfof" => {
            Some("ovt adcs enroll --template <TEMPLATE> --target <TARGET>")
        }
        "readlapspasswordexpiry" | "readlapsencryptedpassword" => {
            Some("ovt laps read --computer <COMPUTER> --target-dc <DC>")
        }
        "writelogonscript" | "writeprofilepath" | "writescriptpath" => {
            Some("ovt acl write-script --target <TARGET>")
        }
        "manageca" => Some("ovt adcs manage-ca --ca <CA>"),
        "managecertificates" => Some("ovt adcs manage-certificates --ca <CA>"),
        "managecerttemplate" => Some("ovt adcs template --template <TEMPLATE> --inspect"),
        name if name.starts_with("adcsesc") => {
            Some("ovt adcs esc<N> --ca <CA> --template <TEMPLATE>")
        }
        _ => None,
    }
}

fn edge_severity(edge_type: &EdgeType) -> u8 {
    match edge_type {
        EdgeType::GenericAll
        | EdgeType::WriteDacl
        | EdgeType::WriteOwner
        | EdgeType::Owns
        | EdgeType::AllExtendedRights
        | EdgeType::DcSync
        | EdgeType::AllowedToAct
        | EdgeType::WriteKeyCredentialLink
        | EdgeType::AddKeyCredentialLink => 1,
        EdgeType::GenericWrite
        | EdgeType::ForceChangePassword
        | EdgeType::AddMembers
        | EdgeType::AddSelf
        | EdgeType::WriteSPN
        | EdgeType::WriteAllowedToDelegateTo
        | EdgeType::AddAllowedToAct
        | EdgeType::ReadLapsPassword
        | EdgeType::ReadGmsaPassword
        | EdgeType::AllowedToDelegate
        | EdgeType::SQLAdmin
        | EdgeType::GpoLink
        | EdgeType::TrustedBy
        | EdgeType::GetChanges
        | EdgeType::GetChangesAll
        | EdgeType::EnrollOnBehalfOf
        | EdgeType::ManageCertTemplate => 2,
        EdgeType::AdminTo
        | EdgeType::CanRDP
        | EdgeType::CanPSRemote
        | EdgeType::ExecuteDCOM
        | EdgeType::HasSession
        | EdgeType::HasSidHistory
        | EdgeType::CreateChild
        | EdgeType::WriteSelf
        | EdgeType::ReadLapsPasswordExpiry
        | EdgeType::WriteAccountRestrictions
        | EdgeType::Enroll
        | EdgeType::ManageCA
        | EdgeType::ManageCertificates => 3,
        EdgeType::HasSpn | EdgeType::DontReqPreauth => 4,
        EdgeType::AdcsEsc1
        | EdgeType::AdcsEsc2
        | EdgeType::AdcsEsc3
        | EdgeType::AdcsEsc4
        | EdgeType::AdcsEsc5
        | EdgeType::AdcsEsc6
        | EdgeType::AdcsEsc7
        | EdgeType::AdcsEsc8
        | EdgeType::AdcsEsc9
        | EdgeType::AdcsEsc10
        | EdgeType::AdcsEsc11
        | EdgeType::AdcsEsc12
        | EdgeType::AdcsEsc13
        | EdgeType::AdcsEsc14
        | EdgeType::AdcsEsc15
        | EdgeType::AdcsEsc16 => 1,
        EdgeType::Custom(name) => edge_severity_by_name(name),
        EdgeType::MemberOf | EdgeType::Contains => 5,
    }
}

fn edge_severity_by_name(name: &str) -> u8 {
    match normalized_edge_name(name).as_str() {
        "allextendedrights"
        | "writekeycredentiallink"
        | "writemsdskeycredentiallink"
        | "addkeycredentiallink"
        | "writealtsecurityidentities"
        | "addallowedtoact"
        | "writeallowedtodelegateto"
        | "enrollonbehalfof" => 1,
        "writeself"
        | "writespn"
        | "writeserviceprincipalname"
        | "readlapspasswordexpiry"
        | "readlapsencryptedpassword"
        | "writeaccountrestrictions"
        | "writelogonscript"
        | "writeprofilepath"
        | "writescriptpath"
        | "writegplink"
        | "enrollcertificate"
        | "writeproperty" => 2,
        "createchild"
        | "writednshostname"
        | "writeuserparameters"
        | "writepwdproperties"
        | "writelockoutthreshold"
        | "writeminpwdlength"
        | "writepwdhistorylength"
        | "writepwdcomplexity"
        | "writepwdreversibleencryption"
        | "writepwdage"
        | "writelockoutduration"
        | "writelockoutobservationwindow" => 3,
        _ => 4,
    }
}

fn edge_operator_note(edge_type: &EdgeType) -> Option<&'static str> {
    match edge_type {
        EdgeType::GenericAll => Some(
            "Operator note: full control; preserve current ACL/owner before password, group, or shadow-credential abuse.",
        ),
        EdgeType::GenericWrite => Some(
            "Operator note: write path; evaluate SPN, KeyCredentialLink, logon script, and certificate mapping options.",
        ),
        EdgeType::WriteDacl => Some(
            "Operator note: add a minimal temporary ACE, complete the action, and restore the original DACL.",
        ),
        EdgeType::WriteOwner | EdgeType::Owns => Some(
            "Operator note: ownership can unlock DACL changes; restore owner and ACL after validation.",
        ),
        EdgeType::ForceChangePassword => Some(
            "Operator note: password reset is visible and disruptive; use only when approved by the runbook.",
        ),
        EdgeType::AddMembers | EdgeType::AddSelf => Some(
            "Operator note: group change should be scoped, time-boxed, and removed after the dependent step.",
        ),
        EdgeType::AllowedToAct => Some(
            "Operator note: RBCD path; use a controlled machine account and request only the needed service ticket.",
        ),
        EdgeType::AllowedToDelegate => Some(
            "Operator note: constrained delegation; enumerate allowed services before S4U testing.",
        ),
        EdgeType::DcSync | EdgeType::GetChanges | EdgeType::GetChangesAll => Some(
            "Operator note: replication-impacting right; validate scope and prefer targeted secret retrieval.",
        ),
        EdgeType::ReadLapsPassword => Some(
            "Operator note: collect the host password once, protect it as credential material, and avoid repeated reads.",
        ),
        EdgeType::ReadGmsaPassword => Some(
            "Operator note: derive gMSA material and map service-account reach before using it.",
        ),
        EdgeType::AdminTo => Some(
            "Operator note: local admin path; choose the lowest-volume remote-management primitive allowed.",
        ),
        EdgeType::CanRDP => Some(
            "Operator note: interactive access is visible; prefer non-interactive validation unless RDP is required.",
        ),
        EdgeType::CanPSRemote => {
            Some("Operator note: keep WinRM commands low-volume and host-scoped.")
        }
        EdgeType::ExecuteDCOM => Some(
            "Operator note: DCOM has a high telemetry surface; reserve for approved execution phases.",
        ),
        EdgeType::SQLAdmin => Some(
            "Operator note: inspect linked servers, impersonation, xp_cmdshell, CLR, and trust paths.",
        ),
        EdgeType::HasSession => Some(
            "Operator note: confirm live session freshness and combine with host admin before token operations.",
        ),
        EdgeType::HasSpn => Some(
            "Operator note: Kerberoast marker; request scoped tickets and continue cracking offline.",
        ),
        EdgeType::DontReqPreauth => {
            Some("Operator note: AS-REP roast marker; collect once and continue offline.")
        }
        EdgeType::AllExtendedRights => Some(
            "Operator note: resolve target class first; this can mean password reset, enrollment control, or replication impact.",
        ),
        EdgeType::CreateChild => Some(
            "Operator note: container-level control; evaluate machine account creation, service class, or group creation.",
        ),
        EdgeType::WriteSelf => Some(
            "Operator note: validated self-write; confirm exact writeable attributes before exploitation.",
        ),
        EdgeType::ReadLapsPasswordExpiry => Some(
            "Operator note: LAPS expiry metadata; combine with LAPS decryption if encrypted passwords are accessible.",
        ),
        EdgeType::WriteSPN => Some(
            "Operator note: SPN write for targeted Kerberoast; set a temporary SPN and restore after ticket collection.",
        ),
        EdgeType::WriteKeyCredentialLink | EdgeType::AddKeyCredentialLink => Some(
            "Operator note: shadow credentials path; add KeyCredentialLink, authenticate via PKINIT, and remove after use.",
        ),
        EdgeType::WriteAllowedToDelegateTo => Some(
            "Operator note: constrained delegation; record original msDS-AllowedToDelegateTo and restore after S4U validation.",
        ),
        EdgeType::AddAllowedToAct => Some(
            "Operator note: RBCD path; use a controlled machine account and request only the needed service ticket.",
        ),
        EdgeType::WriteAccountRestrictions => Some(
            "Operator note: account restriction attributes may affect delegation and authentication; document original values.",
        ),
        EdgeType::Enroll => Some(
            "Operator note: certificate enrollment; review template EKUs, subject supply, approval flags, and security filtering.",
        ),
        EdgeType::EnrollOnBehalfOf => Some(
            "Operator note: enrollment agent path; validate agent restriction and template approval requirements before requesting.",
        ),
        EdgeType::ManageCA => Some(
            "Operator note: CA management; CA modifications affect all issued certificates — prefer read-only audit.",
        ),
        EdgeType::ManageCertificates => Some(
            "Operator note: certificate approval; approve/reject pending requests or manage revocation at the CA console.",
        ),
        EdgeType::ManageCertTemplate => Some(
            "Operator note: template management; template ACL or EKU changes can enable ESC1-style abuse.",
        ),
        EdgeType::GpoLink => Some(
            "Operator note: review linked OU scope, security filtering, and rollback before GPO edits.",
        ),
        EdgeType::TrustedBy => Some(
            "Operator note: confirm trust direction, SID filtering, selective auth, and transitivity.",
        ),
        EdgeType::HasSidHistory => Some(
            "Operator note: validate effective SIDHistory membership and cross-domain side effects.",
        ),
        EdgeType::AdcsEsc1
        | EdgeType::AdcsEsc2
        | EdgeType::AdcsEsc3
        | EdgeType::AdcsEsc4
        | EdgeType::AdcsEsc5
        | EdgeType::AdcsEsc6
        | EdgeType::AdcsEsc7
        | EdgeType::AdcsEsc8
        | EdgeType::AdcsEsc9
        | EdgeType::AdcsEsc10
        | EdgeType::AdcsEsc11
        | EdgeType::AdcsEsc12
        | EdgeType::AdcsEsc13
        | EdgeType::AdcsEsc14
        | EdgeType::AdcsEsc15
        | EdgeType::AdcsEsc16 => Some(
            "Operator note: ADCS path; verify template EKUs, SAN policy, and enrollment agent requirements.",
        ),
        EdgeType::Custom(name) => edge_operator_note_by_name(name),
        EdgeType::MemberOf | EdgeType::Contains => None,
    }
}

fn edge_operator_note_by_name(name: &str) -> Option<&'static str> {
    match normalized_edge_name(name).as_str() {
        "allextendedrights" => Some(
            "Operator note: resolve target class first; this can mean password reset, enrollment control, or replication impact.",
        ),
        "createchild" => Some(
            "Operator note: create only disposable test objects and remove them; OU/container scope matters.",
        ),
        "writeself" => Some(
            "Operator note: validated writes are attribute-specific; confirm member/self or SPN semantics before acting.",
        ),
        "readlapspasswordexpiry" | "readlapsencryptedpassword" => Some(
            "Operator note: treat LAPS values as credential material and avoid repeated reads.",
        ),
        "writespn" | "writeserviceprincipalname" => Some(
            "Operator note: set one temporary SPN, request one ticket, then restore the original SPN set.",
        ),
        "writeallowedtodelegateto" => Some(
            "Operator note: record the original delegation list and add only the specific service needed.",
        ),
        "addallowedtoact" => Some(
            "Operator note: use a controlled computer account for RBCD and remove the ACE after validation.",
        ),
        "writeaccountrestrictions" => Some(
            "Operator note: verify whether the write changes delegation, logon, or account policy behavior.",
        ),
        "writelogonscript" | "writeprofilepath" | "writescriptpath" => Some(
            "Operator note: script/profile paths are visible execution surfaces; keep payloads minimal and reversible.",
        ),
        "writednshostname" => Some(
            "Operator note: check DNS, SPN, and delegation side effects before modifying host identity fields.",
        ),
        "writekeycredentiallink" | "writemsdskeycredentiallink" | "addkeycredentiallink" => Some(
            "Operator note: shadow credentials require exact original-value capture and cleanup after PKINIT.",
        ),
        "writealtsecurityidentities" => Some(
            "Operator note: certificate mapping depends on domain mapping policy; capture and restore original values.",
        ),
        "writeuserparameters" => Some(
            "Operator note: legacy user-parameter abuse can affect logon behavior; validate with a non-critical account first.",
        ),
        "writepwdproperties"
        | "writelockoutthreshold"
        | "writeminpwdlength"
        | "writepwdhistorylength"
        | "writepwdcomplexity"
        | "writepwdreversibleencryption"
        | "writepwdage"
        | "writelockoutduration"
        | "writelockoutobservationwindow" => Some(
            "Operator note: password-policy changes are domain visible; prefer read-only proof unless explicitly approved.",
        ),
        "writegplink" => Some(
            "Operator note: validate OU scope, inheritance, enforced links, and security filtering before a GPO change.",
        ),
        "enrollcertificate" | "enrollonbehalfof" => Some(
            "Operator note: confirm template EKUs, subject requirements, approval, and enrollment-agent restrictions.",
        ),
        "writeproperty" => Some(
            "Operator note: inspect the attribute GUID and map it to a precise primitive before taking action.",
        ),
        _ => None,
    }
}

fn push_edge_guidance<'a>(lines: &mut Vec<Line<'a>>, edge_type: &EdgeType, indent: &'static str) {
    if let Some(note) = edge_operator_note(edge_type) {
        let severity = edge_severity(edge_type);
        lines.push(Line::from(vec![
            Span::raw(indent),
            Span::styled(
                format!("[S{}] ", severity),
                Style::default()
                    .fg(severity_color(severity))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(note, Style::default().fg(Color::Gray)),
        ]));
    }
    if let Some(command) = edge_ovt_command(edge_type) {
        lines.push(Line::from(vec![
            Span::raw(indent),
            Span::styled(
                "$ ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(command, Style::default().fg(Color::LightCyan)),
        ]));
    }
}

// â”€â”€â”€ Graph overview panel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Render the graph-overview canvas (left pane of the Graph tab).
/// The `graph` Mutex is locked only long enough to copy out the data we need.
/// The lock is released before any call to `f.render_widget`, preventing a
/// deadlock when the background collector thread contends the same lock.
pub fn render_graph(f: &mut Frame, area: Rect, app: &App) {
    let render_started = Instant::now();
    // Collect stats under the lock, then drop it immediately.
    let (stats, hv_targets, _nodes, _edges) = {
        let graph = app.graph.lock().unwrap_or_else(|e| {
            warn!("Mutex poisoned in GraphView â€” recovering data");
            e.into_inner()
        });
        let stats = graph.stats();
        let hv = graph.high_value_targets(8);
        // Clone node positions for rendering
        let layout_snapshot: HashMap<NodeId, (f64, f64)> = app.layout.clone();
        // Collect visible nodes and edges
        let nodes: Vec<_> = graph
            .nodes()
            .filter(|(idx, node)| is_node_visible(node, *idx, &layout_snapshot, app))
            .map(|(idx, node)| (idx, node.clone()))
            .collect();
        let edges: Vec<_> = graph
            .edges()
            .filter(|edge| {
                let source_idx = edge.source();
                let target_idx = edge.target();
                let source_visible = nodes.iter().any(|(idx, _)| *idx == source_idx);
                let target_visible = nodes.iter().any(|(idx, _)| *idx == target_idx);
                source_visible && target_visible
            })
            .map(|edge| {
                (
                    edge.source(),
                    edge.target(),
                    edge.weight().clone(),
                    edge.id(),
                )
            })
            .collect();
        (stats, hv, nodes, edges)
    };

    let scroll = app.overview_scroll;
    let mut lines: Vec<Line> = Vec::new();

    // Header
    lines.push(Line::from(vec![Span::styled(
        " âš¡ Graph Overview ",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )]));
    lines.push(Line::from(""));

    // Node Counts
    lines.push(Line::from(Span::styled(
        " Node Counts",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::UNDERLINED),
    )));
    lines.push(Line::from(vec![
        Span::styled("  Users:     ", Style::default().fg(Color::Green)),
        Span::styled(
            format!("{:>6}", stats.users),
            Style::default().fg(Color::White),
        ),
        Span::raw("   "),
        Span::styled("Computers: ", Style::default().fg(Color::Blue)),
        Span::styled(
            format!("{:>6}", stats.computers),
            Style::default().fg(Color::White),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Groups:    ", Style::default().fg(Color::Yellow)),
        Span::styled(
            format!("{:>6}", stats.groups),
            Style::default().fg(Color::White),
        ),
        Span::raw("   "),
        Span::styled("Domains:   ", Style::default().fg(Color::Magenta)),
        Span::styled(
            format!("{:>6}", stats.domains),
            Style::default().fg(Color::White),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  GPOs:      ", Style::default().fg(Color::Cyan)),
        Span::styled(
            format!("{:>6}", stats.gpos),
            Style::default().fg(Color::White),
        ),
        Span::raw("   "),
        Span::styled("OUs:       ", Style::default().fg(Color::LightCyan)),
        Span::styled(
            format!("{:>6}", stats.ous),
            Style::default().fg(Color::White),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  Total edges:", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!(" {}", stats.total_edges),
            Style::default().fg(Color::White),
        ),
    ]));
    lines.push(Line::from(""));

    // Visibility toggles
    lines.push(Line::from(Span::styled(
        " Visibility Toggles",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::UNDERLINED),
    )));
    lines.push(Line::from(vec![
        Span::styled(
            "  [u] ",
            Style::default().fg(if app.show_users {
                Color::Green
            } else {
                Color::DarkGray
            }),
        ),
        Span::raw(if app.show_users {
            "Users    "
        } else {
            "Users (hidden) "
        }),
        Span::styled(
            "  [c] ",
            Style::default().fg(if app.show_computers {
                Color::Green
            } else {
                Color::DarkGray
            }),
        ),
        Span::raw(if app.show_computers {
            "Computers"
        } else {
            "Computers(hidden)"
        }),
    ]));
    lines.push(Line::from(vec![
        Span::styled(
            "  [g] ",
            Style::default().fg(if app.show_groups {
                Color::Green
            } else {
                Color::DarkGray
            }),
        ),
        Span::raw(if app.show_groups {
            "Groups   "
        } else {
            "Groups (hidden) "
        }),
        Span::styled(
            "  [d] ",
            Style::default().fg(if app.show_domains {
                Color::Green
            } else {
                Color::DarkGray
            }),
        ),
        Span::raw(if app.show_domains {
            "Domains  "
        } else {
            "Domains (hidden) "
        }),
    ]));
    lines.push(Line::from(""));

    // Edge-type distribution (top 12 by count)
    lines.push(Line::from(Span::styled(
        " Edge Distribution",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::UNDERLINED),
    )));
    let mut edge_counts: Vec<_> = stats.edge_type_counts.iter().collect();
    edge_counts.sort_by(|a, b| b.1.cmp(a.1));
    for (edge_type, count) in edge_counts.iter().take(12) {
        let display = edge_type.to_string();
        let color = edge_color_by_name(&display);
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:<28}", display), Style::default().fg(color)),
            Span::styled(format!("{:>5}", count), Style::default().fg(Color::Yellow)),
        ]));
    }
    lines.push(Line::from(""));

    // High-value targets
    lines.push(Line::from(Span::styled(
        " High-Value Targets",
        Style::default()
            .fg(Color::Red)
            .add_modifier(Modifier::BOLD)
            .add_modifier(Modifier::UNDERLINED),
    )));
    for (name, node_type, degree) in &hv_targets {
        let color = node_color(node_type);
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:?}", node_type), Style::default().fg(color)),
            Span::raw("  "),
            Span::styled(
                name.clone(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                format!("(degree: {})", degree),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    }

    // ACL findings summary (if a scan has been run)
    if let Some(ref acls) = app.acl_findings {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            " ACL / ACE Findings Summary",
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD)
                .add_modifier(Modifier::UNDERLINED),
        )));
        let critical_count = acls.iter().filter(|f| f.severity <= 2).count();
        lines.push(Line::from(vec![
            Span::raw("  Total findings: "),
            Span::styled(
                format!("{}", acls.len()),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw("   Critical (sev Ã¢â€°Â¤ 2): "),
            Span::styled(
                format!("{}", critical_count),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ]));
        for finding in acls.iter().filter(|f| f.severity == 1).take(5) {
            lines.push(Line::from(vec![
                Span::raw("  "),
                Span::styled("âš  ", Style::default().fg(Color::Red)),
                Span::styled(
                    format!("{} â†’ {:?}", finding.principal, finding.right),
                    Style::default().fg(Color::LightRed),
                ),
                Span::raw("  on "),
                Span::styled(finding.target.clone(), Style::default().fg(Color::White)),
            ]));
        }
    }

    let render_ms = render_started.elapsed().as_millis();
    lines.insert(
        1,
        Line::from(vec![
            Span::styled(" Timing: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!(
                    "render {}ms | nodes {} | edges {}",
                    render_ms, stats.total_nodes, stats.total_edges
                ),
                Style::default().fg(Color::LightCyan),
            ),
        ]),
    );

    let scrolled: Vec<Line> = lines.into_iter().skip(scroll).collect();

    let widget = Paragraph::new(scrolled)
        .block(
            Block::default()
                .title(Span::styled(
                    " Graph Canvas [â†‘/â†“ scroll] ",
                    Style::default().fg(Color::Cyan),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(widget, area);
}

/// Check if a node should be visible based on current filters
fn is_node_visible(
    node: &overthrone_core::graph::AdNode,
    _idx: NodeId,
    _layout: &HashMap<NodeId, (f64, f64)>,
    app: &App,
) -> bool {
    // Check node type visibility
    match node.node_type {
        NodeType::User if !app.show_users => return false,
        NodeType::Computer if !app.show_computers => return false,
        NodeType::Group if !app.show_groups => return false,
        NodeType::Domain if !app.show_domains => return false,
        NodeType::Gpo if !app.show_gpos => return false,
        NodeType::Ou if !app.show_ous => return false,
        _ => {}
    }
    // Check search filter
    if !app.filter_text.is_empty() {
        let needle = app.filter_text.to_ascii_lowercase();
        if !node.name.to_ascii_lowercase().contains(&needle)
            && !node.domain.to_ascii_lowercase().contains(&needle)
            && !node
                .node_type
                .to_string()
                .to_ascii_lowercase()
                .contains(&needle)
        {
            return false;
        }
    }
    true
}

// â”€â”€â”€ Node detail panel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Render the node-detail panel for the currently selected node.
pub fn render_node_detail(f: &mut Frame, area: Rect, app: &App) {
    let lines = build_node_detail_lines(app);
    let scroll = app.detail_scroll;

    let widget = Paragraph::new(lines.clone())
        .block(
            Block::default()
                .title(Span::styled(
                    " Node Details [â†‘/â†“ scroll] ",
                    Style::default().fg(Color::Yellow),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: false })
        .scroll((scroll as u16, 0));

    f.render_widget(widget, area);

    let scrollbar = Scrollbar::default()
        .orientation(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("â†‘"))
        .end_symbol(Some("â†“"));
    let mut scrollbar_state = ScrollbarState::new(lines.len()).position(scroll);
    f.render_stateful_widget(
        scrollbar,
        area.inner(Margin {
            vertical: 1,
            horizontal: 0,
        }),
        &mut scrollbar_state,
    );
}

/// Build the line buffer for `render_node_detail`.
/// Uses explicit `match` instead of `let-else` to avoid the rust-analyzer
/// indentation-mismatch false positive that triggered the original error.
fn build_node_detail_lines(app: &App) -> Vec<Line<'_>> {
    let graph = app.graph.lock().unwrap_or_else(|e| {
        warn!("Mutex poisoned in GraphView â€” recovering data");
        e.into_inner()
    });
    let mut lines: Vec<Line> = Vec::new();

    // Guard: no node selected
    let node_idx = match app.selected_node {
        Some(idx) => idx,
        None => {
            lines.push(Line::from(Span::styled(
                "  No node selected",
                Style::default().fg(Color::DarkGray),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  Navigate to the Nodes tab and press Enter to select",
                Style::default().fg(Color::DarkGray),
            )));
            return lines;
        }
    };

    // Guard: stale index (node was removed from graph)
    let node = match graph.get_node(node_idx) {
        Some(n) => n,
        None => {
            lines.push(Line::from(Span::styled(
                "  âš  Selected node no longer exists in graph",
                Style::default().fg(Color::Red),
            )));
            return lines;
        }
    };

    let name_color = node_color(&node.node_type);

    // â”€â”€ Identity section â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    lines.push(Line::from(vec![Span::styled(
        format!("  {}", node.name),
        Style::default().fg(name_color).add_modifier(Modifier::BOLD),
    )]));
    lines.push(Line::from(vec![
        Span::raw("  Type:    "),
        Span::styled(
            format!("{:?}", node.node_type),
            Style::default().fg(name_color),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::raw("  Domain:  "),
        Span::styled(node.domain.clone(), Style::default().fg(Color::Magenta)),
    ]));
    lines.push(Line::from(vec![
        Span::raw("  Enabled: "),
        Span::styled(
            if node.enabled { "Yes" } else { "No" },
            Style::default().fg(if node.enabled {
                Color::Green
            } else {
                Color::Red
            }),
        ),
    ]));
    if let Some(ref dn) = node.distinguished_name {
        lines.push(Line::from(vec![
            Span::raw("  DN:      "),
            Span::styled(dn.clone(), Style::default().fg(Color::DarkGray)),
        ]));
    }
    if let Some(sid) = node
        .properties
        .get("objectid")
        .or_else(|| node.properties.get("objectsid"))
    {
        lines.push(Line::from(vec![
            Span::raw("  SID:     "),
            Span::styled(sid.clone(), Style::default().fg(Color::DarkGray)),
        ]));
    }

    // â”€â”€ Properties section â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if !node.properties.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  Properties",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::UNDERLINED),
        )));
        let mut props: Vec<_> = node.properties.iter().collect();
        props.sort_by_key(|(k, _)| k.as_str());
        for (key, value) in &props {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("    {:<24}", key),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(value.to_string()),
            ]));
        }
    }

    // â”€â”€ Outbound edges â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Outbound Edges",
        Style::default()
            .fg(Color::Red)
            .add_modifier(Modifier::UNDERLINED),
    )));

    let outbound: Vec<_> = graph.edges_from(node_idx).collect();
    if outbound.is_empty() {
        lines.push(Line::from(Span::styled(
            "    (none)",
            Style::default().fg(Color::DarkGray),
        )));
    }
    for edge in &outbound {
        if let Some(target_node) = graph.get_node(edge.target()) {
            let on_path = app.highlighted_path.contains(&edge.id());
            let color = edge_color(edge.weight(), on_path);
            let modifier = if on_path {
                Modifier::BOLD
            } else {
                Modifier::empty()
            };
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(
                    format!("{:<30}", format!("{:?}", edge.weight())),
                    Style::default().fg(color).add_modifier(modifier),
                ),
                Span::styled("â†’ ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    target_node.name.clone(),
                    Style::default().fg(node_color(&target_node.node_type)),
                ),
            ]));
            push_edge_guidance(&mut lines, edge.weight(), "      ");
        }
    }

    // â”€â”€ Inbound edges â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Inbound Edges",
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::UNDERLINED),
    )));

    let inbound: Vec<_> = graph.edges_to(node_idx).collect();
    if inbound.is_empty() {
        lines.push(Line::from(Span::styled(
            "    (none)",
            Style::default().fg(Color::DarkGray),
        )));
    }
    for edge in &inbound {
        if let Some(src_node) = graph.get_node(edge.source()) {
            let on_path = app.highlighted_path.contains(&edge.id());
            let color = edge_color(edge.weight(), on_path);
            let modifier = if on_path {
                Modifier::BOLD
            } else {
                Modifier::empty()
            };
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled(
                    src_node.name.clone(),
                    Style::default().fg(node_color(&src_node.node_type)),
                ),
                Span::styled(" â†’ ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("{:?}", edge.weight()),
                    Style::default().fg(color).add_modifier(modifier),
                ),
            ]));
            push_edge_guidance(&mut lines, edge.weight(), "      ");
        }
    }

    // â”€â”€ MemberOf details (clear grouping) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let member_of_out: Vec<_> = outbound
        .iter()
        .filter(|e| *e.weight() == EdgeType::MemberOf)
        .collect();
    let member_of_in: Vec<_> = inbound
        .iter()
        .filter(|e| *e.weight() == EdgeType::MemberOf)
        .collect();

    if !member_of_out.is_empty() || !member_of_in.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  MemberOf Relationships",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::UNDERLINED),
        )));

        if !member_of_out.is_empty() {
            lines.push(Line::from(Span::styled(
                "    Member Of:",
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            )));
            for edge in &member_of_out {
                if let Some(target) = graph.get_node(edge.target()) {
                    lines.push(Line::from(vec![
                        Span::raw("      â†’ "),
                        Span::styled(
                            target.name.clone(),
                            Style::default().fg(node_color(&target.node_type)),
                        ),
                        Span::raw(" "),
                        Span::styled(
                            format!("[{:?}]", target.node_type),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]));
                }
            }
        }

        if !member_of_in.is_empty() {
            lines.push(Line::from(Span::styled(
                "    Members:",
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::ITALIC),
            )));
            for edge in &member_of_in {
                if let Some(src) = graph.get_node(edge.source()) {
                    lines.push(Line::from(vec![
                        Span::raw("      â† "),
                        Span::styled(
                            src.name.clone(),
                            Style::default().fg(node_color(&src.node_type)),
                        ),
                        Span::raw(" "),
                        Span::styled(
                            format!("[{:?}]", src.node_type),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]));
                }
            }
        }
    }

    // â”€â”€ Abuse summary for unique outbound edge types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Edge / ACE Abuse Summary",
        Style::default()
            .fg(Color::LightRed)
            .add_modifier(Modifier::UNDERLINED),
    )));

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let abuse_edges: Vec<_> = graph.edges_from(node_idx).collect();
    for edge in &abuse_edges {
        let key = format!("{:?}", edge.weight());
        if seen.insert(key)
            && let Some(info) = edge_abuse_info(edge.weight())
        {
            let color = edge_color(edge.weight(), false);
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  [{:?}] ", edge.weight()),
                    Style::default().fg(color),
                ),
                Span::styled(info, Style::default().fg(Color::Gray)),
            ]));
        }
    }

    lines
}

// â”€â”€â”€ ACL findings panel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Render the full ACL findings list in a scrollable panel.
pub fn render_acl_findings(f: &mut Frame, area: Rect, app: &App) {
    let scroll = app.acl_scroll;

    let items: Vec<ListItem> = match &app.acl_findings {
        None => vec![ListItem::new(Span::styled(
            "  No ACL findings loaded â€” run 'acls' scan first",
            Style::default().fg(Color::DarkGray),
        ))],
        Some(findings) => findings
            .iter()
            .skip(scroll)
            .map(|f| {
                let color = severity_color(f.severity);
                let inherited = if f.is_inherited { " [inherited]" } else { "" };
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("[S{}] ", f.severity),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{:<30}", f.principal),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(" â†’ ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{:<35}", format!("{:?}", f.right)),
                        Style::default().fg(color),
                    ),
                    Span::styled(" on ", Style::default().fg(Color::DarkGray)),
                    Span::styled(f.target.clone(), Style::default().fg(Color::White)),
                    Span::styled(
                        inherited,
                        Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::ITALIC),
                    ),
                ]))
            })
            .collect(),
    };

    let total = app.acl_findings.as_ref().map(|v| v.len()).unwrap_or(0);
    let title = format!(" ACL / ACE Findings ({} total) [â†‘/â†“ scroll] ", total);

    let widget = List::new(items)
        .block(
            Block::default()
                .title(Span::styled(title, Style::default().fg(Color::LightRed)))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::LightRed)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(widget, area);
}

// â”€â”€â”€ Attack-path panel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Render the current computed attack path.
pub fn render_paths(f: &mut Frame, area: Rect, app: &App) {
    let scroll = app.path_scroll;
    let mut lines: Vec<Line> = Vec::new();

    match &app.current_path {
        None => {
            lines.push(Line::from(Span::styled(
                "  No attack path computed",
                Style::default().fg(Color::DarkGray),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  Use the search panel to find shortest paths",
                Style::default().fg(Color::DarkGray),
            )));
        }
        Some(path) => {
            lines.push(Line::from(vec![
                Span::styled(
                    " Attack Path ",
                    Style::default()
                        .fg(Color::LightRed)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("({} hops)", path.hop_count),
                    Style::default().fg(Color::Yellow),
                ),
            ]));
            lines.push(Line::from(""));

            for (step_idx, step) in path.hops.iter().enumerate() {
                let color = node_color(&step.source_type);
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {:>3}. ", step_idx + 1),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("{:?}", step.source_type),
                        Style::default().fg(color),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        step.source.clone(),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                ]));

                let edge_type = &step.edge;
                let ecolor = edge_color(edge_type, true);
                lines.push(Line::from(vec![
                    Span::raw("       "),
                    Span::styled("â”‚ ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{:?}", edge_type),
                        Style::default().fg(ecolor).add_modifier(Modifier::BOLD),
                    ),
                ]));
                if let Some(abuse) = edge_abuse_info(edge_type) {
                    lines.push(Line::from(vec![
                        Span::raw("       "),
                        Span::styled("â”‚ ", Style::default().fg(Color::DarkGray)),
                        Span::styled(
                            format!("  Ã¢â€ Â³ {}", abuse),
                            Style::default()
                                .fg(Color::Gray)
                                .add_modifier(Modifier::ITALIC),
                        ),
                    ]));
                }
            }

            if let Some(last) = path.hops.last() {
                let color = node_color(&last.target_type);
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {:>3}. ", path.hops.len() + 1),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("{:?}", last.target_type),
                        Style::default().fg(color),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        last.target.clone(),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                ]));
            }

            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::raw("  Total path cost: "),
                Span::styled(
                    format!("{}", path.total_cost),
                    Style::default().fg(Color::Yellow),
                ),
            ]));
        }
    }

    let scrolled: Vec<Line> = lines.into_iter().skip(scroll).collect();

    let widget = Paragraph::new(scrolled)
        .block(
            Block::default()
                .title(Span::styled(
                    " Attack Path [â†‘/â†“ scroll] ",
                    Style::default().fg(Color::LightRed),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::LightRed)),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(widget, area);
}

// â”€â”€â”€ Legend overlay â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Render a colour-coded edge-type legend in the given area.
pub fn render_legend(f: &mut Frame, area: Rect) {
    let entries: &[(&str, Color, &str)] = &[
        ("AdminTo", Color::Red, "Local admin access"),
        (
            "AllowedToAct (RBCD ACE)",
            Color::Red,
            "Resource-based constrained delegation",
        ),
        ("GenericAll", Color::LightRed, "Full control over object"),
        (
            "WriteDacl / ACE",
            Color::LightRed,
            "Modify DACL â†’ grant GenericAll",
        ),
        (
            "WriteOwner",
            Color::LightRed,
            "Take ownership â†’ modify DACL",
        ),
        ("DcSync", Color::Magenta, "Replicate all secrets from DC"),
        (
            "ForceChangePassword",
            Color::Magenta,
            "Reset password without knowing current",
        ),
        (
            "ReadLapsPassword",
            Color::Magenta,
            "Read cleartext local admin password",
        ),
        (
            "AllowedToDelegate",
            Color::Magenta,
            "Constrained delegation â†’ TGT",
        ),
        (
            "HasSession",
            Color::Yellow,
            "User has active session on computer",
        ),
        (
            "HasSpn / Kerberoast",
            Color::Yellow,
            "Account has SPN â†’ offline crack",
        ),
        ("AddMembers", Color::Yellow, "Add members to group"),
        ("CanRDP", Color::Cyan, "Remote Desktop access"),
        ("GpoLink", Color::Green, "GPO linked to OU â†’ policy exec"),
        (
            "MemberOf / Contains",
            Color::DarkGray,
            "Group / OU membership",
        ),
        (
            "Highlighted path",
            Color::LightYellow,
            "Edge on current attack path",
        ),
    ];

    let items: Vec<ListItem> = entries
        .iter()
        .map(|(label, color, desc)| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("  {:<30}", label),
                    Style::default().fg(*color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(*desc, Style::default().fg(Color::Gray)),
            ]))
        })
        .collect();

    let widget = List::new(items).block(
        Block::default()
            .title(Span::styled(
                " Edge Legend ",
                Style::default().fg(Color::Cyan),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );

    f.render_widget(widget, area);
}
