//! MSSQL configuration audit module (PowerUpSQL-style).
//!
//! Generates SQL audit queries to assess MSSQL security posture.
//! Does NOT connect to MSSQL directly — generates SQL strings
//! to be run through the existing `MssqlClient`.

use overthrone_core::mssql::MssqlQueryResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Overall MSSQL configuration audit result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MssqlConfigAudit {
    pub checks: Vec<MssqlConfigCheck>,
    pub summary: MssqlAuditSummary,
}

/// A single configuration check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MssqlConfigCheck {
    pub name: String,
    pub category: ConfigCategory,
    pub description: String,
    pub query: String,
    pub vulnerable: bool,
    pub finding: String,
    pub remediation: String,
    pub severity: Severity,
    pub raw_value: Option<String>,
}

/// Configuration check category
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ConfigCategory {
    SurfaceArea,
    Authentication,
    Authorization,
    Encryption,
    Auditing,
    LinkExposure,
    PrivilegeEscalation,
    DatabaseConfig,
}

impl ConfigCategory {
    pub fn description(&self) -> &str {
        match self {
            ConfigCategory::SurfaceArea => {
                "Checks for enabled features that expand the attack surface"
            }
            ConfigCategory::Authentication => "SQL Server authentication settings",
            ConfigCategory::Authorization => "Server role membership and permissions",
            ConfigCategory::Encryption => "TLS/SSL and encryption configuration",
            ConfigCategory::Auditing => "Audit and logging configuration",
            ConfigCategory::LinkExposure => "Linked server configuration exposure",
            ConfigCategory::PrivilegeEscalation => "Privilege escalation vectors",
            ConfigCategory::DatabaseConfig => "Database-level configuration issues",
        }
    }
}

impl std::fmt::Display for ConfigCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigCategory::SurfaceArea => write!(f, "Surface Area"),
            ConfigCategory::Authentication => write!(f, "Authentication"),
            ConfigCategory::Authorization => write!(f, "Authorization"),
            ConfigCategory::Encryption => write!(f, "Encryption"),
            ConfigCategory::Auditing => write!(f, "Auditing"),
            ConfigCategory::LinkExposure => write!(f, "Link Exposure"),
            ConfigCategory::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            ConfigCategory::DatabaseConfig => write!(f, "Database Config"),
        }
    }
}

/// Severity level for findings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "Critical"),
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
            Severity::Info => write!(f, "Info"),
        }
    }
}

/// Summary statistics for an audit
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MssqlAuditSummary {
    pub total_checks: usize,
    pub vulnerable_count: usize,
    pub severity_counts: HashMap<String, usize>,
}

/// Build the full set of MSSQL configuration audit checks (61 total).
pub fn build_mssql_audit_checks() -> Vec<MssqlConfigCheck> {
    let mut checks = Vec::with_capacity(61);

    macro_rules! check {
        ($name:expr, $cat:expr, $desc:expr, $query:expr, $finding:expr, $remediation:expr, $sev:expr) => {
            MssqlConfigCheck {
                name: $name.into(),
                category: $cat,
                description: $desc.into(),
                query: $query.into(),
                vulnerable: false,
                finding: $finding.into(),
                remediation: $remediation.into(),
                severity: $sev,
                raw_value: None,
            }
        };
    }

    // ═══════════════════════════════════════════════════════════
    // Surface Area (10 checks)
    // ═══════════════════════════════════════════════════════════
    checks.push(check!(
        "xp_cmdshell",
        ConfigCategory::SurfaceArea,
        "Checks if xp_cmdshell extended stored procedure is enabled",
        "SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'",
        "xp_cmdshell is enabled — allows OS command execution via SQL",
        "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;",
        Severity::Critical
    ));

    checks.push(check!(
        "clr_enabled",
        ConfigCategory::SurfaceArea,
        "Checks if CLR integration is enabled",
        "SELECT value_in_use FROM sys.configurations WHERE name = 'clr enabled'",
        "CLR integration is enabled — allows unsafe .NET assemblies in SQL Server",
        "EXEC sp_configure 'clr enabled', 0; RECONFIGURE;",
        Severity::High
    ));

    checks.push(check!(
        "ole_automation",
        ConfigCategory::SurfaceArea,
        "Checks if OLE Automation Procedures are enabled",
        "SELECT value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures'",
        "OLE Automation Procedures are enabled — allows COM object instantiation via T-SQL",
        "EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;",
        Severity::High
    ));

    checks.push(check!(
        "ad_hoc_distributed_queries",
        ConfigCategory::SurfaceArea,
        "Checks if Ad Hoc Distributed Queries are enabled",
        "SELECT value_in_use FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries'",
        "Ad Hoc Distributed Queries are enabled — allows OPENROWSET/OPENDATASOURCE to external data sources",
        "EXEC sp_configure 'Ad Hoc Distributed Queries', 0; RECONFIGURE;",
        Severity::Medium
    ));

    checks.push(check!(
        "database_mail_xps",
        ConfigCategory::SurfaceArea,
        "Checks if Database Mail XPs are enabled",
        "SELECT value_in_use FROM sys.configurations WHERE name = 'Database Mail XPs'",
        "Database Mail XPs are enabled — can be abused for data exfiltration",
        "EXEC sp_configure 'Database Mail XPs', 0; RECONFIGURE;",
        Severity::Medium
    ));

    checks.push(check!(
        "xp_regread",
        ConfigCategory::SurfaceArea,
        "Checks if xp_regread extended stored procedure exists",
        "SELECT OBJECT_ID('xp_regread')",
        "xp_regread is available — allows reading Windows registry via SQL",
        "DROP PROCEDURE xp_regread; or restrict access via DENY EXECUTE",
        Severity::High
    ));

    checks.push(check!(
        "xp_dirtree",
        ConfigCategory::SurfaceArea,
        "Checks if xp_dirtree extended stored procedure exists",
        "SELECT OBJECT_ID('xp_dirtree')",
        "xp_dirtree is available — allows directory listing; can be used for SMB relay via \\\\ UNC paths",
        "DROP PROCEDURE xp_dirtree; or restrict access via DENY EXECUTE",
        Severity::Medium
    ));

    checks.push(check!(
        "xp_subdirs",
        ConfigCategory::SurfaceArea,
        "Checks if xp_subdirs extended stored procedure exists",
        "SELECT OBJECT_ID('xp_subdirs')",
        "xp_subdirs is available — allows directory listing; can be used for SMB relay",
        "DROP PROCEDURE xp_subdirs; or restrict access via DENY EXECUTE",
        Severity::Medium
    ));

    checks.push(check!(
        "sp_send_dbmail",
        ConfigCategory::SurfaceArea,
        "Checks if sp_send_dbmail is accessible",
        "SELECT OBJECT_ID('sp_send_dbmail')",
        "sp_send_dbmail is available — can be abused for data exfiltration via email",
        "REVOKE EXECUTE ON sp_send_dbmail FROM PUBLIC",
        Severity::Medium
    ));

    checks.push(check!(
        "linked_server_xp_cmdshell",
        ConfigCategory::SurfaceArea,
        "Checks if xp_cmdshell can be executed via linked servers",
        "SELECT COUNT(*) FROM sys.servers WHERE is_linked = 1 AND is_remote_login_enabled = 1",
        "Linked servers exist with remote login enabled — xp_cmdshell may be reachable via OPENQUERY chain",
        "Disable remote login mapping on linked servers or restrict xp_cmdshell usage",
        Severity::High
    ));

    // ═══════════════════════════════════════════════════════════
    // Authentication (6 checks)
    // ═══════════════════════════════════════════════════════════
    checks.push(check!(
        "sa_account_status",
        ConfigCategory::Authentication,
        "Checks if the sa account is enabled",
        "SELECT name, is_disabled FROM sys.server_principals WHERE name = 'sa'",
        "sa account is enabled — built-in administrator account is a high-value target for brute force",
        "ALTER LOGIN sa DISABLE;",
        Severity::High
    ));

    checks.push(check!(
        "sa_account_password",
        ConfigCategory::Authentication,
        "Checks if the sa account has password policy enforced",
        "SELECT name, is_policy_checked, is_expiration_checked FROM sys.sql_logins WHERE name = 'sa'",
        "sa account does not have password policy enforced — weak passwords may be in use",
        "ALTER LOGIN sa MUST_CHANGE; ALTER LOGIN sa CHECK_POLICY = ON; ALTER LOGIN sa CHECK_EXPIRATION = ON;",
        Severity::Critical
    ));

    checks.push(check!(
        "mixed_authentication",
        ConfigCategory::Authentication,
        "Checks if SQL Server is in mixed authentication mode (SQL + Windows)",
        "SELECT CASE WHEN SERVERPROPERTY('IsIntegratedSecurityOnly') = 0 THEN 1 ELSE 0 END",
        "SQL Server is in mixed authentication mode — SQL logins can bypass Windows authentication",
        "Switch to Windows Authentication mode only",
        Severity::Medium
    ));

    checks.push(check!(
        "empty_passwords",
        ConfigCategory::Authentication,
        "Checks for SQL logins with empty or null passwords",
        "SELECT name, principal_id FROM sys.sql_logins WHERE PWDCOMPARE('', password_hash) = 1 OR password_hash IS NULL",
        "SQL logins with empty or null passwords exist — immediate credential theft risk",
        "DROP LOGIN or ALTER LOGIN with a strong password for each affected login",
        Severity::Critical
    ));

    checks.push(check!(
        "password_policy_disabled",
        ConfigCategory::Authentication,
        "Checks for SQL logins with password policy enforcement disabled",
        "SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0",
        "SQL logins exist with password policy disabled — weak passwords may be in use",
        "ALTER LOGIN [name] CHECK_POLICY = ON for each affected login",
        Severity::High
    ));

    checks.push(check!(
        "password_expiration_disabled",
        ConfigCategory::Authentication,
        "Checks for SQL logins with password expiration disabled",
        "SELECT name FROM sys.sql_logins WHERE is_expiration_checked = 0",
        "SQL logins exist with password expiration disabled — passwords may never rotate",
        "ALTER LOGIN [name] CHECK_EXPIRATION = ON for each affected login",
        Severity::Medium
    ));

    // ═══════════════════════════════════════════════════════════
    // Authorization (8 checks)
    // ═══════════════════════════════════════════════════════════
    checks.push(check!(
        "sysadmin_members",
        ConfigCategory::Authorization,
        "Enumerates members of the sysadmin fixed server role",
        "SELECT p.name FROM sys.server_role_members rm JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id WHERE rm.role_principal_id = (SELECT principal_id FROM sys.server_principals WHERE name = 'sysadmin')",
        "Members of sysadmin role have full control over the SQL Server instance",
        "Review sysadmin membership and remove unnecessary accounts",
        Severity::High
    ));

    checks.push(check!(
        "securityadmin_members",
        ConfigCategory::Authorization,
        "Enumerates members of the securityadmin fixed server role",
        "SELECT p.name FROM sys.server_role_members rm JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id WHERE rm.role_principal_id = (SELECT principal_id FROM sys.server_principals WHERE name = 'securityadmin')",
        "Members of securityadmin can manage logins and grant server-level permissions",
        "Review securityadmin membership and remove unnecessary accounts",
        Severity::High
    ));

    checks.push(check!(
        "serveradmin_members",
        ConfigCategory::Authorization,
        "Enumerates members of the serveradmin fixed server role",
        "SELECT p.name FROM sys.server_role_members rm JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id WHERE rm.role_principal_id = (SELECT principal_id FROM sys.server_principals WHERE name = 'serveradmin')",
        "Members of serveradmin can configure server-wide settings",
        "Review serveradmin membership and remove unnecessary accounts",
        Severity::Medium
    ));

    checks.push(check!(
        "processadmin_members",
        ConfigCategory::Authorization,
        "Enumerates members of the processadmin fixed server role",
        "SELECT p.name FROM sys.server_role_members rm JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id WHERE rm.role_principal_id = (SELECT principal_id FROM sys.server_principals WHERE name = 'processadmin')",
        "Members of processadmin can kill SQL Server processes",
        "Review processadmin membership and remove unnecessary accounts",
        Severity::Medium
    ));

    checks.push(check!(
        "setupadmin_members",
        ConfigCategory::Authorization,
        "Enumerates members of the setupadmin fixed server role",
        "SELECT p.name FROM sys.server_role_members rm JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id WHERE rm.role_principal_id = (SELECT principal_id FROM sys.server_principals WHERE name = 'setupadmin')",
        "Members of setupadmin can add/remove linked servers and manage startup procedures",
        "Review setupadmin membership and remove unnecessary accounts",
        Severity::Medium
    ));

    checks.push(check!(
        "diskadmin_members",
        ConfigCategory::Authorization,
        "Enumerates members of the diskadmin fixed server role",
        "SELECT p.name FROM sys.server_role_members rm JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id WHERE rm.role_principal_id = (SELECT principal_id FROM sys.server_principals WHERE name = 'diskadmin')",
        "Members of diskadmin can manage disk files and backup devices",
        "Review diskadmin membership and remove unnecessary accounts",
        Severity::Low
    ));

    checks.push(check!(
        "dbcreator_members",
        ConfigCategory::Authorization,
        "Enumerates members of the dbcreator fixed server role",
        "SELECT p.name FROM sys.server_role_members rm JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id WHERE rm.role_principal_id = (SELECT principal_id FROM sys.server_principals WHERE name = 'dbcreator')",
        "Members of dbcreator can create, alter, and drop databases",
        "Review dbcreator membership and remove unnecessary accounts",
        Severity::Medium
    ));

    checks.push(check!(
        "bulkadmin_members",
        ConfigCategory::Authorization,
        "Enumerates members of the bulkadmin fixed server role",
        "SELECT p.name FROM sys.server_role_members rm JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id WHERE rm.role_principal_id = (SELECT principal_id FROM sys.server_principals WHERE name = 'bulkadmin')",
        "Members of bulkadmin can run BULK INSERT statements",
        "Review bulkadmin membership and remove unnecessary accounts",
        Severity::Low
    ));

    // ═══════════════════════════════════════════════════════════
    // Encryption (4 checks)
    // ═══════════════════════════════════════════════════════════
    checks.push(check!(
        "encryption_not_required",
        ConfigCategory::Encryption,
        "Checks if force encryption is disabled",
        "SELECT value_in_use FROM sys.configurations WHERE name = 'force encryption'",
        "Force encryption is disabled — network traffic to SQL Server may be unencrypted",
        "Enable force encryption: EXEC sp_configure 'force encryption', 1; RECONFIGURE;",
        Severity::High
    ));

    checks.push(check!(
        "weak_encryption",
        ConfigCategory::Encryption,
        "Checks if weak encryption algorithms are configured",
        "SELECT value_in_use FROM sys.configurations WHERE name = 'network encryption'",
        "Weak encryption algorithms may be in use — consider upgrading to TLS 1.2+",
        "Configure SQL Server to use TLS 1.2+ and disable weak cipher suites",
        Severity::Medium
    ));

    checks.push(check!(
        "certificate_expired",
        ConfigCategory::Encryption,
        "Checks for expired certificates in the SQL Server certificate store",
        "SELECT name, expiry_date FROM sys.certificates WHERE expiry_date < GETDATE()",
        "Expired certificates found — encrypted connections may fail or fall back to unencrypted",
        "Renew expired certificates or replace with valid ones",
        Severity::Medium
    ));

    checks.push(check!(
        "ssl_certificate_not_configured",
        ConfigCategory::Encryption,
        "Checks if a certificate is configured for SSL/TLS",
        "SELECT COUNT(*) FROM sys.certificates WHERE pvt_key_encryption_type IS NOT NULL",
        "No certificate with private key found — SQL Server may not be using trusted SSL/TLS",
        "Create or import a trusted certificate for SQL Server encryption",
        Severity::High
    ));

    // ═══════════════════════════════════════════════════════════
    // Auditing (4 checks)
    // ═══════════════════════════════════════════════════════════
    checks.push(check!(
        "login_auditing_disabled",
        ConfigCategory::Auditing,
        "Checks if login auditing is configured",
        "SELECT value_in_use FROM sys.configurations WHERE name = 'audit level'",
        "Login auditing is not configured — failed/successful logins are not recorded",
        "EXEC sp_configure 'audit level', 2; RECONFIGURE; (2 = failed logins, 3 = all)",
        Severity::Medium
    ));

    checks.push(check!(
        "c2_audit_disabled",
        ConfigCategory::Auditing,
        "Checks if C2 audit tracing is disabled",
        "SELECT value_in_use FROM sys.configurations WHERE name = 'c2 audit mode'",
        "C2 audit mode is disabled — security-relevant events may not be logged",
        "EXEC sp_configure 'c2 audit mode', 1; RECONFIGURE;",
        Severity::Low
    ));

    checks.push(check!(
        "schema_change_audit_disabled",
        ConfigCategory::Auditing,
        "Checks if DDL (schema change) auditing is configured",
        "SELECT COUNT(*) FROM sys.server_audit_specifications WHERE is_state_enabled = 1",
        "No schema change auditing configured — DDL operations (CREATE/ALTER/DROP) are not tracked",
        "CREATE SERVER AUDIT and SERVER AUDIT SPECIFICATION with SCHEMA_OBJECT_CHANGE_GROUP",
        Severity::Low
    ));

    checks.push(check!(
        "failed_login_logging",
        ConfigCategory::Auditing,
        "Checks if failed login logging is sufficient",
        "SELECT value_in_use FROM sys.configurations WHERE name = 'audit level'",
        "Failed login auditing is insufficient — brute force attacks may go unnoticed",
        "EXEC sp_configure 'audit level', 2; RECONFIGURE; to log failed logins",
        Severity::Medium
    ));

    // ═══════════════════════════════════════════════════════════
    // Database Config (6 checks)
    // ═══════════════════════════════════════════════════════════
    checks.push(check!(
        "trustworthy_database",
        ConfigCategory::DatabaseConfig,
        "Checks for databases with TRUSTWORTHY property enabled",
        "SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND name != 'msdb'",
        "Databases have TRUSTWORTHY ON — allows privilege escalation via module signing and cross-db access",
        "ALTER DATABASE [name] SET TRUSTWORTHY OFF for each affected database",
        Severity::High
    ));

    checks.push(check!(
        "cross_db_ownership_chaining",
        ConfigCategory::DatabaseConfig,
        "Checks if cross-db ownership chaining is enabled",
        "SELECT value_in_use FROM sys.configurations WHERE name = 'cross db ownership chaining'",
        "Cross-db ownership chaining is enabled — can bypass permissions between databases",
        "EXEC sp_configure 'cross db ownership chaining', 0; RECONFIGURE;",
        Severity::High
    ));

    checks.push(check!(
        "database_ownership_chaining",
        ConfigCategory::DatabaseConfig,
        "Checks for databases with ownership chaining enabled",
        "SELECT name FROM sys.databases WHERE is_db_chaining_on = 1",
        "Databases have ownership chaining enabled — potential privilege escalation vector",
        "ALTER DATABASE [name] SET DB_CHAINING OFF for each affected database",
        Severity::Medium
    ));

    checks.push(check!(
        "db_owner_public",
        ConfigCategory::DatabaseConfig,
        "Checks if PUBLIC role has excessive permissions in user databases",
        "SELECT d.name AS database_name, p.permission_name FROM sys.databases d CROSS APPLY (SELECT permission_name FROM sys.database_permissions WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID('public') AND class = 0 AND state != 'D') p WHERE d.database_id > 4 AND p.permission_name IS NOT NULL",
        "PUBLIC role has excessive permissions — all users inherit these permissions",
        "REVOKE excessive permissions from PUBLIC role in each affected database",
        Severity::Medium
    ));

    checks.push(check!(
        "auto_close_enabled",
        ConfigCategory::DatabaseConfig,
        "Checks for databases with AUTO_CLOSE enabled",
        "SELECT name FROM sys.databases WHERE is_auto_close_on = 1",
        "Databases have AUTO_CLOSE enabled — frequent open/close cycles cause performance issues and denial of service risk",
        "ALTER DATABASE [name] SET AUTO_CLOSE OFF for each affected database",
        Severity::Low
    ));

    checks.push(check!(
        "auto_shrink_enabled",
        ConfigCategory::DatabaseConfig,
        "Checks for databases with AUTO_SHRINK enabled",
        "SELECT name FROM sys.databases WHERE is_auto_shrink_on = 1",
        "Databases have AUTO_SHRINK enabled — can cause index fragmentation and performance degradation",
        "ALTER DATABASE [name] SET AUTO_SHRINK OFF for each affected database",
        Severity::Low
    ));

    // ═══════════════════════════════════════════════════════════
    // Privilege Escalation (5 checks)
    // ═══════════════════════════════════════════════════════════
    checks.push(check!(
        "impersonate_login",
        ConfigCategory::PrivilegeEscalation,
        "Checks for logins with IMPERSONATE permission on other logins",
        "SELECT p.name, p.type_desc FROM sys.server_permissions sp JOIN sys.server_principals p ON sp.grantee_principal_id = p.principal_id WHERE sp.permission_name = 'IMPERSONATE' AND sp.class = 101 AND sp.type = 'IM'",
        "Logins can impersonate other logins — privilege escalation risk",
        "REVOKE IMPERSONATE ON LOGIN::[target] FROM [grantee]",
        Severity::High
    ));

    checks.push(check!(
        "impersonate_sa",
        ConfigCategory::PrivilegeEscalation,
        "Checks specifically for logins that can impersonate the sa login",
        "SELECT p.name FROM sys.server_permissions sp JOIN sys.server_principals p ON sp.grantee_principal_id = p.principal_id WHERE sp.permission_name = 'IMPERSONATE' AND sp.class = 101 AND sp.major_id = (SELECT principal_id FROM sys.server_principals WHERE name = 'sa')",
        "Logins can impersonate sa — direct path to sysadmin privileges",
        "REVOKE IMPERSONATE ON LOGIN::sa FROM [grantee]",
        Severity::Critical
    ));

    checks.push(check!(
        "execute_as_owner",
        ConfigCategory::PrivilegeEscalation,
        "Checks for procedures with EXECUTE AS OWNER clause",
        "SELECT OBJECT_SCHEMA_NAME(p.object_id) AS schema_name, p.name FROM sys.procedures p JOIN sys.sql_modules m ON p.object_id = m.object_id WHERE m.execute_as_principal_id = -2 AND p.is_ms_shipped = 0",
        "Procedures with EXECUTE AS OWNER exist — may enable privilege escalation if owner is sysadmin",
        "Review and modify EXECUTE AS clauses to use EXECUTE AS CALLER or specific least-privilege principals",
        Severity::High
    ));

    checks.push(check!(
        "execute_as_user",
        ConfigCategory::PrivilegeEscalation,
        "Checks for procedures with EXECUTE AS USER that may enable escalation",
        "SELECT OBJECT_SCHEMA_NAME(p.object_id) AS schema_name, p.name, USER_NAME(m.execute_as_principal_id) AS exec_as_user FROM sys.procedures p JOIN sys.sql_modules m ON p.object_id = m.object_id WHERE m.execute_as_principal_id > 0 AND p.is_ms_shipped = 0",
        "Procedures with EXECUTE AS USER clause exist — may enable privilege escalation",
        "Review each EXECUTE AS USER procedure and ensure least-privilege principals are used",
        Severity::Medium
    ));

    checks.push(check!(
        "public_role_permissions",
        ConfigCategory::PrivilegeEscalation,
        "Checks for dangerous permissions granted to the PUBLIC server role",
        "SELECT p.permission_name, p.class_desc, p.state_desc FROM sys.server_permissions p WHERE p.grantee_principal_id = (SELECT principal_id FROM sys.server_principals WHERE name = 'public') AND p.state != 'D'",
        "PUBLIC role has server-level permissions beyond defaults — all logins inherit these",
        "REVOKE [permission] FROM PUBLIC for each dangerous permission",
        Severity::High
    ));

    // ═══════════════════════════════════════════════════════════
    // Link Exposure (6 checks)
    // ═══════════════════════════════════════════════════════════
    checks.push(check!(
        "linked_servers",
        ConfigCategory::LinkExposure,
        "Counts the number of linked servers configured",
        "SELECT name, data_source, provider FROM sys.servers WHERE is_linked = 1",
        "Linked servers exist — each is a potential lateral movement path",
        "Remove unnecessary linked servers and audit remaining ones",
        Severity::Medium
    ));

    checks.push(check!(
        "cross_domain_linked_servers",
        ConfigCategory::LinkExposure,
        "Checks for linked servers using cross-domain authentication",
        "SELECT s.name, s.data_source FROM sys.servers s WHERE is_linked = 1 AND s.data_source NOT LIKE '%' + @@SERVERNAME + '%'",
        "Cross-domain linked servers exist — may enable lateral movement across trust boundaries",
        "Review cross-domain links and ensure proper authentication controls",
        Severity::High
    ));

    checks.push(check!(
        "linked_server_login_mapping",
        ConfigCategory::LinkExposure,
        "Checks for linked server login mappings that may expose excessive access",
        "SELECT s.name, lm.local_principal_id, lm.remote_name, lm.uses_self_credential FROM sys.servers s JOIN sys.linked_logins lm ON s.server_id = lm.server_id WHERE s.is_linked = 1",
        "Linked server login mappings exist — remote credentials may be cached or mapped broadly",
        "Review and remove unnecessary linked server login mappings",
        Severity::Medium
    ));

    checks.push(check!(
        "openquery_xp_cmdshell_passthrough",
        ConfigCategory::LinkExposure,
        "Assesses risk of xp_cmdshell abuse via OPENQUERY through linked servers",
        "SELECT s.name FROM sys.servers s WHERE is_linked = 1 AND s.is_rpc_out_enabled = 1",
        "Linked servers with RPC out enabled — OPENQUERY can execute xp_cmdshell on remote servers",
        "Disable RPC out on linked servers where not required: EXEC sp_serveroption @server=N'[name]', @optname=N'rpc out', @optvalue=N'false'",
        Severity::Critical
    ));

    checks.push(check!(
        "linked_server_with_rpc",
        ConfigCategory::LinkExposure,
        "Checks for linked servers with RPC enabled",
        "SELECT name FROM sys.servers WHERE is_linked = 1 AND is_rpc_out_enabled = 1",
        "Linked servers have RPC out enabled — allows remote procedure call execution across servers",
        "Disable RPC out on linked servers where not required",
        Severity::High
    ));

    checks.push(check!(
        "local_login_impersonation",
        ConfigCategory::LinkExposure,
        "Checks for logins that are impersonated when connecting to linked servers",
        "SELECT s.name, lm.local_principal_id, p.name AS local_login, lm.remote_name FROM sys.linked_logins lm JOIN sys.servers s ON lm.server_id = s.server_id LEFT JOIN sys.server_principals p ON lm.local_principal_id = p.principal_id WHERE s.is_linked = 1",
        "Linked server login impersonation is configured — local logins automatically map to remote logins",
        "Review and remove automatic login mappings where not required",
        Severity::High
    ));

    // ═══════════════════════════════════════════════════════════
    // Additional PowerUpSQL checks (8 new)
    // ═══════════════════════════════════════════════════════════

    checks.push(check!(
        "sql_agent_jobs_as_other_creds",
        ConfigCategory::PrivilegeEscalation,
        "Checks for SQL Agent jobs that execute as different credentials (proxy or different login)",
        "SELECT j.name AS job_name, p.name AS owner, s.step_name, s.subsystem, s.proxy_id FROM msdb.dbo.sysjobs j JOIN msdb.dbo.sysjobsteps s ON j.job_id = s.job_id JOIN sys.server_principals p ON j.owner_sid = p.sid WHERE s.proxy_id IS NOT NULL OR j.owner_sid != SYSTEM_USER",
        "SQL Agent jobs exist that run under different credentials — job hijacking could escalate privileges",
        "Review job owners and proxy accounts; ensure least-privilege principals for job steps",
        Severity::High
    ));

    checks.push(check!(
        "sql_agent_proxy_accounts",
        ConfigCategory::PrivilegeEscalation,
        "Enumerates SQL Agent proxy accounts which allow job steps to impersonate other credentials",
        "SELECT px.name AS proxy_name, p.name AS principal_name, s.name AS subsystem FROM msdb.dbo.sysproxies px LEFT JOIN msdb.dbo.sysproxylogin pl ON px.proxy_id = pl.proxy_id LEFT JOIN sys.server_principals p ON pl.principal_sid = p.sid LEFT JOIN msdb.dbo.syssubsystems s ON px.subsystem_id = s.subsystem_id",
        "SQL Agent proxy accounts exist — they allow job step execution under different security contexts",
        "Review and remove unnecessary proxy accounts; restrict which logins can use each proxy",
        Severity::Medium
    ));

    checks.push(check!(
        "server_level_ddl_triggers",
        ConfigCategory::SurfaceArea,
        "Checks for server-level DDL triggers that execute on schema changes (potential persistence vector)",
        "SELECT name, is_disabled, create_date, modify_date FROM sys.server_triggers WHERE parent_class_desc = 'SERVER' AND is_ms_shipped = 0",
        "Custom server-level DDL triggers exist — could be backdoors monitoring or blocking schema changes",
        "Review each DDL trigger for legitimate purpose; disable or remove unauthorized triggers",
        Severity::Medium
    ));

    checks.push(check!(
        "database_ownership_non_sysadmin",
        ConfigCategory::Authorization,
        "Checks for databases owned by non-sysadmin principals (potential privilege escalation)",
        "SELECT d.name AS db_name, p.name AS owner_name, p.type_desc AS owner_type FROM sys.databases d JOIN sys.server_principals p ON d.owner_sid = p.sid WHERE d.database_id > 4 AND p.name NOT IN ('sa') AND IS_SRVROLEMEMBER('sysadmin', p.name) = 0",
        "Databases are owned by non-sysadmin principals — database owners inherit CONTROL permission and can escalate to sysadmin via TRUSTWORTHY or chaining",
        "Transfer database ownership to sysadmin: EXEC sp_changedbowner 'sa' for each affected database",
        Severity::High
    ));

    checks.push(check!(
        "service_master_key_weak_encryption",
        ConfigCategory::Encryption,
        "Checks if the Service Master Key (SMK) is encrypted using a weak method (password instead of DPAPI)",
        "SELECT COUNT(*) FROM sys.key_encryptions WHERE key_id = (SELECT key_id FROM sys.symmetric_keys WHERE name = '##MS_ServiceMasterKey##') AND algorithm_desc != 'CRYPTOGRAPHIC_PROVIDER'",
        "Service Master Key is encrypted without DPAPI — may indicate weak SMK protection or manual key management",
        "Ensure SMK is encrypted by the service account DPAPI: RESTORE SERVICE MASTER KEY FROM FILE with proper encryption",
        Severity::Medium
    ));

    checks.push(check!(
        "database_master_key_auto_decryptable",
        ConfigCategory::DatabaseConfig,
        "Checks for Database Master Keys (DMK) encrypted by the service master key (auto-decryptable by any sysadmin)",
        "SELECT DB_NAME(database_id) AS db_name FROM sys.key_encryptions WHERE key_id IN (SELECT key_id FROM sys.symmetric_keys WHERE key_algorithm = 'AES' AND db_id(key_id) > 4)",
        "Database Master Keys exist encrypted by the service master key — any sysadmin or SMK accessor can auto-decrypt them",
        "Consider encrypting DMKs with a password: ALTER MASTER KEY ADD ENCRYPTION BY PASSWORD = 'strong_password'",
        Severity::Medium
    ));

    checks.push(check!(
        "asymmetric_keys_with_login_mappings",
        ConfigCategory::Authorization,
        "Checks for asymmetric keys or certificates that map to server logins (potential impersonation vector)",
        "SELECT p.name AS login_name, p.type_desc, c.name AS credential_name, c.credential_identity FROM sys.server_principals p LEFT JOIN sys.credentials c ON p.credential_id = c.credential_id WHERE p.type IN ('C', 'K')",
        "Asymmetric key or certificate-mapped logins exist — can be used to sign modules or impersonate principals if private key is accessible",
        "Review each key/certificate-mapped login; restrict private key access and remove unnecessary mappings",
        Severity::High
    ));

    checks.push(check!(
        "error_log_failed_logins",
        ConfigCategory::Auditing,
        "Checks the SQL Server error log for indicators of brute-force or failed login attempts by inspecting xp_readerrorlog output",
        "EXEC xp_readerrorlog 0, 1, N'Login failed'",
        "Failed login attempts found in error log — possible brute-force attack against SQL Server",
        "Enable login auditing (sp_configure 'audit level', 2) and monitor for repeated failures",
        Severity::Low
    ));

    // ═══════════════════════════════════════════════════════════
    // Credential Exposure (4 new checks)
    // ═══════════════════════════════════════════════════════════
    checks.push(check!(
        "stored_credentials",
        ConfigCategory::PrivilegeEscalation,
        "Checks for stored credentials in sys.credentials (SQL Server Credential objects)",
        "SELECT credential_id, name, credential_identity, target_type FROM sys.credentials",
        "Stored credential objects exist in sys.credentials — these contain saved secrets that can be extracted",
        "Review each stored credential; remove unnecessary ones and protect with strong access controls",
        Severity::High
    ));

    checks.push(check!(
        "linked_server_password_stored",
        ConfigCategory::LinkExposure,
        "Checks for linked server login mappings that store passwords (uses_self_credential = 0)",
        "SELECT s.name AS server_name, l.remote_name, l.local_principal_id FROM sys.servers s JOIN sys.linked_logins l ON s.server_id = l.server_id WHERE s.is_linked = 1 AND l.uses_self_credential = 0",
        "Linked servers store remote login credentials — these can be extracted and used for lateral movement",
        "Use self-mapped credentials (uses_self_credential = 1) or Windows Authentication where possible",
        Severity::High
    ));

    checks.push(check!(
        "sensitive_column_names",
        ConfigCategory::DatabaseConfig,
        "Scans INFORMATION_SCHEMA.COLUMNS for column names suggesting sensitive data (password, secret, credit, ssn, token, key)",
        "SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE COLUMN_NAME LIKE '%password%' OR COLUMN_NAME LIKE '%secret%' OR COLUMN_NAME LIKE '%credit%' OR COLUMN_NAME LIKE '%ssn%' OR COLUMN_NAME LIKE '%token%' OR COLUMN_NAME LIKE '%private_key%' OR COLUMN_NAME LIKE '%certificate%'",
        "Database columns with sensitive names exist — may contain credentials, PII, or cryptographic material",
        "Review columns with sensitive names; ensure encryption (TDE, Always Encrypted) is applied where needed",
        Severity::Medium
    ));

    checks.push(check!(
        "database_with_pii_columns",
        ConfigCategory::DatabaseConfig,
        "Identifies user databases that contain tables with potential PII columns (email, phone, address, birth, passport)",
        "SELECT DISTINCT TABLE_CATALOG FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_CATALOG NOT IN ('master', 'tempdb', 'model', 'msdb') AND (COLUMN_NAME LIKE '%email%' OR COLUMN_NAME LIKE '%phone%' OR COLUMN_NAME LIKE '%address%' OR COLUMN_NAME LIKE '%birth%' OR COLUMN_NAME LIKE '%passport%' OR COLUMN_NAME LIKE '%social%' OR COLUMN_NAME LIKE '%salary%')",
        "Databases with potential PII columns found — may store sensitive personal data requiring GDPR/HIPAA compliance",
        "Audit data classification, apply column-level encryption or dynamic data masking for PII columns",
        Severity::Info
    ));

    checks
}

/// Categorize a check into a human-readable group string
pub fn categorize_check(check: &MssqlConfigCheck) -> String {
    check.category.to_string()
}

/// Assess a single check result and determine if it is vulnerable.
/// Interprets the `MssqlQueryResult` based on the check's name and query.
pub fn assess_check(check: &MssqlConfigCheck, result: &MssqlQueryResult) -> bool {
    match check.name.as_str() {
        // Surface Area — check if value_in_use = 1 for configuration values
        "xp_cmdshell"
        | "clr_enabled"
        | "ole_automation"
        | "ad_hoc_distributed_queries"
        | "database_mail_xps"
        | "encryption_not_required"
        | "cross_db_ownership_chaining"
        | "c2_audit_disabled" => first_row_first_col_is_1(result),

        // Check value_in_use for audit level: 0 = none, 1 = success, 2 = failure, 3 = all
        "login_auditing_disabled" | "failed_login_logging" => !first_row_first_col_is_ge(result, 2),

        // Check if OBJECT_ID returns non-null
        "xp_regread" | "xp_dirtree" | "xp_subdirs" | "sp_send_dbmail" => {
            first_row_first_col_is_not_null(result)
        }

        // Linked servers — vulnerable if count > 0
        "linked_server_xp_cmdshell"
        | "linked_servers"
        | "linked_server_with_rpc"
        | "openquery_xp_cmdshell_passthrough"
        | "cross_domain_linked_servers"
        | "local_login_impersonation" => result.has_rows(),

        // Linked server login mapping — vulnerable if rows exist
        "linked_server_login_mapping" => result.has_rows(),

        // sa account: vulnerable if NOT disabled (sa is enabled)
        "sa_account_status" => !sa_account_is_disabled(result),

        // sa password: vulnerable if either policy or expiration is unchecked
        "sa_account_password" => sa_password_policy_not_enforced(result),

        // Mixed auth: vulnerable if value is 1 (mixed mode)
        "mixed_authentication" => first_row_first_col_is_1(result),

        // Empty passwords: vulnerable if any rows returned
        "empty_passwords" => result.has_rows(),

        // Password policy/expiration: vulnerable if any rows returned (logins exist without enforcement)
        "password_policy_disabled" | "password_expiration_disabled" => result.has_rows(),

        // Role membership checks — purely informational, always return false (requires manual review)
        "sysadmin_members"
        | "securityadmin_members"
        | "serveradmin_members"
        | "processadmin_members"
        | "setupadmin_members"
        | "diskadmin_members"
        | "dbcreator_members"
        | "bulkadmin_members" => false,

        // Weak encryption heuristic: check if value_in_use is not properly configured
        "weak_encryption" => result.has_rows(),

        // Certificate expired: rows = expired certs found
        "certificate_expired" => result.has_rows(),

        // SSL cert not configured: vulnerable if count is 0
        "ssl_certificate_not_configured" => cert_count_is_zero(result),

        // Schema change audit: vulnerable if count is 0
        "schema_change_audit_disabled" => !result.has_rows(),

        // Trustworthy DB: vulnerable if rows exist
        "trustworthy_database"
        | "database_ownership_chaining"
        | "auto_close_enabled"
        | "auto_shrink_enabled" => result.has_rows(),

        // DB owner public: rows = excessive permissions
        "db_owner_public" => result.has_rows(),

        // Impersonation checks: rows = impersonation grants exist
        "impersonate_login"
        | "impersonate_sa"
        | "execute_as_owner"
        | "execute_as_user"
        | "public_role_permissions" => result.has_rows(),

        // SQL Agent jobs — vulnerable if rows (jobs under other creds exist)
        "sql_agent_jobs_as_other_creds" | "sql_agent_proxy_accounts" => result.has_rows(),

        // DDL triggers — vulnerable if custom triggers exist
        "server_level_ddl_triggers" => result.has_rows(),

        // DB ownership — vulnerable if non-sysadmin owners found
        "database_ownership_non_sysadmin" => result.has_rows(),

        // SMK check — vulnerable if count > 0 (weak encryption method found)
        "service_master_key_weak_encryption" => first_row_first_col_is_not_0(result),

        // DMK auto-decryptable — vulnerable if rows
        "database_master_key_auto_decryptable" => result.has_rows(),

        // Asymmetric key logins — vulnerable if rows
        "asymmetric_keys_with_login_mappings" => result.has_rows(),

        // Error log failed logins — vulnerable if rows (failed logins found)
        "error_log_failed_logins" => result.has_rows(),

        // Stored credentials — vulnerable if rows (credential objects found)
        "stored_credentials"
        | "linked_server_password_stored"
        | "sensitive_column_names"
        | "database_with_pii_columns" => result.has_rows(),

        // Default fallback — assume not vulnerable
        _ => false,
    }
}

/// Format an audit finding for human-readable output
pub fn format_audit_finding(check: &MssqlConfigCheck) -> String {
    let status = if check.vulnerable { "VULNERABLE" } else { "OK" };
    format!(
        "[{}] {} — {} ({})\n  {}",
        status, check.name, check.severity, check.category, check.finding,
    )
}

/// Compute an audit summary from the check results
pub fn audit_summary(checks: &[MssqlConfigCheck]) -> MssqlAuditSummary {
    let total_checks = checks.len();
    let mut vulnerable_count = 0usize;
    let mut severity_counts: HashMap<String, usize> = HashMap::new();

    for check in checks {
        if check.vulnerable {
            vulnerable_count += 1;
        }
        *severity_counts
            .entry(check.severity.to_string())
            .or_insert(0) += 1;
    }

    MssqlAuditSummary {
        total_checks,
        vulnerable_count,
        severity_counts,
    }
}

// ═══════════════════════════════════════════════════════════
// Internal helpers
// ═══════════════════════════════════════════════════════════

fn first_row_first_col_is_1(result: &MssqlQueryResult) -> bool {
    result
        .rows
        .first()
        .and_then(|row| row.first().and_then(|v| v.as_deref()))
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn first_row_first_col_is_ge(result: &MssqlQueryResult, threshold: u64) -> bool {
    result
        .rows
        .first()
        .and_then(|row| row.first().and_then(|v| v.as_deref()))
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v >= threshold)
        .unwrap_or(false)
}

fn first_row_first_col_is_not_null(result: &MssqlQueryResult) -> bool {
    result
        .rows
        .first()
        .and_then(|row| row.first())
        .and_then(|v| v.as_ref())
        .map(|v| !v.is_empty() && v != "NULL" && v != "0x")
        .unwrap_or(false)
}

fn sa_account_is_disabled(result: &MssqlQueryResult) -> bool {
    // The query returns: name, is_disabled
    result
        .rows
        .first()
        .and_then(|row| row.get(1).and_then(|v| v.as_deref()))
        .map(|v| v == "1")
        .unwrap_or(true) // assume disabled if query fails
}

fn sa_password_policy_not_enforced(result: &MssqlQueryResult) -> bool {
    // The query returns: name, is_policy_checked, is_expiration_checked
    let policy = result
        .rows
        .first()
        .and_then(|row| row.get(1).and_then(|v| v.as_deref()))
        .map(|v| v == "1")
        .unwrap_or(false);
    let expiration = result
        .rows
        .first()
        .and_then(|row| row.get(2).and_then(|v| v.as_deref()))
        .map(|v| v == "1")
        .unwrap_or(false);
    !policy || !expiration
}

fn first_row_first_col_is_not_0(result: &MssqlQueryResult) -> bool {
    result
        .rows
        .first()
        .and_then(|row| row.first().and_then(|v| v.as_deref()))
        .map(|v| v != "0")
        .unwrap_or(false)
}

fn cert_count_is_zero(result: &MssqlQueryResult) -> bool {
    result
        .rows
        .first()
        .and_then(|row| row.first().and_then(|v| v.as_deref()))
        .map(|v| v == "0")
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(rows: Vec<Vec<Option<String>>>) -> MssqlQueryResult {
        MssqlQueryResult {
            columns: vec!["value".into()],
            column_types: vec!["int".into()],
            rows,
            rows_affected: 0,
            output_params: Vec::new(),
            return_status: None,
        }
    }

    fn make_multi_col_result(
        columns: Vec<&str>,
        rows: Vec<Vec<Option<String>>>,
    ) -> MssqlQueryResult {
        let col_count = columns.len();
        MssqlQueryResult {
            columns: columns.into_iter().map(|s| s.to_string()).collect(),
            column_types: vec!["nvarchar".into(); col_count],
            rows,
            rows_affected: 0,
            output_params: Vec::new(),
            return_status: None,
        }
    }

    // ── Test 1: at least 57 checks ──
    #[test]
    fn test_build_audit_checks_count() {
        let checks = build_mssql_audit_checks();
        assert!(
            checks.len() >= 57,
            "Expected at least 57 checks, got {}",
            checks.len()
        );
    }

    // ── Test 2: all ConfigCategory variants present ──
    #[test]
    fn test_build_audit_checks_categories() {
        let checks = build_mssql_audit_checks();
        let mut categories: std::collections::HashSet<_> =
            checks.iter().map(|c| &c.category).collect();
        // Remove one to verify
        assert!(categories.remove(&ConfigCategory::SurfaceArea));
        assert!(categories.remove(&ConfigCategory::Authentication));
        assert!(categories.remove(&ConfigCategory::Authorization));
        assert!(categories.remove(&ConfigCategory::Encryption));
        assert!(categories.remove(&ConfigCategory::Auditing));
        assert!(categories.remove(&ConfigCategory::LinkExposure));
        assert!(categories.remove(&ConfigCategory::PrivilegeEscalation));
        assert!(categories.remove(&ConfigCategory::DatabaseConfig));
        assert!(
            categories.is_empty(),
            "Unexpected categories: {:?}",
            categories
        );
    }

    // ── Test 3: at least 8 surface area checks ──
    #[test]
    fn test_build_audit_checks_surface_area_count() {
        let checks = build_mssql_audit_checks();
        let count = checks
            .iter()
            .filter(|c| c.category == ConfigCategory::SurfaceArea)
            .count();
        assert!(
            count >= 9,
            "Expected at least 9 SurfaceArea checks, got {}",
            count
        );
    }

    // ── Test 4: at least 5 auth checks ──
    #[test]
    fn test_build_audit_checks_auth_count() {
        let checks = build_mssql_audit_checks();
        let count = checks
            .iter()
            .filter(|c| c.category == ConfigCategory::Authentication)
            .count();
        assert!(
            count >= 5,
            "Expected at least 5 Authentication checks, got {}",
            count
        );
    }

    // ── Test 5: no check has empty query ──
    #[test]
    fn test_build_audit_checks_all_have_queries() {
        let checks = build_mssql_audit_checks();
        for c in &checks {
            assert!(!c.query.is_empty(), "Check '{}' has empty query", c.name);
        }
    }

    // ── Test 6: no empty remediation ──
    #[test]
    fn test_build_audit_checks_all_have_remediation() {
        let checks = build_mssql_audit_checks();
        for c in &checks {
            assert!(
                !c.remediation.is_empty(),
                "Check '{}' has empty remediation",
                c.name
            );
        }
    }

    // ── Test 7: no empty finding ──
    #[test]
    fn test_build_audit_checks_all_have_finding_template() {
        let checks = build_mssql_audit_checks();
        for c in &checks {
            assert!(
                !c.finding.is_empty(),
                "Check '{}' has empty finding",
                c.name
            );
        }
    }

    // ── Test 8: all categories display without panic ──
    #[test]
    fn test_config_category_display_all() {
        let variants = [
            ConfigCategory::SurfaceArea,
            ConfigCategory::Authentication,
            ConfigCategory::Authorization,
            ConfigCategory::Encryption,
            ConfigCategory::Auditing,
            ConfigCategory::LinkExposure,
            ConfigCategory::PrivilegeEscalation,
            ConfigCategory::DatabaseConfig,
        ];
        for v in &variants {
            let _ = format!("{}", v);
        }
    }

    // ── Test 9: all categories have non-empty description ──
    #[test]
    fn test_config_category_description_all() {
        let variants = [
            ConfigCategory::SurfaceArea,
            ConfigCategory::Authentication,
            ConfigCategory::Authorization,
            ConfigCategory::Encryption,
            ConfigCategory::Auditing,
            ConfigCategory::LinkExposure,
            ConfigCategory::PrivilegeEscalation,
            ConfigCategory::DatabaseConfig,
        ];
        for v in &variants {
            let desc = v.description();
            assert!(!desc.is_empty(), "Category {:?} has empty description", v);
            assert!(desc.len() > 10, "Category {:?} description too short", v);
        }
    }

    // ── Test 10: audit summary with zero vulnerable ──
    #[test]
    fn test_audit_summary_zero_vulnerable() {
        let checks = build_mssql_audit_checks();
        // All vulnerable = false by default
        let summary = audit_summary(&checks);
        assert_eq!(summary.total_checks, checks.len());
        assert_eq!(summary.vulnerable_count, 0);
    }

    // ── Test 11: severity counts correctly ──
    #[test]
    fn test_audit_summary_counts_severities() {
        let checks = build_mssql_audit_checks();
        let summary = audit_summary(&checks);
        let total_from_counts: usize = summary.severity_counts.values().sum();
        assert_eq!(total_from_counts, checks.len());
        // Ensure all used severity levels appear
        for sev in ["Critical", "High", "Medium", "Low"] {
            assert!(
                summary.severity_counts.contains_key(sev),
                "Missing severity '{}' in counts: {:?}",
                sev,
                summary.severity_counts
            );
        }
    }

    // ── Test 12: check defaults ──
    #[test]
    fn test_audit_check_new_has_defaults() {
        let checks = build_mssql_audit_checks();
        for c in &checks {
            assert!(
                !c.vulnerable,
                "Check '{}' should default to vulnerable=false",
                c.name
            );
            assert!(
                c.raw_value.is_none(),
                "Check '{}' should have raw_value=None",
                c.name
            );
        }
    }

    // ── Test 13: serde roundtrip ──
    #[test]
    fn test_audit_check_serde_roundtrip() {
        let check = MssqlConfigCheck {
            name: "xp_cmdshell".into(),
            category: ConfigCategory::SurfaceArea,
            description: "test".into(),
            query: "SELECT 1".into(),
            vulnerable: true,
            finding: "finding".into(),
            remediation: "remediation".into(),
            severity: Severity::Critical,
            raw_value: Some("1".into()),
        };
        let json = serde_json::to_string(&check).unwrap();
        let deserialized: MssqlConfigCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "xp_cmdshell");
        assert_eq!(deserialized.severity, Severity::Critical);
        assert!(deserialized.vulnerable);
        assert_eq!(deserialized.raw_value, Some("1".into()));
    }

    // ── Test 14: no duplicate names ──
    #[test]
    fn test_build_audit_checks_no_duplicate_names() {
        let checks = build_mssql_audit_checks();
        let mut names = std::collections::HashSet::new();
        for c in &checks {
            assert!(names.insert(&c.name), "Duplicate check name: {}", c.name);
        }
    }

    // ── Test 15: categorize_check returns category string ──
    #[test]
    fn test_categorize_check_surface_area() {
        let checks = build_mssql_audit_checks();
        let surface_checks: Vec<_> = checks
            .iter()
            .filter(|c| c.category == ConfigCategory::SurfaceArea)
            .collect();
        assert!(!surface_checks.is_empty());
        for c in &surface_checks {
            assert_eq!(categorize_check(c), "Surface Area");
        }
    }

    // ── Test 16: format_audit_finding includes name and severity ──
    #[test]
    fn test_format_audit_finding() {
        let mut check = MssqlConfigCheck {
            name: "xp_cmdshell".into(),
            category: ConfigCategory::SurfaceArea,
            description: "test".into(),
            query: "SELECT 1".into(),
            vulnerable: true,
            finding: "test finding".into(),
            remediation: "fix it".into(),
            severity: Severity::High,
            raw_value: None,
        };
        let formatted = format_audit_finding(&check);
        assert!(formatted.contains("xp_cmdshell"));
        assert!(formatted.contains("VULNERABLE"));
        assert!(formatted.contains("High"));

        check.vulnerable = false;
        let formatted_ok = format_audit_finding(&check);
        assert!(formatted_ok.contains("OK"));
    }

    // ── Test 17: assess_check xp_cmdshell enabled ──
    #[test]
    fn test_assess_check_xp_cmdshell_enabled() {
        let checks = build_mssql_audit_checks();
        let check = checks.iter().find(|c| c.name == "xp_cmdshell").unwrap();
        let result = make_result(vec![vec![Some("1".into())]]);
        assert!(assess_check(check, &result));
    }

    // ── Test 18: assess_check xp_cmdshell disabled ──
    #[test]
    fn test_assess_check_xp_cmdshell_disabled() {
        let checks = build_mssql_audit_checks();
        let check = checks.iter().find(|c| c.name == "xp_cmdshell").unwrap();
        let result = make_result(vec![vec![Some("0".into())]]);
        assert!(!assess_check(check, &result));
    }

    // ── Test 19: assess_check empty passwords found ──
    #[test]
    fn test_assess_check_empty_passwords_found() {
        let checks = build_mssql_audit_checks();
        let check = checks.iter().find(|c| c.name == "empty_passwords").unwrap();
        let result = make_multi_col_result(
            vec!["name", "principal_id"],
            vec![vec![Some("sa".into()), Some("1".into())]],
        );
        assert!(assess_check(check, &result));
    }

    // ── Test 20: assess_check sa enabled ──
    #[test]
    fn test_assess_check_sa_enabled() {
        let checks = build_mssql_audit_checks();
        let check = checks
            .iter()
            .find(|c| c.name == "sa_account_status")
            .unwrap();
        // row: name, is_disabled
        let result = make_multi_col_result(
            vec!["name", "is_disabled"],
            vec![vec![Some("sa".into()), Some("0".into())]],
        );
        assert!(assess_check(check, &result));
    }

    // ── Test 21: assess_check sa disabled ──
    #[test]
    fn test_assess_check_sa_disabled() {
        let checks = build_mssql_audit_checks();
        let check = checks
            .iter()
            .find(|c| c.name == "sa_account_status")
            .unwrap();
        let result = make_multi_col_result(
            vec!["name", "is_disabled"],
            vec![vec![Some("sa".into()), Some("1".into())]],
        );
        assert!(!assess_check(check, &result));
    }

    // ── Test 22: assess_check no results ──
    #[test]
    fn test_assess_check_no_results_defaults_safe() {
        let checks = build_mssql_audit_checks();
        let result = make_result(vec![]);
        let check = checks.iter().find(|c| c.name == "xp_cmdshell").unwrap();
        assert!(!assess_check(check, &result));
    }

    // ── Test 23: audit_summary vulnerable_count ──
    #[test]
    fn test_audit_summary_with_vulnerable() {
        let mut checks = build_mssql_audit_checks();
        // Mark first 3 as vulnerable
        for c in checks.iter_mut().take(3) {
            c.vulnerable = true;
        }
        let summary = audit_summary(&checks);
        assert_eq!(summary.vulnerable_count, 3);
    }

    // ── Test 24: Weak encryption check ──
    #[test]
    fn test_assess_check_weak_encryption() {
        let checks = build_mssql_audit_checks();
        let check = checks.iter().find(|c| c.name == "weak_encryption").unwrap();
        let result = make_result(vec![vec![Some("0".into())]]);
        assert!(assess_check(check, &result));
    }

    // ── Test 25: MssqlConfigAudit construction ──
    #[test]
    fn test_mssql_config_audit_construction() {
        let checks = build_mssql_audit_checks();
        let summary = audit_summary(&checks);
        let audit = MssqlConfigAudit {
            checks: checks.clone(),
            summary,
        };
        assert_eq!(audit.checks.len(), checks.len());
        assert_eq!(audit.summary.total_checks, checks.len());
    }

    // ── Test 26: sql agent jobs assessed vulnerable with rows ──
    #[test]
    fn test_assess_check_sql_agent_jobs_vulnerable() {
        let checks = build_mssql_audit_checks();
        let check = checks
            .iter()
            .find(|c| c.name == "sql_agent_jobs_as_other_creds")
            .unwrap();
        let result = make_multi_col_result(
            vec!["job_name", "owner", "step_name", "subsystem", "proxy_id"],
            vec![vec![
                Some("job1".into()),
                Some("sa".into()),
                Some("step1".into()),
                Some("CmdExec".into()),
                Some("1".into()),
            ]],
        );
        assert!(assess_check(check, &result));
    }

    // ── Test 27: sql agent proxy accounts assessed vulnerable with rows ──
    #[test]
    fn test_assess_check_sql_agent_proxy_vulnerable() {
        let checks = build_mssql_audit_checks();
        let check = checks
            .iter()
            .find(|c| c.name == "sql_agent_proxy_accounts")
            .unwrap();
        let result = make_multi_col_result(
            vec!["proxy_name", "principal_name", "subsystem"],
            vec![vec![
                Some("Proxy1".into()),
                Some("user1".into()),
                Some("PowerShell".into()),
            ]],
        );
        assert!(assess_check(check, &result));
    }

    // ── Test 28: ddl triggers vulnerable with rows ──
    #[test]
    fn test_assess_check_ddl_triggers_vulnerable() {
        let checks = build_mssql_audit_checks();
        let check = checks
            .iter()
            .find(|c| c.name == "server_level_ddl_triggers")
            .unwrap();
        let result = make_multi_col_result(
            vec!["name", "is_disabled", "create_date", "modify_date"],
            vec![vec![
                Some("trig1".into()),
                Some("0".into()),
                Some("2024-01-01".into()),
                Some("2024-01-01".into()),
            ]],
        );
        assert!(assess_check(check, &result));
    }

    // ── Test 29: db ownership non-sysadmin vulnerable ──
    #[test]
    fn test_assess_check_db_ownership_vulnerable() {
        let checks = build_mssql_audit_checks();
        let check = checks
            .iter()
            .find(|c| c.name == "database_ownership_non_sysadmin")
            .unwrap();
        let result = make_multi_col_result(
            vec!["db_name", "owner_name", "owner_type"],
            vec![vec![
                Some("AppDB".into()),
                Some("bob".into()),
                Some("SQL_LOGIN".into()),
            ]],
        );
        assert!(assess_check(check, &result));
    }

    // ── Test 30: smk weak encryption check ──
    #[test]
    fn test_assess_check_smk_weak_encryption() {
        let checks = build_mssql_audit_checks();
        let check = checks
            .iter()
            .find(|c| c.name == "service_master_key_weak_encryption")
            .unwrap();
        let result = make_result(vec![vec![Some("1".into())]]);
        assert!(assess_check(check, &result));
    }

    // ── Test 31: smk weak encryption not vulnerable when 0 ──
    #[test]
    fn test_assess_check_smk_encryption_ok() {
        let checks = build_mssql_audit_checks();
        let check = checks
            .iter()
            .find(|c| c.name == "service_master_key_weak_encryption")
            .unwrap();
        let result = make_result(vec![vec![Some("0".into())]]);
        assert!(!assess_check(check, &result));
    }

    // ── Test 32: dmk auto-decryptable vulnerable with rows ──
    #[test]
    fn test_assess_check_dmk_auto_decryptable() {
        let checks = build_mssql_audit_checks();
        let check = checks
            .iter()
            .find(|c| c.name == "database_master_key_auto_decryptable")
            .unwrap();
        let result = make_multi_col_result(vec!["db_name"], vec![vec![Some("AppDB".into())]]);
        assert!(assess_check(check, &result));
    }

    // ── Test 33: asymmetric key logins vulnerable with rows ──
    #[test]
    fn test_assess_check_asymmetric_key_logins() {
        let checks = build_mssql_audit_checks();
        let check = checks
            .iter()
            .find(|c| c.name == "asymmetric_keys_with_login_mappings")
            .unwrap();
        let result = make_multi_col_result(
            vec![
                "login_name",
                "type_desc",
                "credential_name",
                "credential_identity",
            ],
            vec![vec![
                Some("KeyLogin".into()),
                Some("CERTIFICATE_MAPPED_LOGIN".into()),
                None,
                None,
            ]],
        );
        assert!(assess_check(check, &result));
    }

    // ── Test 34: error log failed logins vulnerable with rows ──
    #[test]
    fn test_assess_check_error_log_failed_logins() {
        let checks = build_mssql_audit_checks();
        let check = checks
            .iter()
            .find(|c| c.name == "error_log_failed_logins")
            .unwrap();
        let result = make_multi_col_result(
            vec!["LogDate", "ProcessInfo", "Text"],
            vec![vec![
                Some("2024-01-01".into()),
                Some("Logon".into()),
                Some("Login failed for user 'sa'".into()),
            ]],
        );
        assert!(assess_check(check, &result));
    }

    // ── Test 35: new check names are all unique ──
    #[test]
    fn test_new_check_names_are_unique() {
        let checks = build_mssql_audit_checks();
        let new_names = [
            "sql_agent_jobs_as_other_creds",
            "sql_agent_proxy_accounts",
            "server_level_ddl_triggers",
            "database_ownership_non_sysadmin",
            "service_master_key_weak_encryption",
            "database_master_key_auto_decryptable",
            "asymmetric_keys_with_login_mappings",
            "error_log_failed_logins",
        ];
        let check_names: std::collections::HashSet<&str> =
            checks.iter().map(|c| c.name.as_str()).collect();
        for name in &new_names {
            assert!(
                check_names.contains(name),
                "New check '{}' not found in built checks",
                name
            );
        }
    }

    // ── Test 36: stored_credentials vulnerable with rows ──
    #[test]
    fn test_assess_check_stored_credentials_vulnerable() {
        let checks = build_mssql_audit_checks();
        let check = checks
            .iter()
            .find(|c| c.name == "stored_credentials")
            .unwrap();
        let result = make_multi_col_result(
            vec![
                "credential_id",
                "name",
                "credential_identity",
                "target_type",
            ],
            vec![vec![
                Some("1".into()),
                Some("BackupCred".into()),
                Some("DOMAIN\\svc_backup".into()),
                Some("".into()),
            ]],
        );
        assert!(assess_check(check, &result));
    }

    // ── Test 37: stored_credentials not vulnerable with no rows ──
    #[test]
    fn test_assess_check_stored_credentials_safe() {
        let checks = build_mssql_audit_checks();
        let check = checks
            .iter()
            .find(|c| c.name == "stored_credentials")
            .unwrap();
        let result = make_result(vec![]);
        assert!(!assess_check(check, &result));
    }

    // ── Test 38: linked_server_password_stored vulnerable with rows ──
    #[test]
    fn test_assess_check_linked_server_pwd_stored() {
        let checks = build_mssql_audit_checks();
        let check = checks
            .iter()
            .find(|c| c.name == "linked_server_password_stored")
            .unwrap();
        let result = make_multi_col_result(
            vec!["server_name", "remote_name", "local_principal_id"],
            vec![vec![
                Some("SQL02".into()),
                Some("sa".into()),
                Some("1".into()),
            ]],
        );
        assert!(assess_check(check, &result));
    }

    // ── Test 39: sensitive_column_names vulnerable with rows ──
    #[test]
    fn test_assess_check_sensitive_columns() {
        let checks = build_mssql_audit_checks();
        let check = checks
            .iter()
            .find(|c| c.name == "sensitive_column_names")
            .unwrap();
        let result = make_multi_col_result(
            vec!["TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME", "COLUMN_NAME"],
            vec![vec![
                Some("AppDB".into()),
                Some("dbo".into()),
                Some("Users".into()),
                Some("password_hash".into()),
            ]],
        );
        assert!(assess_check(check, &result));
    }

    // ── Test 40: database_with_pii_columns vulnerable with rows ──
    #[test]
    fn test_assess_check_pii_columns() {
        let checks = build_mssql_audit_checks();
        let check = checks
            .iter()
            .find(|c| c.name == "database_with_pii_columns")
            .unwrap();
        let result = make_multi_col_result(vec!["TABLE_CATALOG"], vec![vec![Some("HR_DB".into())]]);
        assert!(assess_check(check, &result));
    }

    // ── Test 41: total check count is 61 ──
    #[test]
    fn test_total_check_count() {
        let checks = build_mssql_audit_checks();
        assert_eq!(
            checks.len(),
            61,
            "Expected 61 audits checks, got {}",
            checks.len()
        );
    }
}
