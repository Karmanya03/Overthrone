use crate::goals::EngagementState;
use crate::planner::{PlanStep, StepResult};
use chrono::Utc;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct TrailWriter {
    path: PathBuf,
}

impl TrailWriter {
    pub(crate) fn start(
        mode: &str,
        domain: &str,
        dc_ip: &str,
        goal: &str,
        resumed: bool,
    ) -> io::Result<Self> {
        let dir = PathBuf::from("loot").join("trails");
        fs::create_dir_all(&dir)?;
        let previous = previous_runs(&dir, domain, dc_ip)?;
        let path = next_path(&dir, domain, dc_ip);
        let writer = Self { path };

        writer.append_raw(&format!(
            "# Overthrone {mode} Trail\n\n- Domain: `{domain}`\n- Domain IP: `{dc_ip}`\n- Goal: {goal}\n- Started: {}\n- Resumed state: {}\n- Prior trails detected: {}\n\n",
            Utc::now().to_rfc3339(),
            if resumed { "yes" } else { "no" },
            previous.len()
        ))?;

        if !previous.is_empty() {
            writer.append_raw("## Prior Run Files\n\n")?;
            for prior in previous {
                writer.append_raw(&format!("- `{}`\n", prior.display()))?;
            }
            writer.append_raw("\n")?;
        }

        Ok(writer)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn append_stage(&self, stage: impl std::fmt::Display, step_count: usize) {
        let _ = self.append_raw(&format!(
            "\n## Phase: {stage}\n\nPlanned pending actions in phase: `{step_count}`\n\n"
        ));
    }

    pub(crate) fn append_step(
        &self,
        step: &PlanStep,
        result: &StepResult,
        state: &EngagementState,
    ) {
        let status = if result.success { "success" } else { "failed" };
        let command_hints = step
            .action
            .ovt_command_hints()
            .into_iter()
            .map(|hint| format!("- `{}`\n", sanitize_inline(&hint)))
            .collect::<String>();
        let _ = self.append_raw(&format!(
            "### [{}] {}\n\n- Action: `{}`\n- Noise: `{:?}`\n- Priority: `{}`\n- Result: `{}`\n- New credentials: `{}`\n- New admin hosts: `{}`\n- Output: {}\n\n#### OVT Tool Hints\n\n{}\n{}\n",
            step.stage,
            step.description,
            step.action.key(),
            step.noise,
            step.priority,
            status,
            result.new_credentials,
            result.new_admin_hosts,
            sanitize_inline(&result.output),
            if command_hints.is_empty() {
                "- No direct operator command hint for this step.\n".to_string()
            } else {
                command_hints
            },
            state_snapshot(state)
        ));
    }

    pub(crate) fn append_decision(&self, label: &str, detail: impl AsRef<str>) {
        let _ = self.append_raw(&format!(
            "- {label}: {}\n",
            sanitize_inline(detail.as_ref())
        ));
    }

    pub(crate) fn append_final(&self, state: &EngagementState, summary: impl AsRef<str>) {
        let _ = self.append_raw(&format!(
            "\n## Final Summary\n\n{}\n\n{}\n",
            sanitize_inline(summary.as_ref()),
            state_snapshot(state)
        ));
    }

    fn append_raw(&self, text: &str) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(text.as_bytes())
    }
}

fn next_path(dir: &Path, domain: &str, dc_ip: &str) -> PathBuf {
    let stem = format!(
        "overthrone_{}_{}",
        sanitize_name(domain),
        sanitize_name(dc_ip)
    );
    for idx in 1..10_000 {
        let path = dir.join(format!("{stem}_run{idx:03}.md"));
        if !path.exists() {
            return path;
        }
    }
    dir.join(format!("{stem}_run{}.md", Utc::now().timestamp()))
}

fn previous_runs(dir: &Path, domain: &str, dc_ip: &str) -> io::Result<Vec<PathBuf>> {
    let prefix = format!(
        "overthrone_{}_{}",
        sanitize_name(domain),
        sanitize_name(dc_ip)
    );
    let mut files = Vec::new();
    if !dir.exists() {
        return Ok(files);
    }
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with(&prefix) && name.ends_with(".md") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn sanitize_name(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if matches!(ch, '.' | '-' | '_') {
            out.push('_');
        }
    }
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

fn sanitize_inline(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}

fn state_snapshot(state: &EngagementState) -> String {
    let stats = state.stats_summary();
    let kerberoastable = join_limited(state.kerberoastable.iter().map(String::as_str), 8);
    let asrep = join_limited(state.asrep_roastable.iter().map(String::as_str), 8);
    let admin_hosts = join_limited(state.admin_hosts.iter().map(String::as_str), 8);
    let laps = join_limited(
        state
            .laps
            .iter()
            .filter(|item| item.readable)
            .map(|item| item.computer_name.as_str()),
        8,
    );
    let delegations = join_limited(
        state
            .constrained_delegation
            .iter()
            .map(|item| item.account.as_str())
            .chain(state.unconstrained_delegation.iter().map(String::as_str))
            .chain(state.rbcd_targets.iter().map(String::as_str)),
        8,
    );
    let recent_loot = join_limited(
        state.loot.iter().rev().map(|item| item.loot_type.as_str()),
        5,
    );
    format!(
        "- Findings: users `{}`, computers `{}`, groups `{}`, credentials `{}`, admin hosts `{}`, kerberoastable `{}`, asrep `{}`, readable LAPS `{}`, delegation findings `{}`\n- Domain admin: `{}`{}\n- Important findings: kerberoastable [{}]; asrep [{}]; admin hosts [{}]; LAPS [{}]; delegation [{}]; recent loot [{}]\n",
        stats.total_users,
        stats.total_computers,
        stats.total_groups,
        stats.credentials_obtained,
        stats.admin_hosts,
        stats.kerberoastable,
        stats.asrep_roastable,
        stats.readable_laps,
        stats.delegation_findings,
        stats.domain_admin,
        stats
            .da_user
            .as_ref()
            .map(|user| format!(" via `{user}`"))
            .unwrap_or_default(),
        kerberoastable,
        asrep,
        admin_hosts,
        laps,
        delegations,
        recent_loot
    )
}

fn join_limited<'a>(items: impl Iterator<Item = &'a str>, limit: usize) -> String {
    let mut values = Vec::new();
    let mut remaining = 0usize;
    for item in items {
        if values.len() < limit {
            values.push(item.to_string());
        } else {
            remaining += 1;
        }
    }
    if remaining > 0 {
        values.push(format!("+{remaining} more"));
    }
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── sanitize_name ──

    #[test]
    fn sanitize_name_keeps_alphanumeric() {
        assert_eq!(sanitize_name("test.local"), "test_local");
    }

    #[test]
    fn sanitize_name_lowercases() {
        assert_eq!(sanitize_name("TEST.DOMAIN"), "test_domain");
    }

    #[test]
    fn sanitize_name_replaces_special_chars() {
        assert_eq!(sanitize_name("dc-01.test_local"), "dc_01_test_local");
    }

    #[test]
    fn sanitize_name_empty_falls_back() {
        assert_eq!(sanitize_name("!@#$"), "unknown");
    }

    #[test]
    fn sanitize_name_keeps_dots_and_dashes() {
        assert_eq!(sanitize_name("dc01.ad.test"), "dc01_ad_test");
    }

    // ── sanitize_inline ──

    #[test]
    fn sanitize_inline_removes_newlines() {
        assert_eq!(sanitize_inline("hello\nworld"), "hello world");
    }

    #[test]
    fn sanitize_inline_removes_carriage_returns() {
        assert_eq!(sanitize_inline("line1\rline2"), "line1 line2");
    }

    #[test]
    fn sanitize_inline_unchanged_when_clean() {
        assert_eq!(sanitize_inline("hello world"), "hello world");
    }

    #[test]
    fn sanitize_inline_handles_empty() {
        assert_eq!(sanitize_inline(""), "");
    }

    // ── join_limited ──

    #[test]
    fn join_limited_empty() {
        assert_eq!(join_limited(std::iter::empty(), 5), "none");
    }

    #[test]
    fn join_limited_under_limit() {
        let items = ["a", "b", "c"];
        assert_eq!(join_limited(items.iter().copied(), 5), "a, b, c");
    }

    #[test]
    fn join_limited_at_limit() {
        let items = ["a", "b", "c"];
        assert_eq!(join_limited(items.iter().copied(), 3), "a, b, c");
    }

    #[test]
    fn join_limited_over_limit() {
        let items = ["a", "b", "c", "d", "e"];
        assert_eq!(join_limited(items.iter().copied(), 3), "a, b, c, +2 more");
    }

    #[test]
    fn join_limited_single_item() {
        assert_eq!(join_limited(std::iter::once("only"), 5), "only");
    }

    // ── next_path logic ──

    #[test]
    fn next_path_uses_correct_prefix() {
        let dir = std::env::temp_dir().join("overthrone_trail_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = next_path(&dir, "test.local", "10.0.0.1");
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("overthrone_test_local_10_0_0_1"));
        assert!(name.ends_with(".md"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── state_snapshot formatting ──

    #[test]
    fn state_snapshot_empty_state() {
        let state = EngagementState::new();
        let snap = state_snapshot(&state);
        assert!(
            snap.contains("users `0`"),
            "snap should mention users: {snap}"
        );
        assert!(
            snap.contains("computers `0`"),
            "snap should mention computers: {snap}"
        );
        assert!(
            snap.contains("Domain admin: `false`"),
            "snap should say Domain admin: false: {snap}"
        );
        assert!(
            snap.contains("kerberoastable [none]"),
            "snap should mention kerberoastable: {snap}"
        );
        assert!(
            snap.contains("asrep [none]"),
            "snap should mention asrep: {snap}"
        );
        assert!(
            snap.contains("admin hosts [none]"),
            "snap should mention admin hosts: {snap}"
        );
    }

    #[test]
    fn state_snapshot_with_data() {
        let mut state = EngagementState::new();
        state.kerberoastable.push("svc_1".into());
        state.has_domain_admin = true;
        state.da_user = Some("admin".into());
        let snap = state_snapshot(&state);
        assert!(
            snap.contains("kerberoastable `1`"),
            "snap should show kerberoastable count: {snap}"
        );
        assert!(
            snap.contains("Domain admin: `true`"),
            "snap should say Domain admin: true: {snap}"
        );
        assert!(
            snap.contains("via `admin`"),
            "snap should mention da user: {snap}"
        );
    }
}
