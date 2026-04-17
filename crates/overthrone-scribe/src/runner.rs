//! Report runner — Top-level orchestrator that drives report generation.
//! Takes an engagement session and produces output in the requested format.

use crate::markdown;
use crate::pdf;
use crate::session::EngagementSession;
use chrono::Utc;
use colored::Colorize;
use overthrone_pilot::runner::AutoPwnResult;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::info;

// ═══════════════════════════════════════════════════════════
// Report Configuration
// ═══════════════════════════════════════════════════════════

/// Output format for the report
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportFormat {
    Markdown,
    Pdf,
    Json,
    All,
}

impl std::fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Markdown => write!(f, "Markdown"),
            Self::Pdf => write!(f, "PDF"),
            Self::Json => write!(f, "JSON"),
            Self::All => write!(f, "All Formats"),
        }
    }
}

/// Configuration for report generation
#[derive(Debug, Clone)]
pub struct ReportConfig {
    /// Output format(s)
    pub format: ReportFormat,
    /// Output directory
    pub output_dir: PathBuf,
    /// Base filename (without extension)
    pub filename_base: String,
    /// Client name
    pub client_name: String,
    /// Assessor name
    pub assessor_name: String,
    /// Assessor company
    pub assessor_company: String,
    /// Whether to redact credential values in the report
    pub redact_credentials: bool,
    /// Include the full action log
    pub include_action_log: bool,
    /// Include raw JSON data as appendix
    pub include_raw_data: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            format: ReportFormat::Markdown,
            output_dir: PathBuf::from("./reports"),
            filename_base: format!("overthrone-report-{}", Utc::now().format("%Y%m%d-%H%M")),
            client_name: "ACME Corp".to_string(),
            assessor_name: "Operator".to_string(),
            assessor_company: "Overthrone".to_string(),
            redact_credentials: true,
            include_action_log: true,
            include_raw_data: false,
        }
    }
}

impl ReportConfig {
    /// Builder — set output format
    pub fn format(mut self, format: ReportFormat) -> Self {
        self.format = format;
        self
    }

    /// Builder — set output directory
    pub fn output_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.output_dir = dir.into();
        self
    }

    /// Builder — set client name
    pub fn client(mut self, name: &str) -> Self {
        self.client_name = name.to_string();
        self
    }

    /// Builder — set assessor info
    pub fn assessor(mut self, name: &str, company: &str) -> Self {
        self.assessor_name = name.to_string();
        self.assessor_company = company.to_string();
        self
    }

    /// Builder — set redaction policy
    pub fn redact(mut self, redact: bool) -> Self {
        self.redact_credentials = redact;
        self
    }

    /// Builder — include raw JSON appendix
    pub fn with_raw_data(mut self, include: bool) -> Self {
        self.include_raw_data = include;
        self
    }

    /// Builder — include action log appendix
    pub fn with_action_log(mut self, include: bool) -> Self {
        self.include_action_log = include;
        self
    }

    /// Construct a timestamped filename base from a domain name
    pub fn filename_from_domain(mut self, domain: &str) -> Self {
        let sanitized = domain.replace(['.', ' '], "_").to_lowercase();
        self.filename_base = format!(
            "overthrone-{}-{}",
            sanitized,
            Utc::now().format("%Y%m%d-%H%M")
        );
        self
    }
}

// ═══════════════════════════════════════════════════════════
// Report Output
// ═══════════════════════════════════════════════════════════

/// Output from report generation
#[derive(Debug, Clone)]
pub struct ReportOutput {
    /// Paths to generated report files
    pub files: Vec<PathBuf>,
    /// Total findings included
    pub finding_count: usize,
    /// Report generation timestamp
    pub generated_at: chrono::DateTime<Utc>,
    /// Overall risk rating string
    pub overall_risk: String,
    /// Whether domain admin was achieved
    pub domain_admin_achieved: bool,
}

impl std::fmt::Display for ReportOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "╔══════════════════════════════════════════╗")?;
        writeln!(f, "║       OVERTHRONE SCRIBE — REPORT         ║")?;
        writeln!(f, "╠══════════════════════════════════════════╣")?;
        writeln!(f, "║  Findings:   {:<27} ║", self.finding_count)?;
        writeln!(f, "║  Risk:       {:<27} ║", self.overall_risk)?;
        writeln!(
            f,
            "║  DA:         {:<27} ║",
            if self.domain_admin_achieved {
                "YES ⚠"
            } else {
                "No"
            }
        )?;
        writeln!(
            f,
            "║  Generated:  {:<27} ║",
            self.generated_at.format("%Y-%m-%d %H:%M UTC")
        )?;
        writeln!(f, "╠══════════════════════════════════════════╣")?;
        for path in &self.files {
            writeln!(f, "║  → {:<37} ║", path.display())?;
        }
        writeln!(f, "╚══════════════════════════════════════════╝")
    }
}

// ═══════════════════════════════════════════════════════════
// Main Generator — Public API
// ═══════════════════════════════════════════════════════════

/// Generate a report from an AutoPwnResult (primary entrypoint)
pub async fn generate_report(
    result: &AutoPwnResult,
    config: &ReportConfig,
) -> anyhow::Result<ReportOutput> {
    info!(
        "{} Generating {} report...",
        "SCRIBE".bold().magenta(),
        config.format
    );

    // Build session from autopwn result
    let session = EngagementSession::from_autopwn(
        result,
        &config.client_name,
        &config.assessor_name,
        &config.assessor_company,
    );

    generate_from_session(&session, config).await
}

/// Generate a report from a pre-built EngagementSession
pub async fn generate_from_session(
    session: &EngagementSession,
    config: &ReportConfig,
) -> anyhow::Result<ReportOutput> {
    // Ensure output directory exists
    tokio::fs::create_dir_all(&config.output_dir).await?;

    let mut output = ReportOutput {
        files: Vec::new(),
        finding_count: session.findings.len(),
        generated_at: Utc::now(),
        overall_risk: session.overall_risk().to_string(),
        domain_admin_achieved: session.domain_admin_achieved,
    };

    // Generate requested format(s)
    match config.format {
        ReportFormat::Markdown => {
            let path = generate_markdown(session, config).await?;
            output.files.push(path);
        }
        ReportFormat::Pdf => {
            let path = generate_pdf(session, config).await?;
            output.files.push(path);
        }
        ReportFormat::Json => {
            let path = generate_json(session, config).await?;
            output.files.push(path);
        }
        ReportFormat::All => {
            output.files.push(generate_markdown(session, config).await?);
            output.files.push(generate_pdf(session, config).await?);
            output.files.push(generate_json(session, config).await?);
        }
    }

    // Print summary banner
    print_report_summary(session, &output);

    Ok(output)
}

/// Generate a report from a saved JSON session file
pub async fn generate_from_file(
    session_path: &std::path::Path,
    config: &ReportConfig,
) -> anyhow::Result<ReportOutput> {
    info!(
        "{} Loading session from {}",
        "SCRIBE".bold().magenta(),
        session_path.display()
    );

    let json_bytes = tokio::fs::read(session_path).await?;
    let session: EngagementSession = serde_json::from_slice(&json_bytes)?;

    info!(
        "  Loaded session '{}' with {} findings",
        session.title,
        session.findings.len()
    );

    generate_from_session(&session, config).await
}

// ═══════════════════════════════════════════════════════════
// Format-specific generators
// ═══════════════════════════════════════════════════════════

async fn generate_markdown(
    session: &EngagementSession,
    config: &ReportConfig,
) -> anyhow::Result<PathBuf> {
    let content = markdown::render(session);
    let path = config
        .output_dir
        .join(format!("{}.md", config.filename_base));

    tokio::fs::write(&path, &content).await?;
    info!(
        "  {} Markdown: {} ({} bytes)",
        "✓".green(),
        path.display(),
        content.len()
    );
    Ok(path)
}

async fn generate_pdf(
    session: &EngagementSession,
    config: &ReportConfig,
) -> anyhow::Result<PathBuf> {
    let bytes = pdf::render(session);
    let path = config
        .output_dir
        .join(format!("{}.pdf", config.filename_base));

    tokio::fs::write(&path, &bytes).await?;
    info!(
        "  {} PDF: {} ({:.1} KB)",
        "✓".green(),
        path.display(),
        bytes.len() as f64 / 1024.0
    );
    Ok(path)
}

async fn generate_json(
    session: &EngagementSession,
    config: &ReportConfig,
) -> anyhow::Result<PathBuf> {
    // Optionally strip raw engagement state to reduce size
    let json_session = if config.include_raw_data {
        serde_json::to_string_pretty(session)?
    } else {
        // Clone and strip heavy fields
        let mut stripped = session.clone();
        stripped.engagement_state = None;
        stripped.autopwn_result = None;
        serde_json::to_string_pretty(&stripped)?
    };

    let path = config
        .output_dir
        .join(format!("{}.json", config.filename_base));

    tokio::fs::write(&path, &json_session).await?;
    info!(
        "  {} JSON: {} ({:.1} KB)",
        "✓".green(),
        path.display(),
        json_session.len() as f64 / 1024.0
    );
    Ok(path)
}

// ═══════════════════════════════════════════════════════════
// Summary Printer
// ═══════════════════════════════════════════════════════════

fn print_report_summary(session: &EngagementSession, output: &ReportOutput) {
    let counts = session.severity_counts();
    let critical = counts
        .get(&crate::session::Severity::Critical)
        .copied()
        .unwrap_or(0);
    let high = counts
        .get(&crate::session::Severity::High)
        .copied()
        .unwrap_or(0);
    let medium = counts
        .get(&crate::session::Severity::Medium)
        .copied()
        .unwrap_or(0);
    let low = counts
        .get(&crate::session::Severity::Low)
        .copied()
        .unwrap_or(0);
    let info_count = counts
        .get(&crate::session::Severity::Informational)
        .copied()
        .unwrap_or(0);

    println!();
    println!(
        "{}",
        "╔══════════════════════════════════════════════════╗"
            .bold()
            .magenta()
    );
    println!(
        "{}",
        "║          OVERTHRONE SCRIBE — COMPLETE            ║"
            .bold()
            .magenta()
    );
    println!(
        "{}",
        "╠══════════════════════════════════════════════════╣".magenta()
    );

    // Findings breakdown
    println!(
        "{}  Findings:  {} total",
        "║".magenta(),
        session.findings.len()
    );
    if critical > 0 {
        println!(
            "{}    {} Critical: {}",
            "║".magenta(),
            "●".red().bold(),
            critical
        );
    }
    if high > 0 {
        println!("{}    {} High:     {}", "║".magenta(), "●".red(), high);
    }
    if medium > 0 {
        println!("{}    {} Medium:   {}", "║".magenta(), "●".yellow(), medium);
    }
    if low > 0 {
        println!("{}    {} Low:      {}", "║".magenta(), "●".green(), low);
    }
    if info_count > 0 {
        println!(
            "{}    {} Info:     {}",
            "║".magenta(),
            "●".blue(),
            info_count
        );
    }

    println!(
        "{}",
        "║                                                  ║".magenta()
    );

    // Domain Admin status
    if session.domain_admin_achieved {
        println!(
            "{}  🎯 Domain Admin: {}",
            "║".magenta(),
            "ACHIEVED".red().bold()
        );
    } else {
        println!(
            "{}  Domain Admin: {}",
            "║".magenta(),
            "Not achieved".dimmed()
        );
    }

    // Stats
    println!(
        "{}  Creds compromised:  {}",
        "║".magenta(),
        session.total_credentials_compromised
    );
    println!(
        "{}  Admin hosts:        {}",
        "║".magenta(),
        session.total_admin_hosts
    );
    println!(
        "{}  Overall risk:       {}",
        "║".magenta(),
        format!("{}", session.overall_risk()).bold()
    );

    println!(
        "{}",
        "║                                                  ║".magenta()
    );

    // File outputs
    println!("{}  Output files:", "║".magenta());
    for path in &output.files {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("?")
            .to_uppercase();
        println!(
            "{}    {} [{}] {}",
            "║".magenta(),
            "→".cyan(),
            ext,
            path.display()
        );
    }

    println!(
        "{}",
        "╚══════════════════════════════════════════════════╝"
            .bold()
            .magenta()
    );
    println!();
}

// ═══════════════════════════════════════════════════════════
// Quick-generate helpers (for CLI integration)
// ═══════════════════════════════════════════════════════════

/// Quick markdown report — minimal config
pub async fn quick_markdown(result: &AutoPwnResult, output_dir: &str) -> anyhow::Result<PathBuf> {
    let domain = result.state.domain.as_deref().unwrap_or("unknown");

    let config = ReportConfig::default()
        .format(ReportFormat::Markdown)
        .output_dir(output_dir)
        .filename_from_domain(domain);

    let output = generate_report(result, &config).await?;
    output
        .files
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No output file generated"))
}

/// Quick all-formats report
pub async fn quick_all(
    result: &AutoPwnResult,
    output_dir: &str,
    client: &str,
    assessor: &str,
    company: &str,
) -> anyhow::Result<ReportOutput> {
    let domain = result.state.domain.as_deref().unwrap_or("unknown");

    let config = ReportConfig::default()
        .format(ReportFormat::All)
        .output_dir(output_dir)
        .filename_from_domain(domain)
        .client(client)
        .assessor(assessor, company)
        .with_raw_data(true)
        .with_action_log(true);

    generate_report(result, &config).await
}

// ═══════════════════════════════════════════════════════════
// Session Persistence (save/load for later reporting)
// ═══════════════════════════════════════════════════════════

/// Save an engagement session to disk as JSON for later report generation
pub async fn save_session(
    session: &EngagementSession,
    path: &std::path::Path,
) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(session)?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, &json).await?;
    info!(
        "  {} Session saved: {} ({:.1} KB)",
        "✓".green(),
        path.display(),
        json.len() as f64 / 1024.0
    );
    Ok(())
}

/// Load an engagement session from a JSON file
pub async fn load_session(path: &std::path::Path) -> anyhow::Result<EngagementSession> {
    let bytes = tokio::fs::read(path).await?;
    let session: EngagementSession = serde_json::from_slice(&bytes)?;
    info!(
        "  {} Session loaded: '{}' ({} findings)",
        "✓".green(),
        session.title,
        session.findings.len()
    );
    Ok(session)
}

/// Merge two sessions (e.g., multiple runs against the same domain)
pub fn merge_sessions(
    base: &EngagementSession,
    additional: &EngagementSession,
) -> EngagementSession {
    let mut merged = base.clone();

    // Merge findings (deduplicate by title)
    let existing_titles: std::collections::HashSet<String> =
        merged.findings.iter().map(|f| f.title.clone()).collect();

    for finding in &additional.findings {
        if !existing_titles.contains(&finding.title) {
            merged.findings.push(finding.clone());
        }
    }

    // Re-sort by severity
    merged
        .findings
        .sort_by_key(|b| std::cmp::Reverse(b.severity));

    // Update stats (take max)
    merged.total_users_enumerated = merged
        .total_users_enumerated
        .max(additional.total_users_enumerated);
    merged.total_computers_enumerated = merged
        .total_computers_enumerated
        .max(additional.total_computers_enumerated);
    merged.total_credentials_compromised = merged
        .total_credentials_compromised
        .max(additional.total_credentials_compromised);
    merged.total_admin_hosts = merged.total_admin_hosts.max(additional.total_admin_hosts);
    merged.domain_admin_achieved = merged.domain_admin_achieved || additional.domain_admin_achieved;

    // Extend scope
    for domain in &additional.scope.domains {
        if !merged.scope.domains.contains(domain) {
            merged.scope.domains.push(domain.clone());
        }
    }

    // Update timeline
    if additional.started_at < merged.started_at {
        merged.started_at = additional.started_at;
    }
    if let Some(other_end) = additional.finished_at {
        match merged.finished_at {
            Some(our_end) if other_end > our_end => merged.finished_at = Some(other_end),
            None => merged.finished_at = Some(other_end),
            _ => {}
        }
    }

    // Bump version
    merged.version = format!("{}-merged", merged.version.trim_end_matches("-merged"));

    info!(
        "  {} Merged sessions: {} findings total",
        "✓".green(),
        merged.findings.len()
    );

    merged
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{
        EngagementScope, EngagementSession, EngagementType, Finding, FindingCategory, Severity,
    };
    use chrono::Utc;

    fn mock_session() -> EngagementSession {
        let mut session = EngagementSession::new(
            "Test AD Assessment",
            "TestCorp",
            "TestOp",
            "Overthrone Labs",
        );
        session.engagement_type = EngagementType::AdAssessment;
        session.scope = EngagementScope {
            domains: vec!["test.local".to_string()],
            ip_ranges: vec!["10.0.0.0/24".to_string()],
            excluded_hosts: vec![],
            rules_of_engagement: vec!["Authorized testing".to_string()],
            objectives: vec!["Find path to DA".to_string()],
        };

        // Add a test finding
        session.findings.push(Finding {
            id: "OT-TEST-001".to_string(),
            title: "Test Kerberoast Finding".to_string(),
            severity: Severity::High,
            cvss_score: 7.5,
            cvss_vector: None,
            category: FindingCategory::KerberosAbuse,
            description: "Test description".to_string(),
            affected_assets: vec!["svc_sql@test.local".to_string()],
            proof_of_concept: vec!["Step 1".to_string(), "Step 2".to_string()],
            evidence: vec![],
            mitre: crate::mapper::map_technique("kerberoast"),
            mitigations: crate::mitigations::get_mitigations("kerberoast"),
            business_impact: "Test impact".to_string(),
            references: vec![],
            discovered_at: Utc::now(),
        });

        session.domain_admin_achieved = true;
        session.total_credentials_compromised = 3;
        session.total_admin_hosts = 2;
        session
    }

    #[test]
    fn test_markdown_render_not_empty() {
        let session = mock_session();
        let md = crate::markdown::render(&session);
        assert!(!md.is_empty());
        assert!(md.contains("Test AD Assessment"));
        assert!(md.contains("Test Kerberoast Finding"));
        assert!(md.contains("MITRE ATT&CK"));
        assert!(md.contains("Remediation Roadmap"));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Informational);
    }

    #[test]
    fn test_session_overall_risk() {
        let session = mock_session();
        // Has a High finding → should be High
        assert!(session.overall_risk() >= Severity::High);
    }

    #[test]
    fn test_severity_counts() {
        let session = mock_session();
        let counts = session.severity_counts();
        assert_eq!(counts.get(&Severity::High).copied().unwrap_or(0), 1);
    }

    #[test]
    fn test_config_builder() {
        let config = ReportConfig::default()
            .format(ReportFormat::All)
            .client("BigBank")
            .assessor("Hacker", "Red Team Inc")
            .redact(true)
            .with_raw_data(false);

        assert_eq!(config.format, ReportFormat::All);
        assert_eq!(config.client_name, "BigBank");
        assert_eq!(config.assessor_name, "Hacker");
        assert_eq!(config.assessor_company, "Red Team Inc");
        assert!(config.redact_credentials);
        assert!(!config.include_raw_data);
    }

    #[test]
    fn test_filename_from_domain() {
        let config = ReportConfig::default().filename_from_domain("corp.local");
        assert!(config.filename_base.contains("corp_local"));
    }

    #[test]
    fn test_merge_sessions() {
        let s1 = mock_session();
        let mut s2 = mock_session();
        s2.findings[0].title = "Different Finding".to_string();
        s2.total_admin_hosts = 10;

        let merged = merge_sessions(&s1, &s2);
        assert_eq!(merged.findings.len(), 2);
        assert_eq!(merged.total_admin_hosts, 10);
        assert!(merged.version.contains("merged"));
    }

    #[test]
    fn test_mitre_mapping() {
        let mappings = crate::mapper::map_technique("kerberoast");
        assert!(!mappings.is_empty());
        assert!(mappings.iter().any(|m| m.technique_id == "T1558"));
    }

    #[test]
    fn test_mitigations() {
        let mits = crate::mitigations::get_mitigations("kerberoast");
        assert!(!mits.is_empty());
        assert!(mits.iter().any(|m| m.title.contains("gMSA")));
    }

    #[tokio::test]
    async fn test_json_roundtrip() {
        let session = mock_session();
        let json = serde_json::to_string_pretty(&session).unwrap();
        let loaded: EngagementSession = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.title, session.title);
        assert_eq!(loaded.findings.len(), session.findings.len());
    }

    #[test]
    fn test_narrative_executive_summary() {
        let session = mock_session();
        let summary = crate::narrative::executive_summary(&session);
        assert!(summary.contains("Overthrone Labs"));
        assert!(summary.contains("Domain Admin"));
        assert!(summary.contains("Critical") || summary.contains("High"));
    }

    #[test]
    fn test_pdf_render_produces_bytes() {
        let session = mock_session();
        let bytes = crate::pdf::render(&session);
        // PDF magic bytes: %PDF
        assert!(bytes.len() > 100);
        assert_eq!(&bytes[0..5], b"%PDF-");
    }

    #[test]
    fn test_report_output_display() {
        let output = ReportOutput {
            files: vec![PathBuf::from("test.md"), PathBuf::from("test.pdf")],
            finding_count: 5,
            generated_at: Utc::now(),
            overall_risk: "HIGH".to_string(),
            domain_admin_achieved: true,
        };
        let display = format!("{}", output);
        assert!(display.contains("OVERTHRONE SCRIBE"));
        assert!(display.contains("test.md"));
        assert!(display.contains("test.pdf"));
    }
}
