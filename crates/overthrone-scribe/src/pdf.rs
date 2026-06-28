//! PDF report renderer — Produces a styled PDF report using printpdf (0.9).
//!
//! The PDF includes a cover page, table of contents, findings with
//! severity badges, MITRE ATT&CK table, and remediation roadmap.

use crate::narrative;
use crate::session::{EngagementSession, EvidenceType, Finding, Severity};
use anyhow::Context;
use overthrone_pilot::goals::EngagementState;
use printpdf::*;

/// PDF page dimensions (A4)
const PAGE_W: Mm = Mm(210.0);
const PAGE_H: Mm = Mm(297.0);
const MARGIN_LEFT: f32 = 25.0;
const MARGIN_TOP: f32 = 270.0;
const MARGIN_BOTTOM: f32 = 25.0;
const LINE_HEIGHT: f32 = 5.0;

/// Font sizes
const TITLE_SIZE: f32 = 24.0;
const HEADING1_SIZE: f32 = 18.0;
const HEADING2_SIZE: f32 = 14.0;
const BODY_SIZE: f32 = 10.0;
const SMALL_SIZE: f32 = 8.0;

// ═══════════════════════════════════════════════════════════
// PDF Context Helper — accumulates Ops for page-based output
// ═══════════════════════════════════════════════════════════

struct PdfContext {
    /// Completed pages ready to be added to the document
    pages: Vec<PdfPage>,
    /// Current page ops being built
    current_ops: Vec<Op>,
    /// Current Y cursor position (from bottom, in mm)
    current_y: f32,
    /// Current page number
    page_num: usize,
    /// Font ID for regular text
    font_id: FontId,
    /// Font ID for bold text
    font_bold_id: FontId,
    /// Font ID for monospace text
    font_mono_id: FontId,
}

impl PdfContext {
    fn new(font_id: FontId, font_bold_id: FontId, font_mono_id: FontId) -> Self {
        Self {
            pages: Vec::new(),
            current_ops: Vec::new(),
            current_y: MARGIN_TOP,
            page_num: 1,
            font_id,
            font_bold_id,
            font_mono_id,
        }
    }

    /// Finalize the current page and start a new one
    fn new_page(&mut self, _label: &str) {
        // Flush current page if it has content
        if !self.current_ops.is_empty() {
            let page = PdfPage::new(PAGE_W, PAGE_H, self.current_ops.drain(..).collect());
            self.pages.push(page);
        }
        self.page_num += 1;
        self.current_y = MARGIN_TOP;
        self.current_ops.clear();

        // Page number footer
        self.current_ops.push(Op::SetTextCursor {
            pos: Point {
                x: Mm(180.0).into(),
                y: Mm(10.0).into(),
            },
        });
        self.current_ops.push(Op::SetFont {
            font: PdfFontHandle::External(self.font_id.clone()),
            size: Pt(SMALL_SIZE),
        });
        self.current_ops.push(Op::ShowText {
            items: vec![TextItem::Text(format!("Page {}", self.page_num))],
        });
    }

    fn check_page_break(&mut self) {
        if self.current_y < MARGIN_BOTTOM {
            self.new_page("Continued");
        }
    }

    fn write_text_at(&mut self, text: &str, size: f32, x: f32, y: f32, font: &FontId) {
        self.current_ops.push(Op::SetTextCursor {
            pos: Point {
                x: Mm(x).into(),
                y: Mm(y).into(),
            },
        });
        self.current_ops.push(Op::SetFont {
            font: PdfFontHandle::External(font.clone()),
            size: Pt(size),
        });
        self.current_ops.push(Op::ShowText {
            items: vec![TextItem::Text(text.to_string())],
        });
    }

    fn write_heading1(&mut self, text: &str) {
        self.check_page_break();
        let y = self.current_y;
        let font = self.font_bold_id.clone();
        self.write_text_at(text, HEADING1_SIZE, MARGIN_LEFT, y, &font);
        self.current_y -= 10.0;
    }

    fn write_heading2(&mut self, text: &str) {
        self.check_page_break();
        let y = self.current_y;
        let font = self.font_bold_id.clone();
        self.write_text_at(text, HEADING2_SIZE, MARGIN_LEFT, y, &font);
        self.current_y -= 7.0;
    }

    fn write_body(&mut self, text: &str) {
        self.check_page_break();
        let y = self.current_y;
        let font = self.font_id.clone();
        self.write_text_at(text, BODY_SIZE, MARGIN_LEFT, y, &font);
        self.current_y -= LINE_HEIGHT;
    }

    fn write_mono(&mut self, text: &str) {
        self.check_page_break();
        let y = self.current_y;
        let font = self.font_mono_id.clone();
        self.write_text_at(text, SMALL_SIZE, MARGIN_LEFT + 5.0, y, &font);
        self.current_y -= LINE_HEIGHT;
    }

    fn write_colored_line(&mut self, text: &str, color: (f32, f32, f32)) {
        self.check_page_break();
        self.current_ops.push(Op::SetFillColor {
            col: Color::Rgb(Rgb::new(color.0, color.1, color.2, None)),
        });
        let y = self.current_y;
        let font = self.font_bold_id.clone();
        self.write_text_at(text, BODY_SIZE, MARGIN_LEFT, y, &font);
        // Reset to black
        self.current_ops.push(Op::SetFillColor {
            col: Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)),
        });
        self.current_y -= LINE_HEIGHT;
    }

    fn write_body_wrapped(&mut self, text: &str) {
        let max_chars = 90;
        for paragraph in text.split('\n') {
            let words: Vec<&str> = paragraph.split_whitespace().collect();
            let mut line = String::new();
            for word in words {
                if line.len() + word.len() + 1 > max_chars {
                    self.write_body(&line);
                    line.clear();
                }
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(word);
            }
            if !line.is_empty() {
                self.write_body(&line);
            }
        }
    }

    fn skip_lines(&mut self, n: usize) {
        self.current_y -= LINE_HEIGHT * n as f32;
    }

    /// Finalize and return all pages (including the last in-progress one)
    fn finish(mut self) -> Vec<PdfPage> {
        if !self.current_ops.is_empty() {
            let page = PdfPage::new(PAGE_W, PAGE_H, self.current_ops);
            self.pages.push(page);
        }
        self.pages
    }
}

// ═══════════════════════════════════════════════════════════
// Main Render Entry Point
// ═══════════════════════════════════════════════════════════

/// Render a PDF report and return the raw bytes
pub fn render(session: &EngagementSession) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(!session.title.is_empty(), "Session title must not be empty");

    let mut doc = PdfDocument::new(&session.title);

    // Load fonts — use system TTF files for Helvetica-like fonts.
    // Gracefully fall back through font styles, then all paths combined.
    let font_regular = load_builtin_font_regular()
        .or_else(|| {
            tracing::warn!("No regular sans-serif font found, trying bold font");
            load_builtin_font_bold()
        })
        .or_else(|| {
            tracing::warn!("No bold font found, trying monospace font");
            load_builtin_font_mono()
        })
        .or_else(|| {
            tracing::warn!("No preferred font found, scanning all font paths");
            let all_candidates = &[
                "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
                "/usr/share/fonts/TTF/LiberationSans-Regular.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                "/System/Library/Fonts/Helvetica.ttc",
                "/Library/Fonts/Arial.ttf",
                "C:\\Windows\\Fonts\\arial.ttf",
                "C:\\Windows\\Fonts\\calibri.ttf",
                "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
                "/usr/share/fonts/TTF/LiberationSans-Bold.ttf",
                "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                "/Library/Fonts/Arial Bold.ttf",
                "C:\\Windows\\Fonts\\arialbd.ttf",
                "C:\\Windows\\Fonts\\calibrib.ttf",
                "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
                "C:\\Windows\\Fonts\\cour.ttf",
                "C:\\Windows\\Fonts\\consola.ttf",
            ];
            load_font_from_paths(all_candidates)
        })
        .context("Could not find any usable font on this system")?;

    let font_bold = load_builtin_font_bold()
        .or_else(|| {
            tracing::warn!("No bold font found, reusing regular font");
            Some(font_regular.clone())
        })
        .context("Could not load bold font")?;

    let font_mono = load_builtin_font_mono()
        .or_else(|| {
            tracing::warn!("No monospace font found, reusing regular font");
            Some(font_regular.clone())
        })
        .context("Could not load monospace font")?;

    let font_id = doc.add_font(&font_regular);
    let font_bold_id = doc.add_font(&font_bold);
    let font_mono_id = doc.add_font(&font_mono);

    let mut ctx = PdfContext::new(font_id, font_bold_id, font_mono_id);

    // ── Cover Page ──
    render_cover_page(&mut ctx, session);

    // ── Executive Summary ──
    ctx.new_page("Executive Summary");
    ctx.write_heading1("1. Executive Summary");
    let summary = narrative::executive_summary(session);
    ctx.write_body_wrapped(&summary);
    ctx.skip_lines(2);

    // Severity table
    ctx.write_heading2("Findings by Severity");
    let counts = session.severity_counts();
    for sev in &[
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Informational,
    ] {
        let count = counts.get(sev).copied().unwrap_or(0);
        if count > 0 {
            let color = severity_color(*sev);
            ctx.write_colored_line(&format!("  {} — {} finding(s)", sev, count), color);
        }
    }

    // ── Findings ──
    for (i, finding) in session.findings.iter().enumerate() {
        ctx.new_page(&format!("Finding {}", i + 1));
        render_finding_page(&mut ctx, finding, i + 1);
    }

    // ── MITRE ATT&CK ──
    ctx.new_page("MITRE ATT&CK");
    ctx.write_heading1("MITRE ATT&CK Mapping");
    let matrix = crate::mapper::build_attack_matrix(&session.findings);
    for (tactic, techniques) in &matrix {
        ctx.write_heading2(tactic);
        for t in techniques {
            ctx.write_body(&format!("  • {} — {}", t.technique_id, t.technique_name));
        }
        ctx.skip_lines(1);
    }

    // ── Remediation ──
    ctx.new_page("Remediation");
    ctx.write_heading1("Remediation Roadmap");
    let finding_types: Vec<&str> = session
        .findings
        .iter()
        .map(|f| match f.category {
            crate::session::FindingCategory::KerberosAbuse => "kerberoast",
            crate::session::FindingCategory::CredentialExposure => "credential_exposure",
            crate::session::FindingCategory::DelegationAbuse => "unconstrained_delegation",
            crate::session::FindingCategory::LateralMovement => "admin_access",
            crate::session::FindingCategory::PrivilegeEscalation => "domain_compromise",
            _ => "credential_exposure",
        })
        .collect();
    let mitigations = crate::mitigations::aggregate_mitigations(&finding_types);
    for (i, mit) in mitigations.iter().enumerate() {
        ctx.write_heading2(&format!("{}. {}", i + 1, mit.title));
        ctx.write_body(&format!(
            "Priority: {} | Effort: {}",
            mit.priority, mit.effort
        ));
        ctx.write_body_wrapped(&mit.description);
        ctx.skip_lines(1);
    }

    // ── ADRecon Inventory Pages ──
    if let Some(ref state) = session.engagement_state {
        render_pdf_adrecon_inventory(&mut ctx, state);
    }

    // Finalize all pages and save
    let pages = ctx.finish();
    let mut warnings = Vec::new();
    Ok(doc
        .with_pages(pages)
        .save(&PdfSaveOptions::default(), &mut warnings))
}

// ═══════════════════════════════════════════════════════════
// Font Loading Helpers
// ═══════════════════════════════════════════════════════════

/// Attempt to load a regular sans-serif font from common system paths.
/// Returns `None` if no font is found (caller should fall back).
fn load_builtin_font_regular() -> Option<ParsedFont> {
    let candidates = [
        // Linux
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/TTF/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        // macOS
        "/System/Library/Fonts/Helvetica.ttc",
        "/Library/Fonts/Arial.ttf",
        // Windows
        "C:\\Windows\\Fonts\\arial.ttf",
        "C:\\Windows\\Fonts\\calibri.ttf",
    ];
    let font = load_font_from_paths(&candidates);
    if font.is_none() {
        tracing::warn!("Could not load regular sans-serif font from any known path");
    }
    font
}

fn load_builtin_font_bold() -> Option<ParsedFont> {
    let candidates = [
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/usr/share/fonts/TTF/LiberationSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/Library/Fonts/Arial Bold.ttf",
        "C:\\Windows\\Fonts\\arialbd.ttf",
        "C:\\Windows\\Fonts\\calibrib.ttf",
    ];
    let font = load_font_from_paths(&candidates);
    if font.is_none() {
        tracing::warn!("Could not load bold sans-serif font from any known path");
    }
    font
}

fn load_builtin_font_mono() -> Option<ParsedFont> {
    let candidates = [
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/TTF/LiberationMono-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/freefont/FreeMono.ttf",
        "/usr/share/fonts/truetype/ubuntu/UbuntuMono-R.ttf",
        "/System/Library/Fonts/Courier.dfont",
        "/Library/Fonts/Courier New.ttf",
        "/System/Library/Fonts/Supplemental/Courier New.ttf",
        "C:\\Windows\\Fonts\\cour.ttf",
        "C:\\Windows\\Fonts\\consola.ttf",
    ];
    let font = load_font_from_paths(&candidates);
    if font.is_none() {
        tracing::warn!("Could not load monospace font from any known path");
    }
    font
}

fn load_font_from_paths(paths: &[&str]) -> Option<ParsedFont> {
    let mut warnings = Vec::new();
    for path in paths {
        if let Ok(bytes) = std::fs::read(path)
            && let Some(font) = ParsedFont::from_bytes(&bytes, 0, &mut warnings)
        {
            return Some(font);
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════
// Page Renderers
// ═══════════════════════════════════════════════════════════

fn render_cover_page(ctx: &mut PdfContext, session: &EngagementSession) {
    // Title
    let font = ctx.font_bold_id.clone();
    ctx.write_text_at(&session.title, TITLE_SIZE, 30.0, 200.0, &font);

    // Metadata
    let lines = [
        format!("Client: {}", session.client_name),
        format!(
            "Assessor: {} ({})",
            session.assessor_name, session.assessor_company
        ),
        format!("Type: {}", session.engagement_type),
        format!(
            "Period: {} — {}",
            session.started_at.format("%Y-%m-%d"),
            session
                .finished_at
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or("Ongoing".to_string())
        ),
        format!("Classification: {}", session.classification),
        format!("Overall Risk: {}", session.overall_risk()),
    ];

    let font_regular = ctx.font_id.clone();
    let mut y = 170.0;
    for line in &lines {
        ctx.write_text_at(line, BODY_SIZE, 30.0, y, &font_regular);
        y -= 6.0;
    }
}

fn render_finding_page(ctx: &mut PdfContext, finding: &Finding, num: usize) {
    ctx.write_heading1(&format!("Finding {} — {}", num, finding.title));
    ctx.skip_lines(1);
    ctx.write_body(&format!(
        "ID: {} | Severity: {} | CVSS: {:.1}",
        finding.id, finding.severity, finding.cvss_score
    ));
    ctx.write_body(&format!("Category: {}", finding.category));
    if let Some(ref vector) = finding.cvss_vector {
        ctx.write_body(&format!("Vector: {}", vector));
    }
    ctx.skip_lines(1);

    ctx.write_heading2("Description");
    ctx.write_body_wrapped(&finding.description);
    ctx.skip_lines(1);

    if !finding.affected_assets.is_empty() {
        ctx.write_heading2("Affected Assets");
        for asset in &finding.affected_assets {
            ctx.write_body(&format!("  • {}", asset));
        }
        ctx.skip_lines(1);
    }

    if !finding.proof_of_concept.is_empty() {
        ctx.write_heading2("Proof of Concept");
        for (i, step) in finding.proof_of_concept.iter().enumerate() {
            ctx.write_body(&format!("  {}. {}", i + 1, step));
        }
        ctx.skip_lines(1);
    }

    // Evidence (redacted for credentials, truncated for long content)
    if !finding.evidence.is_empty() {
        ctx.write_heading2("Evidence");
        for ev in &finding.evidence {
            ctx.write_body(&format!("{} ({:?})", ev.label, ev.content_type));
            let display = if ev.content_type == EvidenceType::Credential {
                "[REDACTED — see secure appendix]".to_string()
            } else if ev.content.len() > 500 {
                format!(
                    "{}…\n(truncated — {} total characters)",
                    &ev.content[..500],
                    ev.content.len()
                )
            } else {
                ev.content.clone()
            };
            for line in display.lines() {
                ctx.write_mono(line);
            }
            ctx.skip_lines(1);
        }
    }

    // MITRE ATT&CK
    if !finding.mitre.is_empty() {
        ctx.write_heading2("MITRE ATT&CK");
        for m in &finding.mitre {
            ctx.write_body(&format!(
                "  • {} — {} ({})",
                m.technique_id, m.technique_name, m.tactic
            ));
        }
        ctx.skip_lines(1);
    }

    // Recommendations with full details
    if !finding.mitigations.is_empty() {
        ctx.write_heading2("Recommendations");
        for mit in &finding.mitigations {
            ctx.write_body(&format!(
                "  • {} [{}] [Effort: {}]",
                mit.title, mit.priority, mit.effort
            ));
            ctx.write_body_wrapped(&format!("    {}", mit.description));
            ctx.skip_lines(1);
        }
    }

    // References
    if !finding.references.is_empty() {
        ctx.write_heading2("References");
        for r in &finding.references {
            ctx.write_body(&format!("  • {}", r));
        }
    }
}

// ═══════════════════════════════════════════════════════════
// ADRecon-Style PDF Inventory Pages
// ═══════════════════════════════════════════════════════════

fn render_pdf_adrecon_inventory(ctx: &mut PdfContext, state: &EngagementState) {
    // Section 9: Domain Inventory
    ctx.new_page("Domain Inventory");
    render_pdf_user_inventory(ctx, state);
    ctx.new_page("Computers & Groups");
    render_pdf_computer_inventory(ctx, state);
    render_pdf_group_inventory(ctx, state);

    // Section 10: Service & Delegation Inventory
    ctx.new_page("Service & Delegation");
    render_pdf_spn_inventory(ctx, state);
    ctx.new_page("Trusts & Delegation");
    render_pdf_trust_inventory(ctx, state);
    render_pdf_delegation_inventory(ctx, state);

    // Section 11: Configuration Audit
    ctx.new_page("Configuration Audit");
    render_pdf_password_policy(ctx, state);
    ctx.new_page("GPOs & LAPS");
    render_pdf_gpo_inventory(ctx, state);
    render_pdf_laps_inventory(ctx, state);
}

fn render_pdf_user_inventory(ctx: &mut PdfContext, state: &EngagementState) {
    ctx.write_heading1("9. Domain Inventory");
    ctx.write_heading2(&format!("User Inventory ({} total)", state.users.len()));
    ctx.skip_lines(1);

    if state.users.is_empty() {
        ctx.write_body("No users discovered.");
        return;
    }

    let max_users = state.users.len().min(50);
    for user in state.users.iter().take(max_users) {
        let upn = user.user_principal_name.as_deref().unwrap_or("-");
        let flags = format!(
            "{}{}{}{}",
            if user.enabled { "E" } else { "D" },
            if user.admin_count { "A" } else { "" },
            if user.has_spn { "S" } else { "" },
            if user.dont_req_preauth { "P" } else { "" },
        );
        ctx.write_body(&format!(
            "  {} ({}) [{}]",
            user.sam_account_name, upn, flags
        ));
    }
    if state.users.len() > 50 {
        ctx.write_body(&format!("... and {} more users", state.users.len() - 50));
    }
    ctx.skip_lines(1);

    let enabled = state.users.iter().filter(|u| u.enabled).count();
    let admins = state.users.iter().filter(|u| u.admin_count).count();
    let spns = state.users.iter().filter(|u| u.has_spn).count();
    let no_preauth = state.users.iter().filter(|u| u.dont_req_preauth).count();
    ctx.write_body(&format!(
        "Enabled: {} | Disabled: {} | Admins: {} | SPNs: {} | No-PreAuth: {}",
        enabled,
        state.users.len() - enabled,
        admins,
        spns,
        no_preauth,
    ));
}

fn render_pdf_computer_inventory(ctx: &mut PdfContext, state: &EngagementState) {
    ctx.write_heading2(&format!(
        "Computer Inventory ({} total)",
        state.computers.len()
    ));

    if state.computers.is_empty() {
        ctx.write_body("No computers discovered.");
        return;
    }

    let max_computers = state.computers.len().min(50);
    for comp in state.computers.iter().take(max_computers) {
        let dns = comp.dns_hostname.as_deref().unwrap_or("-");
        let os = comp.operating_system.as_deref().unwrap_or("Unknown");
        let flags = format!(
            "{}{}",
            if comp.is_dc { "DC " } else { "" },
            if comp.unconstrained_delegation {
                "UCD "
            } else {
                ""
            },
        );
        ctx.write_body(&format!(
            "  {} ({}) [{}] - {}",
            comp.sam_account_name, dns, flags, os
        ));
    }
    if state.computers.len() > 50 {
        ctx.write_body(&format!(
            "... and {} more computers",
            state.computers.len() - 50
        ));
    }
}

fn render_pdf_group_inventory(ctx: &mut PdfContext, state: &EngagementState) {
    ctx.write_heading2(&format!("Group Membership ({} groups)", state.groups.len()));

    if state.groups.is_empty() {
        ctx.write_body("No groups discovered.");
        return;
    }

    let mut groups: Vec<(&String, &Vec<String>)> = state.groups.iter().collect();
    groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    for (group, members) in groups.iter().take(20) {
        ctx.write_body(&format!("  {} ({} members)", group, members.len()));
    }
}

fn render_pdf_spn_inventory(ctx: &mut PdfContext, state: &EngagementState) {
    ctx.write_heading1("10. Service & Delegation Inventory");
    ctx.write_heading2(&format!(
        "Service Principal Names ({} accounts)",
        state.spn_map.len()
    ));

    if state.spn_map.is_empty() {
        ctx.write_body("No SPNs discovered.");
        return;
    }

    let mut spns: Vec<(&String, &Vec<String>)> = state.spn_map.iter().collect();
    spns.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    for (account, spn_list) in spns.iter().take(30) {
        ctx.write_body(&format!("  {}: {}", account, spn_list.join(", ")));
    }
    if spns.len() > 30 {
        ctx.write_body(&format!("... and {} more", spns.len() - 30));
    }
}

fn render_pdf_trust_inventory(ctx: &mut PdfContext, state: &EngagementState) {
    ctx.write_heading2(&format!(
        "Trust Relationships ({} trusts)",
        state.trusts.len()
    ));

    if state.trusts.is_empty() {
        ctx.write_body("No domain trusts discovered.");
        return;
    }

    for trust in &state.trusts {
        ctx.write_body(&format!("  - {}", trust));
    }
}

fn render_pdf_delegation_inventory(ctx: &mut PdfContext, state: &EngagementState) {
    let has_uncon = !state.unconstrained_delegation.is_empty();
    let has_con = !state.constrained_delegation.is_empty();
    let has_rbcd = !state.rbcd_targets.is_empty();

    if !has_uncon && !has_con && !has_rbcd {
        ctx.write_body("No delegation configurations found.");
        return;
    }

    if has_uncon {
        ctx.write_heading2(&format!(
            "Unconstrained Delegation ({} hosts)",
            state.unconstrained_delegation.len()
        ));
        for host in &state.unconstrained_delegation {
            ctx.write_body(&format!("  - {}", host));
        }
        ctx.skip_lines(1);
    }

    if has_con {
        ctx.write_heading2(&format!(
            "Constrained Delegation ({} accounts)",
            state.constrained_delegation.len()
        ));
        for d in &state.constrained_delegation {
            ctx.write_body(&format!(
                "  {} -> {} [{}]",
                d.account,
                d.targets.join(", "),
                d.delegation_type
            ));
        }
        ctx.skip_lines(1);
    }

    if has_rbcd {
        ctx.write_heading2(&format!(
            "Resource-Based Constrained Delegation ({} targets)",
            state.rbcd_targets.len()
        ));
        for target in &state.rbcd_targets {
            ctx.write_body(&format!("  - {}", target));
        }
    }
}

fn render_pdf_password_policy(ctx: &mut PdfContext, state: &EngagementState) {
    ctx.write_heading1("11. Configuration Audit");

    match &state.password_policy {
        Some(policy) => {
            ctx.write_heading2("Password Policy");
            if let Some(v) = policy.min_password_length {
                ctx.write_body(&format!("  Min Password Length: {}", v));
            }
            if let Some(v) = policy.lockout_threshold {
                ctx.write_body(&format!("  Lockout Threshold: {} attempts", v));
            }
            if let Some(ref v) = policy.lockout_duration {
                ctx.write_body(&format!("  Lockout Duration: {}", v));
            }
            if let Some(ref v) = policy.lockout_observation_window {
                ctx.write_body(&format!("  Lockout Window: {}", v));
            }
            if let Some(ref v) = policy.max_password_age {
                ctx.write_body(&format!("  Max Password Age: {}", v));
            }
            if let Some(ref v) = policy.min_password_age {
                ctx.write_body(&format!("  Min Password Age: {}", v));
            }
            if let Some(v) = policy.password_history_length {
                ctx.write_body(&format!("  Password History: {}", v));
            }
            ctx.write_body(&format!(
                "  Complexity: {} | Reversible Encryption: {}",
                if policy.password_complexity_enabled {
                    "Enabled"
                } else {
                    "Disabled"
                },
                if policy.reversible_encryption_enabled {
                    "Enabled"
                } else {
                    "Disabled"
                },
            ));
        }
        None => {
            ctx.write_body("Password policy was not enumerated.");
        }
    }
}

fn render_pdf_gpo_inventory(ctx: &mut PdfContext, state: &EngagementState) {
    if state.gpos.is_empty() && state.gpo_details.is_empty() {
        ctx.write_body("No GPOs discovered.");
        return;
    }

    ctx.write_heading2(&format!(
        "Group Policy Objects ({} total)",
        state.gpos.len()
    ));
    for gpo in &state.gpos {
        ctx.write_body(&format!("  - {}", gpo));
    }
}

fn render_pdf_laps_inventory(ctx: &mut PdfContext, state: &EngagementState) {
    if state.laps.is_empty() {
        ctx.write_body("No LAPS-enabled computers discovered or LAPS not deployed.");
        return;
    }

    ctx.write_heading2(&format!(
        "LAPS Configuration ({} computers)",
        state.laps.len()
    ));
    for laps in &state.laps {
        ctx.write_body(&format!(
            "  {} ({}) - user: {} - pwd: {} - expires: {}",
            laps.computer_name,
            laps.dns_name.as_deref().unwrap_or("-"),
            laps.username,
            if laps.password.is_some() {
                "Available"
            } else {
                "Not readable"
            },
            laps.expiration.as_deref().unwrap_or("N/A"),
        ));
    }
}

fn severity_color(severity: Severity) -> (f32, f32, f32) {
    match severity {
        Severity::Critical => (0.56, 0.27, 0.68),
        Severity::High => (0.91, 0.30, 0.24),
        Severity::Medium => (0.95, 0.61, 0.07),
        Severity::Low => (0.18, 0.80, 0.44),
        Severity::Informational => (0.20, 0.60, 0.86),
    }
}
