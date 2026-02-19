# Scribe Module

Reporting. The difference between a pentest and a crime is documentation.

## Purpose

The `overthrone-scribe` crate generates professional reports from engagement data. PDF, HTML, and JSON output formats with executive summaries, technical details, and remediation recommendations.

## Usage

### CLI

```bash
# Generate PDF report
ovt scribe --format pdf -o engagement-report.pdf

# Generate HTML report
ovt scribe --format html -o report.html

# JSON for SIEM integration
ovt scribe --format json -o findings.json

# With executive summary
ovt scribe --format pdf --executive -o report.pdf
```

### Library

```rust
use overthrone_scribe::runner::{ScribeConfig, run_scribe};
use overthrone_scribe::pdf::generate_pdf;
use overthrone_scribe::markdown::generate_markdown;

let config = ScribeConfig {
    format: OutputFormat::Pdf,
    output_path: "report.pdf".to_string(),
    include_executive_summary: true,
    include_mitigations: true,
    template: None,
};

let result = run_scribe(&engagement_data, &config).await?;
```

## Modules

### mapper

Data transformation and mapping.

**What it does:**
- Converts raw enumeration data to report-ready format
- Groups findings by category
- Calculates severity scores
- Maps to MITRE ATT&CK framework

### markdown

Markdown report generation.

**Output:**
- Executive summary
- Scope and methodology
- Findings by severity
- Attack paths
- Remediation recommendations
- Appendix with raw data

### narrative

Natural language narrative generation.

**What it does:**
- Converts technical findings to readable prose
- Generates attack path descriptions
- Creates timeline narratives
- Summarizes impact

**Example output:**
> The initial foothold was achieved through a phishing campaign targeting the Finance department. The compromised account, `jsmith`, had no special privileges but was a member of the `IT-Support` group. This group had `GenericAll` permissions on the service account `svc_backup`, which in turn had local administrator access on the primary domain controller `DC01`. This created a three-hop attack path to Domain Admin.

### mitigations

Remediation recommendations.

**Categories:**
- Immediate actions (stop the bleeding)
- Short-term fixes (days to weeks)
- Long-term improvements (months)

**Format:**
- Finding description
- Risk explanation
- Recommended fix
- Implementation notes
- References

### pdf

PDF report generation.

**Sections:**
1. Title page
2. Executive summary
3. Scope and methodology
4. Summary of findings
5. Detailed findings (by severity)
6. Attack paths
7. Remediation roadmap
8. Appendix

**Features:**
- Customizable templates
- Logo and branding
- Page numbers and TOC
- Severity color coding

### session

Session and engagement tracking.

**Tracked:**
- Start/end timestamps
- Commands executed
- Credentials used
- Hosts accessed
- Files generated

## Report Structure

### Executive Summary

High-level overview for non-technical stakeholders.

**Contents:**
- Engagement overview
- Key findings count by severity
- Business impact summary
- Top recommendations

### Technical Findings

Detailed technical documentation.

**Per finding:**
- Title and severity
- Description
- Affected systems
- Technical details
- Evidence/screenshots
- Remediation steps
- References

### Attack Paths

Visual and textual attack path documentation.

**Format:**
```
jsmith (Domain User)
  → MemberOf: IT-Support
  → GenericAll: svc_backup
  → AdminTo: DC01$
  → DCSync capabilities

Path length: 4 hops
Total cost: 4
Risk: Critical
```

### MITRE ATT&CK Mapping

All findings mapped to ATT&CK techniques.

**Example:**
| Tactic | Technique | Finding |
|--------|-----------|---------|
| Credential Access | T1110.003 | Password spraying |
| Credential Access | T1558.003 | Kerberoasting |
| Lateral Movement | T1021.002 | PsExec usage |
| Persistence | T1098 | DCSync |

## Output Formats

### PDF

Professional formatted document.

**Features:**
- Customizable cover page
- Table of contents
- Page headers/footers
- Severity color coding
- Embedded screenshots

### HTML

Interactive web-based report.

**Features:**
- Collapsible sections
- Interactive attack graphs
- Searchable content
- Print-friendly CSS

### JSON

Machine-readable output.

**Structure:**
```json
{
  "meta": {
    "generated_at": "2026-02-19T23:30:00Z",
    "tool_version": "0.1.1"
  },
  "executive_summary": {...},
  "findings": [...],
  "attack_paths": [...],
  "mitre_mapping": [...]
}
```

## Customization

### Templates

Place custom templates in `~/.overthrone/templates/`:

```
templates/
├── executive.html
├── finding.html
├── cover.pdf
└── style.css
```

### Configuration

```toml
[scribe]
default_format = "pdf"
include_raw_data = true
redact_passwords = true
severity_threshold = "medium"
custom_template = "~/.overthrone/templates/custom"
```

## Severity Levels

| Level | Score Range | Description |
|-------|-------------|-------------|
| Critical | 9-10 | Domain compromise, DA access |
| High | 7-8 | Privilege escalation, credential theft |
| Medium | 4-6 | Information disclosure, misconfigurations |
| Low | 1-3 | Minor issues, best practice gaps |
| Info | 0 | Informational findings |

## Integration

Scribe integrates with:
- **Reaper** - Enumeration data
- **Pilot** - Attack path history
- **Graph** - Attack graph visualization

## OPSEC Notes

- Reports can be configured to redact passwords
- IP addresses can be anonymized
- Sensitive details can be moved to separate appendix
- JSON output can be filtered before sharing