//! Real DC version detection for CVE assessors.
//!
//! Every CVE assessor in this module tree needs to answer one question before it
//! can say anything useful: *which Windows build is the target?* Previously each
//! assessor guessed by opening a TCP port and returning `None`, then treated
//! `None` as "vulnerable" -- which made every reachable host look exploitable.
//!
//! This module replaces that with an actual measurement:
//!
//! * `srvsvc` `NetrServerGetInfo` level 101 gives us `sv101_version_minor`, the
//!   Windows **build** number (e.g. 20348 = Server 2022). That is the same source
//!   `smbclient -L` and NetExec use for their OS string.
//!
//! ## What this can and cannot tell you
//!
//! `sv101_version_minor` is the build **without** the update build revision
//! (UBR). A DC on `26100.4164` and one on `26100.1` both report `26100`. CVE
//! patch levels are expressed against `build.UBR`, so a build number alone
//! cannot prove a host is patched *or* unpatched. Consequently
//! [`BuildVerdict::Unknown`] is a first-class outcome and assessors must not
//! translate it into "vulnerable". Where a real patch decision is needed, the
//! assessor has to fall back to behavioural evidence (did the server reject the
//! operation?) or the operator has to supply the UBR.

use overthrone_core::proto::epm;
use overthrone_core::proto::smb::SmbSession;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Credentials used to authenticate the version probe.
///
/// A null session works against many DCs for SRVSVC, but hardened ones reject
/// it, so callers that already hold credentials should pass them.
#[derive(Debug, Clone)]
pub struct DcCreds<'a> {
    /// Domain FQDN.
    pub domain: &'a str,
    /// Username.
    pub username: &'a str,
    /// Password, or NT hash when `use_hash` is set.
    pub secret: &'a str,
    /// Whether `secret` is an NT hash rather than a password.
    pub use_hash: bool,
}

/// Outcome of a DC build probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcBuildProbe {
    /// Windows build number, when positively determined (e.g. 20348).
    pub build: Option<u32>,
    /// Marketing release name for `build`, when known (e.g. "Windows Server 2022").
    pub release: Option<String>,
    /// Full `major.0.build` string, when known.
    pub version: Option<String>,
    /// How the result was obtained, for the engagement log.
    pub source: String,
}

impl DcBuildProbe {
    /// A probe that could not determine the build. `source` explains why.
    pub fn unknown(source: impl Into<String>) -> Self {
        Self {
            build: None,
            release: None,
            version: None,
            source: source.into(),
        }
    }

    /// Build the probe result from a parsed `SERVER_INFO_101`.
    pub fn from_server_info(info: &epm::SrvsvcServerInfo, source: impl Into<String>) -> Self {
        Self {
            build: Some(info.build()),
            release: Some(epm::windows_server_release(info.build()).to_string()),
            version: Some(info.version_string()),
            source: source.into(),
        }
    }

    /// Whether a build number was positively determined.
    pub fn is_known(&self) -> bool {
        self.build.is_some()
    }

    /// One-line human summary for logs.
    pub fn summary(&self) -> String {
        match (&self.build, &self.release) {
            (Some(b), Some(r)) => format!("{r} (build {b}) via {}", self.source),
            _ => format!("build unknown ({})", self.source),
        }
    }
}

/// What we can legitimately conclude about a CVE from a build number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BuildVerdict {
    /// Positive evidence that the target predates the fix.
    Vulnerable,
    /// Positive evidence that the target includes the fix.
    Patched,
    /// Not enough information to say. **Must not** be reported as vulnerable.
    Unknown,
}

impl std::fmt::Display for BuildVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vulnerable => write!(f, "VULNERABLE"),
            Self::Patched => write!(f, "patched"),
            Self::Unknown => write!(f, "indeterminate"),
        }
    }
}

/// Encode a Windows `build` + update build revision into a single comparable
/// value, matching the `build.UBR` notation used in Microsoft advisories:
/// `encode_build_ubr(26100, 4164) == 261_004_164`.
pub fn encode_build_ubr(build: u32, ubr: u32) -> u32 {
    build.saturating_mul(10_000).saturating_add(ubr.min(9_999))
}

/// Decide a verdict from a build **including UBR**.
///
/// `fixed_at` lists `(family_floor, first_patched)` pairs in `build.UBR` form,
/// newest family first. A value at or above a family's floor but below that
/// family's patch level is vulnerable; at or above the patch level it is
/// patched. A value below every listed floor is older than anything we model and
/// is reported as vulnerable (conservative for an old lab host, and the caller's
/// log makes the assumption visible).
///
/// Passing `None` for `build_with_ubr` yields [`BuildVerdict::Unknown`] -- this
/// is the case that used to be (incorrectly) reported as vulnerable.
pub fn verdict_for_build(build_with_ubr: Option<u32>, fixed_at: &[(u32, u32)]) -> BuildVerdict {
    let Some(b) = build_with_ubr else {
        return BuildVerdict::Unknown;
    };
    for (floor, patched) in fixed_at {
        if b >= *floor {
            return if b < *patched {
                BuildVerdict::Vulnerable
            } else {
                BuildVerdict::Patched
            };
        }
    }
    BuildVerdict::Vulnerable
}

/// Decide a verdict from a bare build number (no UBR available).
///
/// `families` is the list of Windows build numbers the CVE affects (e.g.
/// `[26100, 20348, 17763]`). Semantics:
///
/// * build below every listed family -> older than anything the CVE targets,
///   so conservatively [`BuildVerdict::Vulnerable`];
/// * build equal to a listed family -> the fix for a cumulative-update CVE lives
///   in the UBR, which a build number does not carry, so
///   [`BuildVerdict::Unknown`]. This is the case that must never be reported as
///   vulnerable on build evidence alone;
/// * build above every listed family -> not affected (already newer than the
///   vulnerable generations), [`BuildVerdict::Patched`].
///
/// Note a build is *below* a family when it is numerically smaller, so order the
/// list ascending for readability; the checks are order-independent.
pub fn verdict_from_build_only(build: Option<u32>, families: &[u32]) -> BuildVerdict {
    let Some(b) = build else {
        return BuildVerdict::Unknown;
    };
    if families.contains(&b) {
        return BuildVerdict::Unknown;
    }
    if families.iter().any(|f| b < *f) {
        // Older than at least one affected generation -> in scope for the CVE.
        return BuildVerdict::Vulnerable;
    }
    BuildVerdict::Patched
}

/// Probe the target's Windows build over SMB using SRVSVC `NetrServerGetInfo`.
///
/// Tries the supplied credentials first (hardened DCs refuse anonymous SRVSVC),
/// then a null session. Never returns an error: a failure to determine the build
/// is represented as [`DcBuildProbe::unknown`] so callers can keep the two
/// cases ("patched" vs "don't know") distinct.
pub async fn probe_dc_build(target: &str, creds: Option<DcCreds<'_>>) -> DcBuildProbe {
    if let Some(c) = creds
        && !c.username.is_empty()
    {
        let session = if c.use_hash {
            SmbSession::connect_with_hash(target, c.domain, c.username, c.secret).await
        } else {
            SmbSession::connect(target, c.domain, c.username, c.secret).await
        };
        match session {
            Ok(s) => match epm::net_server_get_info(&s, "").await {
                Ok(info) => {
                    return DcBuildProbe::from_server_info(
                        &info,
                        "srvsvc/NetrServerGetInfo (authenticated)",
                    );
                }
                Err(e) => debug!("dc_version: authenticated SRVSVC probe failed: {e}"),
            },
            Err(e) => debug!("dc_version: authenticated SMB connect failed: {e}"),
        }
    }

    match SmbSession::connect_anonymous(target).await {
        Ok(s) => match epm::net_server_get_info(&s, "").await {
            Ok(info) => {
                DcBuildProbe::from_server_info(&info, "srvsvc/NetrServerGetInfo (null session)")
            }
            Err(e) => {
                debug!("dc_version: null-session SRVSVC probe failed: {e}");
                DcBuildProbe::unknown("SRVSVC NetrServerGetInfo unavailable")
            }
        },
        Err(e) => {
            debug!("dc_version: null-session SMB connect failed: {e}");
            DcBuildProbe::unknown("SMB connection failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(build: u32) -> epm::SrvsvcServerInfo {
        epm::SrvsvcServerInfo {
            platform_id: 500,
            name: Some("DC01".into()),
            version_major: 10,
            version_minor: build,
            server_type: 0x10,
            comment: None,
        }
    }

    #[test]
    fn probe_from_server_info_populates_build_and_release() {
        let p = DcBuildProbe::from_server_info(&info(20348), "test");
        assert_eq!(p.build, Some(20348));
        assert_eq!(p.release.as_deref(), Some("Windows Server 2022"));
        assert_eq!(p.version.as_deref(), Some("10.0.20348"));
        assert!(p.is_known());
        assert!(p.summary().contains("20348"));
    }

    #[test]
    fn unknown_probe_is_explicitly_not_known() {
        let p = DcBuildProbe::unknown("SMB connection failed");
        assert!(!p.is_known());
        assert!(p.build.is_none());
        assert!(p.summary().contains("unknown"));
    }

    #[test]
    fn encode_build_ubr_matches_advisory_notation() {
        assert_eq!(encode_build_ubr(26100, 4164), 261_004_164);
        assert_eq!(encode_build_ubr(20348, 3556), 203_483_556);
        assert_eq!(encode_build_ubr(26100, 0), 261_000_000);
    }

    #[test]
    fn verdict_unknown_when_build_missing() {
        // The regression that caused every reachable host to look vulnerable.
        assert_eq!(
            verdict_for_build(None, &[(261_000_000, 261_004_164)]),
            BuildVerdict::Unknown
        );
    }

    #[test]
    fn verdict_vulnerable_below_patch_level() {
        let fixes = [(261_000_000, 261_004_164), (203_480_000, 203_483_556)];
        assert_eq!(
            verdict_for_build(Some(encode_build_ubr(26100, 1000)), &fixes),
            BuildVerdict::Vulnerable
        );
        assert_eq!(
            verdict_for_build(Some(encode_build_ubr(20348, 3555)), &fixes),
            BuildVerdict::Vulnerable
        );
    }

    #[test]
    fn verdict_patched_at_or_above_patch_level() {
        let fixes = [(261_000_000, 261_004_164), (203_480_000, 203_483_556)];
        assert_eq!(
            verdict_for_build(Some(encode_build_ubr(26100, 4164)), &fixes),
            BuildVerdict::Patched
        );
        assert_eq!(
            verdict_for_build(Some(encode_build_ubr(26100, 9999)), &fixes),
            BuildVerdict::Patched
        );
        assert_eq!(
            verdict_for_build(Some(encode_build_ubr(20348, 3556)), &fixes),
            BuildVerdict::Patched
        );
    }

    #[test]
    fn verdict_older_family_is_conservatively_vulnerable() {
        let fixes = [(261_000_000, 261_004_164)];
        assert_eq!(
            verdict_for_build(Some(encode_build_ubr(17763, 1)), &fixes),
            BuildVerdict::Vulnerable
        );
    }

    #[test]
    fn build_only_verdict_never_claims_vulnerable_for_affected_family() {
        let families = [26100u32, 20348, 17763];
        // Affected generation with UBR unknown -> must be indeterminate.
        assert_eq!(
            verdict_from_build_only(Some(26100), &families),
            BuildVerdict::Unknown
        );
        assert_eq!(
            verdict_from_build_only(Some(20348), &families),
            BuildVerdict::Unknown
        );
        // No build at all -> indeterminate, never vulnerable.
        assert_eq!(
            verdict_from_build_only(None, &families),
            BuildVerdict::Unknown
        );
        // Older generation (Server 2012 R2 = 9600) -> in scope.
        assert_eq!(
            verdict_from_build_only(Some(9600), &families),
            BuildVerdict::Vulnerable
        );
        // Newer than every affected generation -> not affected.
        assert_eq!(
            verdict_from_build_only(Some(30000), &families),
            BuildVerdict::Patched
        );
    }

    #[test]
    fn verdict_display_is_unambiguous() {
        assert_eq!(BuildVerdict::Vulnerable.to_string(), "VULNERABLE");
        assert_eq!(BuildVerdict::Unknown.to_string(), "indeterminate");
    }
}
