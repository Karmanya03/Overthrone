//! Integration tests for the enhanced DNS resolver module.
//!
//! These tests validate offline functionality (struct creation, constants,
//! fallback behaviour). Tests that require a real network are #[ignore]d.

// ═══════════════════════════════════════════════════════════
//  DnsResolver Struct & Constants
// ═══════════════════════════════════════════════════════════

use overthrone_core::proto::dns::{
    DnsResolver, SrvRecord,
    SRV_LDAP_DC, SRV_KERBEROS, SRV_GC, SRV_KPASSWD, SRV_LDAP,
};

#[test]
fn dns_resolver_system_creates_without_panic() {
    let resolver = DnsResolver::system().expect("system resolver should succeed");
    assert!(resolver.nameserver().is_none());
}

#[test]
fn dns_resolver_with_nameserver_stores_ip() {
    let resolver = DnsResolver::with_nameserver("10.0.0.1").expect("custom ns should succeed");
    assert_eq!(resolver.nameserver(), Some("10.0.0.1"));
}

#[test]
fn dns_resolver_rejects_invalid_ip() {
    let result = DnsResolver::with_nameserver("not-an-ip");
    assert!(result.is_err(), "Invalid IP should fail");
}

#[test]
fn srv_prefix_constants_are_well_formed() {
    let prefixes = [SRV_LDAP_DC, SRV_KERBEROS, SRV_GC, SRV_KPASSWD, SRV_LDAP];
    for prefix in &prefixes {
        assert!(prefix.starts_with('_'), "SRV prefix should start with '_': {}", prefix);
        assert!(prefix.contains("._tcp"), "SRV prefix should contain '._tcp': {}", prefix);
    }
}

#[test]
fn srv_ldap_dc_prefix_correct() {
    assert_eq!(SRV_LDAP_DC, "_ldap._tcp.dc._msdcs");
}

#[test]
fn srv_kerberos_prefix_correct() {
    assert_eq!(SRV_KERBEROS, "_kerberos._tcp");
}

#[test]
fn srv_gc_prefix_correct() {
    assert_eq!(SRV_GC, "_gc._tcp");
}

#[test]
fn srv_kpasswd_prefix_correct() {
    assert_eq!(SRV_KPASSWD, "_kpasswd._tcp");
}

#[test]
fn srv_ldap_prefix_correct() {
    assert_eq!(SRV_LDAP, "_ldap._tcp");
}

#[test]
fn srv_record_struct_fields() {
    let rec = SrvRecord {
        hostname: "dc01.contoso.local".to_string(),
        port: 389,
        priority: 0,
        weight: 100,
        ips: vec!["10.0.0.1".to_string()],
    };
    assert_eq!(rec.hostname, "dc01.contoso.local");
    assert_eq!(rec.port, 389);
    assert_eq!(rec.priority, 0);
    assert_eq!(rec.weight, 100);
    assert_eq!(rec.ips, vec!["10.0.0.1".to_string()]);
}

// ═══════════════════════════════════════════════════════════
//  Backward-compatible free functions (require async runtime)
// ═══════════════════════════════════════════════════════════

#[tokio::test]
async fn resolve_hostname_returns_error_for_bogus() {
    let result = overthrone_core::proto::dns::resolve_hostname(
        "this.host.does.not.exist.invalid.tld",
    )
    .await;
    // Should return an error (no DNS resolution for .invalid.tld)
    assert!(result.is_err(), "Bogus hostname should fail to resolve");
}

#[tokio::test]
async fn lookup_srv_returns_error_for_bogus_domain() {
    let resolver = DnsResolver::system().unwrap();
    let query = format!("{}.invalid.notreal.tld", SRV_LDAP_DC);
    let result = resolver.lookup_srv(&query).await;
    assert!(
        result.is_err() || result.as_ref().is_ok_and(|v| v.is_empty()),
        "SRV lookup for bogus domain should fail or return empty"
    );
}

// ═══════════════════════════════════════════════════════════
//  Live Tests (require network / AD environment)
// ═══════════════════════════════════════════════════════════

#[tokio::test]
#[ignore = "requires live AD domain environment"]
async fn live_discover_domain_controllers() {
    let resolver = DnsResolver::system().unwrap();
    let domain = std::env::var("TEST_AD_DOMAIN").expect("TEST_AD_DOMAIN env var required");
    let dcs = resolver.discover_domain_controllers(&domain).await.unwrap();
    assert!(!dcs.is_empty(), "Should discover at least one DC");
    for (hostname, ips) in &dcs {
        assert!(!hostname.is_empty());
        assert!(!ips.is_empty(), "DC should have at least one resolved IP");
    }
}

#[tokio::test]
#[ignore = "requires live AD domain environment"]
async fn live_discover_all_services() {
    let resolver = DnsResolver::system().unwrap();
    let domain = std::env::var("TEST_AD_DOMAIN").expect("TEST_AD_DOMAIN env var required");
    let services = resolver.discover_all_services(&domain).await.unwrap();
    assert!(!services.is_empty(), "Should discover at least one service");
}
