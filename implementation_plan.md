# Implementation Plan: Complete Stub Features

## Overview
This plan details the implementation of four partially-complete or stub features in Overthrone: NTLM Relay, ADCS Abuse, SCCM Abuse, and MSSQL backend. These features currently have CLI wiring but lack real protocol implementations.

## Types

### NTLM Relay Types (crates/overthrone-relay/src/relay.rs)
```rust
/// Active relay session tracking
pub struct RelaySession {
    pub id: u32,
    pub source_client: SocketAddr,
    pub target: RelayTarget,
    pub protocol: Protocol,
    pub ntlm_negotiate: Vec<u8>,
    pub ntlm_challenge: Vec<u8>,
    pub authenticated: bool,
    pub username: Option<String>,
    pub domain: Option<String>,
}

/// Protocol-specific relay handlers
pub trait ProtocolRelay: Send + Sync {
    async fn handle_negotiate(&mut self, negotiate: &[u8]) -> Result<Vec<u8>>;
    async fn handle_authenticate(&mut self, auth: &[u8]) -> Result<RelayResult>;
    fn protocol(&self) -> Protocol;
}

/// Result of a successful relay
pub struct RelayResult {
    pub success: bool,
    pub username: String,
    pub domain: String,
    pub executed_command: Option<String>,
    pub output: Option<String>,
}
```

### ADCS Types (crates/overthrone-core/src/adcs/mod.rs)
```rust
/// Real certificate request with crypto
pub struct CertificateRequestBuilder {
    subject: String,
    san: Option<String>,
    key_usage: Vec<KeyUsage>,
    extended_key_usage: Vec<String>,
    private_key: Option<RsaPrivateKey>,
}

/// PKCS#10 CSR structure
pub struct Pkcs10Csr {
    version: u8,
    subject: String,
    subject_public_key_info: SubjectPublicKeyInfo,
    attributes: Vec<CsrAttribute>,
    signature: Vec<u8>,
}

/// Certificate response from CA
pub struct CertificateResponse {
    pub certificate: Vec<u8>,  // DER-encoded X.509
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub pfx_data: Vec<u8>,
    pub thumbprint: String,
}
```

### SCCM Types (crates/overthrone-core/src/sccm/mod.rs - NEW FILE)
```rust
/// SCCM site configuration
pub struct SccmSite {
    pub site_code: String,
    pub site_server: String,
    pub management_point: String,
    pub distribution_points: Vec<String>,
}

/// SCCM collection
pub struct SccmCollection {
    pub collection_id: String,
    pub name: String,
    pub member_count: u32,
    pub collection_type: CollectionType,
}

/// SCCM application
pub struct SccmApplication {
    pub app_id: String,
    pub name: String,
    pub deployment_types: Vec<DeploymentType>,
}

/// SCCM abuse result
pub struct SccmAbuseResult {
    pub success: bool,
    pub technique: SccmTechnique,
    pub affected_systems: Vec<String>,
    pub command_output: Option<String>,
}
```

### MSSQL Types (crates/overthrone-core/src/mssql/mod.rs - NEW FILE)
```rust
/// MSSQL connection configuration
pub struct MssqlConfig {
    pub server: String,
    pub port: u16,
    pub database: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub trust_cert: bool,
}

/// MSSQL connection
pub struct MssqlConnection {
    stream: TcpStream,
    config: MssqlConfig,
    logged_in: bool,
}

/// Query result
pub struct MssqlQueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Option<String>>>,
    pub rows_affected: u64,
}

/// Linked server info
pub struct LinkedServer {
    pub name: String,
    pub data_source: String,
    pub provider: String,
    pub catalog: Option<String>,
}
```

## Files

### Files to Modify

| File Path | Changes |
|-----------|---------|
| `crates/overthrone-relay/src/relay.rs` | Complete rewrite with real relay logic |
| `crates/overthrone-relay/src/lib.rs` | Add new types and exports |
| `crates/overthrone-core/src/adcs/mod.rs` | Replace stubs with real implementations |
| `crates/overthrone-cli/src/main.rs` | Update MSSQL command handling |

### Files to Create

| File Path | Purpose |
|-----------|---------|
| `crates/overthrone-relay/src/smb_relay.rs` | SMB-specific relay handler |
| `crates/overthrone-relay/src/http_relay.rs` | HTTP/HTTPS relay handler |
| `crates/overthrone-relay/src/ldap_relay.rs` | LDAP relay handler |
| `crates/overthrone-core/src/adcs/csr.rs` | PKCS#10 CSR generation |
| `crates/overthrone-core/src/adcs/web_enrollment.rs` | ADCS Web Enrollment client |
| `crates/overthrone-core/src/sccm/mod.rs` | SCCM client implementation |
| `crates/overthrone-core/src/sccm/wmi.rs` | WMI queries for SCCM |
| `crates/overthrone-core/src/sccm/abuse.rs` | SCCM abuse techniques |
| `crates/overthrone-core/src/mssql/mod.rs` | MSSQL protocol client |
| `crates/overthrone-core/src/mssql/tds.rs` | TDS protocol implementation |
| `crates/overthrone-core/src/mssql/auth.rs` | MSSQL authentication |

## Functions

### NTLM Relay Functions (relay.rs)

#### New Functions
| Function | Signature | Purpose |
|----------|-----------|---------|
| `start_relay_server` | `async fn start_relay_server(config: RelayConfig) -> Result<RelayController>` | Start the relay listener |
| `handle_client_connection` | `async fn handle_client_connection(client: TcpStream, target: RelayTarget) -> Result<RelayResult>` | Handle incoming connection |
| `relay_smb_auth` | `async fn relay_smb_auth(negotiate: &[u8], target: &str) -> Result<(Vec<u8>, TcpStream)>` | Relay SMB auth |
| `relay_http_auth` | `async fn relay_http_auth(negotiate: &[u8], target: &str) -> Result<(Vec<u8>, TcpStream)>` | Relay HTTP auth |
| `relay_ldap_auth` | `async fn relay_ldap_auth(negotiate: &[u8], target: &str) -> Result<(Vec<u8>, TcpStream)>` | Relay LDAP auth |
| `execute_smb_command` | `async fn execute_smb_command(stream: &mut TcpStream, command: &str) -> Result<String>` | Execute command via SMB |
| `execute_http_command` | `async fn execute_http_command(stream: &mut TcpStream, command: &str) -> Result<String>` | Execute command via HTTP |

#### Modified Functions
| Function | Current State | Required Changes |
|----------|---------------|------------------|
| `NtlmRelay::start` | Sets `running = true`, no actual listening | Implement actual TCP listener with target connections |
| `NtlmRelay::relay_smb` | Logs message, returns Ok | Implement full SMB relay with NTLM message forwarding |
| `NtlmRelay::relay_http` | Logs message, returns Ok | Implement HTTP NTLM relay |

### ADCS Functions (adcs/mod.rs)

#### New Functions
| Function | Signature | Purpose |
|----------|-----------|---------|
| `generate_rsa_keypair` | `fn generate_rsa_keypair(bits: u32) -> Result<(RsaPrivateKey, RsaPublicKey)>` | Generate RSA key pair |
| `build_pkcs10_csr` | `fn build_pkcs10_csr(subject: &str, san: Option<&str>, private_key: &RsaPrivateKey) -> Result<Vec<u8>>` | Build CSR |
| `sign_csr` | `fn sign_csr(csr: &mut Pkcs10Csr, private_key: &RsaPrivateKey) -> Result<()>` | Sign CSR |
| `submit_csr_web_enrollment` | `async fn submit_csr_web_enrollment(ca: &str, template: &str, csr: &[u8]) -> Result<CertificateResponse>` | Submit to CA |
| `parse_certificate_response` | `fn parse_certificate_response(html: &str) -> Result<Vec<u8>>` | Parse CA response |
| `create_pfx` | `fn create_pfx(cert: &[u8], key: &RsaPrivateKey, password: &str) -> Result<Vec<u8>>` | Create PFX file |

#### Modified Functions
| Function | Current State | Required Changes |
|----------|---------------|------------------|
| `enumerate_templates` | Returns mock data | Query LDAP for real templates |
| `request_certificate_esc1` | Returns mock cert | Real CSR generation + Web Enrollment submission |
| `request_certificate_esc6` | Returns mock cert | Real SAN attribute injection |
| `esc8_web_enrollment_relay` | Simulates relay | Real NTLM relay to Web Enrollment |

### SCCM Functions (sccm/mod.rs - NEW FILE)

| Function | Signature | Purpose |
|----------|-----------|---------|
| `connect` | `async fn connect(site_server: &str) -> Result<SccmClient>` | Connect to SCCM |
| `enumerate_sites` | `async fn enumerate_sites(&self) -> Result<Vec<SccmSite>>` | List sites |
| `enumerate_collections` | `async fn enumerate_collections(&self) -> Result<Vec<SccmCollection>>` | List collections |
| `enumerate_applications` | `async fn enumerate_applications(&self) -> Result<Vec<SccmApplication>>` | List applications |
| `abuse_client_push` | `async fn abuse_client_push(&self, target: &str) -> Result<SccmAbuseResult>` | Client push abuse |
| `abuse_application_deploy` | `async fn abuse_application_deploy(&self, collection: &str, payload: &str) -> Result<SccmAbuseResult>` | App deployment abuse |
| `check_vulnerable_settings` | `async fn check_vulnerable_settings(&self) -> Result<Vec<String>>` | Find vulnerabilities |

### MSSQL Functions (mssql/mod.rs - NEW FILE)

| Function | Signature | Purpose |
|----------|-----------|---------|
| `MssqlConnection::connect` | `async fn connect(config: MssqlConfig) -> Result<Self>` | Connect to MSSQL |
| `MssqlConnection::login` | `async fn login(&mut self) -> Result<()>` | TDS login |
| `MssqlConnection::query` | `async fn query(&mut self, sql: &str) -> Result<MssqlQueryResult>` | Execute query |
| `MssqlConnection::execute` | `async fn execute(&mut self, sql: &str) -> Result<u64>` | Execute statement |
| `enable_xp_cmdshell` | `async fn enable_xp_cmdshell(&mut self) -> Result<()>` | Enable xp_cmdshell |
| `execute_xp_cmdshell` | `async fn execute_xp_cmdshell(&mut self, cmd: &str) -> Result<String>` | Run command |
| `enumerate_linked_servers` | `async fn enumerate_linked_servers(&mut self) -> Result<Vec<LinkedServer>>` | List linked servers |
| `execute_on_linked_server` | `async fn execute_on_linked_server(&mut self, server: &str, query: &str) -> Result<MssqlQueryResult>` | Query linked server |

## Classes

### New Classes

| Class | File | Key Methods |
|-------|------|-------------|
| `SmbRelayHandler` | `overthrone-relay/src/smb_relay.rs` | `new()`, `handle_negotiate()`, `handle_authenticate()`, `execute_command()` |
| `HttpRelayHandler` | `overthrone-relay/src/http_relay.rs` | `new()`, `handle_negotiate()`, `handle_authenticate()`, `execute_command()` |
| `LdapRelayHandler` | `overthrone-relay/src/ldap_relay.rs` | `new()`, `handle_negotiate()`, `handle_authenticate()`, `create_user()` |
| `CsrBuilder` | `overthrone-core/src/adcs/csr.rs` | `new()`, `subject()`, `san()`, `key_usage()`, `build()`, `sign()` |
| `WebEnrollmentClient` | `overthrone-core/src/adcs/web_enrollment.rs` | `new()`, `submit_request()`, `retrieve_certificate()` |
| `SccmClient` | `overthrone-core/src/sccm/mod.rs` | `new()`, `connect()`, `enumerate_sites()`, `abuse_client_push()` |
| `MssqlClient` | `overthrone-core/src/mssql/mod.rs` | `new()`, `connect()`, `query()`, `execute_xp_cmdshell()` |
| `TdsProtocol` | `overthrone-core/src/mssql/tds.rs` | `new()`, `send_prelogin()`, `send_login()`, `send_query()` |

### Modified Classes

| Class | File | Changes |
|-------|------|---------|
| `NtlmRelay` | `overthrone-relay/src/relay.rs` | Add actual relay logic, session management, concurrent connections |
| `AdcsClient` | `overthrone-core/src/adcs/mod.rs` | Replace mock methods with real implementations |

## Dependencies

### New Dependencies (Cargo.toml)

```toml
# For ADCS - RSA key generation and X.509 certificates
rsa = "0.9"
x509-parser = "0.15"
pkcs8 = "0.10"
pkcs12 = "0.1"

# For MSSQL - TDS protocol
tokio-util = { version = "0.7", features = ["codec"] }
byteorder = "1.5"

# For SCCM - WMI (Windows only)
[target.'cfg(windows)'.dependencies]
wmi = "0.13"
windows = { version = "0.52", features = ["Win32_System_Wmi"] }

# For NTLM crypto
hmac = "0.12"
sha2 = "0.10"
```

## Testing

### Test Files Required

| Test File | What It Tests |
|-----------|---------------|
| `tests/unit/relay_test.rs` | NTLM relay message handling |
| `tests/unit/adcs_csr_test.rs` | CSR generation, signing |
| `tests/unit/mssql_tds_test.rs` | TDS protocol parsing |
| `tests/unit/sccm_test.rs` | SCCM client logic |
| `tests/integration/relay_integration_test.rs` | Full relay chain |
| `tests/integration/adcs_integration_test.rs` | Certificate enrollment |

### Testing Approach

1. **Unit Tests**: Test individual functions with mock data
   - CSR generation and signing
   - TDS message parsing
   - NTLM message construction
   - Relay state machine transitions

2. **Integration Tests**: Test against real services in lab
   - Relay to real SMB server
   - Certificate enrollment to ADCS
   - MSSQL queries to SQL Server
   - SCCM WMI queries

## Implementation Order

### Phase 1: Core Protocol Implementations
1. Create `crates/overthrone-core/src/mssql/mod.rs` - MSSQL client with TDS protocol
2. Create `crates/overthrone-core/src/mssql/tds.rs` - TDS protocol messages
3. Create `crates/overthrone-core/src/mssql/auth.rs` - MSSQL authentication
4. Add RSA/x509 dependencies to Cargo.toml
5. Create `crates/overthrone-core/src/adcs/csr.rs` - CSR generation with real crypto
6. Create `crates/overthrone-core/src/adcs/web_enrollment.rs` - Web Enrollment client

### Phase 2: Relay Implementation
7. Create `crates/overthrone-relay/src/smb_relay.rs` - SMB relay handler
8. Create `crates/overthrone-relay/src/http_relay.rs` - HTTP relay handler
9. Create `crates/overthrone-relay/src/ldap_relay.rs` - LDAP relay handler
10. Rewrite `crates/overthrone-relay/src/relay.rs` - Main relay controller
11. Update `crates/overthrone-relay/src/lib.rs` - Export new types

### Phase 3: ADCS Full Implementation
12. Update `enumerate_templates` in `adcs/mod.rs` - Real LDAP query
13. Update `request_certificate_esc1` in `adcs/mod.rs` - Real implementation
14. Update `request_certificate_esc6` in `adcs/mod.rs` - Real implementation
15. Update `esc8_web_enrollment_relay` in `adcs/mod.rs` - Real relay

### Phase 4: SCCM Implementation
16. Create `crates/overthrone-core/src/sccm/mod.rs` - Main module
17. Create `crates/overthrone-core/src/sccm/wmi.rs` - WMI queries
18. Create `crates/overthrone-core/src/sccm/abuse.rs` - Abuse techniques
19. Update `crates/overthrone-core/src/adcs/mod.rs` SccmClient - Real implementation

### Phase 5: CLI Integration & Testing
20. Update MSSQL commands in `main.rs` to use new backend
21. Add unit tests for each module
22. Add integration tests
23. Update documentation

## Key Implementation Details

### NTLM Relay Flow
```
Client → [Overthrone Relay] → Target Server
         │
         ├── 1. Receive NTLM Negotiate from Client
         ├── 2. Forward Negotiate to Target
         ├── 3. Receive Challenge from Target
         ├── 4. Forward Challenge to Client
         ├── 5. Receive Authenticate from Client
         ├── 6. Forward Authenticate to Target
         └── 7. Execute command on authenticated session
```

### ADCS ESC1 Flow
```
1. Query LDAP for vulnerable templates
2. Generate RSA 2048-bit key pair
3. Build PKCS#10 CSR with subject + SAN
4. Sign CSR with private key
5. POST to http://CA/certsrv/certfnsh.asp
6. Parse response for certificate
7. Create PFX with cert + private key
```

### MSSQL xp_cmdshell Flow
```
1. Connect via TDS protocol
2. Authenticate (NTLM or SQL auth)
3. Enable advanced options: sp_configure 'show advanced options', 1
4. Enable xp_cmdshell: sp_configure 'xp_cmdshell', 1
5. Execute: xp_cmdshell 'whoami'
6. Parse TDS response for output
```

### SCCM Client Push Abuse
```
1. Query SCCM site via WMI
2. Find computers with client push enabled
3. Trigger client push to attacker-controlled system
4. Intercept NTLM authentication
5. Relay to domain resources