# ADCS Enhancement Plan

## Overview
This plan outlines the steps to complete the remaining Active Directory Certificate Services (ADCS) exploitation capabilities in Overthrone, transitioning them from "detection only" or "stub" to fully functional exploits. 

## Project Type
BACKEND (Rust CLI Tool)

## Success Criteria
- **ESC4 (Template ACLs):** Ability to modify certificate template ACLs via LDAP to make them vulnerable (e.g., adding Enrollee Supplies Subject).
- **ESC5 (CA Config):** Ability to read/write CA registry configuration (e.g., EDITF flags) remotely using RPC/WMI or Remote Registry.
- **ESC7 (CA Permissions):** Ability to modify CA permissions to grant ManageCA/ManageCertificates rights.
- **ESC8 (NTLM Relay):** Functional HTTP listener in `overthrone-relay` that relays NTLM authentication to the AD CS Web Enrollment endpoint.
- **PFX Generation:** Standard-compliant PKCS#12 export with proper MAC calculation, importable by Windows without errors.

## Tech Stack
- **Language:** Rust (Stable)
- **Crates:** `overthrone-core`, `overthrone-cli`, `overthrone-relay`
- **Networking:** LDAP, HTTP, RPC/DCOM
- **Cryptography:** OpenSSL/Ring/Rustls for PKCS#12

## File Structure
- `crates/overthrone-core/src/adcs/esc4.rs`
- `crates/overthrone-core/src/adcs/esc5.rs`
- `crates/overthrone-core/src/adcs/esc7.rs`
- `crates/overthrone-core/src/adcs/pfx.rs` (update)
- `crates/overthrone-relay/src/http_listener.rs`
- `crates/overthrone-relay/src/adcs_relay.rs`

## Task Breakdown

### 1. PFX Export MAC Fix
- **Agent:** `backend-specialist`
- **Skills:** `api-patterns`
- **Priority:** P1
- **Dependencies:** None
- **Task:** Update `pfx.rs` to correctly implement PKCS#12 MAC generation using standard cryptographic libraries instead of the current basic structure.
- **INPUT \u2192 OUTPUT \u2192 VERIFY:** Take raw key/cert \u2192 generate PFX \u2192 verify with `openssl pkcs12 -info -in export.pfx -passin pass:xxx`.

### 2. ESC4 (Template ACL modification) implementation
- **Agent:** `backend-specialist`
- **Skills:** `bash-linux`, `powershell-windows`
- **Priority:** P2
- **Dependencies:** Working LDAP client
- **Task:** Implement LDAP write operations to modify the `ntSecurityDescriptor` and `pKIExtendedKeyUsage` attributes of certificate templates. Include a rollback mechanism to restore original ACLs.
- **INPUT \u2192 OUTPUT \u2192 VERIFY:** Target template \u2192 Modified AD object \u2192 Verify changes using BloodHound/LDAP query.

### 3. ESC7 (CA Permission modification) implementation
- **Agent:** `backend-specialist`
- **Skills:** `powershell-windows`
- **Priority:** P2
- **Dependencies:** RPC/DCOM capabilities
- **Task:** Implement MS-ICPR or RPC calls to modify CA security descriptors natively, or generate the exact DCOM/PowerShell commands required for the operator.
- **INPUT \u2192 OUTPUT \u2192 VERIFY:** Target CA \u2192 Modified permissions \u2192 Verify CA management rights via `certsrv.msc` or RPC query.

### 4. ESC8 (NTLM Relay to ADCS) Integration
- **Agent:** `backend-specialist`
- **Skills:** `api-patterns`
- **Priority:** P1
- **Dependencies:** `overthrone-relay` crate
- **Task:** Flesh out `Esc8RelayTarget` and build an HTTP listener in `overthrone-relay` that extracts NTLM type 1/2/3 messages and relays them to `web_enrollment.rs` endpoints.
- **INPUT \u2192 OUTPUT \u2192 VERIFY:** Incoming HTTP auth \u2192 Relayed auth to /certsrv \u2192 Verify successful certificate enrollment.

## ✅ Phase X: Verification
- [ ] Code compiles without warnings (`cargo check --workspace`).
- [ ] Integration tests pass.
- [ ] Security scan passes (`python .agent/skills/vulnerability-scanner/scripts/security_scan.py .`).
- [ ] Lint runner passes (`python .agent/skills/lint-and-validate/scripts/lint_runner.py .`).
