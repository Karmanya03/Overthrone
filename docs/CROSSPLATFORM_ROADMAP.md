# Cross-Platform Roadmap

Full functional parity on Linux/macOS, including PsExec, SMBExec, and secretsdump equivalents.

## Completed Implementation

All cross-platform work is **complete**. The following have been implemented:

| Component | Windows | Linux/macOS | Status |
|-----------|---------|-------------|--------|
| **SMB File I/O** | smb crate (SSPI) | pavao (libsmbclient) | Done |
| **SMB Named Pipes** | smb crate | pavao | Done |
| **WinRM** | Win32 WS-Man API | Native WS-Man + ntlmclient | Done |
| **NTLM Auth** | SSPI | ntlmclient | Done |
| **Kerberos** | SSPI | Pure Rust | Done |
| **LDAP** | ldap3 | ldap3 | Done |
| **PsExec** | SMB named pipes | SMB named pipes (pavao) | Done |
| **SMBExec** | SMB named pipes | SMB named pipes (pavao) | Done |
| **WMIExec** | SMB named pipes | SMB named pipes (pavao) | Done |
| **DCSync** | MS-DRSR | MS-DRSR | Done |
| **Coercion** | SMB named pipes | SMB named pipes (pavao) | Done |

## Platform Support Matrix

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| LDAP enumeration | Native | Kerberos auth | SSPI | Pure Rust | Pure Rust |
| Kerberoasting | Yes | Yes | Yes |
| AS-REP roasting | Yes | Yes | Yes |
| SMB file operations | Native (smb) | pavao | pavao |
| SMB named pipes | Native (smb) | pavao | pavao |
| PsExec | Yes | Yes | Yes |
| SMBExec | Yes | Yes | Yes |
| WMIExec | Yes | Yes | Yes |
| WinRM | Win32 API | WS-Man | WS-Man |
| Pass-the-Hash | Yes | Yes | Yes |
| DCSync | Yes | Yes | Yes |
| Golden/Silver tickets | Yes | Yes | Yes |
| Attack graph | Yes | Yes | Yes |
| Autopwn | Yes | Yes | Yes |
| Reporting | Yes | Yes | Yes |

## Dependencies by Platform

### Windows Dependencies

```toml
[target.'cfg(windows)'.dependencies]
smb = "0.11.1"
windows = { version = "0.62", features = [
    "Win32_System_RemoteManagement",
    "Win32_Foundation",
    "Win32_Security",
]}
```

No external dependencies. Everything is native via Win32 APIs.

### Linux/macOS Dependencies

```toml
[target.'cfg(not(windows))'.dependencies]
pavao = "0.2"
ntlmclient = "0.2"
quick-xml = { version = "0.39", features = ["serialize"] }
reqwest = { workspace = true }
```

**System requirements:**
- `libsmbclient` - SMB client library
- `smbclient` - CLI tool (optional, for directory listing fallback)

**Installation:**

```bash
# Debian/Ubuntu/Kali
sudo apt install libsmbclient-dev smbclient

# Fedora/RHEL
sudo dnf install libsmbclient-devel samba-client

# macOS
brew install samba
```

## Implementation Details

### SMB (Linux/macOS)

Full SMB implementation via pavao (libsmbclient bindings):

- `connect()` - Authenticate to SMB server
- `check_share_read()` - Test read access
- `check_share_write()` - Test write access
- `list_directory()` - List directory contents
- `read_file()` - Read file contents
- `write_file()` - Write file contents
- `delete_file()` - Delete files
- `download_file()` - Download remote file
- `upload_file()` - Upload local file
- `pipe_transact()` - Named pipe transactions (for PsExec, etc)
- `deploy_payload()` - Deploy executable to admin share
- `cleanup_payload()` - Remove deployed files

### WinRM (Linux/macOS)

Native WS-Management implementation:

- NTLM authentication via `ntlmclient`
- HTTP client via `reqwest`
- SOAP/XML via `quick-xml`
- Full operation support: Create shell, Execute, Receive, Delete

**No external dependencies required.** Pure Rust implementation.

### Named Pipes (Linux/macOS)

Named pipe support via pavao:

```rust
pub async fn pipe_transact(&self, pipe_name: &str, request: &[u8]) -> Result<Vec<u8>>
```

Opens `\\server\IPC$\pipe\{pipe_name}` as a file, writes request, reads response. Works for:
- `svcctl` - Service Control Manager (PsExec, SMBExec)
- `epmapper` - DCOM endpoint mapper
- `drsuapi` - Directory Replication (DCSync)
- `efsrpc` - EFS RPC (coercion)
- `spoolss` - Print spooler (coercion)

## `ovt doctor` Command

Environment diagnostics for troubleshooting:

```bash
ovt doctor                    # Check all dependencies
ovt doctor --dc 10.10.10.1    # Test connectivity to specific DC
ovt doctor -c smb,kerberos    # Check specific components
```

**Checks performed:**
1. Platform detection (Windows/Linux/macOS)
2. smbclient availability (Linux/macOS)
3. libsmbclient library (Linux/macOS)
4. Kerberos configuration (krb5.conf)
5. WinRM adapter availability
6. DC port connectivity (with `--dc`)

## Known Limitations

None. All features work cross-platform.

## Future Enhancements

- ADCS abuse (ESC1-ESC8)
- Shadow Credentials attack
- SCCM/MECM exploitation
- Cross-forest trust abuse improvements
- Interactive TUI with live graph visualization

## References

- [pavao crate](https://docs.rs/pavao/) - libsmbclient bindings
- [ntlmclient crate](https://docs.rs/ntlmclient/) - NTLM authentication
- [libsmbclient](https://www.samba.org/samba/docs/current/man-html/libsmbclient.7.html) - Samba client library
- [WS-Management](https://docs.microsoft.com/en-us/windows/win32/winrm/ws-management-protocol) - WinRM protocol