//! Protocol implementations for AD enumeration

pub mod adws;
pub mod breakfast;
pub mod coerce;
pub mod dcom;
pub mod dns;
pub mod drsr;
pub mod epm;
pub mod even;
pub mod gpo_write;
pub mod kerberos;
pub mod kerberos_brute;
pub mod kpasswd;
pub mod laps_ldaps;
pub mod ldap;
pub mod netbios;
pub mod netlogon;
pub mod ntlm;
pub mod ntlm_leak;
pub mod pkinit;
pub mod printnightmare;
pub mod registry;
pub mod rid;
pub mod secretsdump;
pub mod smb;
pub mod smb2;
pub mod targeted_kerberoast;

pub use coerce::{
    CoerceCreds, CoerceProtocol, CoercionResult, trigger_coerce_tcp, trigger_dfs_coerce,
    trigger_dfs_coerce_ex, trigger_petitpotam, trigger_petitpotam_ex, trigger_printer_bug,
    trigger_printer_bug_ex,
};
pub use epm::rpc_null_session_enumeration;
pub use even::{create_smbexec_output_file, even_backup_log, even_create_file};
pub use kerberos::{
    Checksum, FastArmorParams, RequestTgtOptions, build_encrypted_authenticator_with_authdata,
    build_fast_armor, build_pac_authdata_raw, build_s4u2self_checksum, forge_service_ticket,
    forge_tgt, request_service_ticket_via_as_req, request_tgt, request_tgt_opsec, s4u2proxy,
    s4u2proxy_bronzebit, s4u2self,
};
pub use kerberos_brute::{
    KerberosBruteConfig, KerberosBruteError, KerberosBruteResult, ValidCredential, brute_kerberos,
    brute_kerberos_from_wordlist, parse_asrep_to_hashcat,
};
pub use kpasswd::{
    KpasswdConfig, KpasswdError, KpasswdResult, kpasswd_change_password, kpasswd_reset_password,
};
pub use netbios::{NbnsNodeStatus, SmbNegotiateResult, netbios_discovery, smb_negotiate};
pub use netlogon::{
    ZEROLOGON_MAX_ATTEMPTS_DEFAULT, ZerologonCheckMethod, ZerologonCheckResult,
    ZerologonExploitResult, aes_cfb8_decrypt, aes_cfb8_encrypt, build_password_set2_stub,
    compute_netlogon_credential, netlogon_session_key, normalize_computer_name, zerologon_check,
    zerologon_exploit, zerologon_probe,
};
pub use ntlm_leak::{
    NtlmLeakFile, NtlmLeakFormat, format_ntlm_leak_summary, generate_ntlm_leak,
    generate_ntlm_leak_bundle, normalize_unc, write_ntlm_leak_files,
};
pub use pkinit::{CertificateGenerator, PkinitAuthenticator, PkinitConfig, PkinitResult};
pub use printnightmare::{
    APD_FLAGS_EXPLOIT, DEFAULT_CONFIG_FILE, DEFAULT_ENVIRONMENT, ERROR_ACCESS_DENIED,
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, EnumProbe, PrintDriverInfo,
    PrintNightmareMode, PrintNightmareResult, PrintNightmareVerdict, RPC_E_ACCESS_DENIED,
    STATUS_ACCESS_DENIED, build_add_printer_driver_ex_stub, build_check_stub,
    build_delete_printer_driver_ex_stub, build_enum_printer_drivers_stub_round1,
    build_enum_printer_drivers_stub_round2, classify_add_status, is_rpc_fault,
    parse_drivers_payload, parse_enum_round1, parse_enum_round2, printnightmare_check,
    printnightmare_delete, printnightmare_exploit, printnightmare_list, tail_status,
};
pub use smb2::{SigningDiagnostics, SigningVariant};
pub use targeted_kerberoast::{
    TargetedKerberoastConfig, TargetedKerberoastError, TargetedKerberoastResult,
    check_write_spn_permission, format_hashcat_kerberoast, targeted_kerberoast,
};
