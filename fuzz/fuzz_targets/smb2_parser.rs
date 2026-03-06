#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz the NTLM negotiate message builder used within SMB2 authentication.
/// Also exercises NTLM hash parsing with arbitrary string input.
fuzz_target!(|data: &[u8]| {
    // Fuzz the negotiate message builder with arbitrary domain strings
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = overthrone_core::proto::ntlm::build_negotiate_message(s);
        let _ = overthrone_core::proto::ntlm::parse_ntlm_hash(s);
        let _ = overthrone_core::proto::ntlm::parse_secretsdump_line(s);
    }

    // Fuzz binary NTLM challenge parsing (used during SMB2 session setup)
    let _ = overthrone_core::proto::ntlm::parse_challenge_message(data);
});
