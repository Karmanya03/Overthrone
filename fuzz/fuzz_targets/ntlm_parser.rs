#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz the NTLM challenge message parser with arbitrary byte sequences.
/// Targets `overthrone_core::proto::ntlm::parse_challenge_message`.
fuzz_target!(|data: &[u8]| {
    let _ = overthrone_core::proto::ntlm::parse_challenge_message(data);
});
