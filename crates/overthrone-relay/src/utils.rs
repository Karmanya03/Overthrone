//! Utility functions for NTLM relay and responder
//!
//! Provides helper functions for NTLM calculations,
//! challenge generation, and response validation using
//! the full NTLMv2 implementation from overthrone-core.

use crate::{NtlmChallenge, NtlmResponse, Result};
use overthrone_core::proto::ntlm;

/// Calculate NTLMv2 response for a given challenge.
///
/// This is used for offline cracking validation — NOT for relay
/// (relay forwards the victim's response directly).
pub fn calculate_ntlmv2_response(
    username: &str,
    domain: &str,
    password: &str,
    challenge: &NtlmChallenge,
) -> Result<NtlmResponse> {
    // Compute the NT hash, then NTLMv2 hash
    let nt_hash = ntlm::nt_hash(password);
    let v2_hash = ntlm::ntlmv2_hash(&nt_hash, username, domain);

    // Generate random client challenge
    let client_challenge: [u8; 8] = rand::random();

    // Build a client blob with current timestamp
    let timestamp = ntlm::windows_filetime_now();
    let client_blob = ntlm::build_ntlmv2_client_blob(timestamp, &client_challenge, &[]);

    // Compute NTLMv2 response
    let server_challenge: [u8; 8] = challenge.data[..8].try_into().unwrap_or([0u8; 8]);
    let nt_response = ntlm::ntlmv2_response(&v2_hash, &server_challenge, &client_blob);

    // Compute LMv2 response
    let lm_response = ntlm::lmv2_response(&v2_hash, &server_challenge, &client_challenge);

    Ok(NtlmResponse {
        username: username.to_string(),
        domain: domain.to_string(),
        lm_response,
        nt_response,
    })
}

/// Generate random 8-byte NTLM server challenge
pub fn generate_challenge() -> NtlmChallenge {
    let challenge_data: [u8; 8] = rand::random();

    NtlmChallenge {
        data: challenge_data.to_vec(),
        target_name: "OVERTHRONE".to_string(),
    }
}

/// Validate an NTLMv2 response against a known password
pub fn validate_ntlm_response(
    response: &NtlmResponse,
    challenge: &NtlmChallenge,
    expected_password: &str,
) -> Result<bool> {
    // Compute expected NTLMv2 hash
    let nt_hash = ntlm::nt_hash(expected_password);
    let v2_hash = ntlm::ntlmv2_hash(&nt_hash, &response.username, &response.domain);

    // The NTLMv2 response = NTProofStr(16) + ClientBlob(variable)
    if response.nt_response.len() < 16 {
        return Ok(false);
    }

    let nt_proof_str = &response.nt_response[..16];
    let client_blob = &response.nt_response[16..];

    // Recompute NTProofStr: HMAC-MD5(v2_hash, challenge + client_blob)
    let server_challenge: [u8; 8] = challenge.data[..8].try_into().unwrap_or([0u8; 8]);
    let expected_response = ntlm::ntlmv2_response(&v2_hash, &server_challenge, client_blob);
    let expected_proof = &expected_response[..16];

    // Constant-time comparison would be better, but for a red-team tool this is fine
    Ok(nt_proof_str == expected_proof)
}

/// Parse NTLM message type from raw bytes
pub fn parse_ntlm_message_type(data: &[u8]) -> Option<u8> {
    if data.len() < 12 {
        return None;
    }

    if &data[0..8] != b"NTLMSSP\x00" {
        return None;
    }

    // Message type is a u32 at offset 8, but we return only the low byte
    // since types are 1, 2, 3
    Some(data[8])
}

/// Extract domain from NTLM target info AV_PAIR list
pub fn extract_domain_from_target_info(target_info: &[u8]) -> Option<String> {
    // AV_PAIR: AvId(u16) + AvLen(u16) + Value(AvLen bytes)
    // MsvAvNbDomainName = 0x0002
    let mut pos = 0;
    while pos + 4 <= target_info.len() {
        let av_id = u16::from_le_bytes([target_info[pos], target_info[pos + 1]]);
        let av_len = u16::from_le_bytes([target_info[pos + 2], target_info[pos + 3]]) as usize;
        pos += 4;

        if av_id == 0x0000 {
            break; // MsvAvEOL
        }

        if pos + av_len > target_info.len() {
            break;
        }

        if av_id == 0x0002 {
            // MsvAvNbDomainName — UTF-16LE
            let domain_chars: Vec<u16> = target_info[pos..pos + av_len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            return Some(String::from_utf16_lossy(&domain_chars));
        }

        pos += av_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge() {
        let challenge = generate_challenge();
        assert_eq!(challenge.data.len(), 8);
        assert_eq!(challenge.target_name, "OVERTHRONE");

        // Two challenges should be different (random)
        let challenge2 = generate_challenge();
        assert_ne!(challenge.data, challenge2.data);
    }

    #[test]
    fn test_parse_ntlm_message_type_valid() {
        let mut data = b"NTLMSSP\0".to_vec();
        data.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(parse_ntlm_message_type(&data), Some(0x01));
    }

    #[test]
    fn test_parse_ntlm_message_type_invalid() {
        let data = b"INVALID\0\x01\x00\x00\x00";
        assert_eq!(parse_ntlm_message_type(data), None);
    }

    #[test]
    fn test_parse_ntlm_message_type_too_short() {
        let data = b"NTLM";
        assert_eq!(parse_ntlm_message_type(data), None);
    }

    #[test]
    fn test_extract_domain_from_target_info() {
        // Build a minimal AV_PAIR list:
        // MsvAvNbDomainName(0x0002) + len=8 + "TEST" in UTF-16LE
        // MsvAvEOL(0x0000) + len=0
        let mut info = Vec::new();
        info.extend_from_slice(&0x0002u16.to_le_bytes()); // AvId = NbDomainName
        info.extend_from_slice(&8u16.to_le_bytes()); // AvLen = 8 bytes
        for c in "TEST".encode_utf16() {
            info.extend_from_slice(&c.to_le_bytes());
        }
        info.extend_from_slice(&0x0000u16.to_le_bytes()); // AvId = EOL
        info.extend_from_slice(&0u16.to_le_bytes()); // AvLen = 0

        assert_eq!(
            extract_domain_from_target_info(&info),
            Some("TEST".to_string())
        );
    }

    #[test]
    fn test_extract_domain_empty_info() {
        // Just an EOL pair
        let info = [0x00, 0x00, 0x00, 0x00];
        assert_eq!(extract_domain_from_target_info(&info), None);
    }

    #[test]
    fn test_calculate_ntlmv2_response_format() {
        let challenge = NtlmChallenge {
            data: vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            target_name: "TEST".to_string(),
        };

        let response = calculate_ntlmv2_response("admin", "TEST", "password", &challenge).unwrap();
        assert_eq!(response.username, "admin");
        assert_eq!(response.domain, "TEST");
        // NTLMv2 response = NTProofStr(16) + ClientBlob(28+)
        assert!(response.nt_response.len() >= 44);
        // LMv2 response is always 24 bytes
        assert_eq!(response.lm_response.len(), 24);
    }

    #[test]
    fn test_validate_ntlm_response_correct_password() {
        let challenge = NtlmChallenge {
            data: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
            target_name: "CORP".to_string(),
        };

        let response = calculate_ntlmv2_response("user", "CORP", "secret123", &challenge).unwrap();
        let valid = validate_ntlm_response(&response, &challenge, "secret123").unwrap();
        assert!(valid);
    }

    #[test]
    fn test_validate_ntlm_response_wrong_password() {
        let challenge = NtlmChallenge {
            data: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
            target_name: "CORP".to_string(),
        };

        let response = calculate_ntlmv2_response("user", "CORP", "secret123", &challenge).unwrap();
        let valid = validate_ntlm_response(&response, &challenge, "wrong_password").unwrap();
        assert!(!valid);
    }
}
