//! Utility functions for NTLM relay and responder
//!
//! Provides helper functions for NTLM calculations,
//! challenge generation, and response validation.

use crate::{NtlmChallenge, NtlmResponse, Result};

/// Calculate NTLMv2 response
pub fn calculate_ntlmv2_response(
    _username: &str,
    _domain: &str,
    _password: &str,
    _challenge: &NtlmChallenge,
) -> Result<NtlmResponse> {
    // In a real implementation, this would:
    // 1. Calculate NTLM hash from password
    // 2. Calculate NTLMv2 hash
    // 3. Generate response

    Ok(NtlmResponse {
        username: _username.to_string(),
        domain: _domain.to_string(),
        lm_response: vec![0u8; 24],
        nt_response: vec![0u8; 24],
    })
}

/// Generate random NTLM challenge
pub fn generate_challenge() -> NtlmChallenge {
    // Generate 8-byte random challenge
    let challenge_data: Vec<u8> = (0..8).map(|_| rand::random()).collect();

    NtlmChallenge {
        data: challenge_data,
        target_name: "OVERHRONE".to_string(),
    }
}

/// Validate NTLM response
pub fn validate_ntlm_response(
    _response: &NtlmResponse,
    _challenge: &NtlmChallenge,
    _expected_password: &str,
) -> Result<bool> {
    // In a real implementation, this would:
    // 1. Calculate expected response
    // 2. Compare with provided response
    // 3. Return validation result

    Ok(true) // Mock: always valid for demo
}

/// Parse NTLM message type
pub fn parse_ntlm_message_type(data: &[u8]) -> Option<u8> {
    if data.len() < 8 {
        return None;
    }

    // NTLMSSP signature
    if &data[0..7] != b"NTLMSSP" {
        return None;
    }

    // Message type at offset 8
    Some(data[8])
}

/// Extract domain from NTLM target info
pub fn extract_domain_from_target_info(_target_info: &[u8]) -> Option<String> {
    // In a real implementation, this would parse
    // the NTLM target info structure

    Some("WORKGROUP".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge() {
        let challenge = generate_challenge();
        assert_eq!(challenge.data.len(), 8);
        assert_eq!(challenge.target_name, "OVERHRONE");
    }

    #[test]
    fn test_parse_ntlm_message_type_valid() {
        let mut data = b"NTLMSSP\0".to_vec();
        data.push(0x01); // NEGOTIATE message

        let msg_type = parse_ntlm_message_type(&data);
        assert_eq!(msg_type, Some(0x01));
    }

    #[test]
    fn test_parse_ntlm_message_type_invalid() {
        let data = b"INVALID\0\x01";
        let msg_type = parse_ntlm_message_type(data);
        assert_eq!(msg_type, None);
    }

    #[test]
    fn test_parse_ntlm_message_type_too_short() {
        let data = b"NTLM";
        let msg_type = parse_ntlm_message_type(data);
        assert_eq!(msg_type, None);
    }

    #[test]
    fn test_extract_domain() {
        let domain = extract_domain_from_target_info(&[]);
        assert_eq!(domain, Some("WORKGROUP".to_string()));
    }
}
