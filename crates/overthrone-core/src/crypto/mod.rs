pub mod aes_cts;
pub mod cracker;
pub mod dpapi;
pub mod gpp;
pub mod hmac_util;
pub mod md4;
pub mod rc4_util;
pub mod ticket;

// Re-export key types for convenience
pub use cracker::{
    CrackResult, CrackerConfig, HashCracker, HashType, MaskPattern, Rule, expand_wordlist,
    get_embedded_wordlist, is_hashcat_available, password_to_nt_hash,
};

pub use dpapi::{DpapiBackupKey, LapsCredentials, LapsDecryptor, LapsEncryptedBlob};

// Re-export crypto primitives
pub use md4::{ntlm_hash, ntlm_hash_from_bytes, ntlm_hash_hex, ntlm_verify};
pub use hmac_util::{
    hmac_md5, hmac_md5_multi, hmac_md5_verify,
    hmac_sha1, hmac_sha1_96_aes, hmac_sha1_96_verify,
    nt_owf_v2, ntlmssp_session_base_key, ntlmv2_response,
};
pub use rc4_util::{
    rc4_crypt, rc4_hmac_encrypt, rc4_hmac_decrypt,
    decrypt_sam_hash_rc4, decrypt_lsa_key_pre_vista,
};
pub use aes_cts::{
    aes128_cbc_decrypt, aes128_cbc_encrypt, aes256_cbc_decrypt, aes256_cbc_encrypt,
    aes128_cts_decrypt, aes128_cts_encrypt, aes256_cts_decrypt, aes256_cts_encrypt,
    decrypt_sam_hash_aes, decrypt_lsa_secret_vista, decrypt_lsa_key_vista,
    decrypt_cached_credential, derive_key_aes128, derive_key_aes256,
};
pub use ticket::{
    compute_pac_checksum, compute_pac_checksum_raw, checksum_type_for_etype,
    encrypt_ticket_part, decrypt_ticket_part,
    detect_etype_from_key, validate_key_for_etype, expected_key_length, etype_name,
    build_kirbi, decode_kirbi, write_kirbi_file, read_kirbi_file, build_ccache,
    ETYPE_RC4_HMAC, ETYPE_AES128_CTS, ETYPE_AES256_CTS,
};
