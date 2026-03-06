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
pub use aes_cts::{
    aes128_cbc_decrypt, aes128_cbc_encrypt, aes128_cts_decrypt, aes128_cts_encrypt,
    aes256_cbc_decrypt, aes256_cbc_encrypt, aes256_cts_decrypt, aes256_cts_encrypt,
    decrypt_cached_credential, decrypt_lsa_key_vista, decrypt_lsa_secret_vista,
    decrypt_sam_hash_aes, derive_key_aes128, derive_key_aes256,
};
pub use hmac_util::{
    hmac_md5, hmac_md5_multi, hmac_md5_verify, hmac_sha1, hmac_sha1_96_aes, hmac_sha1_96_verify,
    nt_owf_v2, ntlmssp_session_base_key, ntlmv2_response,
};
pub use md4::{ntlm_hash, ntlm_hash_from_bytes, ntlm_hash_hex, ntlm_verify};
pub use rc4_util::{
    decrypt_lsa_key_pre_vista, decrypt_sam_hash_rc4, rc4_crypt, rc4_hmac_decrypt, rc4_hmac_encrypt,
};
pub use ticket::{
    ETYPE_AES128_CTS, ETYPE_AES256_CTS, ETYPE_RC4_HMAC, build_ccache, build_kirbi,
    checksum_type_for_etype, compute_pac_checksum, compute_pac_checksum_raw, decode_kirbi,
    decrypt_ticket_part, detect_etype_from_key, encrypt_ticket_part, etype_name,
    expected_key_length, read_kirbi_file, validate_key_for_etype, write_kirbi_file,
};
