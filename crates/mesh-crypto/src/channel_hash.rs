//! Primary channel hash (xor of name and PSK bytes).

/// Default public-channel PSK (16-byte factory primary).
pub const DEFAULT_PSK: [u8; 16] = [
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
];

/// XOR of all bytes in a buffer.
pub const fn xor_hash(data: &[u8]) -> u8 {
    let mut code = 0u8;
    let mut i = 0;
    while i < data.len() {
        code ^= data[i];
        i += 1;
    }
    code
}

/// Primary channel hash: xor(channel name) ^ xor(PSK).
pub fn channel_hash(name: &str, psk: &[u8]) -> u8 {
    xor_hash(name.as_bytes()) ^ xor_hash(psk)
}

/// Channel hash for empty name + default PSK (factory primary).
pub const fn default_primary_channel_hash() -> u8 {
    xor_hash(&DEFAULT_PSK)
}

/// Primary channel name aligned with EU_868 `SHORT_SLOW` preset deployments.
pub const SHORT_SLOW_CHANNEL_NAME: &str = "ShortSlow";

/// Hash for the common `ShortSlow` primary channel (name + default PSK).
/// Prefer [`mesh_radio::primary_channel_hash`] when the stored channel name is empty.
pub fn short_slow_channel_hash() -> u8 {
    channel_hash(SHORT_SLOW_CHANNEL_NAME, &DEFAULT_PSK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_primary_hash_golden() {
        assert_eq!(default_primary_channel_hash(), 0x02);
    }

    #[test]
    fn short_slow_channel_hash_matches_observed_mesh() {
        assert_eq!(short_slow_channel_hash(), 0x77);
    }

    #[test]
    fn generate_hash_golden_formula() {
        assert_eq!(channel_hash("", &DEFAULT_PSK), 0x02);
        assert_eq!(channel_hash("ShortSlow", &DEFAULT_PSK), 0x77);
    }
}
