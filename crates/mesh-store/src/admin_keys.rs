//! Built-in admin public keys (always authorized; never exposed via SecurityConfig get).

/// Built-in admin public keys (X25519). Never expose via SecurityConfig get.
pub const BUILTIN_ADMIN_PUBLIC_KEYS: [[u8; 32]; 2] = [
    [
        0x9d, 0x37, 0xec, 0x73, 0x30, 0xca, 0x6e, 0xd0, 0x6d, 0x5b, 0xad, 0x4f, 0xa0, 0xa1, 0x9c,
        0xa3, 0x55, 0x04, 0xb6, 0x56, 0xe7, 0x4b, 0x6f, 0xf0, 0x15, 0xbd, 0x89, 0x9e, 0x31, 0xcc,
        0x44, 0x43,
    ],
    [
        0x6b, 0x8e, 0x2a, 0x78, 0x8e, 0xef, 0x6b, 0x05, 0x87, 0x63, 0x6c, 0x48, 0x29, 0x6f, 0x1c,
        0x08, 0x24, 0x44, 0xce, 0xc1, 0x5d, 0x04, 0x27, 0x24, 0x61, 0x9e, 0xbc, 0x84, 0x04, 0x8c,
        0x2e, 0x61,
    ],
];

/// Empty / cleared configurable admin key slot.
pub const EMPTY_ADMIN_KEY: [u8; 32] = [0u8; 32];

/// True when `remote_pk` is a built-in admin key or a non-empty flash slot.
pub fn is_admin_authorized(remote_pk: &[u8; 32], flash: &[[u8; 32]; 3]) -> bool {
    BUILTIN_ADMIN_PUBLIC_KEYS.iter().any(|k| k == remote_pk)
        || flash
            .iter()
            .any(|k| k != &EMPTY_ADMIN_KEY && k == remote_pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_authorized() {
        let flash = [EMPTY_ADMIN_KEY; 3];
        assert!(is_admin_authorized(&BUILTIN_ADMIN_PUBLIC_KEYS[0], &flash));
        assert!(is_admin_authorized(&BUILTIN_ADMIN_PUBLIC_KEYS[1], &flash));
    }

    #[test]
    fn flash_hit_and_miss() {
        let mut flash = [EMPTY_ADMIN_KEY; 3];
        let key = [0x42u8; 32];
        flash[1] = key;
        assert!(is_admin_authorized(&key, &flash));
        assert!(!is_admin_authorized(&[0x43u8; 32], &flash));
        assert!(!is_admin_authorized(&EMPTY_ADMIN_KEY, &flash));
    }
}
