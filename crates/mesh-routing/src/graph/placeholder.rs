//! Synthetic node ids for unknown `relay_node` header bytes.

/// High-byte prefix for placeholder nodes (`0xFF00_00xx`).
pub const PLACEHOLDER_NODE_PREFIX: u32 = 0xFF00_0000;

pub fn placeholder_node_id(relay_byte: u8) -> u32 {
    PLACEHOLDER_NODE_PREFIX | u32::from(relay_byte)
}

pub fn is_placeholder_node(node_id: u32) -> bool {
    (node_id & 0xFF00_0000) == PLACEHOLDER_NODE_PREFIX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_id_uses_relay_byte() {
        assert_eq!(placeholder_node_id(0xAB), 0xFF00_00AB);
        assert!(is_placeholder_node(0xFF00_00AB));
        assert!(!is_placeholder_node(0xABCD_EF01));
    }
}
