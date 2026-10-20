use mesh_store::{generate_keypair, NodeConfig};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeIdentity {
    pub node_num: u32,
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
}

impl NodeIdentity {
    pub fn from_hardware(seed: [u8; 32]) -> Self {
        let (id0, id1) = read_device_id();
        let node_num = derive_node_num(id0, id1);
        let (private_key, public_key) = generate_keypair(seed, &device_id_bytes(id0, id1));
        Self {
            node_num,
            public_key,
            private_key,
        }
    }

    // Only the exact predictable legacy key pattern is rotated; replacing unrelated imported keys would
    // break established peer identities.
    pub fn replace_predictable_key(&self, config: &mut NodeConfig) -> bool {
        let (id0, id1) = read_device_id();
        self.replace_predictable_key_from_ids(config, id0, id1)
    }

    fn replace_predictable_key_from_ids(
        &self,
        config: &mut NodeConfig,
        id0: u32,
        id1: u32,
    ) -> bool {
        let mut legacy = [0u8; 32];
        legacy[..4].copy_from_slice(&id0.to_le_bytes());
        legacy[4..8].copy_from_slice(&id1.to_le_bytes());
        let old_node_num = id0 ^ id1.rotate_left(13) ^ 0x5AA5_0000;
        let old_node_num = if old_node_num == 0 { 1 } else { old_node_num };
        legacy[8..12].copy_from_slice(&old_node_num.to_le_bytes());
        legacy[12..16].copy_from_slice(&(id0 ^ id1).to_le_bytes());
        let extra = u64::from(id0 ^ id1);
        legacy[16..24].copy_from_slice(&extra.to_le_bytes());
        legacy[24..].copy_from_slice(&extra.rotate_left(17).to_le_bytes());
        if config.private_key != legacy {
            return false;
        }
        if config.node_num == 0
            || config.node_num == u32::MAX
            || mesh_routing::is_placeholder_node(config.node_num)
        {
            config.node_num = self.node_num;
        }
        config.private_key = self.private_key;
        config.public_key = self.public_key;
        true
    }

    pub fn first_boot_config(&self) -> NodeConfig {
        NodeConfig::first_boot(self.node_num, self.private_key, self.public_key)
    }
}

fn read_device_id() -> (u32, u32) {
    unsafe {
        let id0 = core::ptr::read_volatile(0x1000_0060 as *const u32);
        let id1 = core::ptr::read_volatile(0x1000_0064 as *const u32);
        (id0, id1)
    }
}

/// The chip-unique device id as bytes, so it can be mixed into the key
/// derivation.
fn device_id_bytes(id0: u32, id1: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&id0.to_le_bytes());
    out[4..].copy_from_slice(&id1.to_le_bytes());
    out
}

fn derive_node_num(id0: u32, id1: u32) -> u32 {
    let n = id0 ^ id1.rotate_left(13) ^ 0x5AA5_0000;
    let n = if n == u32::MAX || mesh_routing::is_placeholder_node(n) {
        n & 0x7fff_ffff
    } else {
        n
    };
    n.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn predictable_factory_key_is_rotated_but_random_keys_are_preserved() {
        let (private_key, public_key) = generate_keypair([7; 32], &[0; 8]);
        let replacement = NodeIdentity {
            node_num: 1,
            private_key,
            public_key,
        };
        let mut legacy = NodeConfig::first_boot(
            1,
            [
                0x44, 0x33, 0x22, 0x11, 0x88, 0x77, 0x66, 0x55, 0xe8, 0x39, 0x76, 0x85, 0xcc, 0x44,
                0x44, 0x44, 0xcc, 0x44, 0x44, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x98, 0x89,
                0x88, 0x88, 0x00, 0x00,
            ],
            [1; 32],
        );
        legacy.admin_public_keys[0] = [3; 32];
        assert!(replacement.replace_predictable_key_from_ids(&mut legacy, 0x11223344, 0x55667788));
        assert_eq!(legacy.private_key, private_key);
        assert_eq!(legacy.public_key, public_key);
        assert_eq!(legacy.admin_public_keys[0], [3; 32]);
        let mut secure = NodeConfig::first_boot(2, [5; 32], [6; 32]);
        let original = secure;
        assert!(!replacement.replace_predictable_key_from_ids(&mut secure, 0x11223344, 0x55667788));
        assert_eq!(secure, original);
    }
    #[test]
    fn reserved_identifiers_are_remapped_without_collapsing_to_one_id() {
        let id1 = 0x55u32;
        let first = derive_node_num(0xff123456 ^ id1.rotate_left(13) ^ 0x5aa50000, id1);
        let second = derive_node_num(0xff123457 ^ id1.rotate_left(13) ^ 0x5aa50000, id1);
        assert_eq!(first, 0x7f123456);
        assert_eq!(second, 0x7f123457);
        assert!(!mesh_routing::is_placeholder_node(first));
        assert!(!mesh_routing::is_placeholder_node(second));
    }
}
