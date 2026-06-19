//! Stable per-device node identity until flash-backed NodeDB is wired.

use mesh_routing::NodeInfoIdentity;
use mesh_store::generate_keypair;

/// Mesh node number (`!xxxxxxxx` on other nodes) and PKI public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeIdentity {
    pub node_num: u32,
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],
}

impl NodeIdentity {
    /// Derive a stable node id and Curve25519 keypair from nRF52840 factory DEVICEID.
    pub fn from_hardware() -> Self {
        let (id0, id1) = read_device_id();
        let node_num = derive_node_num(id0, id1);
        let mut device_id = [0u8; 16];
        device_id[..4].copy_from_slice(&id0.to_le_bytes());
        device_id[4..8].copy_from_slice(&id1.to_le_bytes());
        device_id[8..12].copy_from_slice(&node_num.to_le_bytes());
        device_id[12..].copy_from_slice(&(id0 ^ id1).to_le_bytes());
        let (private_key, public_key) = generate_keypair(Some(&device_id), u64::from(id0 ^ id1));
        Self {
            node_num,
            public_key,
            private_key,
        }
    }

    pub fn nodeinfo_identity(&self) -> NodeInfoIdentity {
        NodeInfoIdentity::for_node(self.node_num, self.public_key)
    }
}

fn read_device_id() -> (u32, u32) {
    // FICR DEVICEID[0] @ 0x1000_0060, DEVICEID[1] @ 0x1000_0064 (nRF52840 PS).
    unsafe {
        let id0 = core::ptr::read_volatile(0x1000_0060 as *const u32);
        let id1 = core::ptr::read_volatile(0x1000_0064 as *const u32);
        (id0, id1)
    }
}

fn derive_node_num(id0: u32, id1: u32) -> u32 {
    let n = id0 ^ id1.rotate_left(13) ^ 0x5AA5_0000;
    if n == 0 {
        1
    } else {
        n
    }
}
