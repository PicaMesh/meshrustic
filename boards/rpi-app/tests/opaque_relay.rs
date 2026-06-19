use mesh_protocol::PacketHeader;
use mesh_routing::{copy_opaque_payload, relay_header, wire_may_relay, PacketPool, POOL_SIZE};
use static_cell::StaticCell;

/// Simulates relaying a frame whose ciphertext is not decodable (wrong key / unknown port).
#[test]
fn opaque_encrypted_frame_relays_without_decode() {
    static POOL: StaticCell<PacketPool> = StaticCell::new();
    let pool = POOL.init(PacketPool::new());

    const OUR_NODE: u32 = 0x00A1_00B2;
    const CIPHER: [u8; 12] = [
        0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10, 0x20,
    ];

    let header = PacketHeader::from_fields(
        0xFFFF_FFFF,
        0x9988_7766,
        0x0000_00AB,
        0x2B,
        3,
        3,
        true,
        false,
        0,
        0,
    );
    let parsed = header.parse();
    assert!(wire_may_relay(&parsed, false, false));

    let rx = pool.alloc().unwrap();
    {
        let slot = pool.get_mut(rx).unwrap();
        slot.header = header;
        slot.payload[..CIPHER.len()].copy_from_slice(&CIPHER);
        slot.payload_len = CIPHER.len() as u16;
    }

    let tx_hdr = relay_header(&parsed, OUR_NODE).expect("build relay header");
    let tx = pool.alloc().unwrap();
    let mut staging = mesh_routing::PacketSlot::empty();
    {
        let rx_slot = pool.get(rx).unwrap();
        copy_opaque_payload(&mut staging, rx_slot);
    }
    {
        let tx_slot = pool.get_mut(tx).unwrap();
        tx_slot.header = tx_hdr;
        copy_opaque_payload(tx_slot, &staging);
    }

    let out = pool.get(tx).unwrap();
    assert_eq!(&out.payload[..CIPHER.len()], CIPHER);
    assert_eq!(out.header.from, 0x9988_7766);
    assert_eq!(out.header.hop_limit(), 2);
    assert_eq!(out.header.relay_node, 0xB2);

    pool.release(rx);
    pool.release(tx);
    assert_eq!(pool.free_count(), POOL_SIZE);
}
