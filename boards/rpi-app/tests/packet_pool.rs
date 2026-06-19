use mesh_routing::{PacketPool, POOL_SIZE};
use static_cell::StaticCell;

#[test]
fn static_cell_packet_pool_pattern() {
    static POOL: StaticCell<PacketPool> = StaticCell::new();
    let pool = POOL.init(PacketPool::new());

    let h0 = pool.alloc().expect("slot 0");
    let h1 = pool.alloc().expect("slot 1");
    pool.get_mut(h0).unwrap().header.from = 0x1111_1111;
    pool.get_mut(h1).unwrap().header.from = 0x2222_2222;

    assert_eq!(pool.free_count(), POOL_SIZE - 2);
    pool.release(h0);
    pool.release(h1);
    assert_eq!(pool.free_count(), POOL_SIZE);
}
