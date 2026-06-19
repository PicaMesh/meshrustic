use mesh_protocol::{PacketHeader, MAX_LORA_PAYLOAD_LEN, PACKET_HEADER_LEN};

/// Max encrypted payload bytes after the 16-byte header.
pub const MAX_PACKET_PAYLOAD: usize = MAX_LORA_PAYLOAD_LEN + 1 - PACKET_HEADER_LEN;

/// Number of in-flight packets (fixed pool size for MeshRustic).
pub const POOL_SIZE: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketHandle(pub usize);

#[derive(Clone, Copy)]
pub struct PacketSlot {
    pub header: PacketHeader,
    pub payload: [u8; MAX_PACKET_PAYLOAD],
    pub payload_len: u16,
}

impl PacketSlot {
    pub const fn empty() -> Self {
        Self {
            header: PacketHeader {
                to: 0,
                from: 0,
                id: 0,
                flags: 0,
                channel: 0,
                next_hop: 0,
                relay_node: 0,
            },
            payload: [0; MAX_PACKET_PAYLOAD],
            payload_len: 0,
        }
    }
}

pub struct PacketPool {
    slots: [PacketSlot; POOL_SIZE],
    used: [bool; POOL_SIZE],
}

impl Default for PacketPool {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketPool {
    pub const fn new() -> Self {
        Self {
            slots: [PacketSlot::empty(); POOL_SIZE],
            used: [false; POOL_SIZE],
        }
    }

    pub fn alloc(&mut self) -> Option<PacketHandle> {
        for (index, used) in self.used.iter_mut().enumerate() {
            if !*used {
                *used = true;
                self.slots[index] = PacketSlot::empty();
                return Some(PacketHandle(index));
            }
        }
        None
    }

    pub fn release(&mut self, handle: PacketHandle) {
        debug_assert!(handle.0 < POOL_SIZE);
        debug_assert!(self.used[handle.0]);
        self.used[handle.0] = false;
    }

    pub fn get(&self, handle: PacketHandle) -> Option<&PacketSlot> {
        if handle.0 < POOL_SIZE && self.used[handle.0] {
            Some(&self.slots[handle.0])
        } else {
            None
        }
    }

    pub fn get_mut(&mut self, handle: PacketHandle) -> Option<&mut PacketSlot> {
        if handle.0 < POOL_SIZE && self.used[handle.0] {
            Some(&mut self.slots[handle.0])
        } else {
            None
        }
    }

    pub fn free_count(&self) -> usize {
        self.used.iter().filter(|&&used| !used).count()
    }
}

/// RAII release for a single pool slot (uses raw pointer so multiple guards can coexist).
pub struct PacketGuard {
    index: usize,
    pool: *mut PacketPool,
}

impl PacketGuard {
    pub fn new(pool: &mut PacketPool, handle: PacketHandle) -> Self {
        Self {
            index: handle.0,
            pool: pool as *mut PacketPool,
        }
    }

    pub fn slot(&mut self) -> &mut PacketSlot {
        // SAFETY: `index` was allocated and not released; caller must not release twice.
        unsafe {
            (*self.pool)
                .get_mut(PacketHandle(self.index))
                .unwrap_unchecked()
        }
    }
}

impl Drop for PacketGuard {
    fn drop(&mut self) {
        unsafe {
            (*self.pool).release(PacketHandle(self.index));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_cell::StaticCell;

    #[test]
    fn pool_alloc_release() {
        static POOL: StaticCell<PacketPool> = StaticCell::new();
        let pool = POOL.init(PacketPool::new());
        assert_eq!(pool.free_count(), POOL_SIZE);

        let h = pool.alloc().expect("first alloc");
        pool.get_mut(h).unwrap().header.from = 0x1234_5678;
        pool.release(h);
        assert_eq!(pool.free_count(), POOL_SIZE);
    }

    #[test]
    fn pool_exhaustion() {
        static POOL: StaticCell<PacketPool> = StaticCell::new();
        let pool = POOL.init(PacketPool::new());
        let mut handles = [PacketHandle(0); POOL_SIZE];
        for (i, slot) in handles.iter_mut().enumerate() {
            *slot = pool.alloc().unwrap_or_else(|| panic!("alloc {i}"));
        }
        assert!(pool.alloc().is_none());
        for h in handles {
            pool.release(h);
        }
        assert_eq!(pool.free_count(), POOL_SIZE);
    }

    #[test]
    fn guard_releases_on_drop() {
        static POOL: StaticCell<PacketPool> = StaticCell::new();
        let pool = POOL.init(PacketPool::new());
        {
            let h = pool.alloc().unwrap();
            let mut guard = PacketGuard::new(pool, h);
            guard.slot().payload_len = 1;
            assert_eq!(pool.free_count(), POOL_SIZE - 1);
        }
        assert_eq!(pool.free_count(), POOL_SIZE);
    }
}
