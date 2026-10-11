use mesh_protocol::{PacketHeader, MAX_LORA_PAYLOAD_LEN, PACKET_HEADER_LEN};

pub const MAX_PACKET_PAYLOAD: usize = MAX_LORA_PAYLOAD_LEN - PACKET_HEADER_LEN;

pub const POOL_SIZE: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketHandle {
    index: usize,
    generation: u32,
}

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
    generations: [u32; POOL_SIZE],
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
            generations: [0; POOL_SIZE],
        }
    }

    pub fn alloc(&mut self) -> Option<PacketHandle> {
        for (index, used) in self.used.iter_mut().enumerate() {
            if !*used {
                *used = true;
                self.slots[index] = PacketSlot::empty();
                self.generations[index] = self.generations[index].wrapping_add(1);
                return Some(PacketHandle {
                    index,
                    generation: self.generations[index],
                });
            }
        }
        None
    }

    pub fn release(&mut self, handle: PacketHandle) {
        if self.get(handle).is_some() {
            self.used[handle.index] = false;
        }
    }

    pub fn get(&self, handle: PacketHandle) -> Option<&PacketSlot> {
        if handle.index < POOL_SIZE
            && self.used[handle.index]
            && self.generations[handle.index] == handle.generation
        {
            Some(&self.slots[handle.index])
        } else {
            None
        }
    }

    pub fn get_mut(&mut self, handle: PacketHandle) -> Option<&mut PacketSlot> {
        if handle.index < POOL_SIZE
            && self.used[handle.index]
            && self.generations[handle.index] == handle.generation
        {
            Some(&mut self.slots[handle.index])
        } else {
            None
        }
    }

    pub fn free_count(&self) -> usize {
        self.used.iter().filter(|&&used| !used).count()
    }
}

pub struct PacketGuard<'a> {
    handle: PacketHandle,
    pool: &'a mut PacketPool,
}

impl<'a> PacketGuard<'a> {
    pub fn new(pool: &'a mut PacketPool, handle: PacketHandle) -> Self {
        assert!(pool.get(handle).is_some(), "packet slot must be allocated");
        Self { handle, pool }
    }
    pub fn slot(&mut self) -> &mut PacketSlot {
        self.pool
            .get_mut(self.handle)
            .expect("guard owns an allocated slot")
    }
}

impl Drop for PacketGuard<'_> {
    fn drop(&mut self) {
        self.pool.release(self.handle);
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
        let mut handles = [PacketHandle {
            index: 0,
            generation: 0,
        }; POOL_SIZE];
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
            assert_eq!(guard.pool.free_count(), POOL_SIZE - 1);
        }
        assert_eq!(pool.free_count(), POOL_SIZE);
    }
    #[test]
    fn released_handle_cannot_read_or_free_a_reused_slot() {
        let mut pool = PacketPool::new();
        let stale = pool.alloc().unwrap();
        pool.release(stale);
        let live = pool.alloc().unwrap();
        assert_ne!(stale, live);
        assert!(pool.get(stale).is_none());
        assert!(pool.get_mut(stale).is_none());
        pool.release(stale);
        assert!(pool.get(live).is_some());
        assert_eq!(pool.free_count(), POOL_SIZE - 1);
    }
}
