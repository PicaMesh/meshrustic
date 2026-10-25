use crate::layout::STORE_RECORD_LEN_V4;
use crate::{decode, encode, NodeConfig, StoreError, STORE_RECORD_LEN};

const MAGIC: u32 = 0x4d52_4a31;
const RECORD_LEN: usize = STORE_RECORD_LEN + 12;
const RECORD_LEN_V4: usize = STORE_RECORD_LEN_V4 + 12;

pub trait ConfigFlash {
    fn read(&mut self, address: u32, out: &mut [u8]) -> Result<(), StoreError>;
    fn erase_page(&mut self, address: u32) -> Result<(), StoreError>;
    fn write(&mut self, address: u32, bytes: &[u8]) -> Result<(), StoreError>;
}

// A settings update must not destroy identity or admin keys if power fails during writing.
pub struct ConfigJournal<F> {
    flash: F,
    pages: [u32; 2],
}

impl<F: ConfigFlash> ConfigJournal<F> {
    pub fn new(flash: F, spare_page: u32, legacy_page: u32) -> Self {
        assert_ne!(spare_page, legacy_page);
        Self {
            flash,
            pages: [spare_page, legacy_page],
        }
    }

    fn record(&mut self, page: usize) -> Result<Option<(u32, NodeConfig)>, StoreError> {
        let mut bytes = [0; RECORD_LEN];
        self.flash.read(self.pages[page], &mut bytes)?;
        let magic = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        if magic != MAGIC {
            // Legacy installations must keep their only valid page until a journal replacement has been
            // verified. Accept both v5 and pre-v5 raw record sizes.
            if let Ok(cfg) = decode(&bytes[..STORE_RECORD_LEN]) {
                return Ok(Some((0, cfg)));
            }
            return Ok(decode(&bytes[..STORE_RECORD_LEN_V4])
                .ok()
                .map(|cfg| (0, cfg)));
        }
        let checksum = u32::from_le_bytes(bytes[RECORD_LEN - 4..].try_into().unwrap());
        if checksum == crate::layout::crc32(&bytes[..RECORD_LEN - 4]) {
            return Ok(decode(&bytes[8..8 + STORE_RECORD_LEN])
                .ok()
                .map(|cfg| {
                    let generation = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
                    (generation, cfg)
                }));
        }
        let checksum_v4 =
            u32::from_le_bytes(bytes[RECORD_LEN_V4 - 4..RECORD_LEN_V4].try_into().unwrap());
        if checksum_v4 != crate::layout::crc32(&bytes[..RECORD_LEN_V4 - 4]) {
            return Ok(None);
        }
        let generation = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        Ok(decode(&bytes[8..8 + STORE_RECORD_LEN_V4])
            .ok()
            .map(|cfg| (generation, cfg)))
    }

    fn latest(&mut self) -> Result<Option<(usize, u32, NodeConfig)>, StoreError> {
        let first = self.record(0)?;
        let second = self.record(1)?;
        Ok(match (first, second) {
            (Some((a, cfg_a)), Some((b, cfg_b))) => {
                if b.wrapping_sub(a) < 0x8000_0000 {
                    Some((1, b, cfg_b))
                } else {
                    Some((0, a, cfg_a))
                }
            }
            (Some((generation, cfg)), None) => Some((0, generation, cfg)),
            (None, Some((generation, cfg))) => Some((1, generation, cfg)),
            (None, None) => None,
        })
    }

    pub fn load(&mut self) -> Result<Option<NodeConfig>, StoreError> {
        Ok(self.latest()?.map(|(_, _, cfg)| cfg))
    }

    pub fn save(&mut self, config: &NodeConfig) -> Result<(), StoreError> {
        let (page, generation) = self
            .latest()?
            .map(|(page, generation, _)| (1 - page, generation.wrapping_add(1)))
            .unwrap_or((0, 1));
        let mut bytes = [0; RECORD_LEN];
        bytes[..4].copy_from_slice(&MAGIC.to_le_bytes());
        bytes[4..8].copy_from_slice(&generation.to_le_bytes());
        encode(config, &mut bytes[8..8 + STORE_RECORD_LEN])?;
        let checksum = crate::layout::crc32(&bytes[..RECORD_LEN - 4]);
        bytes[RECORD_LEN - 4..].copy_from_slice(&checksum.to_le_bytes());
        self.flash.erase_page(self.pages[page])?;
        self.flash.write(self.pages[page], &bytes)?;
        let expected = decode(&bytes[8..8 + STORE_RECORD_LEN])?;
        if self.record(page)?.map(|(_, cfg)| cfg) != Some(expected) {
            return Err(StoreError::BadCrc);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct MemoryFlash {
        bytes: [u8; 8192],
        fail_after: Option<usize>,
    }
    impl ConfigFlash for MemoryFlash {
        fn read(&mut self, address: u32, out: &mut [u8]) -> Result<(), StoreError> {
            out.copy_from_slice(&self.bytes[address as usize..address as usize + out.len()]);
            Ok(())
        }
        fn erase_page(&mut self, address: u32) -> Result<(), StoreError> {
            self.bytes[address as usize..address as usize + 4096].fill(0xff);
            Ok(())
        }
        fn write(&mut self, address: u32, bytes: &[u8]) -> Result<(), StoreError> {
            let n = self.fail_after.unwrap_or(bytes.len()).min(bytes.len());
            self.bytes[address as usize..address as usize + n].copy_from_slice(&bytes[..n]);
            if n != bytes.len() {
                Err(StoreError::BadCrc)
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn every_interrupted_write_preserves_previous_identity_and_settings() {
        let original = NodeConfig::first_boot(1, [0x11; 32], [0x22; 32]);
        let mut updated = original;
        updated.admin_public_keys[0] = [0x33; 32];
        for cutoff in 0..RECORD_LEN {
            let mut journal = ConfigJournal::new(
                MemoryFlash {
                    bytes: [0xff; 8192],
                    fail_after: None,
                },
                0,
                4096,
            );
            journal.save(&original).unwrap();
            journal.flash.fail_after = Some(cutoff);
            assert!(journal.save(&updated).is_err());
            assert_eq!(journal.load().unwrap(), Some(original));
            journal.flash.fail_after = None;
            journal.save(&updated).unwrap();
            assert_eq!(journal.load().unwrap(), Some(updated));
        }
    }
    #[test]
    fn legacy_record_migrates_without_erasing_its_page_first() {
        let config = NodeConfig::first_boot(1, [1; 32], [2; 32]);
        let mut flash = MemoryFlash {
            bytes: [0xff; 8192],
            fail_after: None,
        };
        encode(&config, &mut flash.bytes[4096..4096 + STORE_RECORD_LEN]).unwrap();
        let mut journal = ConfigJournal::new(flash, 0, 4096);
        assert_eq!(journal.load().unwrap(), Some(config));
        journal.flash.fail_after = Some(20);
        assert!(journal.save(&config).is_err());
        assert_eq!(journal.load().unwrap(), Some(config));
    }
    #[test]
    fn legacy_v4_journal_record_loads_and_rewrites_as_v5() {
        let config = NodeConfig::first_boot(3, [3; 32], [4; 32]);
        let mut flash = MemoryFlash {
            bytes: [0xff; 8192],
            fail_after: None,
        };
        let mut payload = [0u8; STORE_RECORD_LEN];
        encode(&config, &mut payload).unwrap();
        payload[4..8].copy_from_slice(&crate::layout::STORE_VERSION_V4.to_le_bytes());
        payload[STORE_RECORD_LEN_V4 - 4..].fill(0);
        let payload_crc = crate::layout::crc32(&payload[..crate::layout::STORE_CRC_OFFSET_V4]);
        payload[crate::layout::STORE_CRC_OFFSET_V4..STORE_RECORD_LEN_V4]
            .copy_from_slice(&payload_crc.to_le_bytes());

        let mut legacy = [0u8; RECORD_LEN_V4];
        legacy[..4].copy_from_slice(&MAGIC.to_le_bytes());
        legacy[4..8].copy_from_slice(&1u32.to_le_bytes());
        legacy[8..8 + STORE_RECORD_LEN_V4].copy_from_slice(&payload[..STORE_RECORD_LEN_V4]);
        let checksum = crate::layout::crc32(&legacy[..RECORD_LEN_V4 - 4]);
        legacy[RECORD_LEN_V4 - 4..].copy_from_slice(&checksum.to_le_bytes());
        flash.bytes[..RECORD_LEN_V4].copy_from_slice(&legacy);

        let mut journal = ConfigJournal::new(flash, 0, 4096);
        let loaded = journal.load().unwrap().expect("v4 journal loads");
        assert_eq!(loaded.short_name_len, 0);
        assert_eq!(loaded.node_num, 3);
        journal.save(&loaded).unwrap();
        let again = journal.load().unwrap().unwrap();
        assert_eq!(again.node_num, 3);
        let mut check = [0u8; STORE_RECORD_LEN];
        encode(&again, &mut check).unwrap();
        assert_eq!(
            u32::from_le_bytes(check[4..8].try_into().unwrap()),
            crate::layout::STORE_VERSION
        );
    }
    #[test]
    fn generation_order_survives_wrap() {
        let mut journal = ConfigJournal::new(
            MemoryFlash {
                bytes: [0xff; 8192],
                fail_after: None,
            },
            0,
            4096,
        );
        let old = NodeConfig::first_boot(1, [1; 32], [2; 32]);
        journal.save(&old).unwrap();
        journal.flash.bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        let crc = crate::layout::crc32(&journal.flash.bytes[..RECORD_LEN - 4]);
        journal.flash.bytes[RECORD_LEN - 4..RECORD_LEN].copy_from_slice(&crc.to_le_bytes());
        let mut newer = old;
        newer.device_update_interval_secs = 600;
        journal.save(&newer).unwrap();
        assert_eq!(journal.load().unwrap(), Some(newer));
    }
}
