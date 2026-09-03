//! NVMC-backed NodeConfig store (last flash page).

use embassy_nrf::nvmc::Nvmc;
use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};
use mesh_store::{decode, encode, ConfigStore, NodeConfig, StoreError, STORE_RECORD_LEN};

/// Absolute flash address of the config page (one 4 KiB NVMC page).
///
/// **nice!nano / Adafruit UF2** (`nicenano` feature): `0xF3000` — last free page before
/// the bootloader at `0xF4000`. Do not use `0xFF000`; that page is BOOTLOADER_SETTINGS.
///
/// **Bare 1020K app** (no UF2 tail bootloader): last flash page at `0xFF000`.
#[cfg(feature = "nicenano")]
pub const CONFIG_FLASH_ADDR: u32 = 0x000F_3000;
#[cfg(not(feature = "nicenano"))]
pub const CONFIG_FLASH_ADDR: u32 = 0x000F_F000;
pub const CONFIG_FLASH_PAGE_SIZE: u32 = 4096;

/// How [`NvmcConfigStore::load`] resolved the config.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigLoadSource {
    /// Decoded a valid MRST record from NVMC.
    Flash,
    /// Read/decode failed — hardware first-boot defaults (empty admin keys).
    Defaults,
}

/// NVMC ConfigStore at [`CONFIG_FLASH_ADDR`].
pub struct NvmcConfigStore {
    nvmc: Nvmc<'static>,
    defaults: NodeConfig,
}

impl NvmcConfigStore {
    pub fn new(nvmc: Nvmc<'static>, defaults: NodeConfig) -> Self {
        Self { nvmc, defaults }
    }

    /// Load config and report whether flash had a valid record.
    pub fn load_with_source(&mut self) -> (NodeConfig, ConfigLoadSource) {
        let mut buf = [0u8; STORE_RECORD_LEN];
        if self.nvmc.read(CONFIG_FLASH_ADDR, &mut buf).is_err() {
            return (self.defaults, ConfigLoadSource::Defaults);
        }
        match decode(&buf) {
            Ok(cfg) => (cfg, ConfigLoadSource::Flash),
            Err(_) => (self.defaults, ConfigLoadSource::Defaults),
        }
    }
}

impl ConfigStore for NvmcConfigStore {
    fn load(&mut self) -> NodeConfig {
        self.load_with_source().0
    }

    fn save(&mut self, config: &NodeConfig) -> Result<(), StoreError> {
        // Only the 256-byte record is programmed; the rest of the erased page stays 0xFF.
        // Avoid a 4 KiB stack buffer inside the radio task (easy arena/stack blow-up).
        let mut buf = [0u8; STORE_RECORD_LEN];
        encode(config, &mut buf)?;
        self.nvmc
            .erase(
                CONFIG_FLASH_ADDR,
                CONFIG_FLASH_ADDR + CONFIG_FLASH_PAGE_SIZE,
            )
            .map_err(|_| StoreError::BadCrc)?;
        self.nvmc
            .write(CONFIG_FLASH_ADDR, &buf)
            .map_err(|_| StoreError::BadCrc)?;
        Ok(())
    }
}
