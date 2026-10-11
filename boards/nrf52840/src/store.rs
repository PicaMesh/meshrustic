use embassy_nrf::nvmc::Nvmc;
use embedded_storage::nor_flash::{NorFlash, ReadNorFlash};
use mesh_store::{ConfigFlash, ConfigJournal, ConfigStore, NodeConfig, StoreError};

#[cfg(feature = "nicenano")]
pub const CONFIG_FLASH_ADDR: u32 = 0x000F_3000;
#[cfg(not(feature = "nicenano"))]
pub const CONFIG_FLASH_ADDR: u32 = 0x000F_F000;
pub const CONFIG_FLASH_PAGE_SIZE: u32 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigLoadSource {
    Flash,
    Defaults,
}

pub struct NvmcConfigStore {
    journal: ConfigJournal<NvmcFlash>,
    defaults: NodeConfig,
}

impl NvmcConfigStore {
    pub fn new(nvmc: Nvmc<'static>, defaults: NodeConfig) -> Self {
        Self {
            journal: ConfigJournal::new(
                NvmcFlash(nvmc),
                CONFIG_FLASH_ADDR - CONFIG_FLASH_PAGE_SIZE,
                CONFIG_FLASH_ADDR,
            ),
            defaults,
        }
    }

    pub fn load_with_source(&mut self) -> (NodeConfig, ConfigLoadSource) {
        match self.journal.load() {
            Ok(Some(cfg)) => (cfg, ConfigLoadSource::Flash),
            _ => (self.defaults, ConfigLoadSource::Defaults),
        }
    }
}

impl ConfigStore for NvmcConfigStore {
    fn load(&mut self) -> NodeConfig {
        self.load_with_source().0
    }

    fn save(&mut self, config: &NodeConfig) -> Result<(), StoreError> {
        self.journal.save(config)
    }
}

struct NvmcFlash(Nvmc<'static>);
impl ConfigFlash for NvmcFlash {
    fn read(&mut self, address: u32, out: &mut [u8]) -> Result<(), StoreError> {
        self.0.read(address, out).map_err(|_| StoreError::BadCrc)
    }
    fn erase_page(&mut self, address: u32) -> Result<(), StoreError> {
        self.0
            .erase(address, address + CONFIG_FLASH_PAGE_SIZE)
            .map_err(|_| StoreError::BadCrc)
    }
    fn write(&mut self, address: u32, bytes: &[u8]) -> Result<(), StoreError> {
        self.0.write(address, bytes).map_err(|_| StoreError::BadCrc)
    }
}
