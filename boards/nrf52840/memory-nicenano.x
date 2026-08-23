MEMORY
{
    /* nice!nano / Adafruit UF2 bootloader + SoftDevice S140 v6.x (factory default).
     * 0x00026000 - 0x000F0FFF  application (812 KiB max)
     * 0x000F1000 - 0x000F2FFF  spare (do not link)
     * 0x000F3000 - 0x000F3FFF  NodeConfig NVMC page — see src/store.rs
     * 0x000F4000 - 0x000FFFFF  Adafruit UF2 bootloader + settings
     * See Adafruit nRF52840 memory map. */
    FLASH : ORIGIN = 0x00026000, LENGTH = 812K
    RAM : ORIGIN = 0x20008000, LENGTH = 224K
}
