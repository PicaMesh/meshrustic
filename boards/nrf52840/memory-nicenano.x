MEMORY
{
    /* nice!nano / Adafruit UF2 bootloader + SoftDevice S140 v6.x (factory default).
     * 0x00026000 - 0x000ECFFF  application (~796 KB)
     * See Adafruit nRF52840 memory map. */
    FLASH : ORIGIN = 0x00026000, LENGTH = 812K
    RAM : ORIGIN = 0x20008000, LENGTH = 224K
}
