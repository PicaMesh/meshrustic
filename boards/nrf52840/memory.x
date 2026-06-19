MEMORY
{
    /* NOTE 1 K = 1 KiBi = 1024 bytes */
    FLASH : ORIGIN = 0x00000000, LENGTH = 1024K
    RAM : ORIGIN = 0x20000000, LENGTH = 256K

    /* SoftDevice S140 7.3.0 (uncomment if using a softdevice):
    FLASH : ORIGIN = 0x00027000, LENGTH = 868K
    RAM : ORIGIN = 0x20020000, LENGTH = 128K
    */
}
