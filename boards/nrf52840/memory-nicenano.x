MEMORY
{
    /* The application must not overwrite the factory SoftDevice, the two-page configuration
       journal at 0xF2000/0xF3000, or the bootloader and its settings above 0xF4000. */
    FLASH : ORIGIN = 0x00026000, LENGTH = 812K
    RAM : ORIGIN = 0x20008000, LENGTH = 224K
}
