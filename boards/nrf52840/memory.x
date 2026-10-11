MEMORY
{
    /* Two pages are excluded so interrupted configuration writes retain a valid identity. */
    FLASH : ORIGIN = 0x00000000, LENGTH = 1016K
    RAM : ORIGIN = 0x20000000, LENGTH = 256K
}
