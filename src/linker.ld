OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY
{
  RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 128M
}

SECTIONS
{
  .text : {
    KEEP(*(.text.init))
    *(.text .text.*)
  } > RAM

  .rodata : {
    . = ALIGN(8);
    *(.rodata .rodata.*)
  } > RAM

  .data : {
    . = ALIGN(8);
    *(.data .data.*)
  } > RAM

  .bss : {
    . = ALIGN(8);
    __bss_start = .;
    *(.bss .bss.*)
    *(COMMON)
    __bss_end = .;
  } > RAM

  . = ALIGN(16);
  .stack : {
    . += 0x10000; /* 64KB stack */
    __stack_top = .;
  } > RAM
}
