OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY
{
  KERNEL_RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 64K
  USER_TEXT  (rx)  : ORIGIN = 0x80010000, LENGTH = 32K
  USER_STACK (rw)  : ORIGIN = 0x80018000, LENGTH = 32K
  AST_BUFFER (rw)  : ORIGIN = 0x80020000, LENGTH = 64K
  DEED_DMA   (rw)  : ORIGIN = 0x80040000, LENGTH = 4K
}

SECTIONS
{
  /* ========================================================================
     REGION 1: PRIVILEGED M-MODE KERNEL (0x80000000 .. 0x80010000, 64KB)
     Inaccessible to U-Mode (PMP permissions: ---)
     ======================================================================== */
  .text.kernel : {
    __kernel_start = .;
    KEEP(*(.text.init))
    *(.text.kernel .text.kernel.*)
    *(.text .text.*)
  } > KERNEL_RAM

  .rodata.kernel : {
    . = ALIGN(8);
    *(.rodata .rodata.*)
  } > KERNEL_RAM

  .data.kernel : {
    . = ALIGN(8);
    *(.data .data.*)
  } > KERNEL_RAM

  .bss.kernel : {
    . = ALIGN(8);
    __bss_start = .;
    *(.bss .bss.*)
    *(COMMON)
    __bss_end = .;
  } > KERNEL_RAM

  .stack.kernel : {
    . = ALIGN(16);
    . += 0x8000; /* 32KB Privileged Kernel Stack */
    __kernel_stack_top = .;
    __kernel_end = 0x80010000;
  } > KERNEL_RAM

  /* ========================================================================
     REGION 2: UNTRUSTED AGENT EXECUTABLE (0x80010000 .. 0x80018000, 32KB)
     U-Mode permissions: R-X (Non-writable)
     ======================================================================== */
  .user_text : {
    __user_text_start = .;
    KEEP(*(.user_text .user_text.*))
    . = ALIGN(16);
    __user_text_end = 0x80018000;
  } > USER_TEXT

  /* ========================================================================
     REGION 3: UNTRUSTED AGENT STACK (0x80018000 .. 0x80020000, 32KB)
     U-Mode permissions: RW- (Non-executable)
     ======================================================================== */
  .user_stack : {
    __user_stack_start = .;
    . += 0x8000; /* 32KB User Stack */
    __user_stack_top = .;
    __user_stack_end = 0x80020000;
  } > USER_STACK

  /* ========================================================================
     REGION 4: AST STATE MUTATION SPACE (0x80020000 .. 0x80030000, 64KB)
     ======================================================================== */
  .ast_buffer (NOLOAD) : {
    __ast_buffer_start = .;
    . += 0x10000;
    __ast_buffer_end = .;
  } > AST_BUFFER

  /* ========================================================================
     REGION 5: HARDWARE DMA DEED REGION (0x80040000 .. 0x80041000, 4KB)
     ======================================================================== */
  .deed_dma (NOLOAD) : {
    __deed_dma_start = .;
    . += 0x1000;
    __deed_dma_end = .;
  } > DEED_DMA
}
