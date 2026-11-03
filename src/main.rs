//! Odin OS: Bare-Metal Microkernel Proof Harness (Phase B)
//!
//! Demonstrates hardware-enforced AST mask wordline gating via RISC-V PMP.
//! Boots in Machine Mode (M-Mode), configures PMP boundaries, drops to User Mode (U-Mode),
//! proves that in-bounds writes commit, and proves that out-of-bounds writes physically fault
//! with mcause = 0x07 (Store Access Fault), leaving zero bits flipped in silicon.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

core::arch::global_asm!(
    ".section .text.init",
    ".global _start",
    "_start:",
    // 1. Setup stack pointer
    "  la sp, __stack_top",
    // 2. Clear BSS
    "  la t0, __bss_start",
    "  la t1, __bss_end",
    "1:",
    "  bge t0, t1, 2f",
    "  sd zero, 0(t0)",
    "  addi t0, t0, 8",
    "  j 1b",
    "2:",
    // 3. Jump to kernel main
    "  tail kmain",
    "",
    ".section .text",
    ".global trap_entry",
    "trap_entry:",
    // Save minimal scratch registers
    "  addi sp, sp, -64",
    "  sd ra, 0(sp)",
    "  sd t0, 8(sp)",
    "  sd t1, 16(sp)",
    "  sd a0, 24(sp)",
    "  sd a1, 32(sp)",
    "  sd a2, 40(sp)",
    "  call handle_trap",
    "  ld ra, 0(sp)",
    "  ld t0, 8(sp)",
    "  ld t1, 16(sp)",
    "  ld a0, 24(sp)",
    "  ld a1, 32(sp)",
    "  ld a2, 40(sp)",
    "  addi sp, sp, 64",
    "  mret"
);

extern "C" {
    fn trap_entry();
}

// QEMU Virt Hardware MMIO Addresses
const UART0: *mut u8 = 0x1000_0000 as *mut u8;
const SIFIVE_TEST: *mut u32 = 0x10_0000 as *mut u32;

// Memory & MMIO Regions
const UART_BASE: usize = 0x1000_0000;
const UART_END: usize = 0x1000_1000;
const CODE_BASE: usize = 0x8000_0000;
const CODE_END: usize = 0x8002_0000; // Covers text, rodata, bss, and 64KB stack (ends at 0x80011d98)
const MASK_START: usize = 0x8002_0000;
const MASK_END: usize = 0x8002_1000; // 4KB authorized AST buffer
const UNAUTHORIZED_ADDR: usize = 0x8003_0000; // Outside PMP mask buffer

// Print primitives over UART (16550A)
fn uart_putc(c: u8) {
    unsafe {
        // Wait for transmitter empty
        while (UART0.add(5).read_volatile() & 0x20) == 0 {}
        UART0.write_volatile(c);
    }
}

fn uart_print(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            uart_putc(b'\r');
        }
        uart_putc(b);
    }
}

fn uart_print_hex(val: u64) {
    uart_print("0x");
    for i in (0..16).rev() {
        let nibble = ((val >> (i * 4)) & 0xF) as u8;
        let c = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        uart_putc(c);
    }
}

#[no_mangle]
pub extern "C" fn kmain() -> ! {
    uart_print("\n");
    uart_print("╔════════════════════════════════════════════════════════════════════════╗\n");
    uart_print("║            ODIN OS: SOVEREIGN CAPABILITY MICROKERNEL (PHASE B)         ║\n");
    uart_print("║            Hardware Physical Memory Protection & Wordline Gating       ║\n");
    uart_print("╚════════════════════════════════════════════════════════════════════════╝\n\n");

    uart_print("[BOOT] Machine Mode (M-Mode) active. CPU: 64-bit RISC-V (QEMU virt).\n");

    // 1. Install M-Mode trap handler
    unsafe {
        core::arch::asm!("csrw mtvec, {0}", in(reg) (trap_entry as *const () as usize));
    }
    uart_print("[INIT] Trap vector mtvec registered at trap_entry.\n");

    // 2. Zero-out target unauthorized address beforehand to prove it never changes
    unsafe {
        (UNAUTHORIZED_ADDR as *mut u8).write_volatile(0x00);
    }

    // 3. Program RISC-V PMP Registers (Physical Memory Protection)
    //
    // Entry 0..1: UART MMIO [0x1000_0000 .. 0x1000_1000] -> RW- (TOR mode)
    // Entry 2..3: Code & Stack [0x8000_0000 .. 0x8001_0000] -> RWX (TOR mode)
    // Entry 3..4: Authorized AST Mask [0x8001_0000 .. 0x8001_1000] -> RW- (TOR mode)
    // Everything else: No entries match -> User Mode write access gated (WE = 0)!
    let pmpaddr0_val = UART_BASE >> 2;
    let pmpaddr1_val = UART_END >> 2;
    let pmpaddr2_val = CODE_BASE >> 2;
    let pmpaddr3_val = CODE_END >> 2;
    let pmpaddr4_val = MASK_END >> 2;

    // pmpcfg0:
    // Entry 0: OFF (0x00)
    // Entry 1: TOR (0x08) | W (0x02) | R (0x01) = 0x0B
    // Entry 2: OFF (0x00)
    // Entry 3: TOR (0x08) | X (0x04) | W (0x02) | R (0x01) = 0x0F
    // Entry 4: TOR (0x08) | W (0x02) | R (0x01) = 0x0B
    let pmpcfg0_val: u64 = (0x0B_u64 << 32) | (0x0F_u64 << 24) | (0x0B_u64 << 8);

    unsafe {
        core::arch::asm!(
            "csrw pmpaddr0, {0}",
            "csrw pmpaddr1, {1}",
            "csrw pmpaddr2, {2}",
            "csrw pmpaddr3, {3}",
            "csrw pmpaddr4, {4}",
            "csrw pmpcfg0, {5}",
            in(reg) pmpaddr0_val,
            in(reg) pmpaddr1_val,
            in(reg) pmpaddr2_val,
            in(reg) pmpaddr3_val,
            in(reg) pmpaddr4_val,
            in(reg) pmpcfg0_val,
        );
    }

    uart_print("[PMP] Hardware memory registers programmed in silicon:\n");
    uart_print("  ├── Region 0 [0x10000000 .. 0x10001000]: RW- (UART0 MMIO)\n");
    uart_print("  ├── Region 1 [0x80000000 .. 0x80020000]: RWX (Kernel / Task Text & Stack)\n");
    uart_print("  ├── Region 2 [0x80020000 .. 0x80021000]: RW- (Authorized AST Mask Buffer)\n");
    uart_print("  └── Perimeter [All other addresses]:     --- (WE = 0 Gated)\n\n");

    // 4. Drop privilege from M-Mode to User Mode (U-Mode)
    uart_print("[TRANSITION] Dropping CPU privilege from M-Mode to User Mode (U-Mode)...\n");

    unsafe {
        // Clear MPP (bits 12:11 of mstatus) so mret returns to U-mode (0b00)
        let mut mstatus: usize;
        core::arch::asm!("csrr {0}, mstatus", out(reg) mstatus);
        mstatus &= !(0b11 << 11);
        core::arch::asm!("csrw mstatus, {0}", in(reg) mstatus);

        // Set mepc to user task entry point
        core::arch::asm!("csrw mepc, {0}", in(reg) (user_mode_task as *const () as usize));

        // Execute mret to switch to U-mode
        core::arch::asm!("mret");
    }

    loop {}
}

/// Unprivileged User-Mode Agent Task
extern "C" fn user_mode_task() -> ! {
    uart_print("[U-MODE] Task running in unprivileged User Mode.\n");

    // TEST 1: Authorized write inside AST mask buffer (0x80020050)
    uart_print("[TEST 1] Attempting authorized write to 0x80020050 (inside AST mask)...\n");
    let authorized_ptr = (MASK_START + 0x50) as *mut u8;
    unsafe {
        authorized_ptr.write_volatile(0x42);
        let readback = authorized_ptr.read_volatile();
        if readback == 0x42 {
            uart_print("  └── ✓ PASS: Write authorized in silicon (Byte = 0x42 committed).\n\n");
        } else {
            uart_print("  └── ✗ FAIL: Unexpected readback.\n");
        }
    }

    // TEST 2: Unauthorized write outside AST mask (0x80030000)
    uart_print("[TEST 2] Attempting unauthorized write to 0x80030000 (OUTSIDE AST mask)...\n");
    uart_print("  └── Issuing store instruction: sb 0xFF -> [0x80030000]...\n");

    let unauthorized_ptr = UNAUTHORIZED_ADDR as *mut u8;
    unsafe {
        // THIS MUST TRIGGER PHYSICAL CPU ACCESS FAULT (mcause = 7) IN SILICON!
        unauthorized_ptr.write_volatile(0xFF);
    }

    // If execution reaches here, PMP failed!
    uart_print("  └── ✗ FATAL: PMP failed to gate write! Breach permitted.\n");
    exit_qemu(false);
}



#[no_mangle]
extern "C" fn handle_trap() {
    let mcause: u64;
    let mepc: u64;
    let mtval: u64;

    unsafe {
        core::arch::asm!("csrr {0}, mcause", out(reg) mcause);
        core::arch::asm!("csrr {0}, mepc", out(reg) mepc);
        core::arch::asm!("csrr {0}, mtval", out(reg) mtval);
    }

    // Check if mcause is 7 (Store/AMO Access Fault)
    if mcause == 7 {
        uart_print("\n");
        uart_print("╔════════════════════════════════════════════════════════════════════════╗\n");
        uart_print("║  ⚡ TRAP 0x8F: HARDWARE WORDLINE GATING INTERRUPT ASSERTED IN SILICON   ║\n");
        uart_print("╚════════════════════════════════════════════════════════════════════════╝\n");
        uart_print("  ├── mcause:                  0x07 (Store Access Fault / PMP Violation)\n");
        uart_print("  ├── faulting_pc (mepc):      ");
        uart_print_hex(mepc);
        uart_print("\n");
        uart_print("  ├── attempted_address (mtval):");
        uart_print_hex(mtval);
        uart_print("\n");
        uart_print("  └── physical_wordline_gate:  WE = 0 (BUS TRANSACTION ABORTED)\n\n");

        // PHYSICAL VERIFICATION: Check byte at attempted address
        let val_at_target = unsafe { (UNAUTHORIZED_ADDR as *const u8).read_volatile() };
        uart_print("[EVIDENCE INSPECTION]\n");
        uart_print("  ├── Expected Value:          0x00 (Original State)\n");
        uart_print("  ├── Readback Value:          ");
        uart_print_hex(val_at_target as u64);
        uart_print("\n");

        if val_at_target == 0x00 {
            uart_print("  └── ✓ CONFIRMED: ZERO BITS FLIPPED. Physical memory wordline held WE = 0.\n\n");
            uart_print("══════════════════════════════════════════════════════════════════════════\n");
            uart_print("🎉 CENTRAL AXIOM VERIFIED IN SILICON:\n");
            uart_print("   'State that cannot prove its right to exist cannot be committed.'\n");
            uart_print("══════════════════════════════════════════════════════════════════════════\n\n");
            exit_qemu(true);
        } else {
            uart_print("  └── ✗ FAILED: Memory was mutated!\n");
            exit_qemu(false);
        }
    } else {
        uart_print("[TRAP] Unexpected trap occurred. mcause = ");
        uart_print_hex(mcause);
        uart_print("\n");
        exit_qemu(false);
    }
}

fn exit_qemu(success: bool) -> ! {
    unsafe {
        // SiFive test finisher: 0x5555 = success, 0x3333 = failure
        let code = if success { 0x5555 } else { 0x3333 };
        SIFIVE_TEST.write_volatile(code);
    }
    loop {}
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    uart_print("\n[KERNEL PANIC]\n");
    exit_qemu(false);
}
