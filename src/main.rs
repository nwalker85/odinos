//! Odin OS: Bare-Metal Microkernel Proof Harness (Phase B)
//!
//! Demonstrates hardware-enforced AST mask wordline gating via RISC-V PMP.
//! Boots in Machine Mode (M-Mode), configures PMP boundaries, drops to User Mode (U-Mode),
//! proves that in-bounds writes commit, and proves that out-of-bounds writes physically fault
//! with mcause = 0x07 (Store Access Fault), leaving zero bits flipped in silicon.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

mod deed;
mod trap;
mod interlock;

use deed::{TransitionDeed, DEED_SIZE};

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
    ".balign 4",
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

const DEED_DMA_ADDR: usize = 0x8004_0000;

static mut DYNAMIC_MODE: bool = false;
static mut DYNAMIC_TARGET_ADDR: usize = UNAUTHORIZED_ADDR;
static mut DYNAMIC_TARGET_VAL: u8 = 0xFF;

// Print primitives over UART (16550A)
fn uart_putc(c: u8) {
    unsafe {
        // Wait for transmitter empty
        while (UART0.add(5).read_volatile() & 0x20) == 0 {}
        UART0.write_volatile(c);
    }
}

fn uart_try_getc() -> Option<u8> {
    unsafe {
        if (UART0.add(5).read_volatile() & 0x01) != 0 {
            Some(UART0.read_volatile())
        } else {
            None
        }
    }
}

fn uart_getc() -> u8 {
    unsafe {
        while (UART0.add(5).read_volatile() & 0x01) == 0 {}
        UART0.read_volatile()
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

    // 3. Check for dynamic TransitionDeed in DRAM (loaded via QEMU device loader)
    let has_dma_deed = unsafe {
        let magic_ptr = DEED_DMA_ADDR as *const [u8; 2];
        *magic_ptr == deed::DEED_MAGIC
    };

    if has_dma_deed {
        uart_print("[AGENT BRIDGE] TransitionDeed detected in DRAM via Hardware Loader!\n");
        let deed_bytes = unsafe { &*(DEED_DMA_ADDR as *const [u8; DEED_SIZE]) };
        let target_addr = unsafe { *((DEED_DMA_ADDR + DEED_SIZE) as *const u64) } as usize;
        let target_val = unsafe { *((DEED_DMA_ADDR + DEED_SIZE + 8) as *const u8) };

        unsafe {
            DYNAMIC_MODE = true;
            DYNAMIC_TARGET_ADDR = target_addr;
            DYNAMIC_TARGET_VAL = target_val;
            (target_addr as *mut u8).write_volatile(0x00);
        }

        match TransitionDeed::from_bytes(deed_bytes) {
            Ok(deed) => {
                uart_print("[DEED] Verified TransitionDeed: anchor_id = ");
                uart_print_hex(deed.target_ast_anchor_id as u64);
                uart_print(", offset = ");
                uart_print_hex(deed.target_offset as u64);
                uart_print(", length = ");
                uart_print_hex(deed.target_length as u64);
                uart_print("\n");

                let mask_start = MASK_START + deed.target_offset as usize;
                let mask_end = mask_start + deed.target_length as usize;

                let pmpaddr0_val = UART_BASE >> 2;
                let pmpaddr1_val = UART_END >> 2;
                let pmpaddr2_val = CODE_BASE >> 2;
                let pmpaddr3_val = CODE_END >> 2;
                let pmpaddr4_val = mask_start >> 2;
                let pmpaddr5_val = mask_end >> 2;

                let pmpcfg0_val: u64 = (0x0B_u64 << 40) | (0x00_u64 << 32) | (0x0F_u64 << 24) | (0x0B_u64 << 8);

                unsafe {
                    core::arch::asm!(
                        "csrw pmpaddr0, {0}",
                        "csrw pmpaddr1, {1}",
                        "csrw pmpaddr2, {2}",
                        "csrw pmpaddr3, {3}",
                        "csrw pmpaddr4, {4}",
                        "csrw pmpaddr5, {5}",
                        "csrw pmpcfg0, {6}",
                        in(reg) pmpaddr0_val,
                        in(reg) pmpaddr1_val,
                        in(reg) pmpaddr2_val,
                        in(reg) pmpaddr3_val,
                        in(reg) pmpaddr4_val,
                        in(reg) pmpaddr5_val,
                        in(reg) pmpcfg0_val,
                    );
                }

                uart_print("[PMP] Dynamic hardware registers programmed in silicon:\n");
                uart_print("  ├── Region 0 [0x10000000 .. 0x10001000]: RW- (UART0 MMIO)\n");
                uart_print("  ├── Region 1 [0x80000000 .. 0x80020000]: RWX (Kernel / Task Text & Stack)\n");
                uart_print("  ├── Region 2 [");
                uart_print_hex(mask_start as u64);
                uart_print(" .. ");
                uart_print_hex(mask_end as u64);
                uart_print("]: RW- (Authorized TransitionDeed Slice)\n");
                uart_print("  └── Perimeter [All other addresses]:     --- (WE = 0 Gated)\n\n");
            }
            Err(_) => {
                uart_print("[DEED] ✗ FATAL: TransitionDeed cryptographic check failed!\n");
                exit_qemu(false);
            }
        }
    } else {
        // Static Autonomous Phase B Verification Mode
        let pmpaddr0_val = UART_BASE >> 2;
        let pmpaddr1_val = UART_END >> 2;
        let pmpaddr2_val = CODE_BASE >> 2;
        let pmpaddr3_val = CODE_END >> 2;
        let pmpaddr4_val = MASK_END >> 2;

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
    }

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
    if unsafe { DYNAMIC_MODE } {
        uart_print("[U-MODE] Dynamic Agent Task running in unprivileged User Mode.\n");
        let target_addr = unsafe { DYNAMIC_TARGET_ADDR };
        let target_val = unsafe { DYNAMIC_TARGET_VAL };

        uart_print("  ├── Target Memory Address:   ");
        uart_print_hex(target_addr as u64);
        uart_print("\n  ├── Target Mutation Value:   ");
        uart_print_hex(target_val as u64);
        uart_print("\n  └── Issuing store instruction: sb ...\n");

        unsafe {
            (target_addr as *mut u8).write_volatile(target_val);
            let readback = (target_addr as *const u8).read_volatile();
            if readback == target_val {
                uart_print("  └── ✓ PASS: Mutation authorized by TransitionDeed and committed in silicon!\n\n");
                uart_print("══════════════════════════════════════════════════════════════════════════\n");
                uart_print("🎉 HARDWARE DEED CONTRACT FULFILLED: IN-BOUNDS AGENT MUTATION COMMITTED\n");
                uart_print("══════════════════════════════════════════════════════════════════════════\n\n");
                core::arch::asm!("ecall");
            } else {
                uart_print("  └── ✗ FAIL: Unexpected readback.\n");
                core::arch::asm!("ecall");
            }
        }
    }

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

    // Check if mcause is 8 (Environment Call from U-mode)
    if mcause == 8 {
        exit_qemu(true);
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

        let target_addr = if unsafe { DYNAMIC_MODE } {
            unsafe { DYNAMIC_TARGET_ADDR }
        } else {
            UNAUTHORIZED_ADDR
        };

        // PHYSICAL VERIFICATION: Check byte at attempted address
        let val_at_target = unsafe { (target_addr as *const u8).read_volatile() };
        uart_print("[EVIDENCE INSPECTION]\n");
        uart_print("  ├── Target Probed Address:   ");
        uart_print_hex(target_addr as u64);
        uart_print("\n");
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
