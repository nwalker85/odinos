//! Odin OS: Sovereign Capability Microkernel (Phase B.1 Hardened)
//!
//! Features:
//! - Strict Privilege Separation (M-Mode vs U-Mode).
//! - W^X enforcement (User code is R-X, User stack is RW-, Kernel is unmapped in U-Mode).
//! - Revoked U-Mode MMIO access (UART0 MMIO is strictly M-Mode only).
//! - Hardware mscratch stack swapping with nested-trap privilege guard.
//! - Independent Deed Authority Verification (Monotonic Anti-Replay, Pinned Issuer, Payload Integrity Binding).
//! - 14-Case Adversarial Hardware Verification Matrix (with genuine bare-metal deed execution).
//! - Dynamic PASS/FAIL evaluation in M-Mode receipt generator.
//! - Structured JSON Evidence Receipts (distinguishing committed mutations from unmodified memory).

#![no_std]
#![no_main]
#![allow(dead_code)]

use core::panic::PanicInfo;

mod deed;
mod trap;
mod interlock;

use deed::{TransitionDeed, DeedError, DEED_SIZE};

core::arch::global_asm!(
    ".section .text.kernel",
    ".global _start",
    "_start:",
    // 1. Setup privileged kernel stack pointer
    "  la sp, __kernel_stack_top",
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
    ".section .text.kernel",
    ".balign 4",
    ".global trap_entry",
    "trap_entry:",
    // Check if trap originated from U-mode or nested M-mode
    "  csrrw sp, mscratch, sp",
    "  bnez sp, 1f",
    // Nested trap in M-mode: sp was 0, restore sp and continue on kernel stack
    "  csrrw sp, mscratch, sp",
    "1:",
    // Save all 31 registers (256-byte complete architectural register frame)
    "  addi sp, sp, -256",
    "  sd ra, 0(sp)",
    "  sd gp, 8(sp)",
    "  sd tp, 16(sp)",
    "  sd t0, 24(sp)",
    "  sd t1, 32(sp)",
    "  sd t2, 40(sp)",
    "  sd s0, 48(sp)",
    "  sd s1, 56(sp)",
    "  sd a0, 64(sp)",
    "  sd a1, 72(sp)",
    "  sd a2, 80(sp)",
    "  sd a3, 88(sp)",
    "  sd a4, 96(sp)",
    "  sd a5, 104(sp)",
    "  sd a6, 112(sp)",
    "  sd a7, 120(sp)",
    "  sd s2, 128(sp)",
    "  sd s3, 136(sp)",
    "  sd s4, 144(sp)",
    "  sd s5, 152(sp)",
    "  sd s6, 160(sp)",
    "  sd s7, 168(sp)",
    "  sd s8, 176(sp)",
    "  sd s9, 184(sp)",
    "  sd s10, 192(sp)",
    "  sd s11, 200(sp)",
    "  sd t3, 208(sp)",
    "  sd t4, 216(sp)",
    "  sd t5, 224(sp)",
    "  sd t6, 232(sp)",
    // Save previous user sp stored in mscratch
    "  csrr t0, mscratch",
    "  sd t0, 240(sp)",
    // Zero mscratch while running in M-mode (guards against nested traps)
    "  csrw mscratch, zero",
    // Pass pointer to saved register frame as first argument (a0)
    "  mv a0, sp",
    // Call privileged M-Mode trap handler
    "  call handle_trap",
    // Restore user sp to mscratch
    "  ld t0, 240(sp)",
    "  csrw mscratch, t0",
    // Restore complete register frame
    "  ld ra, 0(sp)",
    "  ld gp, 8(sp)",
    "  ld tp, 16(sp)",
    "  ld t0, 24(sp)",
    "  ld t1, 32(sp)",
    "  ld t2, 40(sp)",
    "  ld s0, 48(sp)",
    "  ld s1, 56(sp)",
    "  ld a0, 64(sp)",
    "  ld a1, 72(sp)",
    "  ld a2, 80(sp)",
    "  ld a3, 88(sp)",
    "  ld a4, 96(sp)",
    "  ld a5, 104(sp)",
    "  ld a6, 112(sp)",
    "  ld a7, 120(sp)",
    "  ld s2, 128(sp)",
    "  ld s3, 136(sp)",
    "  ld s4, 144(sp)",
    "  ld s5, 152(sp)",
    "  ld s6, 160(sp)",
    "  ld s7, 168(sp)",
    "  ld s8, 176(sp)",
    "  ld s9, 184(sp)",
    "  ld s10, 192(sp)",
    "  ld s11, 200(sp)",
    "  ld t3, 208(sp)",
    "  ld t4, 216(sp)",
    "  ld t5, 224(sp)",
    "  ld t6, 232(sp)",
    "  addi sp, sp, 256",
    // Restore user sp and re-arm mscratch with kernel stack
    "  csrrw sp, mscratch, sp",
    "  mret"
);

extern "C" {
    fn trap_entry();
    static __kernel_start: u8;
    static __kernel_end: u8;
    static __kernel_stack_top: u8;
    static __user_text_start: u8;
    static __user_text_end: u8;
    static __user_stack_start: u8;
    static __user_stack_top: u8;
    static __ast_buffer_start: u8;
    static __ast_buffer_end: u8;
    static __deed_dma_start: u8;
}

// Hardware MMIO
const UART0: *mut u8 = 0x1000_0000 as *mut u8;
const SIFIVE_TEST: *mut u32 = 0x10_0000 as *mut u32;

// Memory Regions
const USER_TEXT_START: usize = 0x8001_0000;
const USER_TEXT_END: usize = 0x8001_8000;
const USER_STACK_START: usize = 0x8001_8000;
const USER_STACK_END: usize = 0x8002_0000;
const AST_BUFFER_BASE: usize = 0x8002_0000;
const AST_BUFFER_END: usize = 0x8003_0000;
const DEED_DMA_ADDR: usize = 0x8004_0000;

// Trap State Tracker
static mut TRAP_OCCURRED: bool = false;
static mut LAST_MCAUSE: u64 = 0;
static mut LAST_MEPC: u64 = 0;
static mut LAST_MTVAL: u64 = 0;
static mut ORIGINAL_KERNEL_CODE_BYTE: u8 = 0;
static mut ORIGINAL_USER_CODE_BYTE: u8 = 0;

// Current Active Test Parameters
static mut CURRENT_EXPECT_FAULT: bool = false;
static mut CURRENT_TEST_WIDTH: usize = 1;

// Kernel State
static mut LAST_CONSUMED_SEQUENCE: u32 = 0;
static mut ACTIVE_LEASE_START: usize = 0x8002_0040;
static mut ACTIVE_LEASE_END: usize = 0x8002_0060;

// UART Printing (Privileged M-Mode Only)
fn uart_putc(c: u8) {
    unsafe {
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

fn uart_print_dec(mut val: u64) {
    if val == 0 {
        uart_putc(b'0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = 0;
    while val > 0 {
        buf[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        uart_putc(buf[i]);
    }
}

fn setup_pmp() {
    let lease_start = unsafe { ACTIVE_LEASE_START };
    let lease_end = unsafe { ACTIVE_LEASE_END };

    let pmpaddr0_val = USER_TEXT_START >> 2;
    let pmpaddr1_val = USER_TEXT_END >> 2;
    let pmpaddr2_val = USER_STACK_END >> 2;
    let pmpaddr3_val = lease_start >> 2;
    let pmpaddr4_val = lease_end >> 2;

    let pmpcfg0_val: u64 = if lease_start < lease_end && lease_start >= AST_BUFFER_BASE && lease_end <= AST_BUFFER_END {
        (0x0B_u64 << 32) | // Entry 4: TOR | R | W (Authorized Lease)
        (0x00_u64 << 24) | // Entry 3: OFF (Pre-lease gap)
        (0x0B_u64 << 16) | // Entry 2: TOR | R | W (User Stack)
        (0x0D_u64 << 8)  | // Entry 1: TOR | R | X (User Task Executable)
        0x00_u64           // Entry 0: OFF
    } else {
        (0x00_u64 << 32) | // Entry 4: OFF (Lease revoked/expired)
        (0x00_u64 << 24) | // Entry 3: OFF
        (0x0B_u64 << 16) | // Entry 2: TOR | R | W (User Stack)
        (0x0D_u64 << 8)  | // Entry 1: TOR | R | X (User Task Executable)
        0x00_u64           // Entry 0: OFF
    };

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
}

#[no_mangle]
pub extern "C" fn kmain() -> ! {
    uart_print("\n");
    uart_print("╔════════════════════════════════════════════════════════════════════════╗\n");
    uart_print("║     ODIN OS: PHASE B.2 ADVERSARIAL ASSURANCE & EVIDENCE INTEGRITY      ║\n");
    uart_print("║     Genuine Ed25519 Root Verification, W^X & Lease Expiration Suite   ║\n");
    uart_print("╚════════════════════════════════════════════════════════════════════════╝\n\n");

    // 1. Install M-Mode trap handler
    unsafe {
        core::arch::asm!("csrw mtvec, {0}", in(reg) (trap_entry as *const () as usize));
    }
    uart_print("[INIT] M-Mode trap vector registered at trap_entry (.balign 4).\n");

    // 2. Setup mscratch with kernel stack for safe privilege switching
    unsafe {
        core::arch::asm!("csrw mscratch, {0}", in(reg) (&__kernel_stack_top as *const u8 as usize));
    }
    uart_print("[INIT] Hardware mscratch armed with privileged kernel stack.\n");

    // 3. Process TransitionDeed from Hardware DMA Loader if present
    let has_dma_deed = unsafe {
        let magic_ptr = DEED_DMA_ADDR as *const [u8; 2];
        *magic_ptr == deed::DEED_MAGIC
    };

    if has_dma_deed {
        uart_print("[DEED] Hardware DMA loader detected candidate TransitionDeed at 0x80040000.\n");
        let deed_bytes = unsafe { &*(DEED_DMA_ADDR as *const [u8; DEED_SIZE]) };
        match TransitionDeed::from_bytes(deed_bytes) {
            Ok(deed) => {
                let last_seq = unsafe { LAST_CONSUMED_SEQUENCE };
                match deed.verify_authority(last_seq, (AST_BUFFER_END - AST_BUFFER_BASE) as u32) {
                    Ok(()) => {
                        uart_print("  ├── Authority Verification:  PASS (Issuer Authenticated, Anti-Replay Valid)\n");
                        unsafe {
                            LAST_CONSUMED_SEQUENCE = deed.sequence;
                            ACTIVE_LEASE_START = AST_BUFFER_BASE + deed.target_offset as usize;
                            ACTIVE_LEASE_END = ACTIVE_LEASE_START + deed.target_length as usize;
                        }
                    }
                    Err(e) => {
                        uart_print("  └── ✗ REJECTED: Authority verification failed: ");
                        match e {
                            DeedError::UntrustedIssuer => uart_print("UntrustedIssuer (Agent Request != Authority Grant)\n"),
                            DeedError::ReplayDetected => uart_print("ReplayDetected (Sequence Stale)\n"),
                            DeedError::PayloadTampered => uart_print("PayloadTampered (Digest Mismatch)\n"),
                            DeedError::InvalidSignature => uart_print("InvalidSignature (Marker Corrupted)\n"),
                            DeedError::OutOfBoundsLease => uart_print("OutOfBoundsLease\n"),
                            _ => uart_print("ProtocolError\n"),
                        }
                        exit_qemu(false);
                    }
                }
            }
            Err(_) => {
                uart_print("  └── ✗ REJECTED: Malformed TransitionDeed packet.\n");
                exit_qemu(false);
            }
        }
    } else {
        // Standard Authorized Lease Window [0x80020040 .. 0x80020060] (32 bytes)
        unsafe {
            ACTIVE_LEASE_START = 0x8002_0040;
            ACTIVE_LEASE_END = 0x8002_0060;
        }
    }

    // 4. Program Hardened Physical Memory Protection (PMP) Registers
    setup_pmp();

    uart_print("[PMP] Hardened privilege boundary programmed in CPU hardware:\n");
    uart_print("  ├── [0x10000000 .. 0x10001000]: --- (UART0 MMIO: Revoked from U-Mode, M-Mode Only)\n");
    uart_print("  ├── [0x80000000 .. 0x80010000]: --- (Privileged Kernel: Code, Stack, Keys - Default Deny)\n");
    uart_print("  ├── [0x80010000 .. 0x80018000]: R-X (Agent Task Executable: Immutable)\n");
    uart_print("  ├── [0x80018000 .. 0x80020000]: RW- (Agent Task Stack: Non-Executable)\n");
    uart_print("  ├── [0x80020000 .. ");
    uart_print_hex(unsafe { ACTIVE_LEASE_START } as u64);
    uart_print("]: --- (Pre-Lease AST Boundary: Gated)\n");
    uart_print("  ├── [");
    uart_print_hex(unsafe { ACTIVE_LEASE_START } as u64);
    uart_print(" .. ");
    uart_print_hex(unsafe { ACTIVE_LEASE_END } as u64);
    uart_print("]: RW- (Explicitly Authorized TransitionDeed Slice)\n");
    uart_print("  └── Perimeter [All other addresses]:     --- (Hardware Default Deny, WE = 0)\n\n");

    // 5. Zero out test memory locations before launching U-Mode
    unsafe {
        ORIGINAL_KERNEL_CODE_BYTE = (0x8000_0000 as *const u8).read_volatile();
        ORIGINAL_USER_CODE_BYTE = (0x8001_0000 as *const u8).read_volatile();
        (0x8002_003F as *mut u8).write_volatile(0x00);
        (0x8002_0040 as *mut u8).write_volatile(0x00);
        (0x8002_005E as *mut u8).write_volatile(0x00);
        (0x8002_005F as *mut u8).write_volatile(0x00);
        (0x8002_0060 as *mut u8).write_volatile(0x00);
        (0x8002_0061 as *mut u8).write_volatile(0x00);
        (0x8003_0000 as *mut u8).write_volatile(0x00);
    }

    // 6. Transition to U-Mode with isolated user stack
    uart_print("[TRANSITION] Setting mstatus.MPP = U-Mode, switching sp to __user_stack_top...\n");
    uart_print("══════════════════════════════════════════════════════════════════════════\n");
    uart_print("▶ EXECUTING ADVERSARIAL VERIFICATION MATRIX (17 Invariant Tests)\n");
    uart_print("══════════════════════════════════════════════════════════════════════════\n\n");

    unsafe {
        // Clear MPP bits 12:11 to 0b00 (U-Mode)
        let mut mstatus: usize;
        core::arch::asm!("csrr {0}, mstatus", out(reg) mstatus);
        mstatus &= !(0b11 << 11);
        core::arch::asm!("csrw mstatus, {0}", in(reg) mstatus);

        // Set mepc to user task entry point
        core::arch::asm!("csrw mepc, {0}", in(reg) (user_mode_adversarial_suite as *const () as usize));

        // Switch sp to unprivileged user stack
        core::arch::asm!("la sp, __user_stack_top");

        // Drop privilege to U-mode
        core::arch::asm!("mret");
    }

    loop {}
}

// ----------------------------------------------------------------------------
const TEST_NAMES: [&str; 18] = [
    "RESERVED",
    "EXACT_LOWER_BOUND",
    "EXACT_UPPER_BOUND_MINUS_ONE",
    "ONE_BYTE_BELOW_LEASE",
    "ONE_BYTE_ABOVE_LEASE",
    "KERNEL_CODE_WRITE",
    "KERNEL_STACK_WRITE",
    "USER_CODE_WRITE_WX",
    "USER_STACK_EXECUTE_WX",
    "UNMAPPED_PERIMETER_WRITE",
    "MULTIBYTE_OVERLAP_CROSSING",
    "FORGED_DEED_UNTRUSTED_ISSUER",
    "REPLAYED_DEED_SEQUENCE",
    "FORGED_DEED_ED25519_INVALID_SIGNATURE",
    "DEED_TAMPERED_METADATA_ED25519",
    "U_MODE_CSR_TAMPER_PMPCFG0",
    "EXPIRED_LEASE_TEMPORAL_REVOCATION",
    "U_MODE_UART_MMIO_WRITE",
];

// ----------------------------------------------------------------------------
// UNPRIVILEGED USER-MODE TASK (Placed strictly in .user_text)
// ----------------------------------------------------------------------------

#[inline(always)]
unsafe fn user_write_u8(addr: usize, val: u8) {
    core::arch::asm!(
        "sb {0}, 0({1})",
        in(reg) val,
        in(reg) addr,
    );
}

#[inline(always)]
unsafe fn user_write_u32(addr: usize, val: u32) {
    core::arch::asm!(
        "sw {0}, 0({1})",
        in(reg) val,
        in(reg) addr,
    );
}

#[link_section = ".user_text"]
#[inline(always)]
unsafe fn user_zero_buffer(ptr: *mut u8, len: usize) {
    let mut i = 0;
    while i < len {
        core::arch::asm!(
            "sb zero, 0({0})",
            in(reg) (ptr.add(i)),
        );
        i += 1;
    }
}

#[link_section = ".user_text"]
#[inline(always)]
unsafe fn user_write_offset_u8(base: *mut u8, offset: usize, val: u8) {
    core::arch::asm!(
        "sb {0}, 0({1})",
        in(reg) val,
        in(reg) (base.add(offset)),
    );
}

#[link_section = ".user_text"]
#[inline(always)]
unsafe fn user_write_offset_u32(base: *mut u8, offset: usize, val: u32) {
    let b0 = (val & 0xFF) as u8;
    let b1 = ((val >> 8) & 0xFF) as u8;
    let b2 = ((val >> 16) & 0xFF) as u8;
    let b3 = ((val >> 24) & 0xFF) as u8;
    user_write_offset_u8(base, offset, b0);
    user_write_offset_u8(base, offset + 1, b1);
    user_write_offset_u8(base, offset + 2, b2);
    user_write_offset_u8(base, offset + 3, b3);
}

#[allow(dead_code)]
#[link_section = ".user_text"]
#[inline(always)]
unsafe fn user_write_sign_tag(base: *mut u8, offset: usize) {
    user_write_offset_u8(base, offset, 0x53);     // 'S'
    user_write_offset_u8(base, offset + 1, 0x49); // 'I'
    user_write_offset_u8(base, offset + 2, 0x47); // 'G'
    user_write_offset_u8(base, offset + 3, 0x4E); // 'N'
}

#[link_section = ".user_text"]
#[inline(always)]
unsafe fn user_write_untrusted_issuer(base: *mut u8, offset: usize) {
    user_write_offset_u8(base, offset + 0, b'u');
    user_write_offset_u8(base, offset + 1, b'n');
    user_write_offset_u8(base, offset + 2, b't');
    user_write_offset_u8(base, offset + 3, b'r');
    user_write_offset_u8(base, offset + 4, b'u');
    user_write_offset_u8(base, offset + 5, b's');
    user_write_offset_u8(base, offset + 6, b't');
    user_write_offset_u8(base, offset + 7, b'e');
    user_write_offset_u8(base, offset + 8, b'd');
    user_write_offset_u8(base, offset + 9, b'_');
    user_write_offset_u8(base, offset + 10, b'a');
    user_write_offset_u8(base, offset + 11, b'g');
    user_write_offset_u8(base, offset + 12, b'e');
    user_write_offset_u8(base, offset + 13, b'n');
    user_write_offset_u8(base, offset + 14, b't');
    user_write_offset_u8(base, offset + 15, b'_');
}

#[link_section = ".user_text"]
#[inline(always)]
unsafe fn user_write_root_issuer(base: *mut u8, offset: usize) {
    user_write_offset_u8(base, offset + 0, b'd');
    user_write_offset_u8(base, offset + 1, b'i');
    user_write_offset_u8(base, offset + 2, b'd');
    user_write_offset_u8(base, offset + 3, b':');
    user_write_offset_u8(base, offset + 4, b'o');
    user_write_offset_u8(base, offset + 5, b'd');
    user_write_offset_u8(base, offset + 6, b'i');
    user_write_offset_u8(base, offset + 7, b'n');
    user_write_offset_u8(base, offset + 8, b':');
    user_write_offset_u8(base, offset + 9, b'r');
    user_write_offset_u8(base, offset + 10, b'o');
    user_write_offset_u8(base, offset + 11, b'o');
    user_write_offset_u8(base, offset + 12, b't');
    user_write_offset_u8(base, offset + 13, b':');
    user_write_offset_u8(base, offset + 14, b'0');
    user_write_offset_u8(base, offset + 15, b'1');
}

#[link_section = ".user_text"]
#[inline(always)]
unsafe fn user_write_genuine_v2_signature(base: *mut u8, offset: usize) {
    user_write_offset_u32(base, offset + 0, 0x07B324C3);
    user_write_offset_u32(base, offset + 4, 0x5F121B8E);
    user_write_offset_u32(base, offset + 8, 0xC7513103);
    user_write_offset_u32(base, offset + 12, 0x8CF72845);
    user_write_offset_u32(base, offset + 16, 0x28F712AC);
    user_write_offset_u32(base, offset + 20, 0xCA7A69A9);
    user_write_offset_u32(base, offset + 24, 0x58EA3D26);
    user_write_offset_u32(base, offset + 28, 0x348CF105);
    user_write_offset_u32(base, offset + 32, 0x9DC94BCC);
    user_write_offset_u32(base, offset + 36, 0x113F697C);
    user_write_offset_u32(base, offset + 40, 0x47306441);
    user_write_offset_u32(base, offset + 44, 0xE14A6280);
    user_write_offset_u32(base, offset + 48, 0xD7A115BA);
    user_write_offset_u32(base, offset + 52, 0x54BEE401);
    user_write_offset_u32(base, offset + 56, 0xBE9F13F1);
    user_write_offset_u32(base, offset + 60, 0x072BD7F5);
}

#[link_section = ".user_text"]
#[inline(always)]
fn sys_revoke_lease() {
    unsafe {
        core::arch::asm!(
            "li a7, 13",
            "ecall",
            out("a7") _,
        );
    }
}

#[link_section = ".user_text"]
#[no_mangle]
extern "C" fn user_mode_adversarial_suite() -> ! {
    // Test 1: Exact lower bound (0x80020040) -> Expected: Authorized write (PASS)
    emit_receipt_start(1, 0x8002_0040, 1, false);
    unsafe { user_write_u8(0x8002_0040, 0x41); }
    emit_receipt_finish(1, 0x8002_0040, 0x41, 0x41);

    // Test 2: Exact upper bound minus one (0x8002005F) -> Expected: Authorized write (PASS)
    emit_receipt_start(2, 0x8002_005F, 1, false);
    unsafe { user_write_u8(0x8002_005F, 0x42); }
    emit_receipt_finish(2, 0x8002_005F, 0x42, 0x42);

    // Test 3: One byte below lease (0x8002003F) -> Expected: Hardware FAULT (mcause = 7)
    emit_receipt_start(3, 0x8002_003F, 1, true);
    unsafe { user_write_u8(0x8002_003F, 0xEE); }
    emit_receipt_finish(3, 0x8002_003F, 0x00, 0x00);

    // Test 4: One byte above lease (0x80020060) -> Expected: Hardware FAULT (mcause = 7)
    emit_receipt_start(4, 0x8002_0060, 1, true);
    unsafe { user_write_u8(0x8002_0060, 0xEE); }
    emit_receipt_finish(4, 0x8002_0060, 0x00, 0x00);

    // Test 5: Kernel code write (0x80000000) -> Expected: Hardware FAULT (mcause = 7)
    emit_receipt_start(5, 0x8000_0000, 1, true);
    unsafe { user_write_u8(0x8000_0000, 0xEE); }
    emit_receipt_finish(5, 0x8000_0000, 0x00, 0x00);

    // Test 6: Kernel stack write (0x8000FFF8) -> Expected: Hardware FAULT (mcause = 7)
    emit_receipt_start(6, 0x8000_FFF8, 1, true);
    unsafe { user_write_u8(0x8000_FFF8, 0xEE); }
    emit_receipt_finish(6, 0x8000_FFF8, 0x00, 0x00);

    // Test 7: User code write (0x80010000) -> Expected: Hardware FAULT (W^X violation)
    emit_receipt_start(7, 0x8001_0000, 1, true);
    unsafe { user_write_u8(0x8001_0000, 0xEE); }
    emit_receipt_finish(7, 0x8001_0000, 0x00, 0x00);

    // Test 8: User stack execution attempt (0x80018100) -> Expected: Instruction Access Fault (mcause = 1, W^X enforcement)
    emit_receipt_start(8, 0x8001_8100, 0, true);
    unsafe {
        // jalr zero, 0(ra) opcode is 0x00008067
        user_write_u32(0x8001_8100, 0x0000_8067);
        core::arch::asm!(
            "li t0, 0x80018100",
            "jalr ra, 0(t0)",
            out("t0") _,
            out("ra") _,
        );
    }
    emit_receipt_finish(8, 0, 0, 0);

    // Test 9: Unmapped perimeter write (0x80030000) -> Expected: Hardware FAULT
    emit_receipt_start(9, 0x8003_0000, 1, true);
    unsafe { user_write_u8(0x8003_0000, 0xEE); }
    emit_receipt_finish(9, 0x8003_0000, 0x00, 0x00);

    // Test 10: Multi-byte boundary crossing (sw at 0x8002005E extending to 0x80020062)
    // Clear in-bounds lease byte 0x8002005F back to 0x00 to establish clean 4-byte baseline
    unsafe { user_write_u8(0x8002_005F, 0x00); }
    emit_receipt_start(10, 0x8002_005E, 4, true);
    unsafe { user_write_u32(0x8002_005E, 0xDEAD_BEEF); }
    emit_receipt_finish(10, 0x8002_005E, 0x00, 0x00);

    #[repr(C, align(64))]
    struct AlignedDeed {
        data: [u8; DEED_SIZE],
    }

    let mut deed_storage = core::mem::MaybeUninit::<AlignedDeed>::uninit();
    let ptr = deed_storage.as_mut_ptr() as *mut u8;

    // Test 11: Forged TransitionDeed with untrusted issuer identity
    emit_receipt_start(11, 0, 0, false);
    unsafe {
        user_zero_buffer(ptr, DEED_SIZE);
        user_write_offset_u8(ptr, 0, 0x59);
        user_write_offset_u8(ptr, 1, 0x47);
        user_write_offset_u8(ptr, 2, 0x02); // Version 2
        user_write_offset_u32(ptr, 4, 100);
        user_write_untrusted_issuer(ptr, 8);
        user_write_offset_u32(ptr, 0x68, 1000);
        user_write_offset_u32(ptr, 0x74, 10);
        user_write_offset_u32(ptr, 0x78, 10);
    }
    let err_code_11 = sys_verify_deed(ptr);
    // Expected: 1 (DeedError::UntrustedIssuer)
    emit_receipt_finish(11, 0, err_code_11 as u8, 1);

    // Test 12: Replayed TransitionDeed with stale sequence
    emit_receipt_start(12, 0, 0, false);
    unsafe {
        user_zero_buffer(ptr, DEED_SIZE);
        user_write_offset_u8(ptr, 0, 0x59);
        user_write_offset_u8(ptr, 1, 0x47);
        user_write_offset_u8(ptr, 2, 0x02);
        user_write_offset_u32(ptr, 4, 0); // Stale sequence <= LAST_CONSUMED_SEQUENCE
        user_write_root_issuer(ptr, 8);
        user_write_offset_u32(ptr, 0x68, 1000);
        user_write_offset_u32(ptr, 0x74, 10);
        user_write_offset_u32(ptr, 0x78, 10);
    }
    let err_code_12 = sys_verify_deed(ptr);
    // Expected: 2 (DeedError::ReplayDetected)
    emit_receipt_finish(12, 0, err_code_12 as u8, 2);

    // Test 13: Forged Deed with invalid/garbage Ed25519 signature
    emit_receipt_start(13, 0, 0, false);
    unsafe {
        user_zero_buffer(ptr, DEED_SIZE);
        user_write_offset_u8(ptr, 0, 0x59);
        user_write_offset_u8(ptr, 1, 0x47);
        user_write_offset_u8(ptr, 2, 0x02);
        user_write_offset_u32(ptr, 4, 500);
        user_write_root_issuer(ptr, 8);
        user_write_offset_u32(ptr, 0x68, 1000);
        user_write_offset_u32(ptr, 0x74, 10);
        user_write_offset_u32(ptr, 0x78, 10);
        // Fill signature with 0xAA (garbage)
        let mut i = 0;
        while i < 64 {
            user_write_offset_u8(ptr, 0x9C + i, 0xAA);
            i += 1;
        }
    }
    let err_code_13 = sys_verify_deed(ptr);
    // Expected: 4 (DeedError::InvalidSignature)
    emit_receipt_finish(13, 0, err_code_13 as u8, 4);

    // Test 14: Deed metadata tampered after genuine Ed25519 signature generated
    emit_receipt_start(14, 0, 0, false);
    unsafe {
        user_zero_buffer(ptr, DEED_SIZE);
        user_write_offset_u8(ptr, 0, 0x59);
        user_write_offset_u8(ptr, 1, 0x47);
        user_write_offset_u8(ptr, 2, 0x02);
        user_write_offset_u32(ptr, 4, 42);
        user_write_root_issuer(ptr, 8);
        user_write_offset_u32(ptr, 0x68, 1000);
        user_write_offset_u8(ptr, 0x6C, 1);
        user_write_offset_u32(ptr, 0x70, 104);
        user_write_offset_u32(ptr, 0x74, 99); // TAMPERED: was 50 when signed!
        user_write_offset_u32(ptr, 0x78, 20);

        // Copy genuine signature matching original payload (offset=50)
        user_write_genuine_v2_signature(ptr, 0x9C);
    }
    let err_code_14 = sys_verify_deed(ptr);
    // Expected: 4 (DeedError::InvalidSignature)
    emit_receipt_finish(14, 0, err_code_14 as u8, 4);

    // Test 15: U-Mode Privileged CSR access attempt (csrr t0, pmpcfg0) -> Expected: Illegal Instruction (mcause = 2)
    emit_receipt_start(15, 0, 0, true);
    unsafe {
        core::arch::asm!("csrr t0, pmpcfg0");
    }
    emit_receipt_finish(15, 0, 0, 0);

    // Test 16: Expired capability temporal revocation
    emit_receipt_start(16, 0x8002_0040, 1, true);
    // Revoke active lease via microkernel syscall
    sys_revoke_lease();
    // Attempt store to previously valid lease address 0x80020040 -> Expected: Hardware FAULT (mcause = 7)
    unsafe { user_write_u8(0x8002_0040, 0xEE); }
    emit_receipt_finish(16, 0x8002_0040, 0x41, 0x41);

    // Test 17: U-Mode attempt to access UART0 MMIO (0x10000000) -> Expected: Hardware FAULT (mcause = 7)
    emit_receipt_start(17, 0x1000_0000, 1, true);
    unsafe { user_write_u8(0x1000_0000, 0x58); }
    emit_receipt_finish(17, 0x1000_0000, 0x00, 0x00);

    // Finish test suite via clean microkernel exit syscall
    sys_exit(0);
}

// ----------------------------------------------------------------------------
// MICROKERNEL SYSCALL INTERFACE (ecall)
// ----------------------------------------------------------------------------

#[link_section = ".user_text"]
#[inline(always)]
fn sys_exit(code: usize) -> ! {
    unsafe {
        core::arch::asm!(
            "li a7, 2",
            "mv a0, {0}",
            "ecall",
            in(reg) code,
            options(noreturn)
        );
    }
}

#[link_section = ".user_text"]
#[inline(always)]
fn emit_receipt_start(id: usize, addr: usize, width: usize, expect_fault: bool) {
    unsafe {
        core::arch::asm!(
            "li a7, 10",
            "mv a0, {0}",
            "mv a1, {1}",
            "mv a2, {2}",
            "mv a3, {3}",
            "ecall",
            in(reg) id,
            in(reg) addr,
            in(reg) width,
            in(reg) (if expect_fault { 1usize } else { 0usize }),
            out("a7") _,
            out("a0") _,
            out("a1") _,
            out("a2") _,
            out("a3") _,
        );
    }
}

#[link_section = ".user_text"]
#[inline(always)]
fn emit_receipt_finish(id: usize, probed_addr: usize, readback: u8, expected: u8) {
    unsafe {
        core::arch::asm!(
            "li a7, 11",
            "mv a0, {0}",
            "mv a1, {1}",
            "mv a2, {2}",
            "mv a3, {3}",
            "ecall",
            in(reg) id,
            in(reg) probed_addr,
            in(reg) (readback as usize),
            in(reg) (expected as usize),
            out("a7") _,
            out("a0") _,
            out("a1") _,
            out("a2") _,
            out("a3") _,
        );
    }
}

#[link_section = ".user_text"]
#[inline(always)]
fn sys_verify_deed(deed_ptr: *const u8) -> usize {
    let result: usize;
    unsafe {
        core::arch::asm!(
            "li a7, 12",
            "mv a0, {0}",
            "ecall",
            "mv {1}, a0",
            in(reg) deed_ptr,
            out(reg) result,
            out("a7") _,
            out("a0") _,
        );
    }
    result
}

// ----------------------------------------------------------------------------
// PRIVILEGED M-MODE TRAP HANDLER
// ----------------------------------------------------------------------------

#[repr(C)]
struct TrapFrame {
    ra: usize,  // 0
    gp: usize,  // 8
    tp: usize,  // 16
    t0: usize,  // 24
    t1: usize,  // 32
    t2: usize,  // 40
    s0: usize,  // 48
    s1: usize,  // 56
    a0: usize,  // 64
    a1: usize,  // 72
    a2: usize,  // 80
    a3: usize,  // 88
    a4: usize,  // 96
    a5: usize,  // 104
    a6: usize,  // 112
    a7: usize,  // 120
    s2: usize,  // 128
    s3: usize,  // 136
    s4: usize,  // 144
    s5: usize,  // 152
    s6: usize,  // 160
    s7: usize,  // 168
    s8: usize,  // 176
    s9: usize,  // 184
    s10: usize, // 192
    s11: usize, // 200
    t3: usize,  // 208
    t4: usize,  // 216
    t5: usize,  // 224
    t6: usize,  // 232
}

#[no_mangle]
extern "C" fn handle_trap(tf: *const TrapFrame) {
    let frame = unsafe { &*tf };
    let mcause: u64;
    let mepc: u64;
    let mtval: u64;

    unsafe {
        core::arch::asm!("csrr {0}, mcause", out(reg) mcause);
        core::arch::asm!("csrr {0}, mepc", out(reg) mepc);
        core::arch::asm!("csrr {0}, mtval", out(reg) mtval);
    }

    // 1. Environment Call from U-Mode (ecall, mcause = 8)
    if mcause == 8 {
        let a0 = frame.a0;
        let a1 = frame.a1;
        let a2 = frame.a2;
        let a3 = frame.a3;
        let a7 = frame.a7;

        if a7 == 2 {
            // SYS_EXIT
            uart_print("\n══════════════════════════════════════════════════════════════════════════\n");
            uart_print("🎉 ALL 17 ADVERSARIAL INVARIANT TESTS PASSED WITH 100% HARDWARE ENFORCEMENT\n");
            uart_print("══════════════════════════════════════════════════════════════════════════\n\n");
            exit_qemu(true);
        } else if a7 == 10 {
            // RECEIPT START
            unsafe {
                TRAP_OCCURRED = false;
                LAST_MCAUSE = 0;
                CURRENT_EXPECT_FAULT = a3 != 0;
                CURRENT_TEST_WIDTH = a2;
            }
            uart_print("{\n  \"test_id\": ");
            uart_print_dec(a0 as u64);
            uart_print(",\n  \"test_name\": \"");
            if a0 < TEST_NAMES.len() {
                uart_print(TEST_NAMES[a0]);
            } else {
                uart_print("UNKNOWN");
            }
            uart_print("\",\n  \"target_address\": \"");
            uart_print_hex(a1 as u64);
            uart_print("\",\n  \"access_width\": ");
            uart_print_dec(a2 as u64);
            uart_print(",\n  \"expected_fault\": ");
            if a3 != 0 { uart_print("true"); } else { uart_print("false"); }
            uart_print(",\n");
        } else if a7 == 11 {
            // RECEIPT FINISH
            let trap = unsafe { TRAP_OCCURRED };
            let mcause_val = unsafe { LAST_MCAUSE };
            let expect_fault = unsafe { CURRENT_EXPECT_FAULT };
            let test_width = unsafe { CURRENT_TEST_WIDTH };

            let mut all_bytes_unmodified = true;
            let readback_val = if a1 != 0 {
                if test_width == 4 {
                    // Check all 4 bytes across the attempted access span
                    for offset in 0..4 {
                        let b = unsafe { ((a1 + offset) as *const u8).read_volatile() };
                        if b != 0 {
                            all_bytes_unmodified = false;
                        }
                    }
                    unsafe { (a1 as *const u8).read_volatile() }
                } else {
                    unsafe { (a1 as *const u8).read_volatile() }
                }
            } else {
                a2 as u8
            };

            let expected_val = if a0 == 5 {
                unsafe { ORIGINAL_KERNEL_CODE_BYTE }
            } else if a0 == 7 {
                unsafe { ORIGINAL_USER_CODE_BYTE }
            } else {
                a3 as u8
            };

            // Dynamic assertion check: pass is asserted from actual observed outcomes
            let fault_matches = trap == expect_fault;
            let value_matches = if a1 != 0 && test_width == 4 && trap {
                all_bytes_unmodified
            } else {
                readback_val == expected_val
            };
            let test_passed = fault_matches && value_matches;

            uart_print("  \"hardware_fault\": ");
            if trap { uart_print("true"); } else { uart_print("false"); }
            uart_print(",\n  \"mcause\": \"");
            uart_print_hex(mcause_val);
            uart_print("\",\n  \"probed_address\": \"");
            uart_print_hex(a1 as u64);
            uart_print("\",\n  \"readback_value\": \"");
            uart_print_hex(readback_val as u64);
            uart_print("\",\n  \"expected_value\": \"");
            uart_print_hex(expected_val as u64);
            uart_print("\",\n  \"mutation_committed\": ");
            if a1 != 0 && !trap && (readback_val == expected_val) && (expected_val != 0) {
                uart_print("true");
            } else {
                uart_print("false");
            }
            uart_print(",\n  \"memory_unmodified\": ");
            if a1 == 0 {
                uart_print("true");
            } else if trap && value_matches {
                uart_print("true");
            } else {
                uart_print("false");
            }
            uart_print(",\n  \"status\": \"");
            if test_passed {
                uart_print("PASS");
            } else {
                uart_print("FAIL");
            }
            uart_print("\"\n},\n");

            if !test_passed {
                uart_print("\n[VERIFICATION FATAL] Test ");
                uart_print_dec(a0 as u64);
                uart_print(" failed invariant assertion! Halting.\n");
                exit_qemu(false);
            }
        } else if a7 == 12 {
            // SYS_VERIFY_DEED
            let deed_ptr = a0 as usize;
            let res_code: usize = if deed_ptr >= USER_STACK_START && deed_ptr + DEED_SIZE <= USER_STACK_END {
                let deed_bytes = unsafe { &*(deed_ptr as *const [u8; DEED_SIZE]) };
                match TransitionDeed::from_bytes(deed_bytes) {
                    Ok(deed) => {
                        let last_seq = unsafe { LAST_CONSUMED_SEQUENCE };
                        match deed.verify_authority(last_seq, (AST_BUFFER_END - AST_BUFFER_BASE) as u32) {
                            Ok(()) => 0,
                            Err(DeedError::UntrustedIssuer) => 1,
                            Err(DeedError::ReplayDetected) => 2,
                            Err(DeedError::PayloadTampered) => 3,
                            Err(DeedError::InvalidSignature) => 4,
                            Err(DeedError::OutOfBoundsLease) => 5,
                            _ => 99,
                        }
                    }
                    Err(_) => 98,
                }
            } else {
                97 // Pointer out of user bounds
            };

            unsafe {
                let frame_mut = tf as *mut TrapFrame;
                (*frame_mut).a0 = res_code;
            }
        } else if a7 == 13 {
            // SYS_REVOKE_LEASE
            unsafe {
                ACTIVE_LEASE_START = 0;
                ACTIVE_LEASE_END = 0;
            }
            setup_pmp();
        }

        // Advance mepc past the 4-byte ecall instruction
        unsafe {
            core::arch::asm!("csrw mepc, {0}", in(reg) (mepc + 4));
        }
        return;
    }

    // 2. Hardware Store/Load Access Fault (mcause = 7, 5), Illegal Instruction (mcause = 2), Instruction Fault (mcause = 1)
    if mcause == 7 || mcause == 5 || mcause == 2 || mcause == 1 {
        unsafe {
            TRAP_OCCURRED = true;
            LAST_MCAUSE = mcause;
            LAST_MEPC = mepc;
            LAST_MTVAL = mtval;
        }

        // Instruction fetch fault on User Stack (W^X violation): redirect return to caller in .user_text
        if mcause == 1 && mepc >= USER_STACK_START as u64 && mepc < USER_STACK_END as u64 {
            unsafe {
                core::arch::asm!("csrw mepc, {0}", in(reg) frame.ra);
            }
            return;
        }

        // Advance past faulting instruction to allow test runner to continue
        let inst_half = unsafe { (mepc as *const u16).read_volatile() };
        let inst_len: u64 = if (inst_half & 0x03) == 0x03 { 4 } else { 2 };
        unsafe {
            core::arch::asm!("csrw mepc, {0}", in(reg) (mepc + inst_len));
        }
        return;
    }

    uart_print("[FATAL TRAP] Unexpected hardware trap: mcause = ");
    uart_print_hex(mcause);
    uart_print(", mepc = ");
    uart_print_hex(mepc);
    uart_print(", mtval = ");
    uart_print_hex(mtval);
    uart_print("\n");
    exit_qemu(false);
}

fn exit_qemu(success: bool) -> ! {
    unsafe {
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
