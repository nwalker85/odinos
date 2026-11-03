//! Odin OS: Sovereign Capability Microkernel & Wordline Gated Silicon Runtime
//!
//! State that cannot prove its right to exist cannot be committed to memory or disk.

#![cfg_attr(not(test), no_std)]

pub mod deed;
pub mod trap;
pub mod interlock;

pub use deed::{TransitionDeed, DEED_MAGIC, DEED_SIZE, DEED_VERSION_01};
pub use trap::{CausalTrapFrame, VECTOR_TRAP_AST_BOUNDARY};
pub use interlock::{check_wordline_interlock, AstMask};

#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        // Halt physical processor execution on unrecoverable kernel panic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn test_transition_deed_physical_layout() {
        // Assert exact 256-byte cache-line aligned physical specification
        assert_eq!(size_of::<TransitionDeed>(), 256);
        assert_eq!(align_of::<TransitionDeed>(), 64);
    }

    #[test]
    fn test_causal_trap_frame_layout() {
        // Assert 64-byte aligned trap frame
        assert_eq!(align_of::<CausalTrapFrame>(), 64);
        assert!(size_of::<CausalTrapFrame>() <= 128);
    }

    #[test]
    fn test_zero_copy_deed_parsing() {
        // Construct aligned 256-byte buffer
        #[repr(C, align(64))]
        struct AlignedBuffer([u8; 256]);

        let mut raw = AlignedBuffer([0u8; 256]);
        raw.0[0] = 0x59; // 'Y'
        raw.0[1] = 0x47; // 'G'
        raw.0[2] = 0x01; // Version 1
        raw.0[3] = deed::FLAG_IS_MUTATION | deed::FLAG_AST_STRICT;

        // Sequence = 42
        raw.0[4..8].copy_from_slice(&42u32.to_ne_bytes());
        // Lease cycles = 1000
        raw.0[0x68..0x6C].copy_from_slice(&1000u32.to_ne_bytes());
        // Target AST Anchor ID = 104
        raw.0[0x70..0x74].copy_from_slice(&104u32.to_ne_bytes());
        // Target Offset = 50
        raw.0[0x74..0x78].copy_from_slice(&50u32.to_ne_bytes());
        // Target Length = 20
        raw.0[0x78..0x7C].copy_from_slice(&20u32.to_ne_bytes());

        let deed = TransitionDeed::from_bytes(&raw.0).expect("Must parse valid deed zero-copy");
        assert_eq!(deed.sequence, 42);
        assert_eq!(deed.target_ast_anchor_id, 104);
        assert_eq!(deed.target_offset, 50);
        assert_eq!(deed.target_length, 20);
        assert!(deed.is_mutation());
        assert!(deed.is_ast_strict());
    }

    #[test]
    fn test_wordline_interlock_pass_within_bounds() {
        #[repr(C, align(64))]
        struct AlignedBuffer([u8; 256]);

        let mut raw = AlignedBuffer([0u8; 256]);
        raw.0[0] = 0x59;
        raw.0[1] = 0x47;
        raw.0[2] = 0x01;
        raw.0[0x68..0x6C].copy_from_slice(&1000u32.to_ne_bytes()); // lease
        raw.0[0x70..0x74].copy_from_slice(&1u32.to_ne_bytes()); // anchor 1
        raw.0[0x74..0x78].copy_from_slice(&100u32.to_ne_bytes()); // offset 100
        raw.0[0x78..0x7C].copy_from_slice(&50u32.to_ne_bytes()); // length 50

        let deed = TransitionDeed::from_bytes(&raw.0).unwrap();
        // Mask covers 80..200 on anchor 1
        let mask = AstMask::new(1, 80, 200);

        let result = check_wordline_interlock(deed, &mask, 0x8000_1234, 0x00A0_0513, 0x1000_4000, [0u8; 32]);
        assert!(result.is_ok(), "Write within [80..200] must pass wordline interlock");
    }

    #[test]
    fn test_wordline_interlock_trap_out_of_bounds() {
        #[repr(C, align(64))]
        struct AlignedBuffer([u8; 256]);

        let mut raw = AlignedBuffer([0u8; 256]);
        raw.0[0] = 0x59;
        raw.0[1] = 0x47;
        raw.0[2] = 0x01;
        raw.0[0x68..0x6C].copy_from_slice(&1000u32.to_ne_bytes());
        raw.0[0x70..0x74].copy_from_slice(&1u32.to_ne_bytes()); // anchor 1
        raw.0[0x74..0x78].copy_from_slice(&100u32.to_ne_bytes()); // offset 100
        raw.0[0x78..0x7C].copy_from_slice(&150u32.to_ne_bytes()); // length 150 -> span 100..250!

        let deed = TransitionDeed::from_bytes(&raw.0).unwrap();
        // Mask ONLY permits 100..200
        let mask = AstMask::new(1, 100, 200);

        let result = check_wordline_interlock(deed, &mask, 0x8000_5678, 0x00B0_0523, 0x1000_4080, [0xAA; 32]);
        assert!(result.is_err(), "Write exceeding end bound must trigger TRAP_AST_BOUNDARY");

        let trap = result.unwrap_err();
        assert_eq!(trap.faulting_pc, 0x8000_5678);
        assert_eq!(trap.instruction_raw, 0x00B0_0523);
        assert_eq!(trap.active_anchor_id, 1);
        assert_eq!(trap.mask_start_offset, 100);
        assert_eq!(trap.mask_end_offset, 200);
        assert_eq!(trap.attempted_offset, 100);
        assert_eq!(trap.attempted_length, 150);
        assert_eq!(trap.varar_token_hash, [0xAA; 32]);
    }
}
