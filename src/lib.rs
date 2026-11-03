//! Odin OS: Sovereign Capability Microkernel & Wordline Gated Silicon Runtime
//!
//! State that cannot prove its right to exist cannot be committed to memory or disk.

#![cfg_attr(not(test), no_std)]
#![allow(dead_code)]

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
    fn test_ed25519_vector_cross_compat() {
        let pk_bytes: [u8; 32] = [
            0xFD, 0xC8, 0x86, 0xB0, 0xA3, 0xAE, 0xD3, 0x9A, 0x07, 0xF6, 0x5F, 0x21, 0x43, 0x88, 0x64, 0x48,
            0x02, 0xA5, 0x5E, 0x59, 0xDE, 0xC4, 0xB5, 0xED, 0x34, 0x61, 0x2A, 0x2A, 0x79, 0x83, 0x30, 0x19,
        ];
        let sig_bytes: [u8; 64] = [
            0x5F, 0x63, 0xC9, 0x8C, 0x22, 0xC2, 0x7E, 0x68, 0x9E, 0x4D, 0x3D, 0xFE, 0x3E, 0x95, 0x6C, 0xF0,
            0xCE, 0x5D, 0xA3, 0xBA, 0x6D, 0x52, 0x70, 0xD4, 0x79, 0xC2, 0x4A, 0xBB, 0x26, 0x18, 0x84, 0x5E,
            0x51, 0xFC, 0xEC, 0xC8, 0x60, 0x9C, 0x0B, 0x21, 0x4A, 0xFD, 0xF0, 0x45, 0xEF, 0x92, 0x9D, 0xEC,
            0x32, 0x4C, 0x7A, 0x00, 0x6A, 0x7C, 0x75, 0x52, 0xF0, 0xFC, 0x86, 0x76, 0xE6, 0x82, 0xA4, 0x07,
        ];
        let domain = b"ODIN_DEED_V2\x00\x00\x00\x00";
        let mut msg = [0u8; 16 + 156];
        msg[0..16].copy_from_slice(domain);
        for i in 0..156 {
            msg[16 + i] = i as u8;
        }

        let pk = ed25519_compact::PublicKey::from_slice(&pk_bytes).expect("valid pk");
        let sig = ed25519_compact::Signature::from_slice(&sig_bytes).expect("valid sig");
        assert!(pk.verify(&msg, &sig).is_ok(), "Ed25519 signature verification must succeed");
    }

    #[repr(C, align(64))]
    struct AlignedBuffer([u8; 256]);

    fn create_signed_v2_deed_raw(
        seq: u32,
        offset: u32,
        len: u32,
        op: u8,
        issuer: &[u8; 16],
        seed_bytes: &[u8; 32],
    ) -> AlignedBuffer {
        let mut raw = AlignedBuffer([0u8; 256]);
        raw.0[0] = 0x59; // 'Y'
        raw.0[1] = 0x47; // 'G'
        raw.0[2] = deed::DEED_VERSION_02;
        raw.0[3] = deed::FLAG_IS_MUTATION | deed::FLAG_AST_STRICT;
        raw.0[4..8].copy_from_slice(&seq.to_le_bytes());
        raw.0[8..24].copy_from_slice(issuer);
        raw.0[0x68..0x6C].copy_from_slice(&1000u32.to_le_bytes());
        raw.0[0x6C] = op;
        raw.0[0x70..0x74].copy_from_slice(&104u32.to_le_bytes());
        raw.0[0x74..0x78].copy_from_slice(&offset.to_le_bytes());
        raw.0[0x78..0x7C].copy_from_slice(&len.to_le_bytes());

        let seed = ed25519_compact::Seed::from(*seed_bytes);
        let kp = ed25519_compact::KeyPair::from_seed(seed);
        let deed = unsafe { &mut *(raw.0.as_mut_ptr() as *mut TransitionDeed) };
        deed.sign_with_key(&kp.sk);
        raw
    }

    const ROOT_SEED: [u8; 32] = *b"odin_root_authority_seed_v2_key!";
    const ATTACKER_SEED: [u8; 32] = *b"malicious_attacker_signing_key!!";

    #[test]
    fn test_ed25519_valid_signature_acceptance() {
        let raw = create_signed_v2_deed_raw(42, 50, 20, 1, &deed::TRUSTED_ROOT_ISSUER, &ROOT_SEED);
        let deed = TransitionDeed::from_bytes(&raw.0).expect("Must parse valid deed");
        assert!(deed.verify_authority(10, 1000).is_ok(), "Authentic root-signed deed must pass authority verification");
    }

    #[test]
    fn test_ed25519_forged_garbage_signature_rejection() {
        let mut raw = create_signed_v2_deed_raw(42, 50, 20, 1, &deed::TRUSTED_ROOT_ISSUER, &ROOT_SEED);
        // Overwrite signature with forged garbage
        raw.0[0x9C..0xDC].fill(0xAA);
        let deed = TransitionDeed::from_bytes(&raw.0).expect("Must parse deed");
        assert_eq!(deed.verify_authority(10, 1000), Err(deed::DeedError::InvalidSignature));
    }

    #[test]
    fn test_ed25519_unauthorized_key_rejection() {
        // Valid Ed25519 signature, but from unauthorized attacker key
        let raw = create_signed_v2_deed_raw(42, 50, 20, 1, &deed::TRUSTED_ROOT_ISSUER, &ATTACKER_SEED);
        let deed = TransitionDeed::from_bytes(&raw.0).expect("Must parse deed");
        assert_eq!(deed.verify_authority(10, 1000), Err(deed::DeedError::InvalidSignature));
    }

    #[test]
    fn test_ed25519_tampered_target_offset_rejection() {
        let mut raw = create_signed_v2_deed_raw(42, 50, 20, 1, &deed::TRUSTED_ROOT_ISSUER, &ROOT_SEED);
        // Tamper with offset: 50 -> 51
        raw.0[0x74..0x78].copy_from_slice(&51u32.to_le_bytes());
        let deed = TransitionDeed::from_bytes(&raw.0).expect("Must parse deed");
        assert_eq!(deed.verify_authority(10, 1000), Err(deed::DeedError::InvalidSignature));
    }

    #[test]
    fn test_ed25519_tampered_target_length_rejection() {
        let mut raw = create_signed_v2_deed_raw(42, 50, 20, 1, &deed::TRUSTED_ROOT_ISSUER, &ROOT_SEED);
        // Tamper with length: 20 -> 21
        raw.0[0x78..0x7C].copy_from_slice(&21u32.to_le_bytes());
        let deed = TransitionDeed::from_bytes(&raw.0).expect("Must parse deed");
        assert_eq!(deed.verify_authority(10, 1000), Err(deed::DeedError::InvalidSignature));
    }

    #[test]
    fn test_ed25519_tampered_sequence_rejection() {
        let mut raw = create_signed_v2_deed_raw(42, 50, 20, 1, &deed::TRUSTED_ROOT_ISSUER, &ROOT_SEED);
        // Tamper with sequence: 42 -> 43
        raw.0[4..8].copy_from_slice(&43u32.to_le_bytes());
        let deed = TransitionDeed::from_bytes(&raw.0).expect("Must parse deed");
        assert_eq!(deed.verify_authority(10, 1000), Err(deed::DeedError::InvalidSignature));
    }

    #[test]
    fn test_ed25519_tampered_operation_rejection() {
        let mut raw = create_signed_v2_deed_raw(42, 50, 20, 1, &deed::TRUSTED_ROOT_ISSUER, &ROOT_SEED);
        // Tamper with operation opcode: 1 -> 2
        raw.0[0x6C] = 2;
        let deed = TransitionDeed::from_bytes(&raw.0).expect("Must parse deed");
        assert_eq!(deed.verify_authority(10, 1000), Err(deed::DeedError::InvalidSignature));
    }

    #[test]
    fn test_ed25519_cross_protocol_domain_separation_rejection() {
        let mut raw = AlignedBuffer([0u8; 256]);
        raw.0[0] = 0x59;
        raw.0[1] = 0x47;
        raw.0[2] = deed::DEED_VERSION_02;
        raw.0[3] = deed::FLAG_IS_MUTATION | deed::FLAG_AST_STRICT;
        raw.0[4..8].copy_from_slice(&42u32.to_le_bytes());
        raw.0[8..24].copy_from_slice(&deed::TRUSTED_ROOT_ISSUER);
        raw.0[0x68..0x6C].copy_from_slice(&1000u32.to_le_bytes());
        raw.0[0x6C] = 1;
        raw.0[0x70..0x74].copy_from_slice(&104u32.to_le_bytes());
        raw.0[0x74..0x78].copy_from_slice(&50u32.to_le_bytes());
        raw.0[0x78..0x7C].copy_from_slice(&20u32.to_le_bytes());

        // Sign using a different domain separator: b"OTHER_PROTOCOL\x00\x00"
        let mut foreign_msg = [0u8; 172];
        foreign_msg[0..16].copy_from_slice(b"OTHER_PROTOCOL\x00\x00");
        foreign_msg[16..172].copy_from_slice(&raw.0[0..156]);

        let seed = ed25519_compact::Seed::from(ROOT_SEED);
        let kp = ed25519_compact::KeyPair::from_seed(seed);
        let foreign_sig = kp.sk.sign(&foreign_msg, None);
        raw.0[0x9C..0xDC].copy_from_slice(&foreign_sig[..]);

        let deed = TransitionDeed::from_bytes(&raw.0).expect("Must parse deed");
        // Cross-protocol reuse must fail closed!
        assert_eq!(deed.verify_authority(10, 1000), Err(deed::DeedError::InvalidSignature));
    }

    #[test]
    fn test_ed25519_single_bit_flip_signature_rejection() {
        let mut raw = create_signed_v2_deed_raw(42, 50, 20, 1, &deed::TRUSTED_ROOT_ISSUER, &ROOT_SEED);
        // Flip exactly 1 bit in signature
        raw.0[0x9C] ^= 0x01;
        let deed = TransitionDeed::from_bytes(&raw.0).expect("Must parse deed");
        assert_eq!(deed.verify_authority(10, 1000), Err(deed::DeedError::InvalidSignature));
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
        // Issuer = TRUSTED_ROOT_ISSUER
        raw.0[8..24].copy_from_slice(&deed::TRUSTED_ROOT_ISSUER);
        // Lease cycles = 1000
        raw.0[0x68..0x6C].copy_from_slice(&1000u32.to_ne_bytes());
        // Target AST Anchor ID = 104
        raw.0[0x70..0x74].copy_from_slice(&104u32.to_ne_bytes());
        // Target Offset = 50
        raw.0[0x74..0x78].copy_from_slice(&50u32.to_ne_bytes());
        // Target Length = 20
        raw.0[0x78..0x7C].copy_from_slice(&20u32.to_ne_bytes());
        // Attestation header = "SIGN"
        raw.0[0x9C..0xA0].copy_from_slice(b"SIGN");

        // First parse to compute digest
        let temp_deed = TransitionDeed::from_bytes(&raw.0).expect("Must parse valid deed zero-copy");
        let digest = temp_deed.compute_digest();
        raw.0[0xA0..0xA8].copy_from_slice(&digest);

        let deed = TransitionDeed::from_bytes(&raw.0).expect("Must parse valid deed zero-copy");
        assert_eq!(deed.sequence, 42);
        assert_eq!(deed.target_ast_anchor_id, 104);
        assert_eq!(deed.target_offset, 50);
        assert_eq!(deed.target_length, 20);
        assert!(deed.is_mutation());
        assert!(deed.is_ast_strict());

        // Test authority verification: last_sequence = 10, max_bound = 1000
        assert!(deed.verify_authority(10, 1000).is_ok());

        // Replay attack: sequence 42 <= 42
        assert_eq!(deed.verify_authority(42, 1000), Err(deed::DeedError::ReplayDetected));

        // Out of bounds: offset 50 + length 20 = 70 > max_bound 60
        assert_eq!(deed.verify_authority(10, 60), Err(deed::DeedError::OutOfBoundsLease));
    }

    #[test]
    fn test_deed_authority_forgery_rejection() {
        #[repr(C, align(64))]
        struct AlignedBuffer([u8; 256]);

        let mut raw = AlignedBuffer([0u8; 256]);
        raw.0[0] = 0x59;
        raw.0[1] = 0x47;
        raw.0[2] = 0x01;
        raw.0[4..8].copy_from_slice(&100u32.to_ne_bytes());
        // Untrusted issuer
        raw.0[8..24].copy_from_slice(b"untrusted_agent_");
        raw.0[0x74..0x78].copy_from_slice(&10u32.to_ne_bytes());
        raw.0[0x78..0x7C].copy_from_slice(&10u32.to_ne_bytes());
        raw.0[0x9C..0xA0].copy_from_slice(b"SIGN");

        let deed = TransitionDeed::from_bytes(&raw.0).unwrap();
        // Agent Request != Authority Grant: Must be rejected because issuer is untrusted!
        assert_eq!(deed.verify_authority(10, 1000), Err(deed::DeedError::UntrustedIssuer));
    }

    #[test]
    fn test_deed_payload_tampering_rejection() {
        #[repr(C, align(64))]
        struct AlignedBuffer([u8; 256]);

        let mut raw = AlignedBuffer([0u8; 256]);
        raw.0[0] = 0x59;
        raw.0[1] = 0x47;
        raw.0[2] = 0x01;
        raw.0[4..8].copy_from_slice(&100u32.to_ne_bytes());
        raw.0[8..24].copy_from_slice(&deed::TRUSTED_ROOT_ISSUER);
        raw.0[0x68..0x6C].copy_from_slice(&1000u32.to_ne_bytes());
        raw.0[0x74..0x78].copy_from_slice(&10u32.to_ne_bytes());
        raw.0[0x78..0x7C].copy_from_slice(&10u32.to_ne_bytes());
        raw.0[0x9C..0xA0].copy_from_slice(b"SIGN");

        let temp = TransitionDeed::from_bytes(&raw.0).unwrap();
        let digest = temp.compute_digest();
        raw.0[0xA0..0xA8].copy_from_slice(&digest);

        // Adversary tampers with offset (changing from 10 to 80) without re-attesting
        raw.0[0x74..0x78].copy_from_slice(&80u32.to_ne_bytes());

        let deed = TransitionDeed::from_bytes(&raw.0).unwrap();
        assert_eq!(deed.verify_authority(10, 1000), Err(deed::DeedError::PayloadTampered));
    }

    #[test]
    fn test_deed_missing_attestation_marker_rejection() {
        #[repr(C, align(64))]
        struct AlignedBuffer([u8; 256]);

        let mut raw = AlignedBuffer([0u8; 256]);
        raw.0[0] = 0x59;
        raw.0[1] = 0x47;
        raw.0[2] = 0x01;
        raw.0[4..8].copy_from_slice(&100u32.to_ne_bytes());
        raw.0[8..24].copy_from_slice(&deed::TRUSTED_ROOT_ISSUER);
        raw.0[0x68..0x6C].copy_from_slice(&1000u32.to_ne_bytes());
        raw.0[0x74..0x78].copy_from_slice(&10u32.to_ne_bytes());
        raw.0[0x78..0x7C].copy_from_slice(&10u32.to_ne_bytes());
        // Forged or missing marker: "FAKE"
        raw.0[0x9C..0xA0].copy_from_slice(b"FAKE");

        let deed = TransitionDeed::from_bytes(&raw.0).unwrap();
        assert_eq!(deed.verify_authority(10, 1000), Err(deed::DeedError::InvalidSignature));
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

    use proptest::prelude::*;

    proptest! {
        // Invariant 1: Range containment & memory safety
        // \forall w, \neg Authorized(w) \implies MemoryAfter(w) == MemoryBefore(w)
        #[test]
        fn prop_ast_mask_range_confinement(
            anchor_id in 0u32..1000,
            mask_start in 0u32..10_000,
            mask_len in 1u32..5_000,
            write_offset in 0u32..20_000,
            write_len in 1u32..5_000,
        ) {
            let mask_end = mask_start.saturating_add(mask_len);
            let mask = AstMask::new(anchor_id, mask_start, mask_end);

            let is_contained = mask.contains_span(write_offset, write_len);

            let expected = match write_offset.checked_add(write_len) {
                Some(write_end) => write_offset >= mask_start && write_end <= mask_end,
                None => false,
            };

            prop_assert_eq!(is_contained, expected);
        }

        // Invariant 2: Range arithmetic overflow protection
        #[test]
        fn prop_deed_overflow_protection(
            target_offset in (u32::MAX - 1000)..=u32::MAX,
            target_length in 1u32..2000,
            max_bound in 0u32..100_000,
        ) {
            #[repr(C, align(64))]
            struct AlignedBuffer([u8; 256]);
            let mut raw = AlignedBuffer([0u8; DEED_SIZE]);
            raw.0[0] = DEED_MAGIC[0];
            raw.0[1] = DEED_MAGIC[1];
            raw.0[2] = DEED_VERSION_01;
            raw.0[4..8].copy_from_slice(&100u32.to_le_bytes()); // sequence
            raw.0[8..24].copy_from_slice(&deed::TRUSTED_ROOT_ISSUER);
            raw.0[0x68..0x6C].copy_from_slice(&1000u32.to_le_bytes()); // lease
            raw.0[0x74..0x78].copy_from_slice(&target_offset.to_le_bytes());
            raw.0[0x78..0x7C].copy_from_slice(&target_length.to_le_bytes());
            raw.0[0x9C..0xA0].copy_from_slice(b"SIGN");

            if let Ok(deed) = TransitionDeed::from_bytes(&raw.0) {
                let res = deed.verify_authority(50, max_bound);
                prop_assert!(res.is_err());
                prop_assert_eq!(res.unwrap_err(), deed::DeedError::OutOfBoundsLease);
            }
        }

        // Invariant 3: Anti-replay monotonicity
        #[test]
        fn prop_anti_replay_monotonicity(
            last_consumed in 1u32..1_000_000,
            new_sequence in 0u32..2_000_000,
        ) {
            #[repr(C, align(64))]
            struct AlignedBuffer([u8; 256]);
            let mut raw = AlignedBuffer([0u8; DEED_SIZE]);
            raw.0[0] = DEED_MAGIC[0];
            raw.0[1] = DEED_MAGIC[1];
            raw.0[2] = DEED_VERSION_01;
            raw.0[4..8].copy_from_slice(&new_sequence.to_le_bytes());
            raw.0[8..24].copy_from_slice(&deed::TRUSTED_ROOT_ISSUER);
            raw.0[0x68..0x6C].copy_from_slice(&1000u32.to_le_bytes()); // lease
            raw.0[0x74..0x78].copy_from_slice(&100u32.to_le_bytes());
            raw.0[0x78..0x7C].copy_from_slice(&50u32.to_le_bytes());
            raw.0[0x9C..0xA0].copy_from_slice(b"SIGN");

            let temp = TransitionDeed::from_bytes(&raw.0).unwrap();
            let digest = temp.compute_digest();
            raw.0[0xA0..0xA8].copy_from_slice(&digest);

            let deed = TransitionDeed::from_bytes(&raw.0).unwrap();
            let res = deed.verify_authority(last_consumed, 10_000);

            if new_sequence <= last_consumed {
                prop_assert_eq!(res, Err(deed::DeedError::ReplayDetected));
            } else {
                prop_assert!(res.is_ok());
            }
        }

        // Invariant 4: Attestation identity tamper-resistance
        #[test]
        fn prop_adversarial_issuer_mutation(
            mutated_byte_idx in 0usize..16,
            mutation_xor in 1u8..=255,
        ) {
            #[repr(C, align(64))]
            struct AlignedBuffer([u8; 256]);
            let mut raw = AlignedBuffer([0u8; DEED_SIZE]);
            raw.0[0] = DEED_MAGIC[0];
            raw.0[1] = DEED_MAGIC[1];
            raw.0[2] = DEED_VERSION_01;
            raw.0[4..8].copy_from_slice(&100u32.to_le_bytes());
            raw.0[8..24].copy_from_slice(&deed::TRUSTED_ROOT_ISSUER);
            raw.0[8 + mutated_byte_idx] ^= mutation_xor;
            raw.0[0x68..0x6C].copy_from_slice(&1000u32.to_le_bytes()); // lease
            raw.0[0x74..0x78].copy_from_slice(&100u32.to_le_bytes());
            raw.0[0x78..0x7C].copy_from_slice(&50u32.to_le_bytes());
            raw.0[0x9C..0xA0].copy_from_slice(b"SIGN");

            let deed = TransitionDeed::from_bytes(&raw.0).unwrap();
            let res = deed.verify_authority(50, 10_000);
            prop_assert_eq!(res, Err(deed::DeedError::UntrustedIssuer));
        }

        // Invariant 5: Payload integrity binding (any alteration of bytes 0..156 triggers PayloadTampered)
        #[test]
        fn prop_payload_tamper_detection(
            tamper_byte_idx in 0usize..156,
            tamper_xor in 1u8..=255,
        ) {
            #[repr(C, align(64))]
            struct AlignedBuffer([u8; 256]);
            let mut raw = AlignedBuffer([0u8; DEED_SIZE]);
            raw.0[0] = DEED_MAGIC[0];
            raw.0[1] = DEED_MAGIC[1];
            raw.0[2] = DEED_VERSION_01;
            raw.0[4..8].copy_from_slice(&100u32.to_le_bytes());
            raw.0[8..24].copy_from_slice(&deed::TRUSTED_ROOT_ISSUER);
            raw.0[0x68..0x6C].copy_from_slice(&1000u32.to_le_bytes()); // lease
            raw.0[0x74..0x78].copy_from_slice(&100u32.to_le_bytes());
            raw.0[0x78..0x7C].copy_from_slice(&50u32.to_le_bytes());
            raw.0[0x9C..0xA0].copy_from_slice(b"SIGN");

            let temp = TransitionDeed::from_bytes(&raw.0).unwrap();
            let digest = temp.compute_digest();
            raw.0[0xA0..0xA8].copy_from_slice(&digest);

            // Tamper with a payload byte
            raw.0[tamper_byte_idx] ^= tamper_xor;

            if let Ok(deed) = TransitionDeed::from_bytes(&raw.0) {
                let res = deed.verify_authority(50, 10_000);
                prop_assert!(res.is_err(), "Tampered payload must never verify successfully");
            }
        }
    }
}
