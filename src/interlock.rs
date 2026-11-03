//! AST Mask & Wordline Interlock Logic (Hardware Microkernel Stage 3)
//!
//! Evaluates the fundamental inequality:
//! TargetOffset >= MaskStart AND (TargetOffset + TargetLength) <= MaskEnd
//!
//! If the proposed write violates this inequality, the Write Enable line (WE)
//! is held low (0 bits flipped), and a CausalTrapFrame is returned for Vector 0x8F.

use crate::deed::TransitionDeed;
use crate::trap::CausalTrapFrame;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AstMask {
    pub anchor_id: u32,
    pub start_offset: u32,
    pub end_offset: u32,
}

impl AstMask {
    pub const fn new(anchor_id: u32, start_offset: u32, end_offset: u32) -> Self {
        Self {
            anchor_id,
            start_offset,
            end_offset,
        }
    }

    /// Evaluates if a proposed write span is strictly within this AST mask bounds.
    #[inline]
    pub fn contains_span(&self, offset: u32, length: u32) -> bool {
        if offset < self.start_offset {
            return false;
        }
        match offset.checked_add(length) {
            Some(end) => end <= self.end_offset,
            None => false, // Overflow attempt caught
        }
    }
}

/// Hardware Microkernel Stage 3 Wordline Interlock Comparator.
///
/// Returns Ok(()) if the transition deed satisfies the active AST mask,
/// authorizing the memory controller to activate Write Enable (WE = 1).
///
/// Returns Err(CausalTrapFrame) if the write attempts to mutate outside the mask,
/// holding WE = 0 and minting the exact trap frame for Vector 0x8F.
#[inline]
pub fn check_wordline_interlock(
    deed: &TransitionDeed,
    mask: &AstMask,
    faulting_pc: u64,
    instruction_raw: u32,
    target_physical_address: u64,
    varar_token_hash: [u8; 32],
) -> Result<(), CausalTrapFrame> {
    // 1. Verify anchor identity
    let anchor_matches = deed.target_ast_anchor_id == mask.anchor_id;

    // 2. Verify spatial boundary: TargetOffset >= MaskStart && (TargetOffset + TargetLength) <= MaskEnd
    let bounds_match = mask.contains_span(deed.target_offset, deed.target_length);

    if anchor_matches && bounds_match {
        // Physical Wordline Enabled (WE = 1)
        Ok(())
    } else {
        // Physical Wordline Gated (WE = 0)
        // Mint the Causal Trap Frame for Vector 0x8F
        Err(CausalTrapFrame::new(
            faulting_pc,
            instruction_raw,
            target_physical_address,
            deed.issuer_did,
            varar_token_hash,
            mask.anchor_id,
            mask.start_offset,
            mask.end_offset,
            deed.target_offset,
            deed.target_length,
            deed.new_state_digest,
        ))
    }
}
