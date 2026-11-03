//! Causal Trap Frame & Vector 0x8F (TRAP_AST_BOUNDARY)
//!
//! Unlike an amnesic Unix SIGSEGV, Vector 0x8F captures full semantic context
//! when a caller attempts an unauthorized mutation outside its authorized AST bounds.

pub const VECTOR_TRAP_AST_BOUNDARY: usize = 0x8F;

#[repr(C, align(64))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CausalTrapFrame {
    // Execution State
    pub faulting_pc: u64,
    pub instruction_raw: u32,
    pub target_physical_address: u64,

    // Identity Attribution
    pub caller_did: [u8; 16],
    pub varar_token_hash: [u8; 32],

    // Boundary Invariants
    pub active_anchor_id: u32,
    pub mask_start_offset: u32,
    pub mask_end_offset: u32,
    pub attempted_offset: u32,
    pub attempted_length: u32,

    // Blocked Mutation Content
    pub attempted_payload_digest: [u8; 32],
}

impl CausalTrapFrame {
    /// Constructs a causal trap frame when wordline gating (WE=0) triggers.
    pub const fn new(
        faulting_pc: u64,
        instruction_raw: u32,
        target_physical_address: u64,
        caller_did: [u8; 16],
        varar_token_hash: [u8; 32],
        active_anchor_id: u32,
        mask_start_offset: u32,
        mask_end_offset: u32,
        attempted_offset: u32,
        attempted_length: u32,
        attempted_payload_digest: [u8; 32],
    ) -> Self {
        Self {
            faulting_pc,
            instruction_raw,
            target_physical_address,
            caller_did,
            varar_token_hash,
            active_anchor_id,
            mask_start_offset,
            mask_end_offset,
            attempted_offset,
            attempted_length,
            attempted_payload_digest,
        }
    }
}
