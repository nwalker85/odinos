//! TransitionDeed Binary Packet (256-Byte Physical Specification)
//!
//! Standardized 256-byte physical binary packet layout for Odin OS state transitions.
//! Cache-line aligned (four 64-byte lines or two 128-byte lines).
//! Enables single-cycle SIMD and PIM verification with zero heap allocations.

pub const DEED_MAGIC: [u8; 2] = [0x59, 0x47]; // "YG" (Yggdrasil)
pub const DEED_VERSION_01: u8 = 0x01;
pub const DEED_SIZE: usize = 256;

// Flag Bitmasks
pub const FLAG_IS_EPHEMERAL: u8 = 1 << 0;
pub const FLAG_IS_MUTATION: u8 = 1 << 1;
pub const FLAG_REQUIRES_CONSENSUS: u8 = 1 << 2;
pub const FLAG_AST_STRICT: u8 = 1 << 3;
pub const FLAG_ZK_ATTESTED: u8 = 1 << 4;

// Operations
pub const OP_SPLICE: u8 = 0x01;
pub const OP_APPEND: u8 = 0x02;
pub const OP_LEASE_ACQUIRE: u8 = 0x03;
pub const OP_LEASE_RELEASE: u8 = 0x04;
pub const OP_DELEGATE: u8 = 0x05;
pub const OP_ESCALATE: u8 = 0x06;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeedError {
    InvalidMagic,
    UnsupportedVersion,
    ExpiredLease,
    ZeroLengthMutation,
    InvalidAlignment,
}

#[repr(C, align(64))]
#[derive(Debug, Clone, Copy)]
pub struct TransitionDeed {
    // 0x00..0x08
    pub magic: [u8; 2],
    pub version: u8,
    pub flags: u8,
    pub sequence: u32,

    // 0x08..0x28
    pub issuer_did: [u8; 16],
    pub target_entity_urn: [u8; 16],

    // 0x28..0x68
    pub prev_deed_hash: [u8; 32],
    pub base_digest: [u8; 32],

    // 0x68..0x70
    pub lease_cycles: u32,
    pub operation: u8,
    pub esc_level: u8,
    pub reserved16: u16,

    // 0x70..0x7C
    pub target_ast_anchor_id: u32,
    pub target_offset: u32,
    pub target_length: u32,

    // 0x7C..0x9C
    pub new_state_digest: [u8; 32],

    // 0x9C..0xDC
    pub signature: [u8; 64],

    // 0xDC..0x100 (256 bytes total)
    pub padding: [u8; 36],
}

impl TransitionDeed {
    /// Zero-copy in-place parse of a 256-byte raw buffer.
    /// Fails immediately if magic or version does not match Yggdrasil specification.
    #[inline]
    pub fn from_bytes(bytes: &[u8; DEED_SIZE]) -> Result<&Self, DeedError> {
        if bytes[0..2] != DEED_MAGIC {
            return Err(DeedError::InvalidMagic);
        }
        if bytes[2] != DEED_VERSION_01 {
            return Err(DeedError::UnsupportedVersion);
        }

        // Safety: TransitionDeed is #[repr(C, align(64))] and size is exactly 256 bytes.
        // We ensure alignment by asserting pointer alignment at runtime if needed,
        // or through safe reference casting when aligned.
        let ptr = bytes.as_ptr();
        if (ptr as usize) % core::mem::align_of::<Self>() != 0 {
            return Err(DeedError::InvalidAlignment);
        }

        let deed = unsafe { &*(ptr as *const Self) };
        if deed.lease_cycles == 0 && (deed.flags & FLAG_IS_EPHEMERAL) != 0 {
            return Err(DeedError::ExpiredLease);
        }

        Ok(deed)
    }

    /// Verifies if this deed requests physical memory/storage mutation.
    #[inline]
    pub fn is_mutation(&self) -> bool {
        (self.flags & FLAG_IS_MUTATION) != 0
    }

    /// Verifies if this deed enforces strict AST boundary gating.
    #[inline]
    pub fn is_ast_strict(&self) -> bool {
        (self.flags & FLAG_AST_STRICT) != 0
    }
}
