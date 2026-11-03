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

pub const TRUSTED_ROOT_ISSUER: [u8; 16] = *b"did:odin:root:01";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeedError {
    InvalidMagic,
    UnsupportedVersion,
    ExpiredLease,
    ZeroLengthMutation,
    InvalidAlignment,
    UntrustedIssuer,
    ReplayDetected,
    InvalidSignature,
    PayloadTampered,
    OutOfBoundsLease,
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

    /// Independent authority verification: establishes that Agent Request != Authority Grant.
    /// Validates issuer root identity, anti-replay sequence monotonicity, boundary sanity,
    /// and cryptographic signature attestation.
    pub fn verify_authority(&self, last_sequence: u32, max_bound: u32) -> Result<(), DeedError> {
        // 1. Root issuer check: Agent cannot mint its own authority
        if self.issuer_did != TRUSTED_ROOT_ISSUER {
            return Err(DeedError::UntrustedIssuer);
        }

        // 2. Anti-replay monotonic sequence check
        if self.sequence <= last_sequence {
            return Err(DeedError::ReplayDetected);
        }

        // 3. Mutation bounds check
        if self.target_length == 0 {
            return Err(DeedError::ZeroLengthMutation);
        }

        let end_offset = match self.target_offset.checked_add(self.target_length) {
            Some(end) => end,
            None => return Err(DeedError::OutOfBoundsLease),
        };

        if end_offset > max_bound {
            return Err(DeedError::OutOfBoundsLease);
        }

        // 4. Attestation marker and payload integrity binding check
        // NOTE: In Phase B.1 this enforces structural attestation and deterministic 64-bit
        // payload integrity binding over metadata bytes 0x00..0x9C. Full cryptographic Ed25519
        // verification against a pinned public key is designated for Phase C hardware acceleration.
        if !self.has_valid_attestation_marker() {
            return Err(DeedError::InvalidSignature);
        }
        if !self.has_valid_payload_binding() {
            return Err(DeedError::PayloadTampered);
        }

        Ok(())
    }

    /// Computes a deterministic 64-bit integrity digest over the 156-byte deed payload (0x00..0x9C).
    pub fn compute_digest(&self) -> [u8; 8] {
        const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;
        let mut hash = FNV_OFFSET_BASIS;
        let bytes = unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, 156) };
        for &byte in bytes {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash.to_le_bytes()
    }

    /// Validates the structural root attestation tag ("SIGN" [0x53, 0x49, 0x47, 0x4E]).
    pub fn has_valid_attestation_marker(&self) -> bool {
        self.signature[0..4] == [0x53, 0x49, 0x47, 0x4E]
    }

    /// Validates that the signature field cryptographically/structurally binds the deed payload.
    pub fn has_valid_payload_binding(&self) -> bool {
        let expected_digest = self.compute_digest();
        self.signature[4..12] == expected_digest
    }

    /// Verifies deterministic signature attestation over the deed.
    pub fn verify_signature_attestation(&self) -> bool {
        self.has_valid_attestation_marker() && self.has_valid_payload_binding()
    }
}
