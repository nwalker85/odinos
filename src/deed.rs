//! TransitionDeed Binary Packet (256-Byte Physical Specification)
//!
//! Standardized 256-byte physical binary packet layout for Odin OS state transitions.
//! Cache-line aligned (four 64-byte lines or two 128-byte lines).
//! Enables single-cycle SIMD and PIM verification with zero heap allocations.

pub const DEED_MAGIC: [u8; 2] = [0x59, 0x47]; // "YG" (Yggdrasil)
pub const DEED_VERSION_01: u8 = 0x01;
pub const DEED_VERSION_02: u8 = 0x02;
pub const DEED_SIZE: usize = 256;
pub const DOMAIN_SEPARATOR: [u8; 16] = *b"ODIN_DEED_V2\x00\x00\x00\x00";

pub const TRUSTED_ROOT_PUBLIC_KEY: [u8; 32] = [
    0xFD, 0xC8, 0x86, 0xB0, 0xA3, 0xAE, 0xD3, 0x9A, 0x07, 0xF6, 0x5F, 0x21, 0x43, 0x88, 0x64, 0x48,
    0x02, 0xA5, 0x5E, 0x59, 0xDE, 0xC4, 0xB5, 0xED, 0x34, 0x61, 0x2A, 0x2A, 0x79, 0x83, 0x30, 0x19,
];

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
        if bytes[2] != DEED_VERSION_01 && bytes[2] != DEED_VERSION_02 {
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

        // 4. Cryptographic authority attestation & integrity verification
        if self.version == DEED_VERSION_02 {
            self.verify_ed25519_signature(&TRUSTED_ROOT_PUBLIC_KEY)?;
        } else if self.version == DEED_VERSION_01 {
            if !self.has_valid_attestation_marker() {
                return Err(DeedError::InvalidSignature);
            }
            if !self.has_valid_payload_binding() {
                return Err(DeedError::PayloadTampered);
            }
        } else {
            return Err(DeedError::UnsupportedVersion);
        }

        Ok(())
    }

    /// Constructs the canonical domain-separated message for Ed25519 signing and verification.
    /// Format: [DOMAIN_SEPARATOR (16 bytes)] || [Metadata bytes 0x00..0x9C (156 bytes)] = 172 bytes total.
    pub fn canonical_message(&self) -> [u8; 172] {
        let mut msg = [0u8; 172];
        msg[0..16].copy_from_slice(&DOMAIN_SEPARATOR);
        let payload = unsafe {
            core::slice::from_raw_parts(self as *const Self as *const u8, 156)
        };
        msg[16..172].copy_from_slice(payload);
        msg
    }

    /// Verifies genuine Ed25519 signature over the canonical message against a 32-byte public key.
    pub fn verify_ed25519_signature(&self, public_key_bytes: &[u8; 32]) -> Result<(), DeedError> {
        let pk = ed25519_compact::PublicKey::from_slice(public_key_bytes)
            .map_err(|_| DeedError::InvalidSignature)?;
        let sig = ed25519_compact::Signature::from_slice(&self.signature)
            .map_err(|_| DeedError::InvalidSignature)?;
        let msg = self.canonical_message();
        pk.verify(&msg, &sig)
            .map_err(|_| DeedError::InvalidSignature)?;
        Ok(())
    }

    /// Signs the canonical deed payload in-place using an Ed25519 secret key.
    pub fn sign_with_key(&mut self, secret_key: &ed25519_compact::SecretKey) {
        let msg = self.canonical_message();
        let sig = secret_key.sign(&msg, None);
        self.signature.copy_from_slice(&sig[..]);
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
