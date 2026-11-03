# ODIN OS — PHASE B.3.1
## Transaction Semantics & State Integrity Specification

**Role:** Principal Systems Security Architect & Formal Verification Reviewer  
**Repository:** `nwalker85/odinos`  
**Date:** November 3, 2026  
**Status:** Defensible Publication Specification

---

### Executive Summary

A critical distinction in systems security is the difference between **Spatial Confinement** and **Semantic State Integrity**:

- **Spatial Confinement (Enforced by PMP):** Restricts *where* CPU store instructions may write in physical memory. The processor hardware prevents writes outside the configured address window `[lease_start .. lease_end]`.
- **Semantic State Integrity (Enforced by Cryptographic Deeds):** Guarantees *what* state transition is committed. It verifies that the pre-existing state matches `base_digest`, the transaction forms an unbroken causal chain via `prev_deed_hash`, and the resulting post-mutation state bitwise matches `new_digest`.

In Phase B.2, the microkernel demonstrated spatial confinement via PMP registers. However, real-time bus-level write-sniffing cannot dynamically evaluate SHA-256 digests on every individual CPU cycle. 

This document defines the formal transition semantics, examines the `TransitionDeed` fields, and specifies the staging buffer architecture required to bridge spatial confinement and full transactional state integrity.

---

### 1. Cryptographic and Semantic Field Audit of `TransitionDeed`

Every capability is encapsulated in a 256-byte cache-line aligned `TransitionDeed`:

```rust
#[repr(C, align(64))]
pub struct TransitionDeed {
    pub magic: [u8; 2],                // 0x00..0x02: Magic [0x59, 0x47] ("YG")
    pub version: u8,                   // 0x02..0x03: Version (0x02)
    pub flags: u8,                     // 0x03..0x04: Flags (MUTATION, AST_STRICT)
    pub sequence: u32,                 // 0x04..0x08: Monotonic deed nonce
    pub issuer_did: [u8; 16],          // 0x08..0x18: DID of issuing authority
    pub target_entity_urn: [u8; 16],   // 0x18..0x28: Target entity URN
    pub prev_deed_hash: [u8; 32],      // 0x28..0x48: SHA-256 hash of prior deed
    pub base_digest: [u8; 32],         // 0x48..0x68: Expected pre-mutation state digest
    pub lease_cycles: u32,             // 0x68..0x6C: Hardware cycle lifetime
    pub operation: u8,                 // 0x6C..0x6D: Semantic opcode (e.g., OP_SPLICE)
    pub escalation_level: u8,          // 0x6D..0x6E: Privilege escalation level
    pub reserved: u16,                 // 0x6E..0x70: Reserved padding (zeroed)
    pub target_ast_anchor_id: u32,     // 0x70..0x74: Target AST Anchor identifier
    pub target_offset: u32,            // 0x74..0x78: Authorized start offset
    pub target_length: u32,            // 0x78..0x7C: Authorized buffer length
    pub new_state_digest: [u8; 32],    // 0x7C..0x9C: Expected post-mutation digest
    pub signature: [u8; 64],           // 0x9C..0xDC: RFC 8032 Ed25519 signature
    pub _padding: [u8; 36],            // 0xDC..0x100: Pad to exact 256 bytes
}
```

#### Field Categorization & Enforcement Boundary:

| Field | Authenticated by Ed25519? | Evaluated by M-Mode Kernel? | Evaluated by CPU PMP Comparators? | Semantic Purpose |
| :--- | :---: | :---: | :---: | :--- |
| `magic` & `version` | Yes | Yes (Checks `YG` & `0x02`) | No | Protocol identity & wire format |
| `flags` | Yes | Yes (Checks `MUTATION`) | No | Capability type validation |
| `sequence` | Yes | Yes (Checks `> last_sequence`) | No | Anti-replay protection |
| `issuer_did` | Yes | Yes (Checks `did:odin:root:01`) | No | Authority identity binding |
| `target_entity_urn` | Yes | Yes (Checks `urn:ast:kernel`) | No | Entity target binding |
| `prev_deed_hash` | Yes | Yes (Cryptographic chain) | No | Linear transaction history |
| `base_digest` | Yes | Staging verification | No | Pre-condition state integrity |
| `lease_cycles` | Yes | Yes (Syscall revocation) | No | Temporal execution bounds |
| `operation` | Yes | Yes (Opcode validation) | No | Permitted semantic action |
| `target_offset` | Yes | Yes (Configures PMP) | **Yes** (PMP Entry 4 `A=TOR`) | Spatial lower bound |
| `target_length` | Yes | Yes (Configures PMP) | **Yes** (PMP Entry 5 `A=TOR`) | Spatial upper bound |
| `new_state_digest` | Yes | Commit barrier verification | No | Post-condition state integrity |
| `signature` | Verified against 172B msg | Yes (Ed25519 check) | No | Root cryptographic proof |

---

### 2. State Transition Lifecycle (Formal State Machine)

To achieve complete semantic integrity alongside hardware spatial confinement, the transaction lifecycle follows five explicit phases:

```
  ┌────────────────────────────────────────────────────────────────────────┐
  │                         STATE MACHINE PHASES                           │
  └────────────────────────────────────────────────────────────────────────┘

  [PROPOSED] ──► 1. Agent submits proposed mutation to PDP
       │
       ▼
  [AUTHORIZED] ─► 2. PDP verifies policy, allocates seq, signs TransitionDeed
       │
       ▼
  [LEASED] ────► 3. M-Mode validates deed, maps PMP to Staging Buffer (RW-)
       │
       ▼
  [MUTATING] ──► 4. U-Mode Agent executes stores inside Staging Buffer
       │
       ▼
  [VERIFYING] ─► 5. Agent calls sys_commit_deed(); M-Mode verifies:
       │            a. SHA-256(Staging Buffer) == deed.new_state_digest
       │            b. SHA-256(Prior State)    == deed.base_digest
       │            c. deed.prev_deed_hash     == last_committed_deed_hash
       │
       ├────────────────────────┬────────────────────────┐
       │ (Integrity Verified)   │ (Digest Mismatch)      │ (Hardware Trap)
       ▼                        ▼                        ▼
  [COMMITTED]              [ABORTED]                [REVOKED]
  Atomic copy to           Staging wiped;           PMP collapsed;
  canonical AST RAM;       Zero bytes commit to     Task terminated;
  Sequence advanced.       canonical memory.        State unmodified.
```

---

### 3. Attack Resistance Analysis

1. **Spatial Escape Attack (Writing outside lease):**
   - *Attempt:* Agent executes `sb t1, 0x80030000`.
   - *Defense:* Hardware PMP comparators assert `mcause = 7` before the memory bus can commit the write.
   - *Result:* **Blocked in Hardware (Single Cycle).**

2. **Semantic State Corruption Attack (Writing garbage within lease):**
   - *Attempt:* Agent writes random bytes to `0x80020040` within its authorized spatial window.
   - *Defense:* The writes alter the staging slice, but when `sys_commit_deed()` executes, `SHA-256(Staging)` does not match `deed.new_state_digest`.
   - *Result:* **Transaction Aborted; Canonical State Preserved.**

3. **Pre-Condition Fork Attack (Mutating stale baseline):**
   - *Attempt:* Agent attempts to commit a mutation based on outdated document state.
   - *Defense:* Kernel checks `deed.base_digest` against current canonical memory hash. If concurrent edits modified the buffer, the base digests diverge.
   - *Result:* **Transaction Aborted (Optimistic Concurrency Control).**

4. **Replay & Sequence Hijack Attack:**
   - *Attempt:* Agent replays an earlier validly signed deed.
   - *Defense:* Kernel checks `deed.sequence > kernel.last_sequence`. Replayed deeds are rejected with status `0x02`.
   - *Result:* **Blocked by Kernel Monotonic Invariant.**

---

### 4. Conclusion

Odin OS achieves defense-in-depth by separating spatial boundary enforcement (guaranteed at the processor hardware level by RISC-V PMP comparators) from semantic transition integrity (guaranteed cryptographically by hash chains and digest verification). This architecture eliminates both out-of-bounds memory corruption and unauthorized in-bounds state mutation.
