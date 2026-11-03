# Odin OS Phase B.3 — Transaction Semantics & State Integrity Audit

**Author:** Principal Kernel Security Engineer & Independent Research Verification Lead  
**Scope:** Transactional State Guarantees, Digest Validation, Causal Chaining, and Semantic Boundary Analysis  
**Governing Question:** Does PMP spatial write confinement guarantee semantic state transition integrity?  

---

## 1. Executive Finding: Spatial Confinement vs Semantic Integrity

A fundamental contribution of this audit is establishing the boundary between **spatial access enforcement** and **semantic state transition integrity**:

$$\text{PMP Spatial Confinement } (\text{Address } \in [L_{\text{start}}, L_{\text{end}})) \;\not\equiv\; \text{Semantic State Transition Integrity}$$

RISC-V Physical Memory Protection (PMP) operates at the CPU memory bus interface. It guarantees that any store instruction issued to an address outside an authorized range triggers an immediate hardware trap (`mcause = 7`), preventing unauthorized bytes from being committed to the memory controller.

However, PMP alone does **not** evaluate:
1. Whether the initial state of the memory buffer matched the expected `base_digest`.
2. Whether the mutated bytes committed by the agent inside the authorized range match the cryptographically promised `new_digest`.
3. Whether the transition's causal predecessor (`prev_deed_hash`) matches the prior committed transaction.

In Phase B.2, Odin OS establishes **spatial confinement** with 100% hardware enforcement. The complete semantic transition pipeline represents an architectural layer that builds upon PMP spatial gating.

---

## 2. TransitionDeed Field Classification Taxonomy

Each of the 256 bytes in a `TransitionDeed` is audited and categorized into one of five functional classes:

```
Field Name             Offset         Size     Cryptographically Signed?   Enforcement Level in Phase B.2 / B.3
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
magic                  0x00 .. 0x02    2 B     Yes (via Canonical Msg)     Actively Enforced (Magic == "YG")
version                0x02 .. 0x03    1 B     Yes (via Canonical Msg)     Actively Enforced (Version == 0x02)
flags                  0x03 .. 0x04    1 B     Yes (via Canonical Msg)     Semantically Validated
sequence               0x04 .. 0x08    4 B     Yes (via Canonical Msg)     Actively Enforced (Monotonic > LastSeq)
issuer_did             0x08 .. 0x18   16 B     Yes (via Canonical Msg)     Actively Enforced (Matches Root DID)
target_urn             0x18 .. 0x28   16 B     Yes (via Canonical Msg)     Authenticated & Recorded
prev_deed_hash         0x28 .. 0x48   32 B     Yes (via Canonical Msg)     Authenticated & Recorded (Causal Hash)
base_digest            0x48 .. 0x68   32 B     Yes (via Canonical Msg)     Authenticated & Recorded (Pre-State Hash)
lease_cycles           0x68 .. 0x6C    4 B     Yes (via Canonical Msg)     Authenticated & Recorded
operation              0x6C .. 0x6D    1 B     Yes (via Canonical Msg)     Authenticated & Recorded (Opcode)
esc_level              0x6D .. 0x6E    1 B     Yes (via Canonical Msg)     Authenticated & Recorded
reserved               0x6E .. 0x70    2 B     Yes (via Canonical Msg)     Authenticated (Must be Zero)
anchor_id              0x70 .. 0x74    4 B     Yes (via Canonical Msg)     Authenticated & Recorded (AST ID)
target_offset          0x74 .. 0x78    4 B     Yes (via Canonical Msg)     Actively Enforced (Checked PMP Base)
target_length          0x78 .. 0x7C    4 B     Yes (via Canonical Msg)     Actively Enforced (Checked PMP Bound)
new_digest             0x7C .. 0x9C   32 B     Yes (via Canonical Msg)     Authenticated & Recorded (Post-State Hash)
signature              0x9C .. 0xDC   64 B     N/A (Self-Authenticating)   Actively Enforced (Ed25519 Signature)
padding                0xDC .. 0x100  36 B     No                          Zero Padding (Cache Line Align)
```

### Analysis of Functional Classes:
- **Actively Enforced (In Silicon / Microkernel):**
  - `magic`, `version`, `sequence`, `issuer_did`, `target_offset`, `target_length`, and `signature`.
  - Violations of any of these fields immediately prevent PMP programming and reject execution at the microkernel boundary.
- **Cryptographically Authenticated but Recorded (Passive):**
  - `prev_deed_hash`, `base_digest`, `new_digest`, `target_urn`, `operation`, `lease_cycles`, `anchor_id`.
  - These fields are protected against post-issuance tampering by the Ed25519 signature. An attacker cannot modify them without invalidating the signature. However, the microkernel does not currently compute SHA-256 digests over RAM to confirm memory matches `base_digest` prior to write, or `new_digest` after write.

---

## 3. Atomic State Commit vs Interrupted Transitions

### 3.1 Interrupted Mutation Scenario
Consider an agent granted an active lease for `0x80020040..0x80020060`.
Suppose the agent performs 3 stores:
1. `sb 0xAA -> 0x80020040` (Succeeds)
2. `sb 0xBB -> 0x80020041` (Succeeds)
3. `sb 0xCC -> 0x80030000` (Faults with `mcause = 7`)

*What is the state of memory after the fault?*
- Bytes `0x80020040` and `0x80020041` hold `0xAA` and `0xBB`.
- Address `0x80030000` is unmodified (`0x00`).
- The transition was partially executed.

### 3.2 Architectural Mitigation: Two-Phase Commit with Shadow AST Buffering
To elevate Odin OS from spatial containment to full transactional atomicity:
1. **Phase 1 (Speculative Mutation in Scratch Buffer):** The agent mutates state inside a dedicated user-space staging slice.
2. **Phase 2 (Digest Ratification & Shadow Swap):**
   - The agent executes microkernel syscall `SYS_COMMIT_TRANSITION(deed_ptr)`.
   - The microkernel hashes the staging slice.
   - If `hash == deed.new_digest`, M-Mode updates the master pointer or copies state atomically.
   - If `hash != deed.new_digest` or a fault occurred, the staging slice is discarded.

---

## 4. Summary & Research Classification

- **Established Claim:** Odin OS hardware PMP strictly prevents any store instruction outside the authorized range $[O, O+L)$ from committing to memory.
- **Boundary Qualification:** State transition atomicity and digest matching (`base_digest` $\rightarrow$ `new_digest`) are cryptographic commitments certified by the root authority, but active post-mutation digest verification by the microkernel is an architectural requirement for Phase C rather than an established property of Phase B.2.
