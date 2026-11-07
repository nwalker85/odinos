# Odin OS: Comprehensive Claim-to-Evidence Registry

**Document Identifier:** ODIN-DOC-CER-001  
**Classification:** Independent Peer-Review & Assurance Package  
**Target Release:** Phase B.3.2 Canonical Baseline  
**Revision:** 2026-11-07  

---

## 1. Assurance Status Definitions

In accordance with rigorous peer-review standards, every technical claim in Odin OS is assigned an explicit, conservative assurance status:

* **`REPRODUCED`**: Directly executed and independently validated during the clean-room verification pipeline on this specific commit (`68f45c1`).
* **`MODEL-CHECKED`**: Verified via formal mathematical models (Z3 SMT QF_BV). Proves properties of the abstract specification, not compiled machine code.
* **`QUALIFIED`**: Verified under explicit, documented operating assumptions (e.g. software emulation under QEMU 11.1.3 virt); known silicon differences require additional mitigations.
* **`PROPOSED`**: Architectural design specified in documentation for future development; not implemented in the current prototype.
* **`CONTRADICTED`**: Available evidence conflicts with or invalidates the claim.

---

## 2. Granular Technical Claims Registry

```
Summary of Registered Claims:
├── Layer A: Cryptographic Authorization
│   ├── ODIN-C002 [REPRODUCED]    Decoupled PDP Authority Isolation
│   ├── ODIN-C003 [REPRODUCED]    Pure #![no_std] Ed25519 Signature Verification
│   └── ODIN-C004 [MODEL-CHECKED] Anti-Replay Monotonic Sequence Nonce
├── Layer B: Hardware Enforcement
│   ├── ODIN-C001 [REPRODUCED]    PRIORITY: Spatial Mutation Isolation via PMP
│   ├── ODIN-C005 [REPRODUCED]    Bi-Directional W^X Privilege Separation
│   ├── ODIN-C006 [REPRODUCED]    Dynamic Temporal Capability Lease Revocation
│   ├── ODIN-C007 [REPRODUCED]    Privileged CSR & MMIO Perimeter Isolation
│   ├── ODIN-C008 [QUALIFIED]     Multi-Byte Protection Boundary Crossing
│   └── ODIN-C014 [PROPOSED]      Physical Silicon & Autonomous Timer Migration
├── Layer C: Transactional & Content Integrity
│   ├── ODIN-C009 [MODEL-CHECKED] Bounded Integer Offset Arithmetic Immunity
│   ├── ODIN-C010 [REPRODUCED]    Independent Layer B Host Trace & Receipt Audit
│   └── ODIN-C011 [PROPOSED]      Shadow AST Staging & In-Kernel SHA-256 Digest Commit
└── Layer D: Semantic & Business Appropriateness
    ├── ODIN-C012 [INVARIANT]     Decoupling of Spatial Access from Business Intent
    └── ODIN-C013 [REPRODUCED]    Two-Layer Prompt Injection Deflection with Gemma 4
```

---

### ODIN-C001 — Spatial Mutation Isolation (PRIORITY TARGET)

* **Exact Statement:** Under QEMU virt (rv64), an untrusted U-Mode task executing arbitrary RISC-V instructions cannot retire a store instruction to any physical memory address outside the explicitly configured `[lease_start, lease_end)` window without triggering an architectural Store Access Fault (`mcause = 0x07`), aborting the write and leaving the target memory byte unmodified.
* **Assurance Category:** Layer B (Hardware Enforcement)
* **Scope & Environment:** QEMU 11.1.3 `virt` (64-bit RISC-V `riscv64gc-unknown-none-elf`).
* **Trusted Components (TCB):** CPU PMP comparators, M-Mode microkernel trap handler, memory domain layout (`linker.ld`).
* **Explicit Assumptions:** 
  1. QEMU softmmu PMP checks match RISC-V Privileged ISA v1.12.
  2. PMP Top-of-Range (TOR) comparators are programmed without overlapping higher-priority entries.
* **Source Implementation:**
  * PMP Setup: [`src/main.rs:226..260`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/src/main.rs#L226-L260) (`setup_pmp`)
  * Trap Handler: [`src/main.rs:857..1054`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/src/main.rs#L857-L1054) (`handle_trap`)
  * Adversarial Runner: [`src/main.rs:565..630`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/src/main.rs#L565-L630)
* **Supporting Tests:**
  * In-bounds lower bound (`0x80020040`): Test 1 (Commit, `mcause = 0x00`)
  * In-bounds upper bound minus one (`0x8002005F`): Test 2 (Commit, `mcause = 0x00`)
  * One byte below lease (`0x8002003F`): Test 3 (Trap, `mcause = 0x07`, readback `0x00`)
  * One byte above lease (`0x80020060`): Test 4 (Trap, `mcause = 0x07`, readback `0x00`)
  * Unmapped perimeter (`0x80030000`): Test 9 (Trap, `mcause = 0x07`, readback `0x00`)
* **Supporting Raw Evidence:**
  * File: [`peer-review/evidence/qemu-adversarial-matrix.txt`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/peer-review/evidence/qemu-adversarial-matrix.txt)
  * File: [`peer-review/evidence/layer-b-evidence-verifier.txt`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/peer-review/evidence/layer-b-evidence-verifier.txt)
* **Reproduction Command:** `cargo run --release`
* **Expected vs Actual Observations:**
  * Expected: All out-of-bounds stores trap with `mcause = 7`, `hardware_fault = true`, `memory_unmodified = true`.
  * Observed: Confirmed across Tests 3, 4, and 9. Zero bits flipped at probed target addresses.
* **Known Counterexamples / Edge Cases:**
  * Unaligned multi-byte stores straddling the lease boundary (evaluated in `ODIN-C008`).
* **Exclusions & Non-Goals:**
  * Does not defend against microarchitectural cache-timing side channels (Spectre/Meltdown).
  * Does not generalize atomicity guarantees to physical silicon without shadow AST staging buffers.
* **Assurance Status:** **`REPRODUCED`**
* **Falsification Procedure:** Refer to Protocol `PROTO-01` in [`FALSIFICATION_PROTOCOLS.md`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/peer-review/FALSIFICATION_PROTOCOLS.md).

---

### ODIN-C002 — Decoupled Policy Decision Point (PDP) Authority Isolation

* **Exact Statement:** Private cryptographic signing keys are completely isolated from U-Mode agent tasks and transport bridges; capability minting requires independent evaluation against declarative security policies across 12 distinct attack vectors.
* **Assurance Category:** Layer A (Cryptographic Authorization)
* **Scope & Environment:** Host Python Environment (`tools/pdp_authority_service.py`).
* **Trusted Components (TCB):** Host Python interpreter, OS process isolation, root seed storage.
* **Explicit Assumptions:** Host operating system account running the PDP is not compromised.
* **Source Implementation:**
  * PDP Service: [`tools/pdp_authority_service.py`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/tools/pdp_authority_service.py)
  * Compile Key Injector: [`build.rs`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/build.rs)
* **Supporting Tests:** `tests/test_authority_isolation.py` (12 unit test vectors).
* **Supporting Raw Evidence:** [`peer-review/evidence/authority-isolation-suite.txt`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/peer-review/evidence/authority-isolation-suite.txt)
* **Reproduction Command:** `python3 -m unittest tests/test_authority_isolation.py`
* **Expected vs Actual Observations:** All 12 adversarial requests rejected (unauthorized anchors, invalid opcodes, oversized spans, rogue DIDs, sequence resets).
* **Assurance Status:** **`REPRODUCED`**

---

### ODIN-C003 — Pure #![no_std] Ed25519 Signature Verification

* **Exact Statement:** The microkernel verifies RFC 8032 Ed25519 digital signatures in pure `#![no_std]` without dynamic heap allocation (`no_alloc`), rejecting invalid keys, single-bit signature flips, and tampered payloads.
* **Assurance Category:** Layer A (Cryptographic Authorization)
* **Scope & Environment:** RISC-V Bare-Metal M-Mode & Host Rust Unittests.
* **Trusted Components (TCB):** `ed25519-compact` v2.6.0 crate, microkernel deed parser.
* **Source Implementation:** [`src/deed.rs:185..194`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/src/deed.rs#L185-L194) (`verify_ed25519_signature`)
* **Supporting Tests:**
  * Matrix Tests 11, 13, 14 (QEMU bare-metal)
  * Host Tests: `test_ed25519_single_bit_flip_signature_rejection`, `test_ed25519_unauthorized_key_rejection`, `prop_payload_tamper_detection`.
* **Supporting Raw Evidence:** [`peer-review/evidence/host-unit-tests.txt`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/peer-review/evidence/host-unit-tests.txt)
* **Reproduction Command:** `cargo test --lib --target aarch64-apple-darwin`
* **Assurance Status:** **`REPRODUCED`**

---

### ODIN-C004 — Anti-Replay Monotonic Sequence Nonce Enforcement

* **Exact Statement:** TransitionDeeds resubmitted with an identical or stale sequence number ($s \le \text{last\_seq}$) are rejected with `DeedError::ReplayDetected`. resubmission is mathematically unsatisfiable under strict monotonicity assumptions.
* **Assurance Category:** Layer A (Cryptographic Authorization)
* **Scope & Environment:** Microkernel runtime and Z3 SMT Formal Model.
* **Source Implementation:** [`src/deed.rs:141`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/src/deed.rs#L141); [`formal/sequence_anti_replay.smt2`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/formal/sequence_anti_replay.smt2)
* **Supporting Tests:** Matrix Test 12; Z3 Theorems 4 & 5.
* **Supporting Raw Evidence:** [`peer-review/evidence/smt-proofs.txt`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/peer-review/evidence/smt-proofs.txt)
* **Reproduction Command:** `z3 formal/sequence_anti_replay.smt2`
* **Assurance Status:** **`MODEL-CHECKED`** and **`REPRODUCED`**
* **Limitation:** In-memory sequence resets on hard CPU power loss unless persistent NVRAM is provisioned.

---

### ODIN-C005 — Bi-Directional $W \oplus X$ Privilege Separation

* **Exact Statement:** User task code memory is mapped as read-execute (`R-X`, store attempts fault with `mcause = 7`), while user stack memory is read-write non-executable (`RW-`, instruction fetch attempts fault with `mcause = 1` and are safely redirected to caller return address).
* **Assurance Category:** Layer B (Hardware Enforcement)
* **Source Implementation:** [`src/main.rs:239..240`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/src/main.rs#L239-L240), [`src/main.rs:1039..1045`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/src/main.rs#L1039-L1045)
* **Supporting Tests:** Matrix Test 7 (code write) & Test 8 (stack execute); Mutations M06 & M15.
* **Supporting Raw Evidence:** [`peer-review/evidence/qemu-adversarial-matrix.txt`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/peer-review/evidence/qemu-adversarial-matrix.txt)
* **Assurance Status:** **`REPRODUCED`**

---

### ODIN-C006 — Dynamic Temporal Capability Lease Revocation

* **Exact Statement:** Microkernel syscall 13 (`SYS_REVOKE_LEASE`) clears active lease boundaries and collapses the corresponding PMP register window to `OFF`. Subsequent store attempts to the previously valid lease slice immediately trigger an architectural Store Access Fault (`mcause = 7`).
* **Assurance Category:** Layer B (Hardware Enforcement)
* **Source Implementation:** [`src/main.rs:1014..1021`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/src/main.rs#L1014-L1021); [`src/main.rs:252`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/src/main.rs#L252)
* **Supporting Tests:** Matrix Test 16; Mutation M09.
* **Supporting Raw Evidence:** [`peer-review/evidence/qemu-adversarial-matrix.txt`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/peer-review/evidence/qemu-adversarial-matrix.txt)
* **Assurance Status:** **`REPRODUCED`**

---

### ODIN-C007 — Privileged CSR & MMIO Perimeter Isolation

* **Exact Statement:** Untrusted User Mode cannot access or manipulate PMP configuration registers (`pmpcfg0`, trapping with `mcause = 2`) or UART0 MMIO registers (`0x10000000`, trapping with `mcause = 7`).
* **Assurance Category:** Layer B (Hardware Enforcement)
* **Source Implementation:** [`src/main.rs:234`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/src/main.rs#L234); Linker script Domain 0 layout.
* **Supporting Tests:** Matrix Tests 15 & 17; Mutation M07.
* **Supporting Raw Evidence:** [`peer-review/evidence/qemu-adversarial-matrix.txt`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/peer-review/evidence/qemu-adversarial-matrix.txt)
* **Assurance Status:** **`REPRODUCED`**

---

### ODIN-C008 — Multi-Byte Protection Boundary Crossing (Test 10)

* **Exact Statement:** Under QEMU virt, an unaligned 4-byte store straddling a protection boundary (`0x8002005E`, crossing into unauthorized address `0x80020060`) raises a Store Access Fault (`mcause = 7`) and leaves all 4 target bytes unmodified (`0x00`).
* **Assurance Category:** Layer B (Hardware Enforcement)
* **Scope & Environment:** QEMU 11.1.3 virt (rv64).
* **Qualification & Limitation:** RISC-V Unprivileged Architecture §2.6 explicitly does not guarantee atomicity for misaligned accesses. Physical silicon cores may commit lower bytes prior to trapping on the boundary.
* **Source Implementation:** [`src/main.rs:623..637`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/src/main.rs#L623-L637)
* **Supporting Tests:** Matrix Test 10.
* **Supporting Raw Evidence:** [`peer-review/evidence/qemu-adversarial-matrix.txt`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/peer-review/evidence/qemu-adversarial-matrix.txt)
* **Assurance Status:** **`QUALIFIED`** (Holds in QEMU; requires shadow AST staging for physical silicon portability).

---

### ODIN-C009 — Bounded Integer Offset Arithmetic Immunity

* **Exact Statement:** Checked addition on deed offset and span length (`target_offset.checked_add(target_length)`) prevents integer overflow wrapping and rejects out-of-bounds wrap attacks. Verified mathematically in Z3 QF_BV.
* **Assurance Category:** Layer C (Transactional Integrity)
* **Source Implementation:** [`src/deed.rs:149`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/src/deed.rs#L149); [`formal/deed_bounds_verification.smt2`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/formal/deed_bounds_verification.smt2)
* **Supporting Tests:** Z3 Theorem 1; `prop_deed_overflow_protection`.
* **Supporting Raw Evidence:** [`peer-review/evidence/smt-proofs.txt`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/peer-review/evidence/smt-proofs.txt)
* **Assurance Status:** **`MODEL-CHECKED`** and **`REPRODUCED`**

---

### ODIN-C010 — Independent Layer B Host Trace & Receipt Audit

* **Exact Statement:** The external Layer B Python verifier strictly validates raw execution receipts, verifies monotonic sequence continuity (1..17), re-evaluates all assertions independently of kernel telemetry, and detects injected forged PASS records.
* **Assurance Category:** Layer C (Transactional Integrity)
* **Source Implementation:** [`tools/verify_evidence.py`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/tools/verify_evidence.py)
* **Supporting Tests:** 10 unit tests in `tests/test_evidence_verifier_adversarial.py`.
* **Supporting Raw Evidence:** [`peer-review/evidence/layer-b-evidence-verifier.txt`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/peer-review/evidence/layer-b-evidence-verifier.txt)
* **Reproduction Command:** `python3 tools/verify_evidence.py`
* **Assurance Status:** **`REPRODUCED`**

---

### ODIN-C011 — Shadow AST Staging Buffers & Digest Commit

* **Exact Statement:** State mutations are staged in an unprivileged scratch buffer, hashed via SHA-256, compared against `new_digest`, and atomically committed via microkernel memory barriers.
* **Assurance Category:** Layer C (Transactional Integrity)
* **Assurance Status:** **`PROPOSED`** (Phase C Architecture Roadmap).
* **Current Boundary:** Not implemented in Phase B.3.2 prototype. The prototype enforces spatial write windows, not post-commit digest validation.

---

### ODIN-C012 — Decoupling of Hardware Capability from Business Semantic Appropriateness

* **Exact Statement:** Processor Physical Memory Protection (PMP) enforces spatial access bounds, but cannot judge whether an authorized mutation is contextually appropriate under business logic or application rules.
* **Assurance Category:** Layer D (Semantic Appropriateness)
* **Assurance Status:** **`ARCHITECTURAL INVARIANT`** (Foundational Design Axiom).
* **Implication:** Even with 100% hardware PMP enforcement, an agent can commit undesirable state if authorized by an errant or misconfigured PDP.

---

### ODIN-C013 — Two-Layer Adversarial Prompt Injection Deflection with Gemma 4

* **Exact Statement:** When an autonomous LLM (`google/gemma-4-e4b`) is prompted with an adversarial jailbreak to write to unmapped kernel memory (`0x80030000`), the mutation is blocked at Layer 1 by the PDP (denying deed issuance) and, if injected directly into U-Mode, trapped at Layer 2 by CPU PMP comparators (`mcause = 7`, zero bits committed).
* **Assurance Category:** Layer D (Semantic Appropriateness)
* **Source Implementation:** [`tools/gemma_odin_bridge.py`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/tools/gemma_odin_bridge.py)
* **Supporting Raw Evidence:** [`peer-review/evidence/gemma-bridge-execution.txt`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/peer-review/evidence/gemma-bridge-execution.txt)
* **Reproduction Command:** `python3 tools/gemma_odin_bridge.py`
* **Assurance Status:** **`REPRODUCED`**

---

### ODIN-C014 — Physical Silicon & Autonomous Hardware Timer Migration

* **Exact Statement:** Physical silicon deployment on AMD Kria KV260 and StarFive JH7110 with hardware timer-interrupt lease revocation (`mcycle`/`mtimecmp`) and non-volatile sequence storage.
* **Assurance Category:** Layer B (Hardware Enforcement)
* **Assurance Status:** **`PROPOSED`** (Phase C Roadmap).
