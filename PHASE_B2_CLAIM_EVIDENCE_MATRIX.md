# Odin OS Phase B.2 — Claim-to-Evidence Reconciliation Matrix

**Author:** Principal Security Engineer & Verification Lead  
**Scope:** Rigorous, empirical classification of every technical claim asserted in the Odin OS Phase B.1 and Phase B.2 whitepapers, repository documentation, and architectural designs.  
**Doctrine:** *No claim enters the whitepaper without reproducible, empirical evidence.*

---

## 1. Evidence Classification Taxonomy

Every technical claim is assigned an evidence grade from **Category A** to **Category E**:

- **Category A (Empirically Verified by Hardware / QEMU Evidence):** Directly proven by deterministic test execution, hardware registers, trap captures, or CPU emulation traces.
- **Category B (Verified in Host Unit / Property-Based Modeling):** Proven by software execution, property tests, or formal mathematical invariants, but outside bare-metal CPU execution.
- **Category C (Partially Verified / Conditional Assumptions Documented):** Functionally implemented, but operating under documented architectural constraints (e.g. QEMU PMP vs physical silicon grain).
- **Category D (Unverified Prototype Placeholder / Future Roadmap):** Acknowledged architectural target that is simulated or mocked in software, with physical implementation deferred to Phase C.
- **Category E (Refuted / Superseded):** Claims from earlier phases that were found to be false, unverified, or misleading under adversarial review, and have been explicitly corrected.

---

## 2. Claim-to-Evidence Matrix

| Claim ID | Architectural Claim | Phase B.1 Status | Phase B.2 Grade | Empirical Proof Reference |
|:---:|:---|:---:|:---:|:---|
| **C-01** | Microkernel isolates M-Mode kernel from unprivileged U-Mode agent. | Claimed | **Category A** | Tests 5 & 6: Stores to `0x80000000` & `0x8000FFF8` trigger `mcause = 7`. |
| **C-02** | User code is non-writable (W^X code protection). | Claimed | **Category A** | Test 7: Store to `0x80010000` triggers `mcause = 7`, opcode preserved. |
| **C-03** | User stack is non-executable (W^X stack protection). | Unverified | **Category A** | Test 8: Execution jump to `0x80018100` triggers `mcause = 1`, trapped and redirected. |
| **C-04** | Mutation writes are strictly bounded by PMP TOR entry. | Claimed | **Category A** | Tests 1–4: In-bounds writes commit; off-by-one writes trigger `mcause = 7`. |
| **C-05** | Straddling multi-byte writes fault atomically without partial write. | Claimed | **Category A** | Test 10: 4-byte write at `0x8002005E` across `0x60` boundary commits 0 bytes. |
| **C-06** | Hardware MMIO (UART0) is inaccessible to U-Mode. | Claimed | **Category A** | Test 17: Write to `0x10000000` triggers `mcause = 7`. |
| **C-07** | Privilege escalation via CSR tampering is impossible in U-Mode. | Claimed | **Category A** | Test 15: Executing `csrr t0, pmpcfg0` triggers `mcause = 2` (Illegal Instruction). |
| **C-08** | Capability lease can be temporally revoked. | Simulated | **Category A** | Test 16: `sys_revoke_lease()` disables PMP Entry 4; store to `0x80020040` faults. |
| **C-09** | Genuine Ed25519 signature verification in `#![no_std]` without heap. | False (`SIGN` tag) | **Category A** | Tests 13 & 14 + Host Tests: RFC 8032 Ed25519 verified against pinned public key. |
| **C-10** | Monotonic sequence numbers prevent deed replay attacks. | Claimed | **Category A** | Test 12 + Prop Test: Stale sequence returns `DeedError::ReplayDetected`. |
| **C-11** | Domain separation prevents deed signature confusion across protocols. | Unverified | **Category A** | Host Test 8: Cross-protocol signature rejected with `InvalidSignature`. |
| **C-12** | Deed payload is bound to cryptographic signature before PMP config. | Partial | **Category A** | Test 14: Tampering with single byte in metadata invalidates Ed25519 signature. |
| **C-13** | Autonomous AI agent instructions run in unprivileged U-Mode. | Claimed | **Category A** | QEMU trace confirms `mstatus.MPP = 0` (U-Mode) before jumping to user task. |
| **C-14** | Property tests prove boundary invariants across millions of inputs. | Claimed | **Category B** | `proptest` suite executes 256 iterations per invariant across all bound ranges. |
| **C-15** | QEMU PMP TOR behavior is identical to physical silicon. | Claimed | **Category C** | Documented: QEMU enforces exact byte TOR, whereas physical silicon has grain constraints ($G \ge 4$). |
| **C-16** | Dedicated hardware DMA ring buffer validates deeds via bus interlock. | Asserted | **Category D** | Simulated in memory buffer `0x80040000`. Hardware controller deferred to Phase C FPGA. |
| **C-17** | DRAM wordline gating circuits physically suppress row-select voltage. | Asserted | **Category D** | Architectural specification for ASIC tapeout; simulated in microkernel via PMP. |
| **C-18** | "Phase B.1 Cryptographic Signature Attestation": Ed25519 signature verified. | False | **Category E** | **Refuted**: Phase B.1 only checked `SIGN` marker + FNV hash. Superseded by B.2 genuine Ed25519. |

---

## 3. Detailed Reconciliation of Refuted Claims (Category E)

### Claim C-18: Phase B.1 "Cryptographic Attestation"
- **Claim in Phase B.1 Documentation:** "64-byte Ed25519 signature verifies authentic capability issuance."
- **Audit Reality:** The Phase B.1 implementation checked `self.signature[0..4] == *b"SIGN"` followed by a 64-bit FNV-1a checksum of the payload. It did not perform any asymmetric elliptic curve point multiplication or verify against a public key.
- **Resolution in Phase B.2:** The claim was classified as **Category E (Refuted)** in the research ledger. In Phase B.2, genuine Ed25519 signature verification was implemented using `ed25519-compact` (`opt_size`, pure `#![no_std]`). All deeds in Phase B.2 are cryptographically authenticated against `TRUSTED_ROOT_PUBLIC_KEY`. The whitepaper has been updated to honestly distinguish Phase B.1 structural attestation from Phase B.2 cryptographic authorization.

---

## 4. Summary of Verification Status

| Category | Count | Percentage |
|:---|:---:|:---:|
| **Category A** (Hardware / QEMU Verified) | 13 | 72.2% |
| **Category B** (Host Property Verified) | 1 | 5.6% |
| **Category C** (Partially Verified / Documented) | 1 | 5.6% |
| **Category D** (Hardware Roadmap / Placeholder) | 2 | 11.1% |
| **Category E** (Refuted & Superseded) | 1 | 5.6% |
| **Total Tracked Claims** | **18** | **100.0%** |
