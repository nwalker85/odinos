# Odin OS: Known Architectural Limitations & Unresolved Proof Obligations

**Document Identifier:** ODIN-DOC-KL-001  
**Classification:** Independent Peer-Review & Assurance Package  
**Target Release:** Phase B.3.2 Canonical Baseline  
**Revision:** 2026-11-07  

---

## 1. Executive Purpose

To maintain scientific integrity and prevent overclaiming, this document catalogs the exact architectural limitations, hardware discrepancies, and unresolved proof obligations of the Odin OS Phase B.3.2 prototype. 

Reviewers should treat these limitations as documented non-guarantees when evaluating the research claims.

---

## 2. Catalog of Known Limitations

### Limitation 1: Simulation vs. Physical Silicon Differences

* **Description:** All empirical runtime benchmarks, adversarial matrices, and trap verifications were conducted under QEMU 11.1.3 `virt` (`riscv64gc-unknown-none-elf`). Software emulation differs from physical silicon in three critical architectural areas:
  1. **PMP Grain Size ($G$, Minimum Granularity $2^{G+2}$ Bytes):** Under the RISC-V Privileged Architecture Specification (§3.7), `pmpaddr` registers encode physical addresses shifted right by 2 bits, yielding a minimum region granularity of $2^{G+2}$ bytes. In QEMU `virt`, the PMP grain size is $G = 0$ (4-byte minimum region alignment, against which our 32-byte test lease `[0x80020040, 0x80020060)` aligns cleanly). Standard commodity physical RISC-V silicon typically implements grain sizes of $G = 2$ ($2^{2+2} = 16$-byte alignment), $G = 4$ ($2^{4+2} = 64$-byte cache-line alignment), or $G = 6$ ($2^{6+2} = 256$-byte alignment). On physical silicon with $G > 0$, PMP TOR boundaries must be aligned to $2^{G+2}$ bytes, or sub-grain regions will be masked to the coarser hardware boundary.
  2. **Store Pipeline Write-Buffer Draining:** QEMU softmmu evaluates accesses synchronously. On pipelined out-of-order physical cores, store-to-load forwarding and write-buffer queues require explicit hardware memory barriers (`fence rw, rw` or `fence.i`) before and after PMP CSR reconfiguration to guarantee that in-flight stores do not retire under stale capability windows.
  3. **Misaligned Split-Access Store Atomicity (ODIN-C001 vs. ODIN-C008):** In all empirical tests (including Matrix Test 10), **Unauthorized-Byte Preservation** is strictly guaranteed: out-of-bounds bytes are never corrupted or modified. Under QEMU virt, the processor evaluates unaligned 4-byte boundary stores atomically before retirement, leaving both in-bounds and out-of-bounds bytes unmodified. However, under the RISC-V Unprivileged Architecture Specification (§2.6):
     > *"Misaligned memory accesses are not guaranteed to be atomic."*  
     Physical silicon cores may commit the lower in-bounds half of an unaligned store before raising an access fault on the out-of-bounds portion. Therefore, complete store atomicity across boundaries is qualified by ODIN-C008 and remains an open physical-silicon proof obligation.
* **Mitigation Required for Physical Deployment:** Phase C physical silicon deployment mandates pairing hardware PMP comparators with dual-buffer shadow AST staging buffers (`ODIN-C011`) to enforce all-or-nothing transactional commit.

---

### Limitation 2: Autonomous Preemption & Cycle Revocation

* **Description:** In the Phase B.3.2 prototype, capability leases are revoked explicitly via microkernel syscall 13 (`sys_revoke_lease`). The prototype does not yet enforce autonomous capability expiration via hardware timer interrupts.
* **Impact:** If an untrusted agent task enters an infinite loop (`loop {}`) without issuing a store or invoking a syscall, the single-hart microkernel cannot preempt the agent unless external hardware interrupts are enabled.
* **Unresolved Obligation:** Programming the machine-mode timer registers (`mtime` and `mtimecmp`) to trigger periodic preemption traps (`mcause = 0x8000000000000007`) is designated as Phase C development.

---

### Limitation 3: Spatial Confinement vs. Content/Digest Integrity

* **Description:** Odin OS Phase B.3.2 enforces **spatial capability containment** (where writes occur) and **temporal lease bounds** (when writes occur). It does not verify that memory contents bitwise match cryptographic digests.
* **Distinction:**
  * The `TransitionDeed` structure reserves fields for `base_digest` (pre-state hash) and `new_digest` (expected post-state hash).
  * In the Phase B.3.2 microkernel, these fields are parsed and cryptographically authenticated under the Ed25519 signature, but the kernel does not execute in-situ SHA-256 hashing over DRAM contents before and after writes.
* **Current Boundary:** A malicious agent with an authorized lease for `[0x40..0x60]` can write arbitrary byte patterns within those 32 bytes without triggering a microkernel fault, provided the store does not exceed `0x60`. Verifying that the written bytes conform to `new_digest` requires shadow AST commit barriers, cataloged as **PROPOSED ARCHITECTURE** for Phase C.

---

### Limitation 4: Non-Volatile Sequence Nonce Persistence

* **Description:** Anti-replay sequence protection (`last_sequence`) is maintained in kernel Machine-Mode RAM.
* **Failure Scenario:** Upon a cold CPU reset, power failure, or hypervisor reboot, the in-memory sequence counter resets to zero. If the Policy Decision Point is not re-keyed or synchronized across reboots, stale deeds could theoretically be resubmitted after a reboot.
* **Mitigation in Prototype:** Mode B provides a persistent disk-backed sequence journal for the host PDP (`tools/pdp_authority_service.py`), but bare-metal microkernel persistence requires non-volatile secure EEPROM/NVRAM on physical silicon.

---

### Limitation 5: Formal Model Abstraction Gap

* **Description:** Formal verification was conducted using Z3 5.3.1 over abstract SMT-LIB2 models (`QF_BV` bitvectors):
  * `deed_bounds_verification.smt2`: Proves bounded integer overflow and memory disjointness.
  * `sequence_anti_replay.smt2`: Proves sequence monotonicity.
* **Abstraction Gap:** The formal SMT models prove properties of the mathematical abstraction. They do not constitute formal machine-checked proofs of the compiled RISC-V machine instructions (unlike seL4's Isabelle/HOL binary verification). Bugs in `rustc`, LLVM code generation, or inline assembly could violate the mathematical model.

---

### Limitation 6: Root Authority Private Key Custody

* **Description:** In Mode B (Independently Provisioned Authority), the PDP root signing key is loaded from an external seed file on the host filesystem.
* **Threat Surface:** Mode B relies on host operating system file permissions (`chmod 600`) and process memory isolation. Odin OS does not implement hardware security module (HSM), TPM, or ARM TrustZone / RISC-V Keystone enclave custody for the root signing key. Compromise of the host administrator account compromises the signing authority.

---

## 3. Summary of Unresolved Research Obligations

| Research Obligation | Current Prototype Baseline | Target Resolution Platform | Priority |
| :--- | :--- | :--- | :---: |
| **Physical Silicon Bus Verification** | QEMU 11.1.3 `virt` softmmu | AMD Kria KV260 / StarFive JH7110 | Phase C (P0) |
| **Autonomous Hardware Preemption** | Explicit syscall (`sys_revoke_lease`) | RISC-V `mtimecmp` timer interrupts | Phase C (P1) |
| **Shadow AST Transactional Commit** | Spatial PMP bounds enforcement | Dual-buffer commit barrier with SHA-256 | Phase C (P0) |
| **Non-Volatile Sequence NVRAM** | In-memory RAM counter (`last_seq`) | I2C/SPI Secure EEPROM non-volatile counter | Phase C (P1) |
| **End-to-End Binary Verification** | Z3 SMT over QF_BV mathematical models | Translation validation / Sail RISC-V model | Phase D (P2) |
