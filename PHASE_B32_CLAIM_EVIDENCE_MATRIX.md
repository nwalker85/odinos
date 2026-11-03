# ODIN OS — PHASE B.3.2
## Claim vs. Evidence Matrix (Publication Audit)

**Role:** Scientific Publication Integrity Auditor  
**Repository:** `nwalker85/odinos`  
**Date:** November 3, 2026  
**Status:** Independent Audit Baseline

---

### Classification Standards

- **DEMONSTRATED:** Directly verified by reproducible automated tests, traces, or machine-checked SMT queries within the specified boundary.
- **QUALIFIED:** Valid under explicit, documented operating assumptions (e.g. software emulation under QEMU or requiring external staging buffers on physical silicon).
- **PROPOSED:** Architectural design specified in documentation for future development; not implemented in the current prototype.
- **UNSUPPORTED:** Claim not substantiated by implementation or contradicted by evidence.

---

### Granular Claim Audit Matrix

| Claim ID | Exact Claim (Quoted from Whitepaper) | Implementation Path & Function | Empirical Evidence | Execution Boundary | Status | Confidence | Technical Boundary & Qualification |
| :---: | :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| **C-01** | *"Integration of RFC 8032 Ed25519 digital signature verification in pure `#![no_std]` without heap allocation (`no_alloc`), bound to a 32-byte pinned root public key"* | `src/deed.rs:185..194` (`verify_ed25519_signature`) | Host Tests 10, 17, 19, 20; Matrix Tests 11, 13, 14 | M-Mode Kernel (`#![no_std]`) | **DEMONSTRATED** | HIGH | Verified using `ed25519-compact` with zero dynamic allocations. |
| **C-02** | *"Domain partitioning configuring user code as read-execute (`R-X`, store attempts fault with `mcause = 7`)"* | `src/main.rs:240` (`setup_pmp`), PMP Entry 1 (`TOR`, `0x0D`) | Matrix Test 7 (`mcause = 7`, store trapped, memory unmodified) | QEMU virt (rv64) | **DEMONSTRATED** | HIGH | Observed in QEMU PMP comparator checks. |
| **C-03** | *"User stack memory is read-write non-executable (`RW-`, instruction fetch attempts fault with `mcause = 1` and are safely redirected to caller return addresses)"* | `src/main.rs:239` (`setup_pmp`), PMP Entry 2; `src/main.rs:848..855` (trap handler) | Matrix Test 8 (`mcause = 1`, trap caught, redirected to `frame.ra`) | QEMU virt (rv64) | **DEMONSTRATED** | HIGH | Verified that executing stack code triggers Instruction Access Fault and resumes safely. |
| **C-04** | *"Privileged syscall interface (`SYS_REVOKE_LEASE`, `ecall 13`) that dynamically collapses PMP comparator windows to `OFF`"* | `src/main.rs:1014..1020` (syscall 13 handler) | Matrix Test 16 (`mcause = 7` upon subsequent store to revoked slice) | QEMU virt (rv64) | **DEMONSTRATED** | HIGH | Calling syscall 13 clears `ACTIVE_LEASE_START/END` and sets PMP entry to `OFF`. |
| **C-05** | *"All 17 adversarial test cases passed under emulation, comprising processor-enforced access faults and software-enforced authorization checks"* | `src/main.rs:565..730` (test matrix) | `cargo run --release`; Matrix receipts 1..17 | QEMU virt (rv64) | **DEMONSTRATED** | HIGH | Tests 1–10, 15–17 are hardware PMP/CSR faults; Tests 11–14 are M-mode syscall checks. |
| **C-06** | *"Authorized memory stores execute under configured PMP permissions without per-store kernel mediation"* | RISC-V PMP Hardware Architecture | Matrix Tests 1 & 2; Gemma bridge Scenario 1 | QEMU virt (rv64) | **DEMONSTRATED** | HIGH | Store instructions execute directly in U-mode when within PMP bounds without entering M-mode. Cycle latency unmeasured. |
| **C-07** | *"Out-of-bounds mutation attempts are rejected at the PDP or trapped by processor PMP checks with no modification to inspected memory locations"* | `tools/pdp_authority_service.py` & `src/main.rs:859` | Authority Tests 1..6; Matrix Tests 3, 4, 9, 10 | Host PDP & QEMU virt | **DEMONSTRATED** | HIGH | PDP rejects out-of-bounds requests; direct store attempts trap with `mcause = 7` in QEMU. |
| **C-08** | *"The PDP supports two operational modes: Mode A (Deterministic Research Fixture) ... and Mode B (Independently Provisioned Authority)"* | `tools/pdp_authority_service.py:53..86` & `build.rs` | Authority Tests 11 & 12 (`test_authority_isolation.py`) | Host Python PDP & Rust Build | **DEMONSTRATED** | HIGH | Mode A uses documented test key; Mode B loads CSPRNG seed and fails closed if missing. |
| **C-09** | *"Multi-byte store at `0x8002005E` raises Store Access Fault (`mcause = 7`) and leaves target memory unmodified (`0x00`) under QEMU virt"* | `src/main.rs:623..637` (Test 10) | Matrix Test 10 receipt (`mcause = 7`, readback `0x00`) | QEMU virt (rv64) | **DEMONSTRATED** | HIGH | Observed directly in QEMU 11.1.3 softmmu. |
| **C-10** | *"Misaligned store atomicity on physical silicon across protection boundaries"* | Theoretical Architecture | RISC-V Unprivileged ISA Section 2.6 | Physical Silicon | **QUALIFIED** | MEDIUM | RISC-V §2.6 permits non-atomic split transfers; physical deployment mandates shadow AST staging buffers. |
| **C-11** | *"Machine-checked properties of the formal SMT models for bounded overflow, disjointness, and anti-replay"* | `formal/*.smt2` | Z3 5.3.1 solving (`unsat` in 0.02s); SMT mutation tests | Z3 SMT Solver (`QF_BV`) | **DEMONSTRATED** | HIGH | Verified that properties hold in the SMT model and mutants produce `sat`. |
| **C-12** | *"Controlled mutation testing demonstrating detection sensitivity across 15 injected faults (15/15 killed)"* | `PHASE_B3_MUTATION_REPORT.md` | Injected faults M01..M15 | QEMU & Host Tests | **DEMONSTRATED** | HIGH | All 15 injected architectural faults detected and terminated by test suite. |
| **C-13** | *"External Layer B verifier independently validates receipts and trace continuity"* | `tools/verify_evidence.py` | Host execution trace audit (`ea85087981c0...`) | Host Python Verifier | **DEMONSTRATED** | HIGH | Verifies all 13 schema fields, monotonic sequence 1..17, and recalculates invariants. |
| **C-14** | *"Shadow AST staging buffers, in-kernel SHA-256 computation, and atomic state commit (`sys_commit_deed`)"* | None (Documented in `PHASE_B32_SEMANTIC_INTEGRITY_STATUS.md`) | Specification only | Proposed Architecture | **PROPOSED** | N/A | Classed as proposed Phase C architecture; not claimed as implemented in the prototype paper. |

---

### Audit Summary

Across 14 granular claims:
- **12 Claims DEMONSTRATED** with empirical tests, traces, or SMT models.
- **1 Claim QUALIFIED** (misaligned store atomicity on physical silicon governed by RISC-V §2.6).
- **1 Claim PROPOSED** (shadow AST staging buffers and commit barriers).
- **0 Claims UNSUPPORTED.**

All claims published in the Odin OS whitepaper correspond strictly to verified implementation artifacts.
