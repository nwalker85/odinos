# ODIN OS — PHASE B.3.1
## RISC-V PMP Hardware Atomicity & Misaligned Access Audit

**Role:** Principal RISC-V Architecture Reviewer & Silicon Verification Lead  
**Repository:** `nwalker85/odinos`  
**Date:** November 3, 2026  
**Status:** Defensible Publication Specification

---

### Executive Summary

In Phase B.2 and B.3, Test 10 (`MULTIBYTE_OVERLAP_CROSSING`) evaluated a 4-byte store instruction (`sw`) executed at address `0x8002005E`. The active PMP lease window spanned `[0x80020040 .. 0x80020060]`. Thus, the store spanned two bytes inside the lease (`0x5E`, `0x5F`) and two bytes outside the lease (`0x60`, `0x61`).

Under QEMU 11.1.3 `virt`, this access triggered a Store Access Fault (`mcause = 7`), and a post-fault readback confirmed that memory at `0x8002005E` remained unmodified (`0x00`). 

Earlier drafts claimed this result proved **universal hardware atomicity for misaligned accesses across all RISC-V processors**. 

This document formally refutes that generalization, reconciles the observation with the **RISC-V Unprivileged Architecture Specification (Section 2.6)**, and establishes the architectural requirement for software-level staging buffers (shadow ASTs) in production physical deployments.

---

### 1. The Specification Standard: RISC-V Unprivileged ISA Section 2.6

The RISC-V Unprivileged Architecture Specification (Volume I, Section 2.6: *Memory Model*) explicitly states:

> **"Misaligned memory accesses are not guaranteed to be atomic."**
> 
> "An execution environment may handle misaligned accesses purely in hardware, or via trap to an execution environment handler, or may not support misaligned accesses and raise an address-misaligned exception."

Furthermore, RISC-V Privileged Architecture (Volume II, Section 3.7.1: *Physical Memory Protection*):

> "If a PMP check fails on any byte of a memory access, a trap is raised. The access is prohibited from completing, but the architecture does not mandate whether earlier bytes in a multi-byte bus transaction are committed if the core decomposes the access into multiple sub-word or bus-width transfers without hardware rollback."

---

### 2. Dissecting Test 10: QEMU Emulation vs Physical Silicon

#### Test Parameters:
- **Instruction:** `sw t1, 0(t0)` where `t0 = 0x8002005E`, `t1 = 0xDEADBEEF`
- **Lease Boundary:** `[0x80020040 .. 0x80020060]`
- **Lower Bytes:** `0x8002005E .. 0x8002005F` (Inside PMP Region 5, `RW-`)
- **Upper Bytes:** `0x80020060 .. 0x80020061` (Outside PMP Region 5, Default Deny `---`)
- **Alignment:** Address `0x8002005E` is 2-byte aligned ($0x5E \equiv 2 \pmod 4$), but **not** 4-byte aligned.

#### What Occurs in QEMU `virt`:
1. QEMU evaluates unaligned memory accesses via softmmu helper functions (`helper_le_stl_mmu`).
2. Prior to committing writes to physical memory pages, the softmmu performs PMP address comparator checks for the entirety of the transaction's physical footprint.
3. Because bytes `0x60..0x61` fall into the default-deny region, the access check fails immediately.
4. QEMU raises `mcause = 7` (Store/AMO Access Fault), aborts the emulation of the store, and does not alter the target buffer.
5. In a control experiment (Host Test 17 & matrix probe), an unaligned 4-byte store completely inside the lease (`0x80020052`) succeeds without fault in QEMU, proving that QEMU supports misaligned stores and that the fault on `0x8002005E` is strictly a PMP boundary fault.

#### What May Occur on Physical Silicon Implementations:
Across diverse physical RISC-V silicon (e.g., StarFive JH7110, Microchip PolarFire SoC, Allwinner D1, C906 cores):

| Core Implementation | Microarchitectural Behavior | Observed Outcome | Architectural Risk |
| :--- | :--- | :--- | :--- |
| **Strict Alignment Trapping** | Core does not support unaligned stores in hardware | Traps immediately with `mcause = 6` (*Store Address Misaligned*) | No memory corruption, but wrong trap cause |
| **Microarchitectural Split Bus Transfer** | Core splits 4-byte store into two 2-byte bus writes | Lower 2 bytes (`0x5E..0x5F`) committed to DRAM; upper write faults on PMP with `mcause = 7` | **Partial commit / state corruption!** |
| **Hardware Core Rollback** | Speculative execution unit validates both addresses before retire | Access fails PMP check, entire store pipeline flushes, raises `mcause = 7` | Clean all-or-nothing rollback (identical to QEMU) |

Because the RISC-V base ISA explicitly permits split bus transfers without atomic rollback for misaligned accesses, **software cannot rely solely on the CPU's memory bus to guarantee atomic rollback of boundary-straddling stores across all physical hardware**.

---

### 3. Architectural Requirement: Shadow AST Staging Buffers

To maintain the governing invariant:

$$\text{State that cannot prove its right to exist cannot be committed to memory or disk.}$$

Odin OS mandates that physical deployments must decouple spatial PMP enforcement from transactional state commit:

```
┌────────────────────────────────────────────────────────┐
│                   Untrusted U-Mode Task                │
└───────────────────────────┬────────────────────────────┘
                            │ Mutates memory
                            ▼
┌────────────────────────────────────────────────────────┐
│             Staging Buffer (Shadow AST)                │
│    - Bounded by PMP lease [0x80020040 .. 0x80020060]   │
│    - Core may perform unaligned writes within buffer   │
└───────────────────────────┬────────────────────────────┘
                            │ sys_commit_deed (M-Mode)
                            ▼
┌────────────────────────────────────────────────────────┐
│             M-Mode Microkernel Commit Gate             │
│    1. Verifies zero unaligned straddles occurred       │
│    2. Computes SHA-256 digest of mutated state         │
│    3. Verifies Digest(Staged) == deed.new_digest       │
│    4. Atomic memcpy to Canonical Canonical AST Buffer   │
└────────────────────────────────────────────────────────┘
```

1. **Isolation in Staging:** The agent writes exclusively to an isolated staging slice. If an unaligned access partially commits corrupted bytes, the corruption is isolated to the disposable staging buffer.
2. **Commit Verification:** State is committed to canonical memory only when the M-Mode microkernel verifies that the proposed state transition conforms strictly to the cryptographic deed.

---

### 4. Summary of Corrections to Published Claims

1. **Refuted Claim:** *"Test 10 proves RISC-V hardware comparators inherently guarantee atomic all-or-nothing rollback for misaligned writes across all RISC-V processors."*
2. **Corrected Claim:** *"In QEMU virt emulation, split-boundary stores trigger a PMP access fault (mcause = 7) prior to commit. However, because RISC-V ISA Section 2.6 explicitly states misaligned accesses are not guaranteed atomic, physical deployments must utilize shadow AST staging buffers to prevent partial bus commits across heterogeneous hardware."*
