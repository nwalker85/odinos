# Odin OS: Independent Reproducibility Guide

**Document Identifier:** ODIN-DOC-REP-001  
**Classification:** Independent Peer-Review & Assurance Package  
**Target Release:** Phase B.3.2 Canonical Baseline  
**Pull Request:** [PR #10](https://github.com/nwalker85/odinos/pull/10) (`clean-zenodo-artifacts-354e271c`)  
**Permanent Archive DOI:** [`10.5281/zenodo.23928302`](https://doi.org/10.5281/zenodo.23928302)  
**Revision:** 2026-11-07  

---

> **Repository Access & Provenance Notice for Reviewers:**  
> The upstream GitHub repository [`nwalker85/odinos`](https://github.com/nwalker85/odinos) is open and publicly accessible. Reviewers can clone the live repository without authentication to reproduce the active codebase and test suites.
> 
> **Archive Lineage on Zenodo ([Concept DOI 10.5281/zenodo.23928301](https://doi.org/10.5281/zenodo.23928301)):**
> For immutable baseline reproduction matching specific publication milestones, reviewers can download the frozen release archives from Zenodo:
> - **Version 1 ([DOI 10.5281/zenodo.23928302](https://doi.org/10.5281/zenodo.23928302)):** Frozen Phase B.3.2 release candidate baseline (`cec5b2d`, tarball MD5 `9caa2e1433d655fcf8d4aa3c3b2985d1`, 299 KB).
> - **Version 2 ([DOI 10.5281/zenodo.24044570](https://doi.org/10.5281/zenodo.24044570)):** The complete Independent Peer-Review & Assurance Package (`PR #10`, tarball MD5 `0bbcbe69d64d9a8406a15ceda82d6831`, 480 KB), incorporating `peer-review/` protocols and Apache-2.0 licensing.
> 
> Reviewers can execute all reproducibility steps directly from a clone of the public repository (`git clone https://github.com/nwalker85/odinos.git`) or from the unpacked Zenodo release tarballs.

---

## 1. System & Toolchain Specification

All experiments reported in the Odin OS Phase B.3.2 release candidate and peer-review package are reproducible using standard open-source tools without proprietary hardware.

### Verified Test Environment (Clean-Room Host)
* **Operating System:** macOS 27.0.1 (Darwin 27.0.0, arm64)
* **Rust Toolchain:** `rustc 1.98.0 (88d9e12ae 2026-08-18)` / `cargo 1.98.0`
* **Rust Target:** `riscv64gc-unknown-none-elf`
* **QEMU Emulator:** `qemu-system-riscv64 version 11.1.3`
* **SMT Theorem Prover:** `Z3 version 5.3.1 (64-bit)`
* **Python Runtime:** `Python 3.14.8` (Standard Library only; zero pip requirements)
* **Document Engine:** `typst 0.15.1`

---

## 2. Fast-Path Verification: Canonical Release Pipeline

To execute all 9 automated release verification gates in clean-room unattended mode (< 2 seconds):

```bash
python3 tools/verify_release.py
```

### Gate Execution Matrix

| Gate # | Test Description | Command Executed | Expected Duration | Expected Outcome |
| :---: | :--- | :--- | :---: | :---: |
| **G1** | Host Unit & Property Suite | `cargo test --lib --target aarch64-apple-darwin` | 0.04s | 23 passed; 0 failed |
| **G2** | Bare-Metal Microkernel Build | `cargo build --release --target riscv64gc-unknown-none-elf` | 0.03s | Exit code 0 |
| **G3** | QEMU Adversarial Matrix | `cargo run --release` | 0.07s | 17/17 passed; exit 0 |
| **G4** | PDP Authority Isolation | `python3 -m unittest tests/test_authority_isolation.py` | 0.06s | 12 passed; 0 failed |
| **G5** | Verifier Adversarial Audit | `python3 -m unittest tests/test_evidence_verifier_adversarial.py` | 0.04s | 10 passed; 0 failed |
| **G6** | Layer B Host Evidence Verifier | `python3 tools/verify_evidence.py` | 0.02s | Audit successful; exit 0 |
| **G7** | Formal Proof 1 (Bounds) | `z3 formal/deed_bounds_verification.smt2` | 0.02s | 3x `unsat` |
| **G8** | Formal Proof 2 (Anti-Replay) | `z3 formal/sequence_anti_replay.smt2` | 0.01s | 2x `unsat` |
| **G9** | Deterministic Whitepaper Build | `typst compile zenodo/odin-os-whitepaper.typ zenodo/odin-os-whitepaper.pdf` | 0.18s | Exact 6 pages |

---

## 3. Detailed Step-by-Step Reproduction Instructions

### Step 1: Microkernel Compilation
Builds the standalone `#![no_std]` ELF binary targeting 64-bit RISC-V:
```bash
cargo build --release --target riscv64gc-unknown-none-elf
```
* **Artifact Produced:** `target/riscv64gc-unknown-none-elf/release/odin-kernel`
* **Expected Output:**
  ```text
  Finished `release` profile [optimized] target(s)
  ```

### Step 2: 17-Case Adversarial QEMU Matrix
Executes the microkernel under QEMU 11.1.3 `virt` without an OS or BIOS:
```bash
cargo run --release
```
* **Hardware Traps Verified:**
  * Tests 1–2: In-bounds writes commit to memory (`mcause = 0x00`).
  * Tests 3–4: One-byte below (`0x8002003F`) and one-byte above (`0x80020060`) trap with Store Access Fault (`mcause = 0x07`).
  * Tests 5–6: Kernel code and kernel stack writes trap with `mcause = 0x07`.
  * Test 7: User task code modification traps with `mcause = 0x07` ($W \oplus X$).
  * Test 8: User stack execution attempt traps with `mcause = 0x01` and is safely redirected.
  * Test 9: Unmapped address store traps with `mcause = 0x07`.
  * Test 10: Multi-byte cross-boundary store traps with `mcause = 0x07` (all 4 bytes unmodified).
  * Tests 11–14: TransitionDeed forgery, replay, invalid signature, and tampered metadata rejected by microkernel deed verifier.
  * Test 15: U-Mode read of `pmpcfg0` traps with Illegal Instruction (`mcause = 0x02`).
  * Test 16: Post-revocation write traps with `mcause = 0x07`.
  * Test 17: U-Mode write to UART0 MMIO (`0x10000000`) traps with `mcause = 0x07`.

### Step 3: Formal SMT Verification via Z3
Verifies bounded arithmetic, memory disjointness, and anti-replay properties:
```bash
z3 formal/deed_bounds_verification.smt2
z3 formal/sequence_anti_replay.smt2
```
* **Expected Output:**
  ```text
  unsat
  unsat
  unsat
  unsat
  unsat
  ```
* **Interpretation:** `unsat` proves that the negation of the safety property has no satisfying assignment—the safety invariants hold across all modeled 64-bit bitvectors.

### Step 4: Host Cryptographic & Mutation Tests
Executes unit tests and property-based fuzz tests:
```bash
cargo test --lib --target aarch64-apple-darwin
```
* **Coverage:** 23 tests including proptest fuzzing for sequence monotonicity, payload tampering, and offset overflow.

### Step 5: External Trace & Receipt Auditing (Layer B)
Verifies raw UART logs against JSON receipts independently of the kernel:
```bash
python3 tools/verify_evidence.py
```
* **Expected Output:**
  ```text
  [AUDIT SUCCESSFUL]
    ✓ Verified Receipts Count:   17 / 17
    ✓ Schema Validation:         PASS (All 13 fields strictly typed)
    ✓ Sequence Continuity:       PASS (Strict IDs 1..17 without gaps/dups)
    ✓ Independent Invariants:    PASS (Zero forged PASS labels)
  ```

### Step 6: Neural Inference Bridge (Gemma 4)
Couples the Policy Decision Point and QEMU microkernel to local neural inference:
```bash
python3 tools/gemma_odin_bridge.py
```
* **Note:** If a local LM Studio server running `google/gemma-4-e4b` on port 6701 is detected, live inference is used. If offline, the script falls back deterministically to documented test payloads. Both scenarios execute without failure.
