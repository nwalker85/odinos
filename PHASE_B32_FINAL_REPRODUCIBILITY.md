# ODIN OS — PHASE B.3.2
## Final Clean-Room Reproducibility & Provenance Report

**Role:** Scientific Reproducibility Lead & Independent Verification Auditor  
**Repository:** `nwalker85/odinos`  
**Branch:** `feat/phase-b32-publication-integrity`  
**Date:** November 3, 2026  
**Status:** 100% Reproducible Systems Artifact

---

### 1. Build Environment & Exact Toolchain Specification

| Component | Version Specification | Execution Context |
| :--- | :--- | :--- |
| **Rust Compiler** | `rustc 1.98.0 (88d9e12ae 2026-08-18)` | Host: `aarch64-apple-darwin` |
| **Cargo Package Manager** | `cargo 1.98.0 (797e8a9bc 2026-08-05)` | Target: `riscv64gc-unknown-none-elf` & native host |
| **Microkernel Linker** | `rust-lld` / LLVM LLD | Script: `src/linker.ld` (RAM base `0x80000000`) |
| **QEMU System Emulator** | `QEMU emulator version 11.1.3` | Machine: `virt`, CPU: `rv64`, Bios: `none` |
| **Python Runtime** | `Python 3.14.8` | Libraries: `pynacl`, `pypdf` |
| **Theorem Prover** | `Z3 version 5.3.1 - 64 bit` | Logic: `QF_BV` |
| **Typesetter** | `typst 0.15.1` | Document: `zenodo/odin-os-whitepaper.typ` |

---

### 2. Evidence Execution Audit: Newly Executed vs. Historically Referenced

To ensure complete transparency, this release distinguishes between newly executed tests and historical records:

#### Newly Executed in Phase B.3.2 (Clean-Room Run):
1. **Host-Side Unit Tests (23/23 PASS, 0.01s):**
   ```bash
   cargo test --lib --target aarch64-apple-darwin
   ```
   *Result:* 23 passed, 0 failed, 0 ignored. Confirmed zero-copy deserialization, RFC 8032 Ed25519 signature checks, cross-protocol domain separation rejection, and checked arithmetic.
2. **RISC-V Bare-Metal Adversarial Matrix (17/17 PASS, 0.8s):**
   ```bash
   cargo run --release
   ```
   *Result:* 17/17 invariant tests passed in QEMU `virt`. Confirmed exact bounds, stack non-executability, code non-writability, unprivileged CSR faulting, and MMIO access revoking.
3. **Authority Isolation & Mandatory Attacks Suite (12/12 PASS, 0.025s):**
   ```bash
   python3 -m unittest tests/test_authority_isolation.py
   ```
   *Result:* 12/12 tests passed. Confirmed default-deny policy, spatial bounds checks, sequence restart persistence, and Mode B CSPRNG key separation / fail-closed semantics.
4. **Machine-Checked SMT Properties (5/5 UNSAT, 0.02s):**
   ```bash
   for f in formal/*.smt2; do echo -n "$f: "; z3 "$f"; done
   ```
   *Result:* All 5 properties solved with `unsat`. SMT mutation queries confirmed models yield `sat` when checks are disabled.
5. **Layer B External Host Verifier (17/17 VERIFIED):**
   ```bash
   python3 tools/verify_evidence.py
   ```
   *Result:* Trace SHA-256 (`ea85087981c0...`) and receipts validated; zero forged labels.
6. **Manuscript PDF Compilation & Text Extraction Audit:**
   ```bash
   typst compile zenodo/odin-os-whitepaper.typ zenodo/odin-os-whitepaper.pdf
   ```
   *Result:* PDF generated; programmatic text audit confirmed all 6 rejected phrases removed.

#### Historically Referenced (Preserved from Phase B.2/B.3 Baseline):
- **15 Mutation Test Cases (M01..M15):** Documented in `PHASE_B3_MUTATION_REPORT.md` (15/15 killed). Re-verified by reference; individual manual fault injections were not re-injected in this pass to prevent source tree dirtying.

---

### 3. Release Provenance & Cryptographic Hashes

All release artifacts are bound by SHA-256:

```
# Compiled Kernel ELF
5d914428e7343bfe0e4499e119240fb22c5e014b5ca3595530d909e8c53b6ce1  target/riscv64gc-unknown-none-elf/release/odin-kernel

# Academic Whitepaper Typst Source
bdc5be2d18316e2422f93614fc5e4ef17abb1829fa857f7df18946fe63faf017  zenodo/odin-os-whitepaper.typ

# Compiled Academic Whitepaper PDF
6163fb4bafba454b7d24dac65e29d4ff49f00e0fd5ecf90f3389452cfc5facb1  zenodo/odin-os-whitepaper.pdf

# Formal SMT Model Specifications
f582d2a80a2edb4f0f0100d929a3b29413f4991a9676653cd9d6b57c35853e09  formal/deed_bounds_verification.smt2
99504b5c97aebd6b92b335dccb155b4e867d3fd7731f74b42d7e218add4dde09  formal/sequence_anti_replay.smt2

# Empirical Trace and Receipts
a3c5abc7ffaa67705875c15ba964cebe9a970406f3e4b27c5cbed38e869fd1d6  zenodo/receipts/adversarial_matrix_receipts.json
ea85087981c0dd1d922623d1331879dbcb1d8f45db2fb7716e43dd67f8d146ca  zenodo/receipts/raw_execution_trace.txt
```
