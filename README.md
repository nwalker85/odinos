# Odin OS: Cryptographically Authorized Memory Mutation in a RISC-V PMP Environment

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23928302.svg)](https://doi.org/10.5281/zenodo.23928302)
[![Phase](https://img.shields.io/badge/Release-Phase%20B.3.2-blue.svg)](https://github.com/nwalker85/odinos)
[![Target](https://img.shields.io/badge/Target-riscv64gc--unknown--none--elf-informational.svg)](https://github.com/nwalker85/odinos)
[![Formal Proofs](https://img.shields.io/badge/Z3%20SMT-5.3.1%20Verified%20(unsat)-success.svg)](formal/)
[![Mutation Testing](https://img.shields.io/badge/Mutants-15%2F15%20Killed-success.svg)](PHASE_B3_MUTATION_REPORT.md)
[![License](https://img.shields.io/badge/License-MIT%20%2F%20CC--BY--4.0-brightgreen.svg)](LICENSE)

**Odin OS** is a bare-metal, zero-allocation (`#![no_std]`) 64-bit RISC-V microkernel that anchors autonomous AI agent capability boundaries in processor Physical Memory Protection (PMP) comparators. 

Operating on the central axiom:
> **"State that cannot prove its right to exist cannot be committed to memory or disk."**  
> $$\text{Agent Request} \ne \text{Authority Grant}$$

Odin OS enforces capability isolation via cache-line aligned (256-byte) binary tokens termed **TransitionDeeds**, signed with RFC 8032 Ed25519 digital signatures verified with zero dynamic allocations against a pinned 32-byte root public key.

---

## The Peer Reviewer's Guide

### 1. The Core Architectural Boundary: PEP vs. PDP
When evaluating Odin OS, it is essential to distinguish between **access enforcement** and **business appropriateness**:
* **Policy Enforcement Point (PEP — Odin OS Microkernel & Hardware PMP):** Odin OS acts strictly as a hardware-enforced PEP. It enforces **spatial confinement** (stores cannot occur outside authorized byte windows) and **temporal containment** (leases collapse to `OFF` on revocation). The microkernel is intentionally agnostic to business semantics: it verifies cryptographic rights to access physical memory, not whether a business mutation makes application-level sense.
* **Policy Decision Point (PDP — Upstream Authority):** Evaluates agent mutation requests against declarative domain policies (e.g. verifying agent identity, AST anchor whitelist, allowable operations, lease duration caps) and holds the Ed25519 root private key.
* **Application Semantic Correctness:** Verifying high-level agent reasoning or application AST invariants is decoupled from the microkernel's Trusted Computing Base (TCB).

```
[ Untrusted Agent (U-Mode) ] ─── Propose Mutation ───► [ Policy Decision Point (PDP) ]
             │                                                    │
             │                                           Evaluates Domain Policy &
             │                                           Signs TransitionDeed (Ed25519)
             ▼                                                    │
[ Issues Store (e.g. sb) ] ◄── Valid TransitionDeed ──────────────┘
             │
             ▼
[ Processor PMP Comparators ] ──── In Lease Bounds? ───► YES ───► Retires to DRAM
             │
             └──── Out of Bounds? ─────────────────────► NO  ───► Hardware Access Fault
                                                                  (mcause = 7, Store Access Fault)
                                                                  (Memory Unmodified, WE = 0)
```

### 2. Primary Falsifiable Claim
For peer reviewers seeking an exact, bounded claim to falsify:
> **Primary Claim:** Under an untrusted U-Mode agent executing arbitrary instructions, no memory store instruction can retire to any physical memory location outside the explicitly signed `[lease_start, lease_end)` window or after revocation without triggering a processor-level Store Access Fault (`mcause = 0x07`) that aborts the write and preserves memory unmodified.

---

## Claim-to-Evidence Matrix

| Claim ID | Property | TCB & Assumptions | Supporting Artifact / Test | Explicitly Outside Scope |
| :---: | :--- | :--- | :--- | :--- |
| **C1** | **Spatial Isolation** | RISC-V PMP comparators, M-Mode trap handler | Adversarial Tests 1–4, 9, 10; Z3 Proof 1 (`deed_bounds_verification.smt2`) | Timing side-channels; non-atomic split stores on unverified physical silicon. |
| **C2** | **Temporal Revocation** | M-Mode microkernel syscall 13 (`SYS_REVOKE_LEASE`) | Adversarial Test 16; Mutation M09 | Autonomous hardware timer-interrupt preemption (`mcycle`). |
| **C3** | **Cryptographic Authority** | `ed25519-compact` (`no_std`), pinned 32B root key | Adversarial Tests 11, 13, 14; Mutations M01, M02, M11–M13 | Compromise of the PDP signing key outside the microkernel. |
| **C4** | **Anti-Replay Monotonicity** | In-kernel sequence counter `last_seq` | Adversarial Test 12; Mutation M03; Z3 Proof 2 (`sequence_anti_replay.smt2`) | NVRAM counter rollback across hard power loss without re-keying. |
| **C5** | **Bi-directional $W \oplus X$** | PMP Entry 1 (`R-X`), Entry 2 (`RW-`); trap handler | Adversarial Tests 7 & 8; Mutations M06, M15 | Return-Oriented Programming (ROP) in valid user text. |
| **C6** | **Semantic Appropriateness** | External Policy Decision Point (PDP) | PDP Suite (12 attack vectors rejected) | **Outside Odin OS PEP Scope**. Microkernel enforces spatial capability, not business logic. |

---

## Quickstart: Clean-Room Reproduction in 60 Seconds

### Prerequisites
* Rust nightly with RISC-V bare-metal target: `rustup target add riscv64gc-unknown-none-elf`
* QEMU RISC-V emulator: `qemu-system-riscv64` (>= 8.0)
* Z3 Theorem Prover: `z3` (>= 5.3)
* Python 3.10+
* Typst (for paper compilation): `typst` (>= 0.11)

### Execution Commands

```bash
# 1. Run host unit and property tests (23 passed in ~0.02s)
cargo test --lib --target aarch64-apple-darwin

# 2. Build bare-metal microkernel
cargo build --release --target riscv64gc-unknown-none-elf

# 3. Execute 17-case QEMU adversarial verification matrix
cargo run --release

# 4. Verify machine-checked Z3 formal proofs (QF_BV)
for f in formal/*.smt2; do echo -n "$f: "; z3 "$f"; done

# 5. Run authority isolation tests (12 cases) & Layer B external verifier
python3 -m unittest tests/test_authority_isolation.py
python3 tools/verify_evidence.py

# 6. Execute Canonical Release Verification Pipeline (All gates)
make verify-release
```

---

## Repository Navigation & Audit Documentation

* [`zenodo/odin-os-whitepaper.pdf`](zenodo/odin-os-whitepaper.pdf) — Complete publication whitepaper manuscript.
* [`zenodo/odin-os-whitepaper.typ`](zenodo/odin-os-whitepaper.typ) — Typst source for the whitepaper.
* [`PHASE_B32_CLAIM_EVIDENCE_MATRIX.md`](PHASE_B32_CLAIM_EVIDENCE_MATRIX.md) — 14-claim publication audit with DEMONSTRATED, QUALIFIED, and PROPOSED classifications.
* [`PHASE_B32_ADVERSARIAL_REVIEW.md`](PHASE_B32_ADVERSARIAL_REVIEW.md) — Hostile peer review defense covering 14 academic rejection grounds.
* [`PHASE_B31_PMP_ATOMICITY.md`](PHASE_B31_PMP_ATOMICITY.md) — Deep architectural analysis of split-bus accesses across protection boundaries under RISC-V ISA §2.6.
* [`PHASE_B3_MUTATION_REPORT.md`](PHASE_B3_MUTATION_REPORT.md) — 15 architectural and cryptographic mutations injected and killed (15/15).
* [`formal/`](formal/) — Machine-checked Z3 SMT specifications for deed bounds and sequence monotonicity.
* [`tools/verify_release.py`](tools/verify_release.py) — Automated gate verifier ensuring clean-room reproducibility.

---

## Permanent Archival Citation

```bibtex
@misc{walker2026odinos,
  author       = {Nathan Walker},
  title        = {{Odin OS: Cryptographically Authorized Memory Mutation in a RISC-V PMP-Enforced Agent Execution Environment}},
  year         = {2026},
  month        = nov,
  publisher    = {Zenodo},
  version      = {v0.1.0-rc.b32},
  doi          = {10.5281/zenodo.23928302},
  url          = {https://doi.org/10.5281/zenodo.23928302}
}
```

---

## License

* **Microkernel Source & Verification Tools:** [MIT License](LICENSE)
* **Whitepaper & Documentation:** [Creative Commons Attribution 4.0 International (CC-BY-4.0)](https://creativecommons.org/licenses/by/4.0/)
