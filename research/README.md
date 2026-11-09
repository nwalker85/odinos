# Odin OS: Research & Technical Audit Archive
### Development Trajectory, Historical Milestones, and Architectural Specifications

This directory contains the complete technical audit trail, security evaluations, formal correspondences, and hardware roadmaps produced during the development of Odin OS.

To ensure pristine repository hygiene, historical and phase-specific documentation is organized hierarchically below rather than cluttering the repository root.

---

## Directory Navigation

```
research/
├── README.md             # This master index
├── hardware/             # Physical silicon justification & Phase C roadmap
└── phases/
    ├── b2/               # Phase B.2: Initial Adversarial Assurance & Threat Modeling
    ├── b3/               # Phase B.3: Dynamic Capability Leases & Mutation Testing
    ├── b3.1/             # Phase B.3.1: PMP Atomicity & Authority Isolation
    └── b3.2/             # Phase B.3.2: Publication Integrity & Peer-Review Defense
```

---

## 1. Physical Silicon & Hardware Roadmaps (`research/hardware/`)

* [`HARDWARE_JUSTIFICATION_KRIA_KV260.md`](hardware/HARDWARE_JUSTIFICATION_KRIA_KV260.md) — Comprehensive technical justification for deploying Odin OS on the AMD Kria KV260 Vision AI Starter Kit, detailing memory controller bus topology, cache coherence, and hardware PMP interlock.
* [`PHASE_C_HARDWARE_READINESS.md`](hardware/PHASE_C_HARDWARE_READINESS.md) — Transition roadmap from QEMU `virt` machine emulation to bare-metal physical silicon (JH7110 / VisionFive 2 and FPGA soft-cores).

---

## 2. Historical Development Trajectory (`research/phases/`)

### Phase B.2: Adversarial Assurance & Initial Threat Model
* [`PHASE_B2_THREAT_MODEL.md`](phases/b2/PHASE_B2_THREAT_MODEL.md) — Fundamental threat model, adversary capabilities (U-Mode arbitrary code execution), and in-scope vs. out-of-scope boundaries.
* [`PHASE_B2_TEST_MATRIX.md`](phases/b2/PHASE_B2_TEST_MATRIX.md) — Adversarial execution test suite under QEMU covering boundary violations, W^X traps, and CSR isolation.
* [`PHASE_B2_MUTATION_RESULTS.md`](phases/b2/PHASE_B2_MUTATION_RESULTS.md) — Early fault-injection experiments verifying microkernel trap responses.
* [`PHASE_B2_SECURITY_AUDIT.md`](phases/b2/PHASE_B2_SECURITY_AUDIT.md) — Systematic audit of memory corruption defenses and PMP entry configurations.
* [`PHASE_B2_CLAIM_EVIDENCE_MATRIX.md`](phases/b2/PHASE_B2_CLAIM_EVIDENCE_MATRIX.md) — Initial claim-to-evidence verification matrix.

### Phase B.3: Dynamic Capability Leases & Mutation Testing
* [`PHASE_B3_MUTATION_REPORT.md`](phases/b3/PHASE_B3_MUTATION_REPORT.md) — **15/15 Mutants Killed**: Comprehensive report on deliberate architectural and cryptographic mutations injected into the kernel and killed by the test suite (100% detection sensitivity).
* [`PHASE_B3_LEASE_STATE_MACHINE.md`](phases/b3/PHASE_B3_LEASE_STATE_MACHINE.md) — Formal specification of the 5-stage transition deed lease lifecycle (`NONE` $\rightarrow$ `PROPOSED` $\rightarrow$ `LEASED` $\rightarrow$ `REVOKED`).
* [`PHASE_B3_FORMAL_ASSURANCE.md`](phases/b3/PHASE_B3_FORMAL_ASSURANCE.md) — Z3 SMT formal models for arithmetic overflow bounds and monotonic sequence counter non-reuse.
* [`PHASE_B3_PMP_ARCHITECTURE_AUDIT.md`](phases/b3/PHASE_B3_PMP_ARCHITECTURE_AUDIT.md) — PMP register allocation trade-offs, TOR (Top-of-Range) vs. NAPOT (Naturally Aligned Power-of-Two) alignment.
* [`PHASE_B3_TRANSITION_INTEGRITY.md`](phases/b3/PHASE_B3_TRANSITION_INTEGRITY.md) — Atomic transition guarantees and roll-forward state consistency across exceptions.
* [`PHASE_B3_AUTHORITY_AUDIT.md`](phases/b3/PHASE_B3_AUTHORITY_AUDIT.md) — Cryptographic trust anchor verification, Ed25519 pure `#![no_std]` implementation audit.
* [`PHASE_B3_EVIDENCE_SPEC.md`](phases/b3/PHASE_B3_EVIDENCE_SPEC.md) — Specification for Layer B external cryptographic receipts and SHA-256 digest chains.
* [`PHASE_B3_CLAIM_EVIDENCE_MATRIX.md`](phases/b3/PHASE_B3_CLAIM_EVIDENCE_MATRIX.md) — Intermediate audit tracking verification status.
* [`PHASE_B3_BASELINE_MANIFEST.md`](phases/b3/PHASE_B3_BASELINE_MANIFEST.md) — Baseline artifact ledger for Phase B.3 release.

### Phase B.3.1: Authority Isolation & PMP Boundary Hardening
* [`PHASE_B31_PMP_ATOMICITY.md`](phases/b3.1/PHASE_B31_PMP_ATOMICITY.md) — **RISC-V ISA §2.6 Reconciliation**: Exhaustive architectural analysis of split-bus accesses across protection boundaries, establishing the necessity of shadow staging buffers on physical silicon.
* [`PHASE_B31_AUTHORITY_ISOLATION.md`](phases/b3.1/PHASE_B31_AUTHORITY_ISOLATION.md) — Decoupled Policy Decision Point (PDP) architecture and process-level DAC key isolation.
* [`PHASE_B31_TRANSACTIONAL_INTEGRITY.md`](phases/b3.1/PHASE_B31_TRANSACTIONAL_INTEGRITY.md) — State machine transitions under power-fault and trap conditions.
* [`PHASE_B31_FORMAL_CORRESPONDENCE.md`](phases/b3.1/PHASE_B31_FORMAL_CORRESPONDENCE.md) — Line-by-line mapping between Z3 formal SMT theorems and the Rust `#![no_std]` microkernel implementation.
* [`PHASE_B31_REPRODUCIBILITY_REPORT.md`](phases/b3.1/PHASE_B31_REPRODUCIBILITY_REPORT.md) — Independent clean-room execution protocol and test logs.
* [`PHASE_B31_CLAIM_EVIDENCE_MATRIX.md`](phases/b3.1/PHASE_B31_CLAIM_EVIDENCE_MATRIX.md) — Refined claim taxonomy and evidence mapping.
* [`PHASE_B31_EXECUTIVE_AUDIT.md`](phases/b3.1/PHASE_B31_EXECUTIVE_AUDIT.md) — Release readiness and gate audit summary.
* [`PHASE_B31_PUBLICATION_GATE.md`](phases/b3.1/PHASE_B31_PUBLICATION_GATE.md) — Pre-publication criteria evaluation.

### Phase B.3.2: Publication Integrity & Peer-Review Defense
* [`PHASE_B32_ADVERSARIAL_REVIEW.md`](phases/b3.2/PHASE_B32_ADVERSARIAL_REVIEW.md) — **Hostile Peer Review Defense**: Preemptive analysis and formal rebuttals covering 14 academic rejection grounds.
* [`PHASE_B32_CLAIM_EVIDENCE_MATRIX.md`](phases/b3.2/PHASE_B32_CLAIM_EVIDENCE_MATRIX.md) — Granular publication claim-evidence mapping covering all 14 claims.
* [`PHASE_B32_TRUST_ROOT_VERIFICATION.md`](phases/b3.2/PHASE_B32_TRUST_ROOT_VERIFICATION.md) — Verification of the pinned root public key and zero-entropy fallback elimination.
* [`PHASE_B32_SEMANTIC_INTEGRITY_STATUS.md`](phases/b3.2/PHASE_B32_SEMANTIC_INTEGRITY_STATUS.md) — Architectural specification for shadow AST commit barriers.
* [`PHASE_B32_FORMAL_SOUNDNESS.md`](phases/b3.2/PHASE_B32_FORMAL_SOUNDNESS.md) — Soundness guarantees and boundary analysis of the Z3 verification model.
* [`PHASE_B32_FINAL_RELEASE_AUDIT.md`](phases/b3.2/PHASE_B32_FINAL_RELEASE_AUDIT.md) — Master synthesis of Phase B.3.2 release candidate.
* [`PHASE_B32_FINAL_REPRODUCIBILITY.md`](phases/b3.2/PHASE_B32_FINAL_REPRODUCIBILITY.md) — Release verification audit and environment lock.
* [`PHASE_B32_MANUSCRIPT_AUDIT.md`](phases/b3.2/PHASE_B32_MANUSCRIPT_AUDIT.md) — Line-by-line factual audit of whitepaper assertions against code.
* [`PHASE_B32_PUBLICATION_GATE.md`](phases/b3.2/PHASE_B32_PUBLICATION_GATE.md) — Final release gate checklist.
* [`PHASE_B32_RELEASE_MANIFEST.md`](phases/b3.2/PHASE_B32_RELEASE_MANIFEST.md) — Baseline release SHA-256 digest manifest.
