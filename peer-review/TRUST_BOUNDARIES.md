# Odin OS: System Trust Boundaries & Assurance Model

**Document Identifier:** ODIN-DOC-TB-001  
**Classification:** Independent Peer-Review & Assurance Package  
**Target Release:** Phase B.3.2 Canonical Baseline  
**Revision:** 2026-11-07  

---

## 1. Executive Purpose

This document defines the formal trust boundaries, component classifications, and the four-layer assurance model of Odin OS. Its objective is to enable an independent reviewer to establish:
1. Which components are trusted, which are untrusted adversaries, and which are untrusted transport channels.
2. The exact division of responsibility between cryptographic authorization, hardware enforcement, transactional integrity, and business appropriateness.
3. Where the authority to declare an operation "safe" begins and ends, preventing circular assurance arguments.

---

## 2. The Four Assurance Layers

Odin OS explicitly separates security and correctness guarantees into four distinct layers. A failure in one layer cannot be mitigated by assuming correctness in another.

```
┌─────────────────────────────────────────────────────────────────────────┐
│ LAYER D: Semantic & Business Appropriateness                            │
│ Question: "Was the resulting action appropriate under business rules?"  │
│ Authority: Application Domain / Enterprise Policy / Human Authority     │
│ Guarantee: NONE from Microkernel. Hardware PMP does not judge intent.   │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Authorizes Intent
┌────────────────────────────────────▼────────────────────────────────────┐
│ LAYER A: Cryptographic Authorization (Policy Decision Point)            │
│ Question: "Did the trusted authority sign this specific deed request?"  │
│ Authority: Policy Decision Point (PDP) / Root Ed25519 Key Holder        │
│ Guarantee: Zero-trust token issuance; anti-replay sequence allocation. │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Issues TransitionDeed
┌────────────────────────────────────▼────────────────────────────────────┐
│ LAYER B: Hardware Enforcement (Policy Enforcement Point)                │
│ Question: "Can unprivileged instructions write outside active bounds?"  │
│ Authority: RISC-V PMP Comparators & M-Mode Trap Handler                │
│ Guarantee: CPU access fault (mcause=7) before write commits to memory.  │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Commits Bytes
┌────────────────────────────────────▼────────────────────────────────────┐
│ LAYER C: Transactional & Content Integrity                              │
│ Question: "Does memory content exactly match the signed post-state?"    │
│ Authority: SHA-256 Digest Barrier & Shadow AST Buffers (Phase C Spec)   │
│ Guarantee: Current prototype enforces spatial bounds, not hash digests. │
└─────────────────────────────────────────────────────────────────────────┘
```

### Layer A: Cryptographic Authorization (PDP)
* **Core Question:** Does the trusted authority permit this specific agent to access this specific memory span?
* **Mechanism:** The Policy Decision Point (`pdp_authority_service.py`) evaluates incoming agent requests against declarative security policies. If approved, it signs a 256-byte cache-line aligned `TransitionDeed` using an RFC 8032 Ed25519 root private key.
* **Assumptions:** 
  1. The host environment housing the PDP private key is not compromised.
  2. The root public key pinned in kernel read-only memory matches the PDP signing key.
  3. The sequence counter allocation is strictly monotonic.
* **Non-Guarantees:** The PDP does not control the physical bus or execution pipeline. If an agent gains write permissions, the PDP cannot prevent out-of-order execution or hardware bus faults.

### Layer B: Hardware Enforcement (PEP)
* **Core Question:** Does processor hardware physically restrict U-Mode execution to the granted spatial and temporal capability window?
* **Mechanism:** RISC-V Physical Memory Protection (PMP) CSRs (`pmpcfg0`, `pmpaddr0`..`pmpaddr7`) configured by the M-Mode microkernel into Top-of-Range (TOR) matching regions.
* **Guarantees:**
  * Spatial confinement: Any store instruction attempting to retire outside `[lease_start, lease_end)` triggers an architectural Store Access Fault (`mcause = 7`).
  * Privilege confinement: User task code is `R-X` (store faults); user stack is `RW-` (fetch faults with `mcause = 1`).
  * Register isolation: U-Mode attempts to read or write PMP CSRs trigger Illegal Instruction (`mcause = 2`).
  * Temporal revocation: Syscall 13 (`SYS_REVOKE_LEASE`) collapses PMP Entry 4 to `OFF`, revoking access immediately.
* **Assumptions:** The CPU hardware PMP comparators conform strictly to the RISC-V Privileged Architecture Specification.
* **Non-Guarantees:** Hardware PMP only controls *where* and *when* writes occur. It does not inspect the payload content, evaluate whether the bytes represent valid AST code, or prevent logic errors within the permitted span.

### Layer C: Transactional & Content Integrity
* **Core Question:** Do the mutated memory bytes strictly match the expected cryptographic digest (`new_digest`), and is commit all-or-nothing?
* **Distinction:** Spatial permission (Layer B) allows bytes to be written. Content integrity (Layer C) guarantees that *only* the authorized payload is written, and that partial failures rollback cleanly.
* **Current Status in Phase B.3.2:**
  * Spatial isolation is **DEMONSTRATED** under QEMU virt.
  * In-kernel SHA-256 digest validation and atomic shadow AST staging buffers are **PROPOSED ARCHITECTURE** for Phase C. The current prototype checks bounds, not cryptographic digest post-state equality.

### Layer D: Semantic & Business Appropriateness
* **Core Question:** Was the agent's action desirable, correct, and aligned with high-level business goals?
* **Critical Reviewer Boundary:** **Hardware memory protection cannot establish semantic correctness.**
  * If an autonomous AI agent is tricked by a semantic prompt into requesting a mutation that deletes critical business records, and the PDP policy permits that agent to delete those records, Odin OS will commit the write.
  * Odin OS guarantees that an attacker cannot bypass the policy or write to unpermitted addresses. It does not replace application-level validation, formal specification of business logic, or human governance.

---

## 3. Component Trust Boundary Matrix

| Component | Privilege Level | Trust Classification | Cryptographic Keys Held | Failure Impact |
| :--- | :---: | :---: | :---: | :--- |
| **CPU Hardware (PMP / Core)** | Silicon / Hardware | **Trusted Enforcer** | None | Total system compromise if comparators fail. |
| **M-Mode Microkernel** | Machine Mode (M) | **Trusted Computing Base (TCB)** | Pinned 32B Root Public Key (`TRUSTED_ROOT_PUBLIC_KEY`) | Microkernel bug compromises privilege separation. |
| **Policy Decision Point (PDP)** | Host Process / Enclave | **Trusted Authority** | Ed25519 Root Private Key (`seed`) | Forgery of deeds possible if PDP is compromised. |
| **Layer B Host Verifier** | Host Python Tool | **Auditing Verifier** | None | Does not compromise kernel runtime; fails release audit if tampered. |
| **Autonomous Agent Task** | User Mode (U) | **Untrusted Adversary** | None | Expected to be adversarial, compromised, or errant. |
| **Host Transport Bridge** | Network / Unix Socket | **Untrusted Transport Channel** | None | Assumed fully MITM-compromiseable. |

---

## 4. Anti-Circularity & Evidence Integrity Principles

To ensure that assurance claims are scientifically defensible, Odin OS enforces three anti-circularity rules:

1. **No Self-Attestation as Exclusive Proof:**  
   The microkernel outputting `"status": "PASS"` over UART is treated as unverified telemetry. Proof requires independent external auditing by Layer B (`tools/verify_evidence.py`), which recalculates invariants from raw probed memory addresses and hardware trap causes.

2. **Clean Separation of Test Fixtures and Production Authority:**  
   Mode A (Deterministic Research Fixture) is documented as an insecure, fixed-key evaluation harness for offline reproducibility. Mode B (Independently Provisioned Authority) loads an external CSPRNG seed and fails closed if missing. Mode A signatures are rejected by Mode B kernels.

3. **Explicit Boundary Between Simulation and Silicon:**  
   QEMU virt provides an idealized execution environment where misaligned split-access stores fault atomically. Physical silicon behavior is explicitly cataloged as an unresolved obligation requiring shadow AST buffers under RISC-V ISA §2.6.
