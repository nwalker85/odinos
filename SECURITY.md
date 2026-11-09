# Security Policy & Vulnerability Disclosure

## Supported Versions

| Version | Supported | Verification Status | Archival Reference |
| :--- | :--- | :--- | :--- |
| **v0.1.0-rc.b32** | **Yes** | 9/9 Release Gates Passing | [DOI: 10.5281/zenodo.24044570](https://doi.org/10.5281/zenodo.24044570) |
| < v0.1.0-rc.b32 | No | Historical Milestones | [DOI: 10.5281/zenodo.23928302](https://doi.org/10.5281/zenodo.23928302) |

---

## Threat Model & In-Scope Vulnerabilities

Odin OS investigates hardware-anchored capability confinement for untrusted autonomous agents. When evaluating whether a potential flaw constitutes a security vulnerability, refer to the formal [Trust Boundaries Specification](peer-review/TRUST_BOUNDARIES.md) and [Known Limitations](peer-review/KNOWN_LIMITATIONS.md).

### In-Scope Vulnerabilities
We actively solicit reports and consider the following within our security envelope:
1. **PMP Boundary Bypass:** Any sequence of unprivileged U-Mode instructions that successfully commits a store to physical memory outside the active `TransitionDeed` lease window $[G_{\text{base}}, G_{\text{base}} + G_{\text{len}})$ without triggering `mcause = 7`.
2. **Cryptographic Authority Forgery:** Bit-flipped, forged, or truncated `TransitionDeed` tokens accepted as valid by the `#![no_std]` Ed25519 verification engine.
3. **Replay & Sequence Violations:** Successful replay of a previously executed deed without triggering sequence counter monotonicity rejection.
4. **W^X Memory Violations:** Execution of instructions from writable heap/staging memory, or modification of executable kernel/user text segments.
5. **Privilege Escalation:** Unprivileged modification of Machine-Mode Control and Status Registers (CSRs) or MMIO controller regions.
6. **Integer Overflow & Arithmetic Wrapping:** Wrapping or arithmetic bypass in deed bounds calculation (`checked_add`).

### Out-of-Scope (Documented Boundaries)
Per the Odin OS Assurance Model, the following are explicitly out of scope for the microkernel Policy Enforcement Point (PEP):
* **Semantic Business Appropriateness (ODIN-C012):** The microkernel verifies cryptographic rights to access physical memory, not whether a business mutation makes application-level sense. Upstream semantic validation is delegated to the independent Policy Decision Point (PDP).
* **Physical Silicon Store Atomicity (ODIN-C008):** Non-atomic split-bus writes across misaligned boundaries on physical silicon under RISC-V ISA §2.6 are a known physical-silicon proof obligation addressed via Phase C Shadow AST staging buffers.
* **Microarchitectural Side-Channels:** Hardware cache-timing attacks (Spectre/Meltdown) inherent to shared silicon execution cores.

---

## Reporting a Vulnerability

We practice coordinated vulnerability disclosure. If you discover an architectural flaw, implementation bug, or boundary bypass in Odin OS, please report it privately:

1. **Email:** Send your encrypted or plain text findings to `security@ravenhelm.dev` and `nwalker85@gmail.com`.
2. **GitHub Security Advisory:** Submit a private disclosure via [GitHub Security Advisories](https://github.com/nwalker85/odinos/security/advisories/new).
3. **Contents of Report:**
   * Vulnerability category and impacted component (`src/pmp.rs`, `src/deed.rs`, `src/main.rs`).
   * Minimal reproducible proof-of-concept (PoC) or QEMU trace demonstrating the violation.
   * Observed vs. expected CPU trap or memory state.
   * Suggested remediation, if identified.

### Response Timelines
* **Initial Response:** Within 48 hours of receipt.
* **Triage & Reproduction:** Within 7 business days.
* **Patch & Disclosure:** A public advisory and CVE/erratum will be coordinated within 30 days of confirmed remediation.
