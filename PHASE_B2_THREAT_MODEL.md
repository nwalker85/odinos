# Odin OS Phase B.2 — Formal Threat Model & Trust Boundary Analysis

**Author:** Principal Security Engineer & Verification Lead  
**Scope:** Threat Landscape, Privilege Boundaries, and Exploit Demonstration for Autonomous Agent Capability Enforcement  
**Architecture:** RISC-V 64-bit Bare-Metal Microkernel  

---

## 1. System Axiom & Trust Hierarchy

### 1.1 The Governing Axiom
> *State that cannot prove its right to exist cannot be committed to memory or disk.*

In Odin OS, memory writes are not permitted based on process identity, Ambient Authority, or software conventions. Every physical memory mutation requires a cryptographic `TransitionDeed` lease that binds the agent to an exact byte span for a finite duration.

### 1.2 Component Classification Matrix

```
Component                Privilege Level   Trust Classification   Security Capabilities & Failure Modes
────────────────────────────────────────────────────────────────────────────────────────────────────────────
CPU Hardware (PMP/CSRs)  Silicon           TRUSTED                Enforces address checks, W^X, and fault generation.
M-Mode Microkernel       Machine Mode      TRUSTED (TCB)          Validates deeds, configures PMP, handles traps.
Pinned Root Public Key   Kernel Read-Only  TRUSTED                Cryptographic trust root for signature checks.
Monotonic Sequence State Microkernel BSS   TRUSTED                Prevents replay attacks across deed requests.
Autonomous Agent         User Mode (U)     UNTRUSTED              Adversary. Executes untrusted model instructions.
Agent Memory Stack       User Mode (U)     UNTRUSTED              Temporary stack state; strictly non-executable (RW-).
Python / LLM Bridge      Host / Serial     UNTRUSTED              Facilitates communication; assumed fully compromiseable.
DMA Deed Buffer          Hardware Ring     CONDITIONALLY TRUSTED  Input channel parsed by microkernel prior to use.
```

---

## 2. Adversarial Threat Vectors & Attack Scenarios

### Vector 1: Malicious or Compromised Python Bridge
- **Adversary Model:** The Python bridge or host environment is subverted by prompt injection or remote code execution.
- **Goal:** Grant unauthorized write access to arbitrary physical memory locations (e.g. kernel code at `0x80000000` or UART MMIO at `0x10000000`).
- **Phase B.1 Vulnerability:** In Phase B.1, deed validation checked a non-cryptographic `SIGN` marker and an unkeyed FNV-1a checksum. An attacker with bridge access could forge valid deeds without possessing private keys.
- **Phase B.2 Countermeasure:** The microkernel verifies genuine Ed25519 digital signatures. The private signing key (`ROOT_SEED`) is held exclusively by an independent root authority and is unavailable to the agent or bridge. Without the private key, forging a signature is computationally infeasible ($O(2^{128})$ operations).

### Vector 2: User-Mode Memory Out-of-Bounds Store
- **Adversary Model:** An untrusted agent executes instructions that attempt to write outside its leased address range.
- **Goal:** Corrupt neighboring AST state, kernel data structures, or hardware registers.
- **Countermeasure:** PMP Entry 4 restricts store operations strictly to `[lease_start .. lease_end)`. Stores one byte below (`0x8002003F`) or one byte above (`0x80020060`) instantly trigger a Store Access Fault (`mcause = 7`), terminating the mutation with zero bits flipped.

### Vector 3: User Stack Shellcode Execution (W^X Violation)
- **Adversary Model:** The agent writes RISC-V shellcode into its stack buffer (`0x80018100`) and executes `jalr ra, 0(t0)`.
- **Goal:** Execute arbitrary instructions in U-Mode with elevated or unmonitored privileges.
- **Countermeasure:** PMP Entry 2 configures the stack region as `RW-` (`0x0B`). The CPU instruction fetch engine generates an Instruction Access Fault (`mcause = 1`). M-Mode traps the violation and redirects execution away from the stack.

### Vector 4: Replay Attacks
- **Adversary Model:** The agent or bridge captures an authentic past deed and resubmits it after the authorized transaction has completed.
- **Goal:** Re-open an expired lease or execute duplicate state transitions.
- **Countermeasure:** The microkernel enforces monotonic sequence progression (`deed.sequence > LAST_CONSUMED_SEQUENCE`). Resubmitted sequence numbers return `DeedError::ReplayDetected`.

### Vector 5: Temporal Boundary Violations (Stale Leases)
- **Adversary Model:** The agent attempts to write to memory after its lease has expired or been revoked.
- **Goal:** Mutate memory after authority has ended.
- **Countermeasure:** When `sys_revoke_lease()` (`ecall 13`) or lease expiration occurs, PMP Entry 4 is cleared to `OFF`. Subsequent writes to the previously authorized memory address trigger hardware faults.

---

## 3. Exploit Demonstration: Compromising Phase B.1 Attestation

To mathematically prove why Phase B.1 was vulnerable and why Phase B.2 is necessary, we demonstrate the concrete exploit against Phase B.1's attestation check.

### 3.1 The Exploit Code
In Phase B.1, the deed validation logic in `deed.rs` was:
```rust
// Phase B.1 Vulnerable Validation:
fn verify_authority_v1(&self, max_bound: u32) -> bool {
    let fnv_digest = compute_fnv1a(&self.raw_bytes[0..156]);
    self.signature[0..4] == *b"SIGN" && 
    self.signature[4..12] == fnv_digest.to_le_bytes()
}
```

An adversarial Python script could mint arbitrary capability deeds for any address:
```python
# Exploit: Arbitrary capability forgery in Phase B.1 without keys
deed = bytearray(256)
deed[0:2] = b"YG"
deed[2] = 1 # Version 1
deed[4:8] = struct.pack("<I", 99999) # Sequence
deed[8:24] = b"did:odin:root:01".ljust(16, b"\x00") # Spoofed root issuer
deed[112:124] = struct.pack("<III", 1, 0, 0x1000) # Arbitrary lease bounds!

# Compute public FNV-1a hash
h = 0xcbf29ce484222325
for b in deed[:156]:
    h = ((h ^ b) * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF

deed[156:160] = b"SIGN"
deed[160:168] = struct.pack("<Q", h)
# Result: Microkernel accepts this deed as fully authorized!
```

### 3.2 Proof of Vulnerability Elimination in Phase B.2
In Phase B.2, `deed.version == 0x02` mandates genuine Ed25519 signature verification against `TRUSTED_ROOT_PUBLIC_KEY`.
When the same exploit payload is presented to Phase B.2:
- Test 13: Forged deed with garbage/unkeyed signature returns `DeedError::InvalidSignature` (error code 4).
- Test 14: Tampered deed payload after authentic signing returns `DeedError::InvalidSignature` (error code 4).

The attack is rendered completely ineffective at the silicon microkernel boundary.
