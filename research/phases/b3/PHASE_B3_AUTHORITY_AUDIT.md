# Odin OS Phase B.3 — Authority Lifecycle & Trust-Root Audit

**Author:** Principal Kernel Security Engineer & Independent Research Verification Lead  
**Scope:** Cryptographic Key Custody, Policy Decision Points (PDP), Signing Oracle Analysis, and Canonical Deed Parsing  
**Baseline:** Phase B.2 Microkernel Cryptographic Implementation  

---

## 1. Executive Trust-Boundary Architecture

The central security invariant of Odin OS is:

$$\text{Agent Request} \neq \text{Authority Grant}$$

A digital signature is not magic: it merely proves that a holder of a private key endorsed a byte sequence. If the entity possessing the private key signs unvetted requests on behalf of an autonomous agent without evaluating an independent authorization policy, the system degenerates into a **Confused Deputy / Signing Oracle**.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ HOST / UNTRUSTED BOUNDARY                                                       │
│                                                                                 │
│   ┌─────────────────────┐                     ┌─────────────────────────────┐   │
│   │   Autonomous AI     │  Proposes Mutation  │   Host Python Bridge        │   │
│   │   Agent (LLM)       ├────────────────────►│   (Untrusted Channel)       │   │
│   └─────────────────────┘                     └──────────────┬──────────────┘   │
│                                                              │                  │
└──────────────────────────────────────────────────────────────┼──────────────────┘
                                                               │ Submits Intent
                                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ TRUSTED AUTHORITY BOUNDARY (Out-of-Band Policy Engine)                          │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ Policy Decision Point (PDP)                                             │   │
│   │ - Validates requested AST span against agent role & capability grant    │   │
│   │ - Checks causal chain against canonical state registry                  │   │
│   │ - Enforces maximum lease duration & monotonic sequence allocation       │   │
│   └────────────────────────────────────┬────────────────────────────────────┘   │
│                                        │ Authorized Policy Approval             │
│                                        ▼                                        │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ Policy Enforcement Point (Signer / Hardware Security Module)            │   │
│   │ - Private Key (ROOT_SEED) isolated from Agent and Bridge                │   │
│   │ - Signs Canonical Message: [DOMAIN_SEPARATOR || Deed_Metadata]          │   │
│   └────────────────────────────────────┬────────────────────────────────────┘   │
└────────────────────────────────────────┼────────────────────────────────────────┘
                                         │ Signed TransitionDeed (256B)
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│ CPU SILICON & MICROKERNEL BOUNDARY                                              │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ M-Mode Microkernel (TCB)                                                │   │
│   │ - Possesses ONLY TRUSTED_ROOT_PUBLIC_KEY (32 bytes in ROM)               │   │
│   │ - Possesses ZERO private key material                                   │   │
│   │ - Verifies Ed25519 signature before programming PMP                     │   │
│   └────────────────────────────────────┬────────────────────────────────────┘   │
│                                        │ Programs PMP Entry 4 (RW-)             │
│                                        ▼                                        │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │ Hardware PMP Comparator Gates (Silicon)                                 │   │
│   │ - Hardware Store Access Fault (mcause = 7) on any unleased address      │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Answers to Trust-Root Lifecycle Inquiries

### 1. Where is `ROOT_SEED` generated and stored?
In the Phase B.2 prototype, `ROOT_SEED` (`b"odin_root_authority_seed_v2_key!"`) is provisioned as an environmental test fixture in `tools/gemma_odin_bridge.py`. 
*Audit Classification:* For research and QEMU demonstration, this seed serves as the root authority fixture. In production, this seed must be held in an isolated Hardware Security Module (HSM) or enclave, completely separated from the agent execution host.

### 2. Is any private-key material embedded in the kernel image?
**Audit Finding: ZERO private-key material exists in `odin-kernel`.**
Inspection of `src/main.rs`, `src/deed.rs`, and the compiled release binary `odin-kernel` proves that the kernel image contains **only** the 32-byte public key:
```rust
pub const TRUSTED_ROOT_PUBLIC_KEY: [u8; 32] = [
    0xFD, 0xC8, 0x86, 0xB0, 0xA3, 0xAE, 0xD3, 0x9A,
    0x07, 0xF6, 0x5F, 0x21, 0x43, 0x88, 0x64, 0x48,
    0x02, 0xA5, 0x5E, 0x59, 0xDE, 0xC4, 0xB5, 0xED,
    0x34, 0x61, 0x2A, 0x2A, 0x79, 0x83, 0x30, 0x19,
];
```
Even if an attacker gains arbitrary read access to the microkernel memory or binary, no signing capability is compromised.

### 3. Can the agent or bridge access a signing oracle?
If the Python bridge signs any request produced by Gemma 4 without independent policy verification, the bridge constitutes an **unconstrained signing oracle**.
*Requirement:* The bridge must not sign deeds directly. The signing service must implement an independent Policy Decision Point (PDP) that validates:
- Is the agent permitted to mutate the requested AST node?
- Does the requested byte length exceed the static grant?
- Is the lease duration within acceptable cycle limits?
If any check fails, signing is denied.

### 4. Does the signed payload cover every security-relevant field?
**Audit Finding: YES.**
The canonical message constructed by `canonical_message()` in `src/deed.rs` covers 172 contiguous bytes:
$$\text{Canonical Message} = \text{DOMAIN\_SEPARATOR (16B)} \mathbin{\Vert} \text{Deed Metadata (156B, 0x00..0x9C)}$$
This explicitly signs:
- `magic` (0x00..0x02) and `version` (0x02..0x03)
- `flags` (0x03..0x04)
- `sequence` (0x04..0x08) — anti-replay counter
- `issuer_did` (0x08..0x18) — authority identity
- `target_urn` (0x18..0x28) — target entity
- `prev_deed_hash` (0x28..0x48) — causal predecessor
- `base_digest` (0x48..0x68) — pre-mutation state hash
- `lease_cycles` (0x68..0x6C) — execution duration
- `operation`, `esc_level`, `reserved` (0x6C..0x70)
- `anchor_id`, `target_offset`, `target_length` (0x70..0x7C) — exact memory bounds
- `new_digest` (0x7C..0x9C) — post-mutation state hash

Any bit flipped in any of these fields invalidates the Ed25519 signature.

### 5. Can a valid signature authorize a different operation through alternate parsing?
**Audit Finding: NO.**
`TransitionDeed` uses strict `#[repr(C, align(64))]` with explicit little-endian fixed-width integer fields. There are no variable-length fields, TLV encodings, or pointer indirections. Alternate parsing or canonicalization ambiguity is mathematically impossible under this layout.

---

## 3. Adversarial Attack Resistance Matrix

| Attack Vector | Simulated Attacker Action | Expected Microkernel Response | Tested Invariant |
|:---|:---|:---|:---:|
| **Forged Issuer DID** | Attacker flips 1 byte in `issuer_did` (`did:odin:root:02`) | Rejection (`DeedError::UntrustedIssuer`) | Host Test 2 & Matrix Test 11 |
| **Garbage Signature** | Attacker fills signature with arbitrary non-zero bytes | Rejection (`DeedError::InvalidSignature`) | Host Test 8 & Matrix Test 13 |
| **Tampered Offset** | Valid deed signed for offset `50`; attacker changes to `99` | Rejection (`DeedError::InvalidSignature`) | Host Test 18 & Matrix Test 14 |
| **Tampered Length** | Valid deed signed for length `20`; attacker expands to `100` | Rejection (`DeedError::InvalidSignature`) | Host Test 10 |
| **Tampered Sequence** | Valid deed signed for seq `100`; attacker lowers to `50` | Rejection (`DeedError::InvalidSignature`) | Host Test 7 |
| **Tampered Operation** | Valid deed signed for `OP_LEASE_ACQUIRE`; changed to `OP_SPLICE` | Rejection (`DeedError::InvalidSignature`) | Host Test 9 |
| **Cross-Protocol Replay** | Attacker uses valid Ed25519 signature from different protocol | Rejection (`DeedError::InvalidSignature`) | Host Test 5 |
| **Unauthorized Key** | Attacker signs valid deed using an unauthorized private key | Rejection (`DeedError::InvalidSignature`) | Host Test 21 |
| **Bit-Flip Sensitivity** | Attacker flips a single bit in the 64-byte signature | Rejection (`DeedError::InvalidSignature`) | Host Test 6 |

---

## 4. Conclusion & Stage 2 Finding

The cryptographic engine in `odin-kernel` enforces genuine mathematical authority. The microkernel possesses no private keys and cannot be coerced into authorizing arbitrary memory leases. However, to eliminate the signing oracle risk on the host, the signing interface must be recognized as an independent Policy Decision Point (PDP), not an agent convenience wrapper.
