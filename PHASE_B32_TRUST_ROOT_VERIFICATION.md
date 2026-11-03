# ODIN OS — PHASE B.3.2
## Cryptographic Trust-Root Audit & Remediation Report

**Role:** Independent Cryptographic Protocol Engineer & Security Auditor  
**Repository:** `nwalker85/odinos`  
**Date:** November 3, 2026  
**Status:** Defensible Trust-Root Architecture

---

### Executive Summary & Finding Disclosure

An independent investigation into the cryptographic trust-root of Odin OS confirmed a critical vulnerability in earlier Phase B.2/B.3 documentation and prototype implementation:

$$\text{Disclosed Root Seed: } \texttt{b"odin\_root\_authority\_seed\_v2\_key!"}$$

1. **Byte-for-Byte Public Key Equivalence:**  
   Deriving the Ed25519 public key from the 32-byte seed `b"odin_root_authority_seed_v2_key!"` via RFC 8032 yields:
   ```
   FD C8 86 B0 A3 AE D3 9A 07 F6 5F 21 43 88 64 48
   02 A5 5E 59 DE C4 B5 ED 34 61 2A 2A 79 83 30 19
   ```
   This byte sequence is **identical** to the microkernel's pinned public key in `src/deed.rs`.

2. **Security Consequence:**  
   Because the private seed was committed to the public Git repository and documented in markdown reports, **the prototype key possessed zero secrecy**. Any untrusted entity with access to the source code could derive the signing key and forge validly signed `TransitionDeed` capabilities. Extracting the seed into `tools/pdp_authority_service.py` within the same repository did not establish cryptographic secrecy.

---

### 1. Two-Mode Trust-Root Architecture (Phase B.3.2 Remediation)

To maintain rigorous scientific reproducibility while establishing a realistic path to secure deployment, Odin OS now formally decouples its cryptographic authority into two explicitly documented operating modes:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ODIN OS AUTHORITY MODES                         │
├───────────────────────────────────┬────────────────────────────────────┤
│   MODE A: DETERMINISTIC FIXTURE   │   MODE B: INDEPENDENT AUTHORITY    │
├───────────────────────────────────┼────────────────────────────────────┤
│ • Public test seed (hardcoded)    │ • CSPRNG-generated 32-byte seed   │
│ • Fixed compile-time public key   │ • Stored OUTSIDE git repository    │
│ • Deterministic test runs         │ • Pinned at compile/boot via env   │
│ • ZERO CLAIM OF SECRECY           │ • Fails closed if missing/corrupt  │
│ • Unsuitable for production       │ • Zero logging / serialization     │
└───────────────────────────────────┴────────────────────────────────────┘
```

#### Mode A — Deterministic Research Fixture (Default)
- **Purpose:** Enables 100% deterministic, offline reproducibility of unit tests (`cargo test`), QEMU bare-metal matrix runs (`cargo run`), and external verifier audits without requiring local key generation or secret provisioning.
- **Root Seed:** `FIXTURE_ROOT_SEED = b"odin_root_authority_seed_v2_key!"`
- **Default Public Key:** `[0xFD, 0xC8, 0x86, 0xB0, ... 0x30, 0x19]`
- **Explicit Limitation:** **No claim of private-key secrecy.** Resistance against an adversary who possesses the fixture key is not claimed.

#### Mode B — Independently Provisioned Authority
- **Purpose:** Production and deployment environments requiring genuine cryptographic isolation.
- **Key Generation:** 32-byte high-entropy seed generated via a cryptographically secure pseudorandom number generator (CSPRNG, e.g. `secrets.token_bytes(32)` or hardware TRNG).
- **Storage & Custody:** Stored strictly outside the repository (e.g., `~/.config/odin/authority_seed.bin` with `chmod 600` or an HSM/enclave). Loaded via `ODIN_AUTHORITY_SEED_PATH` or `ODIN_AUTHORITY_SEED_HEX`.
- **Kernel Provisioning:** The matching public key is injected at compile time via `build.rs` using `ODIN_ROOT_PUBKEY_HEX` or via secure boot parameters:
  ```rust
  // build.rs generates root_key.rs included in deed.rs
  pub const TRUSTED_ROOT_PUBLIC_KEY: [u8; 32] = <Provisioned Public Key>;
  ```
- **Fail-Closed Semantics:** If `mode == "provisioned"` and key material is missing, unreadable, or not exactly 32 bytes, the PDP raises `SecurityError` and halts immediately. It never silently falls back to the insecure fixture seed.
- **Zero Exposure:** The private key is never logged, printed, serialized into JSON receipts, or embedded in commit metadata.

---

### 2. Empirical Verification Evidence

The test suite [`tests/test_authority_isolation.py`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel/tests/test_authority_isolation.py) was updated and executed to verify both modes across 12 test cases:

| Test ID | Test Description | Authority Mode | Injected Condition | Result |
| :---: | :--- | :---: | :--- | :---: |
| **01** | Unauthorized Anchor | Mode A | Anchor `999` (Allowed: `104`) | **DENIED (PASS)** |
| **02** | Unauthorized Opcode | Mode A | Opcode `0x99` (Allowed: `1`) | **DENIED (PASS)** |
| **03** | Oversized Mutation | Mode A | Length `64B` (Max: `32B`) | **DENIED (PASS)** |
| **04** | Excessive Lease Time | Mode A | Lease `5,000,000` cycles | **DENIED (PASS)** |
| **05** | Unknown Agent Identity | Mode A | `agent:rogue-ai` | **DENIED (PASS)** |
| **06** | Out-of-Bounds Range | Mode A | Offsets `< 0x40` and `> 0x60` | **DENIED (PASS)** |
| **07** | Zero-Length Mutation | Mode A | Length `0` | **DENIED (PASS)** |
| **08** | Post-Sign Tampering | Mode A | 1-bit flip in `target_offset` | **SIG FAIL (PASS)** |
| **09** | Monotonic Restarts | Mode A | Sequence persists across restart | **PASS (1 $\rightarrow$ 2)** |
| **10** | Receipt Hash Binding | Mode A | SHA-256 matches issued deed | **PASS** |
| **11** | Mode B Separation | Mode B | CSPRNG seed; verify against Mode A key | **FAIL-CLOSED (PASS)** |
| **12** | Mode B Fail-Closed | Mode B | Missing / corrupt key material | **SecurityError (PASS)** |

**Execution Log:**
```bash
python3 -m unittest tests/test_authority_isolation.py
# Ran 12 tests in 0.042s -> OK
```

---

### 3. Precise Security Limitations

1. **No Hardware Security Module (HSM):** Mode B relies on host-level OS file permissions and process boundaries. It does not provide tamper-resistant physical secure element protection.
2. **Threat Model Boundary:** If the host OS administrator account is fully compromised, an attacker with root privileges can read memory or files belonging to the PDP process.
3. **Key Rotation & Revocation:** Key rotation requires rebuilding the microkernel image with the updated `ODIN_ROOT_PUBKEY_HEX` or re-flashing the boot ROM. Dynamic in-memory key revocation is not implemented in this prototype.
