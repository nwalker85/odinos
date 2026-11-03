# Odin OS Phase B.3 — Capability Lease State Machine & Lifecycle Specification

**Author:** Principal Kernel Security Engineer & Independent Research Verification Lead  
**Scope:** Formal State Machine Specification, Replay Prevention, Explicit Revocation, and Autonomous Expiration Analysis  
**System:** Odin OS (`odin-kernel`) Bare-Metal Microkernel  

---

## 1. Disambiguation: Replay vs Revocation vs Expiration

Three distinct security mechanisms govern capability lifecycles. Conflating them leads to false claims of temporal enforcement:

1. **Replay Prevention (Sequence Monotonicity):**
   - **Mechanism:** Enforced by monotonic sequence checking:
     $$\text{deed.sequence} > \text{LAST\_CONSUMED\_SEQUENCE}$$
   - **Property:** A deed that was previously consumed cannot be re-submitted to re-open a capability lease.
   - **Current Implementation:** Actively enforced in `src/deed.rs` and tested in Test 12.

2. **Explicit Revocation (Intentional Termination):**
   - **Mechanism:** A privileged event (e.g. `sys_revoke_lease`, `ecall 13`) resets PMP Entry 4 to `OFF`.
   - **Property:** The capability lease is terminated on demand before any further writes can commit.
   - **Current Implementation:** Actively enforced in `src/main.rs` and tested in Test 16.

3. **Temporal Expiration (Autonomous Lifetime Termination):**
   - **Mechanism:** A hardware timer or cycle counter (e.g. `mcycle` or `mtimecmp`) fires an interrupt when `lease_cycles` elapses, automatically tearing down PMP Entry 4.
   - **Audit Finding:** In Phase B.2, `lease_cycles` is recorded in the signed deed, but **autonomous cycle-counted hardware expiration is not yet driven by a timer interrupt**. Revocation currently occurs via explicit microkernel syscalls or task exit.
   - **Research Classification:** Temporal expiration via autonomous cycle counting is documented as an architectural target, not an established Phase B.2 property.

---

## 2. Formal Capability State Machine Specification

We define the complete state machine governing TransitionDeed capabilities:

$$\mathcal{S} = \{ \text{UNISSUED}, \text{ISSUED}, \text{VERIFIED}, \text{ACTIVE}, \text{CONSUMED}, \text{REVOKED}, \text{EXPIRED}, \text{TERMINATED} \}$$

```
                ┌──────────────┐
                │   UNISSUED   │
                └──────┬───────┘
                       │ Event: Host Root Signer issues deed
                       │ Guard: Valid DID, bounds sanity, seq > last_seq
                       ▼
                ┌──────────────┐
                │    ISSUED    │
                └──────┬───────┘
                       │ Event: sys_verify_deed(deed_ptr)
                       │ Guard: Ed25519 valid, issuer matches, seq > last_seq
                       ▼
                ┌──────────────┐
                │   VERIFIED   │
                └──────┬───────┘
                       │ Event: kmain activates lease
                       │ Action: Program PMP Entry 4 (TOR, RW-), demote to U-Mode
                       ▼
         ┌─────────────┴─────────────┐
         │          ACTIVE           │◄───────────────────┐
         └──┬──────────┬───────────┬─┘                    │
            │          │           │                      │ In-Bounds Store (1 cycle)
            │          │           │                      │ Address in [L_start, L_end)
            │          │           └──────────────────────┘
            │          │
            │          │ Event: sys_revoke_lease() [ecall 13]
            │          │ Action: Clear PMP Entry 4 to OFF
            │          ▼
            │   ┌──────────────┐
            │   │   REVOKED    │
            │   └──────┬───────┘
            │          │
            │ Event: Task completes mutation / sys_commit_transition
            │ Action: Advance LAST_CONSUMED_SEQUENCE, clear PMP Entry 4
            ▼          │
     ┌──────────────┐  │
     │   CONSUMED   │  │
     └──────┬───────┘  │
            │          │
            ▼          ▼
     ┌─────────────────────────┐
     │       TERMINATED        │ (PMP Entry 4 == OFF, Memory Default Deny)
     └─────────────────────────┘
```

---

## 3. State Transition Table & Guards

| Current State | Triggering Event | Transition Guard | Next State | Action / Hardware Effect |
|:---|:---|:---|:---|:---|
| `UNISSUED` | Policy Approval | Agent role permits requested AST anchor | `ISSUED` | Sign canonical message with Ed25519 private key. |
| `ISSUED` | `sys_verify_deed` | Signature valid, Issuer matches root DID, Sequence $> \text{LastSeq}$ | `VERIFIED` | Returns `0` (Success). Microkernel acknowledges capability. |
| `ISSUED` | `sys_verify_deed` | Signature invalid or tampered | `TERMINATED` | Returns `DeedError::InvalidSignature` (4). No PMP change. |
| `ISSUED` | `sys_verify_deed` | Sequence $\le \text{LastSeq}$ | `TERMINATED` | Returns `DeedError::ReplayDetected` (2). No PMP change. |
| `VERIFIED` | Microkernel Lease Entry | Lease within AST buffer bounds | `ACTIVE` | Program `pmpaddr3/4`, set `pmpcfg0` Entry 4 = `0x0B` (`RW-`). |
| `ACTIVE` | Agent Store Instruction | Target $\in [\text{lease\_start}, \text{lease\_end})$ | `ACTIVE` | Memory controller commits store in 1 clock cycle. |
| `ACTIVE` | Agent Store Instruction | Target $\notin [\text{lease\_start}, \text{lease\_end})$ | `ACTIVE` (Trapped) | CPU raises `mcause = 7`. Memory unmodified (`WE = 0`). |
| `ACTIVE` | `sys_revoke_lease` (ecall 13)| Privileged M-Mode syscall | `REVOKED` | Clear `pmpcfg0` Entry 4 to `OFF`. Subsequent stores fault. |
| `ACTIVE` | Task Completion (`ecall 2`) | Clean task exit | `CONSUMED` | Update `LAST_CONSUMED_SEQUENCE = deed.sequence`. |
| `REVOKED` | Any Store Instruction | Any physical address in revoked slice | `TERMINATED` | Hardware Store Access Fault (`mcause = 7`). |

---

## 4. Reset & Persistence Semantics

1. **Sequence Survivability across Resets:**
   - In bare-metal QEMU without non-volatile storage, `LAST_CONSUMED_SEQUENCE` resides in BSS RAM (`0x8000F0E0`).
   - A hardware reset clears RAM, resetting sequence state to `0`.
   - *Requirement for Production:* In Phase C physical silicon, `LAST_CONSUMED_SEQUENCE` must be persisted in non-volatile battery-backed SRAM or flash storage to guarantee anti-replay monotonicity across power cycles.
2. **Sequence Number Wraparound:**
   - The sequence field is a 32-bit unsigned integer ($2^{32} \approx 4.29 \times 10^9$ transitions).
   - At 100 transitions per second, wraparound occurs after ~1.36 years of continuous execution.
   - *Invariant:* If `sequence == u32::MAX`, the microkernel must freeze authority acceptance until a key rotation re-anchors sequence space at zero under a new root key.
