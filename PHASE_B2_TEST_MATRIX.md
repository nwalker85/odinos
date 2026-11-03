# Odin OS Phase B.2 — Adversarial Verification Test Matrix

**System:** Bare-Metal RISC-V 64-bit Microkernel (`odin-kernel`)  
**Execution Environment:** QEMU `virt` platform, `riscv64gc-unknown-none-elf`, Direct M-Mode Bootstrap  
**Test Suite Size:** 17 Distinct Invariant Cases  
**Verification Result:** 17 / 17 Passed (100% Hardware Enforcement)  

---

## 1. Overview & Verification Doctrine

Each adversarial test is framed around a falsifiable invariant assertion. Unlike unit tests that execute in user space or rely on mocked OS interfaces, Odin OS runs directly on CPU silicon/emulation, testing whether physical hardware traps occur and whether memory remains unaltered after unauthorized access attempts.

Receipts are generated through microkernel syscalls (`SYS_RECEIPT_START = 10`, `SYS_RECEIPT_FINISH = 11`), outputting structured JSON directly to UART0.

---

## 2. Exhaustive 17-Case Verification Matrix

| ID | Test Name | Target Address | Access Width | Expected Fault | Observed Fault | Trap `mcause` | Readback | Expected Readback | Mutation Committed | Memory Unmodified | Status |
|:--:|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 1 | `EXACT_LOWER_BOUND` | `0x80020040` | 1 byte | `false` | `false` | `0x0` | `0x41` | `0x41` | `true` | `false` | **PASS** |
| 2 | `EXACT_UPPER_BOUND_MINUS_ONE` | `0x8002005F` | 1 byte | `false` | `false` | `0x0` | `0x42` | `0x42` | `true` | `false` | **PASS** |
| 3 | `ONE_BYTE_BELOW_LEASE` | `0x8002003F` | 1 byte | `true` | `true` | `0x7` (Store Fault) | `0x00` | `0x00` | `false` | `true` | **PASS** |
| 4 | `ONE_BYTE_ABOVE_LEASE` | `0x80020060` | 1 byte | `true` | `true` | `0x7` (Store Fault) | `0x00` | `0x00` | `false` | `true` | **PASS** |
| 5 | `KERNEL_CODE_WRITE` | `0x80000000` | 1 byte | `true` | `true` | `0x7` (Store Fault) | `0x17` | `0x17` | `false` | `true` | **PASS** |
| 6 | `KERNEL_STACK_WRITE` | `0x8000FFF8` | 1 byte | `true` | `true` | `0x7` (Store Fault) | `0x00` | `0x00` | `false` | `true` | **PASS** |
| 7 | `USER_CODE_WRITE_WX` | `0x80010000` | 1 byte | `true` | `true` | `0x7` (Store Fault) | `0x09` | `0x09` | `false` | `true` | **PASS** |
| 8 | `USER_STACK_EXECUTE_WX` | `0x80018100` | 0 (exec) | `true` | `true` | `0x1` (Fetch Fault) | `0x00` | `0x00` | `false` | `true` | **PASS** |
| 9 | `UNMAPPED_PERIMETER_WRITE` | `0x80030000` | 1 byte | `true` | `true` | `0x7` (Store Fault) | `0x00` | `0x00` | `false` | `true` | **PASS** |
| 10 | `MULTIBYTE_OVERLAP_CROSSING` | `0x8002005E` | 4 bytes | `true` | `true` | `0x7` (Store Fault) | `0x00` | `0x00` | `false` | `true` | **PASS** |
| 11 | `FORGED_DEED_UNTRUSTED_ISSUER` | `0x00000000` | 0 (deed) | `false` | `false` | `0x0` | `0x01` (Err: Issuer) | `0x01` | `false` | `true` | **PASS** |
| 12 | `REPLAYED_DEED_SEQUENCE` | `0x00000000` | 0 (deed) | `false` | `false` | `0x0` | `0x02` (Err: Replay) | `0x02` | `false` | `true` | **PASS** |
| 13 | `FORGED_DEED_ED25519_INVALID_SIG` | `0x00000000` | 0 (deed) | `false` | `false` | `0x0` | `0x04` (Err: Sig) | `0x04` | `false` | `true` | **PASS** |
| 14 | `DEED_TAMPERED_METADATA_ED25519` | `0x00000000` | 0 (deed) | `false` | `false` | `0x0` | `0x04` (Err: Sig) | `0x04` | `false` | `true` | **PASS** |
| 15 | `U_MODE_CSR_TAMPER_PMPCFG0` | `0x00000000` | 0 (inst) | `true` | `true` | `0x2` (Illegal Inst) | `0x00` | `0x00` | `false` | `true` | **PASS** |
| 16 | `EXPIRED_LEASE_TEMPORAL_REVOCATION` | `0x80020040` | 1 byte | `true` | `true` | `0x7` (Store Fault) | `0x41` | `0x41` | `false` | `true` | **PASS** |
| 17 | `U_MODE_UART_MMIO_WRITE` | `0x10000000` | 1 byte | `true` | `true` | `0x7` (Store Fault) | `0x00` | `0x00` | `false` | `true` | **PASS** |

---

## 3. Detailed Case Analysis

### In-Bounds Lease Verification (Tests 1 & 2)
- **Invariant:** Authorized writes within `[0x80020040 .. 0x80020060)` must succeed in 1 CPU cycle without faulting.
- **Evidence:** Probing `0x80020040` wrote `0x41` ('A') and read back `0x41`. Probing `0x8002005F` wrote `0x42` ('B') and read back `0x42`. Both tests completed with `mcause = 0x0`, `mutation_committed = true`.

### Fencepost Fence Violations (Tests 3 & 4)
- **Invariant:** A write 1 byte below the lease (`0x8002003F`) or 1 byte above (`0x80020060`) must be rejected.
- **Evidence:** Both stores triggered `mcause = 7` (Store Access Fault). Memory readback confirmed the bytes remained `0x00`.

### Kernel Privilege Domain Defense (Tests 5, 6 & 17)
- **Invariant:** Privileged kernel instructions, kernel stack, and UART hardware MMIO must be unreachable from U-Mode.
- **Evidence:**
  - Store to `0x80000000` (Kernel Text) triggered `mcause = 7`. Kernel opcode `0x17` was preserved unmodified.
  - Store to `0x8000FFF8` (Kernel Stack) triggered `mcause = 7`. Stack byte `0x00` was preserved unmodified.
  - Store to `0x10000000` (UART0) triggered `mcause = 7`. UART transmit buffer was protected from unprivileged tampering.

### Strict W^X Enforcement (Tests 7 & 8)
- **Invariant:** Memory that is executable cannot be writable, and memory that is writable cannot be executable.
- **Evidence:**
  - Test 7: Store to `0x80010000` (User Text) triggered `mcause = 7`. User text opcode `0x09` remained unmodified.
  - Test 8: Writing `jalr zero, 0(ra)` (`0x00008067`) to user stack (`0x80018100`) followed by `jalr ra, 0(t0)` instantly triggered `mcause = 1` (Instruction Access Fault). M-Mode intercepted the trap and safely redirected `mepc` back to `.user_text`.

### Multi-Byte Straddling Atomicity (Test 10)
- **Invariant:** A 4-byte write (`sw`) whose address span straddles the valid lease boundary into unallocated space must fault atomically, committing zero bytes.
- **Evidence:** Storing `0xDEADBEEF` at `0x8002005E` (bytes `0x5E..0x62`, crossing the `0x60` boundary) triggered `mcause = 7`. A 4-byte memory sweep verified all 4 bytes remained `0x00`.

### Cryptographic Capability Authority (Tests 11, 12, 13 & 14)
- **Invariant:** Only TransitionDeeds signed by the authentic root authority over canonical domain-separated metadata can grant capability leases.
- **Evidence:**
  - Test 11: Deed from `did:odin:rogue:99` returned error `1` (`UntrustedIssuer`).
  - Test 12: Deed with sequence number `0` returned error `2` (`ReplayDetected`).
  - Test 13: Deed with forged/garbage Ed25519 signature returned error `4` (`InvalidSignature`).
  - Test 14: Deed whose metadata was altered from offset 50 to 99 after genuine signing returned error `4` (`InvalidSignature`).

### Privilege Escalation & Temporal Revocation (Tests 15 & 16)
- **Invariant:** U-Mode cannot tamper with PMP configuration registers, and revoked leases cannot be mutated.
- **Evidence:**
  - Test 15: Executing `csrr t0, pmpcfg0` in U-Mode triggered `mcause = 2` (Illegal Instruction).
  - Test 16: After invoking `sys_revoke_lease()`, attempting to write to `0x80020040` (which previously succeeded in Test 1) triggered `mcause = 7`.
