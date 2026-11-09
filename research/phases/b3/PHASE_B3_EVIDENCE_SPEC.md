# Odin OS Phase B.3 — Evidence Pipeline & Verifier Specification

**Author:** Principal Kernel Security Engineer & Independent Research Verification Lead  
**Scope:** Two-Layer Evidence Pipeline Architecture (Layer A In-Kernel vs Layer B External Verifier)  
**Security Rule:** *The external verifier must not accept a test run simply because the kernel reports `"status": "PASS"`.*  

---

## 1. Two-Layer Verification Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│ LAYER A: IN-KERNEL OBSERVATION ENGINE (M-Mode)                          │
│                                                                         │
│   - Executes test suite directly in U-Mode on CPU/QEMU silicon          │
│   - Hardware comparators raise access faults (mcause = 7, 5, 2, 1)      │
│   - M-Mode captures trap frame, probed address, readback byte           │
│   - Serializes empirical receipts to UART0 in structured JSON           │
│   - Validates dynamic assertion: if assertion fails, halts QEMU (0x3333)│
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ Raw UART Byte Stream
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ LAYER B: HOST-SIDE INDEPENDENT VERIFIER (`tools/verify_evidence.py`)    │
│                                                                         │
│   - Validates QEMU process exit code (Must be 0 / 0x5555)               │
│   - Strict Schema Validation: All 13 receipt fields must match types    │
│   - Sequence Integrity: Tests 1..17 strictly ascending without gaps     │
│   - Re-Computes Invariants:                                             │
│       fault_matches = (hardware_fault == expected_fault)                │
│       val_matches   = (readback_value == expected_value)                │
│   - Anti-Forged PASS Gate: Rejects any receipt where status == "PASS"   │
│     but independent re-computation evaluates to FALSE                   │
│   - Checksums raw trace and matches against evidence repository         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Receipt Schema Specification

Every receipt emitted by Odin OS must adhere to the following 13-field typed JSON schema:

```json
{
  "test_id": 5,
  "test_name": "KERNEL_CODE_WRITE",
  "target_address": "0x0000000080000000",
  "access_width": 1,
  "expected_fault": true,
  "hardware_fault": true,
  "mcause": "0x0000000000000007",
  "probed_address": "0x0000000080000000",
  "readback_value": "0x0000000000000017",
  "expected_value": "0x0000000000000017",
  "mutation_committed": false,
  "memory_unmodified": true,
  "status": "PASS"
}
```

### Field Definitions:
1. `test_id` (`int`): Monotonic sequential index ($1 \dots 17$).
2. `test_name` (`str`): Invariant test identifier string.
3. `target_address` (`str`): Hex-formatted physical address target.
4. `access_width` (`int`): Stride width in bytes ($1, 4$). For execution or deed syscalls, `0`.
5. `expected_fault` (`bool`): Ground-truth invariant expectation.
6. `hardware_fault` (`bool`): Actual observed hardware trap occurred.
7. `mcause` (`str`): RISC-V hardware machine cause register value.
8. `probed_address` (`str`): Physical address read back by M-Mode after write attempt.
9. `readback_value` (`str`): Byte or word value read back from probed address.
10. `expected_value` (`str`): Expected ground-truth memory value.
11. `mutation_committed` (`bool`): Whether target memory was mutated by the operation.
12. `memory_unmodified` (`bool`): Whether physical memory remained bitwise unchanged.
13. `status` (`str`): In-kernel evaluation (`PASS` or `FAIL`).

---

## 3. Adversarial Evidence Tampering Resistance

The Layer B verifier (`tools/verify_evidence.py`) was subjected to 10 deliberate evidence-tampering attacks:

| Tampering Vector | Attack Injected into Trace | Verifier Response | Result |
|:---|:---|:---|:---:|
| **Forged PASS** | Changed `hardware_fault: true` to `false` on Test 5 while keeping `status: PASS` | `FORGED PASS DETECTED in Test #5: Kernel claimed PASS but fault_matches=False` | **REJECTED** |
| **Receipt Suppression** | Deleted Test 10 from raw trace | `Sequence gap or out-of-order receipt: expected ID 10, got 11` | **REJECTED** |
| **Receipt Duplication** | Cloned Test 4 JSON block into trace | `Duplicate test receipt detected: test_id=4` | **REJECTED** |
| **Missing Final Test** | Deleted Test 17 from raw trace | `Expected 17 receipts, found only 16!` | **REJECTED** |
| **Banner Omission** | Stripped `🎉 ALL 17 ADVERSARIAL...` banner from trace | `Invalid trace: Microkernel final pass banner missing or incomplete.` | **REJECTED** |
| **Malformed JSON** | Injected trailing comma or unquoted token in receipt | `Malformed JSON in receipt #3` | **REJECTED** |
| **Schema Type Mismatch** | Changed `access_width: 1` to `access_width: "1"` (string) | `Receipt #1 field 'access_width' invalid type: expected int, got str` | **REJECTED** |
| **Missing Field** | Deleted `expected_value` field from receipt | `Receipt #8 missing field: expected_value` | **REJECTED** |
| **Value Discrepancy** | Changed `readback_value` to `0xFF` on Test 1 | `FORGED PASS DETECTED in Test #1: val_matches=False` | **REJECTED** |
| **Receipts JSON Drift** | Modifying `adversarial_matrix_receipts.json` without updating trace | `Discrepancy detected between raw trace receipts and saved receipts JSON!` | **REJECTED** |

---

## 4. Verification Command

To independently audit any raw trace or receipt bundle:
```bash
python3 tools/verify_evidence.py
```
Exit code is `0` on 100% mathematical and schema verification, or `1` with explicit error output on any defect.
