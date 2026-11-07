# Odin OS: Independent Falsification Protocols

**Document Identifier:** ODIN-DOC-FP-001  
**Classification:** Independent Peer-Review & Assurance Package  
**Target Release:** Phase B.3.2 Canonical Baseline  
**Revision:** 2026-11-07  

---

## 1. Objective & Reviewer Instructions

This document provides actionable, step-by-step falsification protocols for independent systems-security researchers. 

**Scientific Falsification Directive:**  
Your objective as a reviewer is not to verify that tests pass under normal conditions. Your objective is to design inputs, modify configuration parameters, or construct execution sequences that **disprove or invalidate** the stated security invariants.

Every protocol below provides:
1. **Objective:** The precise invariant being challenged.
2. **Setup:** Required tools and configuration.
3. **Procedure:** Exact commands or code modifications required.
4. **Expected Behavior:** System response if the invariant holds.
5. **Falsification Condition:** Concrete observable result that invalidates the claim.
6. **Evidence Collection:** Specific registers, memory dumps, and logs to capture.
7. **Limitations:** What passing the test still does not prove.

---

## 2. Priority Protocols

### PROTO-01: Spatial Boundary Breach (ODIN-C001)

* **Objective:** Falsify the claim that an unprivileged U-Mode task cannot commit a store instruction to memory outside its granted TransitionDeed lease.
* **Target Invariant:** If `target_address < lease_start` or `target_address >= lease_end`, CPU must raise Store Access Fault (`mcause = 7`), leaving memory byte unchanged.
* **Setup:** Standard QEMU 11.1.3 `virt` environment.
* **Procedure:**
  1. Open [`src/main.rs`](file:///Users/nate/src/platforms/ravenhelm/odin-kernel-wt-clean-zenodo/src/main.rs).
  2. In `user_mode_adversarial_suite()`, insert an unprivileged store targeting:
     * One byte below lease: `0x8002_003F` with byte `0xAA`
     * One byte above lease: `0x8002_0060` with byte `0xBB`
     * Remote DRAM address: `0x8003_5000` with byte `0xCC`
  3. Compile and run: `cargo run --release`.
* **Expected Behavior:** QEMU triggers an architectural trap (`mcause = 7`), invokes `handle_trap`, records `TRAP_OCCURRED = true`, advances `mepc`, and reads back the original byte (`0x00`).
* **Falsification Condition:**
  * **Falsified if:** The target address reads back `0xAA`, `0xBB`, or `0xCC`, OR
  * **Falsified if:** Execution terminates without triggering `mcause = 7`.
* **Evidence Collection:** Capture `mepc`, `mtval`, readback value at target address, and UART JSON receipt.
* **Limitation:** Passing this test under QEMU virt demonstrates compliance with QEMU's softmmu PMP model; it does not prove physical silicon bus timing behavior.

---

### PROTO-02: Multi-Byte Protection Boundary Crossing (ODIN-C008)

* **Objective:** Falsify the claim that a multi-byte store straddling a PMP boundary does not partially commit bytes.
* **Target Invariant:** A 4-byte store at `0x8002005E` (bytes `[0x5E..0x5F]` inside lease, `[0x60..0x61]` outside) must not mutate either in-bounds or out-of-bounds bytes.
* **Setup:** Standard QEMU test harness.
* **Procedure:**
  1. Initialize all bytes in `0x8002005E..0x80020062` to `0x00`.
  2. Issue a 32-bit store instruction in U-Mode: `sw 0xDEADBEEF, 0(0x8002005E)`.
  3. Inspect all 4 bytes across the boundary.
* **Expected Behavior:** Under QEMU 11.1.3 virt, the processor evaluates the full access span before retirement, traps with `mcause = 7`, and leaves all 4 bytes as `0x00`.
* **Falsification Condition:**
  * **Falsified if:** In-bounds bytes `0x8002005E..0x8002005F` commit `0xEF, 0xBE` while upper bytes fault (partial commit / atomic fracture).
* **Evidence Collection:** Dump memory span `0x80020058..0x80020068` before and after store execution.
* **Physical Silicon Note:** On physical hardware cores conforming only to base RISC-V ISA §2.6, misaligned stores may commit partially. This test is explicitly qualified for QEMU emulation.

---

### PROTO-03: Temporal Capability Leakage (ODIN-C006)

* **Objective:** Falsify the claim that capability lease revocation immediately denies write permissions.
* **Target Invariant:** After `SYS_REVOKE_LEASE` (ecall 13), subsequent stores to the previously valid address `0x80020040` must trigger a Store Access Fault.
* **Setup:** Standard QEMU test harness.
* **Procedure:**
  1. Perform an authorized write to `0x80020040` (value `0x41`, succeeds).
  2. Invoke microkernel syscall 13: `sys_revoke_lease()`.
  3. Attempt an immediate second write to `0x80020040` with value `0x99`.
* **Expected Behavior:** The second store traps with `mcause = 7`. Memory at `0x80020040` remains `0x41`.
* **Falsification Condition:**
  * **Falsified if:** The second store succeeds without fault, OR memory updates to `0x99`.
* **Evidence Collection:** Trace PMP Entry 4 configuration before and after syscall 13.

---

### PROTO-04: Bi-Directional $W \oplus X$ Privilege Bypass (ODIN-C005)

* **Objective:** Falsify the claim that user text is immutable and user stack is non-executable.
* **Target Invariant:**
  * Store to user code (`0x80010000`) traps with `mcause = 7`.
  * Instruction fetch from user stack (`0x80018100`) traps with `mcause = 1` and redirects safely.
* **Setup:** Standard QEMU test harness.
* **Procedure:**
  1. In U-Mode, attempt `sb 0xFF, 0(0x80010000)`.
  2. Write opcode `0x00008067` (`jalr zero, 0(ra)`) to user stack `0x80018100` and execute `jalr ra, 0(t0)`.
* **Expected Behavior:**
  * Code write triggers Store Access Fault (`mcause = 7`).
  * Stack execute triggers Instruction Access Fault (`mcause = 1`), caught by trap handler and redirected back to `frame.ra` in `.user_text`.
* **Falsification Condition:**
  * **Falsified if:** User text byte is modified, OR
  * **Falsified if:** Code executes from user stack without fault, OR
  * **Falsified if:** The CPU enters an infinite trap recursion loop on stack fetch.

---

### PROTO-05: PMP CSR Privilege Escalation (ODIN-C007)

* **Objective:** Falsify the claim that U-Mode cannot modify or inspect PMP configuration.
* **Target Invariant:** Any unprivileged read or write to `pmpcfg0` or `pmpaddr0`..`pmpaddr7` must trap with Illegal Instruction (`mcause = 2`).
* **Setup:** Standard QEMU test harness.
* **Procedure:**
  1. In U-Mode, execute `csrr t0, pmpcfg0`.
  2. In U-Mode, execute `csrw pmpcfg0, zero`.
* **Expected Behavior:** The processor triggers an Illegal Instruction trap (`mcause = 2`).
* **Falsification Condition:**
  * **Falsified if:** `csrr` returns PMP configuration into `t0` without fault, OR
  * **Falsified if:** `csrw` clears PMP entries, opening physical memory to U-Mode.

---

### PROTO-06: Cryptographic TransitionDeed Forgery (ODIN-C003)

* **Objective:** Falsify the claim that deeds with forged signatures or untrusted issuers are rejected.
* **Target Invariant:** `sys_verify_deed()` must return nonzero error code and refuse to grant write permissions.
* **Setup:** Standard host unit tests and QEMU microkernel syscalls.
* **Procedure:**
  1. Construct a deed with a valid payload but signed by a rogue private key.
  2. Construct a deed with a valid signature and flip a single bit in the 64-byte signature block.
  3. Construct a deed with an untrusted issuer DID (`[0xEE; 16]`).
  4. Submit each deed to `sys_verify_deed(ptr)`.
* **Expected Behavior:**
  * Rogue key returns `DeedError::InvalidSignature` (error code 4).
  * Flipped bit returns `DeedError::InvalidSignature` (error code 4).
  * Untrusted DID returns `DeedError::UntrustedIssuer` (error code 1).
* **Falsification Condition:**
  * **Falsified if:** Any forged, flipped, or unauthorized deed returns `0` (Success) or programs PMP registers.

---

### PROTO-07: Monotonic Anti-Replay Sequence Nonce (ODIN-C004)

* **Objective:** Falsify the claim that replayed TransitionDeeds are rejected.
* **Target Invariant:** A deed with `sequence <= last_sequence` must be rejected with `DeedError::ReplayDetected` (error code 2).
* **Setup:** Standard QEMU test harness.
* **Procedure:**
  1. Submit a valid deed with `sequence = 100`.
  2. Resubmit the identical deed with `sequence = 100`.
  3. Submit a deed with `sequence = 99`.
  4. Submit a deed with `sequence = 0`.
* **Expected Behavior:** Subsequent submissions return error code 2.
* **Falsification Condition:**
  * **Falsified if:** A deed with an identical or lower sequence number is accepted.
* **Limitation:** If the microkernel is hard-reset or power-cycled, `last_sequence` in RAM resets to 0. Falsifying persistence across power cycles confirms a known limitation documented in `KNOWN_LIMITATIONS.md`.

---

### PROTO-08: Integer Overflow Lease Clamping (ODIN-C009)

* **Objective:** Falsify the claim that integer wrap attacks on lease bounds are blocked.
* **Target Invariant:** `target_offset + target_length > u32::MAX` must fail closed.
* **Setup:** Standard host unit tests and Z3 SMT prover.
* **Procedure:**
  1. Pass `target_offset = 0xFFFF_FFF0` and `target_length = 0x20` to `verify_authority()`.
  2. Run Z3 SMT bounds verification: `z3 formal/deed_bounds_verification.smt2`.
* **Expected Behavior:** Rust checked addition (`checked_add`) returns `None`, mapping to `DeedError::OutOfBoundsLease`. Z3 returns `unsat`.
* **Falsification Condition:**
  * **Falsified if:** The lease wraps around to address `0x00000010` and grants low memory access, OR
  * **Falsified if:** Z3 outputs `sat` with an integer overflow counterexample.

---

### PROTO-09: Semantic In-Bounds Tampering (ODIN-C012)

* **Objective:** Demonstrate the fundamental boundary between hardware PEP enforcement and business semantic correctness.
* **Target Invariant:** Hardware PMP allows memory writes within authorized byte spans regardless of whether the modified data makes business sense.
* **Setup:** Live QEMU execution.
* **Procedure:**
  1. Obtain a valid TransitionDeed authorizing write access to AST buffer `[0x40..0x60]`.
  2. Instead of writing the expected integer AST node, write random garbage bytes (`0xDE, 0xAD, 0xBE, 0xEF`).
  3. Read back the memory.
* **Expected Behavior:** The write succeeds without a hardware fault (`mcause = 0x00`).
* **Scientific Significance:** This confirms that **Odin OS is a spatial/temporal capability monitor, not an application-level business validator.** Hardware PMP cannot and does not guarantee that the mutated bytes represent sound business logic.
