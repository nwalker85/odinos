# ODIN OS — PHASE B.3.2
## Formal Soundness & SMT Model Verification Report

**Role:** Formal Methods Reviewer & Cryptographic Protocol Auditor  
**Repository:** `nwalker85/odinos`  
**Tool:** Z3 Theorem Prover version 5.3.1 (`QF_BV`)  
**Date:** November 3, 2026  
**Status:** Defensible Formal Model Assurance

---

### Executive Summary

In Phase B.3.1, SMT-LIB2 models were reported as proving "mathematical impossibility" of bounds violations and replay attacks. An external audit correctly noted that passing SMT queries can be misleading if the underlying queries are vacuous, tautological, or poorly bound to the source code.

This audit evaluates the soundness of both SMT models (`formal/deed_bounds_verification.smt2` and `formal/sequence_anti_replay.smt2`), introduces controlled mutations to demonstrate that the models admit concrete counterexamples when properties are violated, and establishes the precise boundary between **machine-checked properties of the formal model** and **implementation-level code verification**.

---

### 1. Formal Property Specifications & Correspondence

#### Property 1: Bounded Integer Overflow Immunity
- **Formal Statement:** No validly accepted deed can cause `target_offset + target_length` to wrap around in 32-bit arithmetic.
- **Bit Widths & Logic:** `BitVec 32`, zero-extended to `BitVec 64` in `QF_BV`.
- **Variables:** `target_offset: (_ BitVec 32)`, `target_length: (_ BitVec 32)`, `max_bound: (_ BitVec 32)`.
- **Assumptions:** `max_bound = 65536` (`0x10000`).
- **Acceptance Predicate (`deed_valid`):**
  ```smt2
  (and
    (bvugt target_length (_ bv0 32))
    (not (bvugt (bvadd offset_64 length_64) (_ bv4294967295 64)))
    (bvule (bvadd target_offset target_length) max_bound))
  ```
- **Negated Counterexample Query:**
  ```smt2
  (assert deed_valid)
  (assert (bvuge target_offset end_offset)) ; Wrap-around condition!
  (check-sat)
  ```
- **Solver Outcome:** `unsat` (0.005s).
- **Rust Code Correspondence:** `src/deed.rs:146..149`:
  ```rust
  let end_offset = match self.target_offset.checked_add(self.target_length) {
      Some(end) => end,
      None => return Err(DeedError::OutOfBoundsLease),
  };
  ```
- **Unmodeled Behavior & Limitations:** The SMT model abstracts the Rust CPU carry flag check via 64-bit zero-extended comparison. It models arithmetic bounds, but does not verify machine instructions or memory bus electrical properties.

#### Property 2: Privileged Memory Disjointness
- **Formal Statement:** For all valid combinations of `target_offset` and `target_length`, the physical lease window is strictly disjoint from Kernel RAM (`0x80000000..0x80010000`), User Text (`0x80010000..0x80018000`), User Stack (`0x80018000..0x80020000`), and UART MMIO (`0x10000000..0x10001000`).
- **Bit Widths:** 64-bit address arithmetic (`BitVec 64`).
- **Negated Query:** `(assert (or overlaps_kernel overlaps_user_text overlaps_user_stack overlaps_uart))`
- **Solver Outcome:** `unsat` (0.006s).
- **Rust Code Correspondence:** `src/main.rs:226..260` (`setup_pmp`).
- **Limitations:** Models static physical address ranges; assumes linker script base addresses are immutable.

#### Property 3: Strict Buffer Containment
- **Formal Statement:** For all valid deeds, `physical_lease_end <= 0x80030000` (`AST_BUFFER_END`).
- **Negated Query:** `(assert (bvugt physical_lease_end ast_buffer_end))`
- **Solver Outcome:** `unsat` (0.004s).
- **Rust Code Correspondence:** `src/deed.rs:151..153` (`end_offset > max_bound`).

#### Properties 4 & 5: Anti-Replay Monotonicity (Identical & Stale Sequences)
- **Formal Statement:** A transition deed sequence number $s_2$ submitted after $s_1$ cannot be accepted if $s_2 \le s_1$.
- **Negated Query (Identical):** `(assert (and accept_1 (= seq_2 seq_1) accept_2))` $\rightarrow$ `unsat`.
- **Negated Query (Stale):** `(assert (and accept_1 (bvule seq_2 seq_1) accept_2))` $\rightarrow$ `unsat`.
- **Rust Code Correspondence:** `src/deed.rs:137..139`:
  ```rust
  if self.sequence <= last_sequence {
      return Err(DeedError::ReplayDetected);
  }
  ```
- **Limitations:** Models two consecutive transaction turns; does not model non-volatile storage persistence across power loss (which is handled by Mode B / future NVRAM).

---

### 2. Controlled Mutation Testing of SMT Models

To refute any hypothesis of vacuous truth or tautological proofs, controlled faults were injected into the formal models:

#### SMT Mutation 1: Disabling Overflow Protection
- **Injected Mutation in `deed_bounds_verification.smt2`:**  
  Replaced `(not add_overflows)` with `true` in `deed_valid`.
- **Solver Response:**  
  Immediately returns **`sat`** with concrete counterexample:
  ```smt2
  target_offset = 0xfffffffb  (4,294,967,291)
  target_length = 0x00000010  (16)
  end_offset    = 0x0000000b  (11 <= max_bound 65536)
  target_offset >= end_offset (True: 0xfffffffb >= 0x0000000b)
  ```
- **Finding:** The original `unsat` was strictly produced by `add_overflows`. Without checked addition, wrap-around attacks succeed.

#### SMT Mutation 2: Relaxing Anti-Replay Strict Inequality
- **Injected Mutation in `sequence_anti_replay.smt2`:**  
  Replaced `(bvugt seq_2 last_seq_1)` with `(bvuge seq_2 last_seq_1)`.
- **Solver Response:**  
  Immediately returns **`sat`** with concrete counterexample:
  ```smt2
  seq_1      = 0xced5d4d9
  last_seq_0 = 0xbbf37973  (accept_1 = True)
  last_seq_1 = 0xced5d4d9
  seq_2      = 0xced5d4d9  (seq_2 == seq_1, accept_2 = True!)
  ```
- **Finding:** The anti-replay proof is sound and non-vacuous. Permitting non-strict inequalities immediately admits replay attacks in the solver.

---

### 3. Required Standardized Terminology

In all academic publications, whitepapers, and technical reports:
- **Approved Phrasing:** *"Machine-checked properties of the formal SMT models under documented assumptions."*
- **Prohibited Phrasing:** *"The microkernel implementation is formally verified,"* or *"Mathematically impossible to bypass the kernel."* (Reserved strictly for deductive source-to-binary verification frameworks such as Creusot, Prusti, or seL4/Isabelle).
