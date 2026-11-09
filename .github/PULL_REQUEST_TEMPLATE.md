## Summary of Changes
<!-- Provide a clear, concise overview of what this PR introduces or remediates. -->

## Motivation & Context
<!-- Why is this change necessary? Reference specific issue numbers or claims (ODIN-C001..C014). -->

## Non-Negotiable Invariants Checklist
Please verify each of the following before submitting:

- [ ] **Zero Dynamic Allocations:** Code maintains strict `#![no_std]` without heap usage or `alloc` crate.
- [ ] **Cache Line Alignment:** `TransitionDeed` remains exactly 256 bytes (`#[repr(C, align(64))]`).
- [ ] **PMP Wordline Gating:** Boundary checks fail closed; out-of-bounds writes trap immediately (`mcause = 7`).
- [ ] **SMT Correspondence:** Any modification to bounds or sequence counting is accompanied by verified Z3 proofs in `formal/`.
- [ ] **Clean Git History:** PR follows conventional commit conventions (`feat`, `fix`, `refactor`, `docs`).

## Verification & Test Evidence
- [ ] Host unit tests pass: `cargo test --lib`
- [ ] Bare-metal target compiles: `cargo build --release --target riscv64gc-unknown-none-elf`
- [ ] QEMU adversarial matrix passes: `cargo run --release`
- [ ] Z3 formal SMT proofs pass: `z3 formal/*.smt2`
- [ ] Canonical release pipeline passes: `python3 tools/verify_release.py` (9/9 gates, DECISION: GO)
