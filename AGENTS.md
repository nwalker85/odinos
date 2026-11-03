# `odin-kernel` Authority & Agent Guidelines

## 1. Overview
The bare-metal `#![no_std]` capability microkernel and wordline-gated silicon runtime for **Odin OS**.

- **Architectural Specification**: [`~/docs/30-projects/sovereign-canon/07-Odin-OS-Operating-System-Theory-and-Silicon-Interlock.md`](file:///Users/nate/docs/30-projects/sovereign-canon/07-Odin-OS-Operating-System-Theory-and-Silicon-Interlock.md)
- **Primary Target**: `riscv64gc-unknown-none-elf` (Bare-metal 64-bit RISC-V)
- **Central Axiom**: *"State that cannot prove its right to exist cannot be committed to memory or disk."*

## 2. Invariants & Rules
1. **Zero Runtime Allocations**: All binary structs (`TransitionDeed`, `CausalTrapFrame`, `AstMask`) must remain strictly `#![no_std]` with zero heap dependencies.
2. **64-Byte Cache Line Alignment**: `TransitionDeed` must remain exactly 256 bytes (`#[repr(C, align(64))]`), matching two 128-byte or four 64-byte physical CPU cache lines.
3. **Wordline Gating (WE = 0)**: Any proposed memory mutation spanning outside an active `AstMask` must physically fail closed and mint a `CausalTrapFrame` for Interrupt Vector `0x8F` (`TRAP_AST_BOUNDARY`).
4. **Git Custody**: Obey Ravenhelm `.bare/` worktree rules and conventional commits. Never push directly to main.

## 3. Verification Commands
- Host Unit Tests: `cargo test --lib`
- Bare-Metal RISC-V Build: `cargo build --target riscv64gc-unknown-none-elf`
- Bare-Metal Release Build: `cargo build --release --target riscv64gc-unknown-none-elf`
