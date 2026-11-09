# Contributing to Odin OS

Thank you for your interest in contributing to Odin OS. 

Odin OS is a research bare-metal `#![no_std]` RISC-V microkernel investigating hardware-enforced capability confinement for autonomous agents. Because the microkernel enforces provable, machine-checked security invariants, all contributions must adhere to strict architectural constraints.

---

## Non-Negotiable Architectural Invariants

Every pull request must maintain the following core invariants:

1. **Zero Runtime Dynamic Allocations:** The microkernel operates entirely in `#![no_std]` mode without an allocator or dynamic heap. Binary structures (`TransitionDeed`, `CausalTrapFrame`) must be stack- or statically allocated.
2. **256-Byte Cache Line Alignment:** `TransitionDeed` must maintain `#[repr(C, align(64))]` and measure exactly 256 bytes, matching two 128-byte or four 64-byte physical CPU cache lines.
3. **Wordline Gating Fail-Closed:** Memory mutations outside the active deed window $[G_{\text{base}}, G_{\text{base}} + G_{\text{len}})$ must fault with Store Access Fault (`mcause = 7`). Under no circumstances may an unauthorized byte be committed.
4. **Formal SMT Correspondence:** Any modification to lease bounds checking or sequence counters must be mirrored and machine-checked in the Z3 formal models under `formal/`.

---

## Development Environment & Toolchain

To build, test, and formally verify Odin OS locally, install:

* **Rust Toolchain:** Rust `stable` with the bare-metal target:
  ```bash
  rustup target add riscv64gc-unknown-none-elf
  ```
* **QEMU Emulator:** `qemu-system-riscv64` (v11.1+ recommended):
  ```bash
  # macOS (Homebrew)
  brew install qemu
  # Debian / Ubuntu
  sudo apt-get install qemu-system-misc
  ```
* **Z3 Theorem Prover:** Z3 SMT solver (v5.3+):
  ```bash
  # macOS
  brew install z3
  # Ubuntu
  sudo apt-get install z3
  ```
* **Typst Manuscript Compiler:** Typst CLI (v0.15+):
  ```bash
  cargo install --locked typst-cli
  ```

---

## Workflow & Pull Request Process

1. **Work from a Dedicated Branch / Worktree:**
   Never push directly to `main`. Isolate all edits on a dedicated topic branch:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. **Execute the Verification Pipeline:**
   Before opening a pull request, run the canonical verification harness:
   ```bash
   python3 tools/verify_release.py
   ```
   All 9 release gates must report `PASS` with a final `DECISION: GO`.
3. **Conventional Commits:**
   Use conventional commit formatting:
   * `feat(...)`: New architectural feature or test case
   * `fix(...)`: Bug fix or boundary hardening
   * `refactor(...)`: Code cleanup or structural reorganization without behavior change
   * `docs(...)`: Documentation, whitepaper, or citation update
   * `formal(...)`: Modifications to Z3 SMT specifications
4. **Open a Pull Request:**
   Submit your pull request against `main`. Ensure the PR checklist in `.github/PULL_REQUEST_TEMPLATE.md` is fully completed.
