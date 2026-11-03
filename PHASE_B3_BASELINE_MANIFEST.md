# Odin OS Phase B.3 — Immutable Baseline Manifest

**Audit Phase:** Phase B.3 Baseline Establishment  
**Timestamp:** 2026-11-03T09:16:00-06:00  
**Baseline Git Commit:** `e4c9dbaa9be6886d8b711a04de07ea70ae9910f0`  
**Commit Message:** `feat(phase-b2): adversarial assurance, cryptographic authority, and evidence integrity (#6)`  
**Branch:** `feat/phase-b3-publication-candidate` (branched from clean `main` at `e4c9dba`)  
**Working Tree Status:** Clean  

---

## 1. Environment & Toolchain Identification

- **Host Operating System:** macOS (Darwin 24.3.0, arm64 / Apple Silicon)
- **Rust Compiler:** `rustc 1.98.0 (88d9e12ae 2026-08-18)`
- **Cargo Package Manager:** `cargo 1.98.0 (797e8a9bc 2026-08-05)`
- **Target Triple:** `riscv64gc-unknown-none-elf`
- **Linker:** `rust-lld` (invoked via `-C link-arg=-Tsrc/linker.ld`)
- **QEMU Emulator:** `qemu-system-riscv64 11.1.3`
- **Typst Compiler:** `typst 0.15.1`
- **Python Runtime:** `Python 3.14.0` with `PyNaCl 1.5.0`

---

## 2. Cryptographic Source & Dependency Lock Hashes (SHA-256)

| Artifact Path | SHA-256 Digest | Purpose |
|:---|:---:|:---|
| `Cargo.lock` | `2b55b9d0b2079d5837e7c1209af5130d6b488c6efc2fb1bccde40bb1db6046f2` | Pinned dependency tree |
| `Cargo.toml` | `a834d0b3a99660c5027305b36cb5b223d7b1a71755fc4588568e0f7e86a95f11` | Crate configuration & profiles |
| `src/linker.ld` | `6086e2fd191a7cd4217d9f5d34f6b60954cb45ab3e0ad36ef593fb0609208012` | 5-region physical memory map |
| `src/lib.rs` | `9dcf0f5904f0c6f7026dbba61232ce6157c59b4bdee192066e1da74dbc8ec117` | Crate root & 23 host unit/prop tests |
| `src/main.rs` | `3b550c9948621c027279179536bb1bb2718584bc62d47196726035167b736a67` | M-Mode kernel & 17-test QEMU suite |
| `src/deed.rs` | `9bc336ac0f56c912e4c34be0225e5722413014ba726ad84e20155391c12b1df5` | TransitionDeed v2 & Ed25519 verifier |
| `target/riscv64gc-unknown-none-elf/release/odin-kernel` | `5d914428e7343bfe0e4499e119240fb22c5e014b5ca3595530d909e8c53b6ce1` | Compiled release ELF microkernel |
| `zenodo/receipts/adversarial_matrix_receipts.json` | `a3c5abc7ffaa67705875c15ba964cebe9a970406f3e4b27c5cbed38e869fd1d6` | Baseline 17-test JSON receipts |
| `zenodo/receipts/raw_execution_trace.txt` | `fef3815426fa6430356e3154633b22eca105ffd70c5fad6c0878e10745ceb06e` | Baseline QEMU UART log |
| `zenodo/odin-os-whitepaper.pdf` | `0a3d03b755380c98d3209104e6a27d778ea25889af2e5f08cd90039ee4bab6fb` | Baseline academic whitepaper |

---

## 3. Reproduction Evidence Verification

### 3.1 Host Test Suite Reproduction
- **Command:** `cargo test --lib --target aarch64-apple-darwin`
- **Result:** `ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s`
- **Status:** **100% REPRODUCED**.

### 3.2 Bare-Metal QEMU Invariant Suite Reproduction
- **Command:** `cargo run --release`
- **Invocation:** `qemu-system-riscv64 -machine virt -nographic -bios none -kernel target/riscv64gc-unknown-none-elf/release/odin-kernel`
- **Banner Banner:** `🎉 ALL 17 ADVERSARIAL INVARIANT TESTS PASSED WITH 100% HARDWARE ENFORCEMENT`
- **Process Exit Code:** `0` (via SiFive test finity register `0x100000 <- 0x5555`)
- **Status:** **100% REPRODUCED**.

### 3.3 Mutation Testing Baseline Sensitivity
- **Reported in Phase B.2:** 10 / 10 killed (100%).
- **Sample Invariant Verification:** Mutation M06 (mapping user code as RWX) triggers `[VERIFICATION FATAL] Test 7 failed invariant assertion! Halting.` and exits with code `0x3333`.
- **Status:** **100% REPRODUCED**.

---

## 4. Discrepancy & Gap Assessment (Phase B.2 Baseline Findings)

Under rigorous Stage 1 audit, the following findings are formally logged before making code changes:

1. **Test 10 Misalignment Confounding:**
   Test 10 executes a 4-byte store (`sw`) at `0x8002005E`, extending to `0x80020062` across the `0x80020060` lease end. Address `0x8002005E` is not 4-byte naturally aligned ($0x5E \not\equiv 0 \pmod 4$). In RISC-V, misaligned stores may raise `mcause = 6` (Store address misaligned) on hardware without hardware misaligned store support, or `mcause = 7` (Store access fault) if PMP intercepts first or if the second sub-access faults. In QEMU `virt`, `mcause = 7` is emitted. A dedicated test must isolate natural alignment boundary crossing vs misaligned access.
2. **Authority Lifecycle / Signing Oracle Separation:**
   In Phase B.2, `ROOT_SEED` (`b"odin_root_authority_seed_v2_key!"`) is in `tools/gemma_odin_bridge.py`. While the microkernel only possesses the public key `TRUSTED_ROOT_PUBLIC_KEY`, the host bridge currently acts as both the agent prompter and the root signer. The signer does not enforce an independent authorization policy check before signing.
3. **Transaction Semantics & Digests:**
   `TransitionDeed` has `base_digest` and `new_digest`, but the Phase B.2 microkernel does not verify pre-mutation memory digests against `base_digest` or post-mutation memory digests against `new_digest`. State integrity is currently constrained by PMP address bounds, not by semantic state hashing.
4. **Autonomous Temporal Cycle Counting:**
   Lease duration (`lease_cycles`) is present in the deed, but revocation is driven by explicit microkernel syscall (`sys_revoke_lease`, `ecall 13`) rather than a hardware `mcycle` trap interrupt.
5. **Evidence Verifier Independence:**
   Phase B.2 evaluated receipts inside M-Mode and printed JSON to UART. An independent external Layer B verification script is needed to validate receipt schemas, test sequences, missing receipts, and process exit codes without trusting kernel claims.

These 5 findings form the operational agenda for Phase B.3.
