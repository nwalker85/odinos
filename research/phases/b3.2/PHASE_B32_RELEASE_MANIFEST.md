# ODIN OS — PHASE B.3.2
## Publication Release Manifest & Integrity Package

**Repository:** `nwalker85/odinos`  
**Branch:** `feat/phase-b32-publication-integrity`  
**Release Candidate:** `v0.1.0-rc.b32`  
**Date:** November 3, 2026  
**Canonical Entry Point:** `make verify-release`  
**Status:** Frozen Publication Release Candidate

---

### Conspicuous Research Fixture Disclosure

> [!WARNING]
> **PUBLIC RESEARCH FIXTURE DISCLOSURE (MODE A):**  
> By default, this repository and its deterministic test harnesses execute in **Mode A**, using the public, deliberately insecure test signing seed:
> ```
> FIXTURE_ROOT_SEED = b"odin_root_authority_seed_v2_key!"
> ```
> This key is public knowledge and is included solely to guarantee 100% deterministic, offline reproducibility of unit tests, QEMU simulations, and SMT proofs without requiring local key infrastructure. **It provides zero confidentiality or production security.**
> 
> For deployments requiring cryptographic secrecy, the Policy Decision Point supports **Mode B (Independently Provisioned Authority)**, which loads a cryptographically secure 32-byte seed from an external, secured path (`ODIN_AUTHORITY_SEED_PATH`) and requires the microkernel to be compiled with `ODIN_ROOT_PUBKEY_HEX`. Mode B fails closed if keys are absent or invalid.

---

### 1. Cryptographic Package Manifest & Checksum Ledger

Every artifact in the release package is bound by SHA-256 and verified via `make verify-release`:

| Artifact Path | Description | SHA-256 Digest |
| :--- | :--- | :--- |
| `target/riscv64gc-unknown-none-elf/release/odin-kernel` | Microkernel ELF Binary | `5d914428e7343bfe0e4499e119240fb22c5e014b5ca3595530d909e8c53b6ce1` |
| `zenodo/odin-os-whitepaper.typ` | Whitepaper Typst Source | `c183c8dd314496ac4977b7b27f91102750494f1d2137768b700f023a46c46ce7` |
| `zenodo/odin-os-whitepaper.pdf` | Deterministic Compiled PDF | `28f62e14bbb670e0efd7f5aa058c3d782adb6cc315f23ce948251b35cb43e167` |
| `zenodo/zenodo.json` | Zenodo Archival Metadata | `b1cac35bad767f406bf0ff675dbd50213cf1f3f6b39169dfba0b562ce1f1a2d1` |
| `Cargo.lock` | Rust Dependency Lockfile | `2b55b9d0b2079d5837e7c1209af5130d6b488c6efc2fb1bccde40bb1db6046f2` |
| `formal/deed_bounds_verification.smt2` | Bounds SMT Model | `f582d2a80a2edb4f0f0100d929a3b29413f4991a9676653cd9d6b57c35853e09` |
| `formal/sequence_anti_replay.smt2` | Anti-Replay SMT Model | `99504b5c97aebd6b92b335dccb155b4e867d3fd7731f74b42d7e218add4dde09` |
| `zenodo/receipts/adversarial_matrix_receipts.json` | 17-Test Structured Receipts | `a3c5abc7ffaa67705875c15ba964cebe9a970406f3e4b27c5cbed38e869fd1d6` |
| `zenodo/receipts/raw_execution_trace.txt` | Raw UART QEMU Trace | `fef3815426fa6430356e3154633b22eca105ffd70c5fad6c0878e10745ceb06e` |

---

### 2. Clean-Room Reproduction Instructions

The entire verification pipeline is encapsulated in a single command:

```bash
make verify-release
```

Or execute individual sub-targets:
```bash
make test             # Host unit tests (23 cases)
make qemu             # Bare-metal microkernel matrix (17 cases)
make authority-tests  # Authority isolation tests (12 cases)
make verifier-tests   # Adversarial verifier tamper tests (10 cases)
make smt              # Formal SMT models (Z3)
make paper            # Deterministic whitepaper compilation (SOURCE_DATE_EPOCH=1700000000)
```

---

### 3. Release Distribution Controls

In compliance with repository policy:
- **No public release or tag push** to GitHub or Zenodo is executed automatically.
- All modifications are contained within pull request branches awaiting explicit approval from Nathan Walker (`@nwalker85`).
