# ODIN OS — PHASE B.3.2
## Publication Release Manifest & Integrity Package

**Repository:** `nwalker85/odinos`  
**Branch:** `feat/phase-b32-publication-integrity`  
**Release Candidate Tag:** `v0.1.0-rc.b32`  
**Date:** November 3, 2026  
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

Every artifact in the release package is bound by SHA-256:

| Artifact Path | Description | SHA-256 Digest |
| :--- | :--- | :--- |
| `target/riscv64gc-unknown-none-elf/release/odin-kernel` | Microkernel ELF Binary | `5d914428e7343bfe0e4499e119240fb22c5e014b5ca3595530d909e8c53b6ce1` |
| `zenodo/odin-os-whitepaper.typ` | Whitepaper Typst Source | `bdc5be2d18316e2422f93614fc5e4ef17abb1829fa857f7df18946fe63faf017` |
| `zenodo/odin-os-whitepaper.pdf` | Whitepaper Compiled PDF | `6163fb4bafba454b7d24dac65e29d4ff49f00e0fd5ecf90f3389452cfc5facb1` |
| `zenodo/zenodo.json` | Zenodo Archival Metadata | `b1cac35bad767f406bf0ff675dbd50213cf1f3f6b39169dfba0b562ce1f1a2d1` |
| `Cargo.lock` | Rust Dependency Lockfile | `2b55b9d0b2079d5837e7c1209af5130d6b488c6efc2fb1bccde40bb1db6046f2` |
| `formal/deed_bounds_verification.smt2` | Bounds SMT Model | `f582d2a80a2edb4f0f0100d929a3b29413f4991a9676653cd9d6b57c35853e09` |
| `formal/sequence_anti_replay.smt2` | Anti-Replay SMT Model | `99504b5c97aebd6b92b335dccb155b4e867d3fd7731f74b42d7e218add4dde09` |
| `zenodo/receipts/adversarial_matrix_receipts.json` | 17-Test Structured Receipts | `a3c5abc7ffaa67705875c15ba964cebe9a970406f3e4b27c5cbed38e869fd1d6` |
| `zenodo/receipts/raw_execution_trace.txt` | Raw UART QEMU Trace | `ea85087981c0dd1d922623d1331879dbcb1d8f45db2fb7716e43dd67f8d146ca` |

---

### 2. Clean-Room Reproduction Instructions

```bash
# 1. Host unit tests (23 tests: deserialization, Ed25519, W^X layout)
cargo test --lib --target aarch64-apple-darwin

# 2. Bare-metal RISC-V microkernel compilation & QEMU adversarial matrix
cargo run --release

# 3. Authority Isolation & Mandatory Attacks Suite (12 tests)
python3 -m unittest tests/test_authority_isolation.py

# 4. Layer B External Host Verifier Audit
python3 tools/verify_evidence.py

# 5. Machine-checked formal SMT model verification
for f in formal/*.smt2; do echo -n "$f: "; z3 "$f"; done

# 6. Academic Whitepaper Compilation
typst compile zenodo/odin-os-whitepaper.typ zenodo/odin-os-whitepaper.pdf
```

---

### 3. Release Distribution Controls

In compliance with repository policy:
- **No public release or tag push** to GitHub or Zenodo is executed automatically.
- All modifications are contained within pull request branches awaiting explicit approval from Nathan Walker (`@nwalker85`).
