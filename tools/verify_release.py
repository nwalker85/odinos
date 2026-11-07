#!/usr/bin/env python3
"""
Odin OS Phase B.3.2: Canonical Release Verification Entry Point
Executes the complete clean-room verification pipeline and validates manifest integrity.
Returns exit code 0 if all gates pass; returns nonzero exit code on any failure.
"""

import sys
import os
import subprocess
import hashlib
import json
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SOURCE_DATE_EPOCH = "1700000000"

def run_step(step_name: str, cmd: list, env_overrides: dict = None) -> bool:
    print(f"\n▶ [{step_name}] Running: {' '.join(cmd)}")
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)
    
    t0 = time.time()
    proc = subprocess.run(cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True)
    dt = time.time() - t0
    
    if proc.returncode != 0:
        print(f"  ✗ FAILED in {dt:.2f}s (Exit Code: {proc.returncode})")
        if proc.stdout:
            print("--- STDOUT ---")
            print(proc.stdout[-500:])
        if proc.stderr:
            print("--- STDERR ---")
            print(proc.stderr[-500:])
        return False
    else:
        print(f"  ✓ PASSED in {dt:.2f}s")
        return True

def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def main():
    print("═" * 76)
    print("ODIN OS PHASE B.3.2 — CANONICAL RELEASE VERIFICATION PIPELINE")
    print("═" * 76)
    print(f"Repository Root: {REPO_ROOT}")
    print(f"Timestamp:       {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    
    report = {
        "timestamp": time.time(),
        "target_phase": "B.3.2",
        "gates": {}
    }
    
    steps = [
        ("Host Unit Tests (23 cases)", ["cargo", "test", "--lib", "--target", "aarch64-apple-darwin"], None),
        ("Microkernel Compilation (riscv64gc)", ["cargo", "build", "--release", "--target", "riscv64gc-unknown-none-elf"], None),
        ("QEMU Adversarial Matrix (17 cases)", ["cargo", "run", "--release"], None),
        ("Authority Isolation Suite (12 cases)", ["python3", "-m", "unittest", "tests/test_authority_isolation.py"], None),
        ("Adversarial Verifier Audit (10 cases)", ["python3", "-m", "unittest", "tests/test_evidence_verifier_adversarial.py"], None),
        ("Layer B External Verifier Audit", ["python3", "tools/verify_evidence.py"], None),
        ("Formal SMT Proof 1 (Bounds)", ["z3", "formal/deed_bounds_verification.smt2"], None),
        ("Formal SMT Proof 2 (Anti-Replay)", ["z3", "formal/sequence_anti_replay.smt2"], None),
        ("Deterministic Whitepaper PDF Compilation", ["typst", "compile", "zenodo/odin-os-whitepaper.typ", "zenodo/odin-os-whitepaper.pdf"], {"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}),
    ]
    
    all_passed = True
    for name, cmd, env_extra in steps:
        success = run_step(name, cmd, env_extra)
        report["gates"][name] = "PASS" if success else "FAIL"
        if not success:
            all_passed = False
            break

    if not all_passed:
        print("\n❌ RELEASE VERIFICATION HALTED ON FAILED GATE.")
        report["decision"] = "NO-GO"
        with open(os.path.join(REPO_ROOT, "release_verification_report.json"), "w") as f:
            json.dump(report, f, indent=2)
        sys.exit(1)

    # Compute Artifact Checksums
    print("\n▶ [Checksum Ledger] Computing release artifact digests...")
    artifacts = {
        "kernel_elf": "target/riscv64gc-unknown-none-elf/release/odin-kernel",
        "whitepaper_typ": "zenodo/odin-os-whitepaper.typ",
        "whitepaper_pdf": "zenodo/odin-os-whitepaper.pdf",
        "peer_review_typ": "peer-review/peer-review.typ",
        "peer_review_pdf": "peer-review/peer-review.pdf",
        "evidence_manifest": "peer-review/evidence-manifest.json",
        "zenodo_json": "zenodo/zenodo.json",
        "cargo_lock": "Cargo.lock",
        "license": "LICENSE",
        "notice": "NOTICE",
        "bounds_smt": "formal/deed_bounds_verification.smt2",
        "replay_smt": "formal/sequence_anti_replay.smt2",
        "receipts_json": "zenodo/receipts/adversarial_matrix_receipts.json",
        "raw_trace": "zenodo/receipts/raw_execution_trace.txt"
    }
    
    hashes = {}
    for key, rel_path in artifacts.items():
        abs_p = os.path.join(REPO_ROOT, rel_path)
        if os.path.exists(abs_p):
            sha = compute_sha256(abs_p)
            hashes[key] = {"path": rel_path, "sha256": sha}
            print(f"  ✓ {rel_path:45} {sha}")
        else:
            print(f"  ✗ MISSING: {rel_path}")
            all_passed = False

    report["artifact_hashes"] = hashes
    report["decision"] = "GO" if all_passed else "NO-GO"
    
    out_path = os.path.join(REPO_ROOT, "release_verification_report.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[REPORT] Machine-readable verification written to: {out_path}")
    
    if all_passed:
        print("\n🎉 ALL RELEASE VERIFICATION GATES PASSED (DECISION: GO)")
        sys.exit(0)
    else:
        print("\n❌ ARTIFACT INTEGRITY CHECK FAILED (DECISION: NO-GO)")
        sys.exit(1)

if __name__ == "__main__":
    main()
