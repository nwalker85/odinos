#!/usr/bin/env python3
"""
Odin OS Phase B.3.2: Adversarial Testing Suite for Layer B Evidence Verifier (tools/verify_evidence.py)
Directly attempts to defeat the external verifier with corrupted, forged, reordered,
and synthetic execution traces.

Verifies the boundary between:
- Level A (Self-reported status string in JSON)
- Level B (Externally recomputed invariant verification from raw measurements)
- Level C (Clean-room reproduced execution from source)
"""

import sys
import os
import unittest
import tempfile
import json
import re

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
from verify_evidence import verify_raw_trace, EXPECTED_TEST_COUNT

class TestEvidenceVerifierAdversarial(unittest.TestCase):
    def setUp(self):
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.valid_trace_path = os.path.join(self.repo_root, "zenodo/receipts/raw_execution_trace.txt")
        self.valid_receipts_path = os.path.join(self.repo_root, "zenodo/receipts/adversarial_matrix_receipts.json")
        with open(self.valid_trace_path, "r", encoding="utf-8") as f:
            self.valid_trace_content = f.read()

    def _write_temp_trace(self, content: str) -> str:
        tmp = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt")
        tmp.write(content)
        tmp.close()
        return tmp.name

    def test_01_baseline_valid_trace_passes(self):
        """Valid baseline trace must pass verification."""
        res = verify_raw_trace(self.valid_trace_path, self.valid_receipts_path)
        self.assertEqual(res["status"], "VERIFIED_PASS")
        self.assertEqual(res["verified_tests"], EXPECTED_TEST_COUNT)

    def test_02_tampered_forged_pass_on_failing_measurement(self):
        """Attack: Kernel claims PASS on a test where hardware_fault != expected_fault."""
        # Mutate Test 3 (One byte below lease): expected_fault is true, change hardware_fault to false but keep PASS
        tampered = self.valid_trace_content.replace(
            '"test_id": 3,\n  "test_name": "ONE_BYTE_BELOW_LEASE",\n  "target_address": "0x000000008002003f",\n  "access_width": 1,\n  "expected_fault": true,\n  "hardware_fault": true,',
            '"test_id": 3,\n  "test_name": "ONE_BYTE_BELOW_LEASE",\n  "target_address": "0x000000008002003f",\n  "access_width": 1,\n  "expected_fault": true,\n  "hardware_fault": false,'
        )
        tpath = self._write_temp_trace(tampered)
        try:
            with self.assertRaises(ValueError) as ctx:
                verify_raw_trace(tpath)
            self.assertIn("FORGED PASS DETECTED in Test #3", str(ctx.exception))
        finally:
            os.remove(tpath)

    def test_03_tampered_readback_value_mismatch(self):
        """Attack: Readback value does not match expected value, but labeled PASS."""
        # Mutate Test 1 (Exact lower bound): expected 0x41, change readback to 0x00
        tampered = self.valid_trace_content.replace(
            '"test_id": 1,\n  "test_name": "EXACT_LOWER_BOUND",\n  "target_address": "0x0000000080020040",\n  "access_width": 1,\n  "expected_fault": false,\n  "hardware_fault": false,\n  "mcause": "0x0000000000000000",\n  "probed_address": "0x0000000080020040",\n  "readback_value": "0x0000000000000041"',
            '"test_id": 1,\n  "test_name": "EXACT_LOWER_BOUND",\n  "target_address": "0x0000000080020040",\n  "access_width": 1,\n  "expected_fault": false,\n  "hardware_fault": false,\n  "mcause": "0x0000000000000000",\n  "probed_address": "0x0000000080020040",\n  "readback_value": "0x0000000000000000"'
        )
        tpath = self._write_temp_trace(tampered)
        try:
            with self.assertRaises(ValueError) as ctx:
                verify_raw_trace(tpath)
            self.assertIn("FORGED PASS DETECTED in Test #1", str(ctx.exception))
        finally:
            os.remove(tpath)

    def test_04_sequence_gap_detection(self):
        """Attack: Attacker omits Test 5 or jumps from Test 4 to Test 6."""
        # Change test_id 5 to 6
        tampered = self.valid_trace_content.replace('"test_id": 5,', '"test_id": 6,', 1)
        tpath = self._write_temp_trace(tampered)
        try:
            with self.assertRaises(ValueError) as ctx:
                verify_raw_trace(tpath)
            self.assertIn("Sequence gap or out-of-order receipt", str(ctx.exception))
        finally:
            os.remove(tpath)

    def test_05_duplicate_receipt_detection(self):
        """Attack: Duplicate receipt inserted into trace."""
        # Duplicate Test 1 receipt
        match = re.search(r"\{\s*\"test_id\": 1,.*?\n\}", self.valid_trace_content, re.DOTALL)
        self.assertIsNotNone(match)
        receipt_1 = match.group(0)
        tampered = self.valid_trace_content.replace(receipt_1, receipt_1 + ",\n" + receipt_1, 1)
        tpath = self._write_temp_trace(tampered)
        try:
            with self.assertRaises(ValueError) as ctx:
                verify_raw_trace(tpath)
            # Either duplicate detected or sequence mismatch
            self.assertTrue("Duplicate test receipt" in str(ctx.exception) or "Sequence gap" in str(ctx.exception))
        finally:
            os.remove(tpath)

    def test_06_missing_required_schema_field(self):
        """Attack: Receipt is missing a required schema field (e.g. mcause)."""
        tampered = self.valid_trace_content.replace('"mcause": "0x0000000000000000",\n', '', 1)
        tpath = self._write_temp_trace(tampered)
        try:
            with self.assertRaises(ValueError) as ctx:
                verify_raw_trace(tpath)
            self.assertIn("missing field: mcause", str(ctx.exception))
        finally:
            os.remove(tpath)

    def test_07_truncated_trace_detection(self):
        """Attack: Trace is cut short (e.g. only 10 receipts instead of 17)."""
        # Find Test 11 and truncate before it
        pos = self.valid_trace_content.find('"test_id": 11,')
        self.assertGreater(pos, 0)
        truncated = self.valid_trace_content[:pos].rsplit("},", 1)[0] + "}\n"
        truncated += "══════════════════════════════════════════════════════════════════════════\n"
        truncated += "🎉 ALL 17 ADVERSARIAL INVARIANT TESTS PASSED WITH 100% HARDWARE ENFORCEMENT\n"
        tpath = self._write_temp_trace(truncated)
        try:
            with self.assertRaises(ValueError) as ctx:
                verify_raw_trace(tpath)
            self.assertIn("Expected 17 receipts, found only", str(ctx.exception))
        finally:
            os.remove(tpath)

    def test_08_missing_kernel_initialization_banner(self):
        """Attack: Stream is missing the Odin OS boot initialization banner."""
        tampered = self.valid_trace_content.replace("ODIN OS:", "CORRUPTED_KERNEL:")
        tpath = self._write_temp_trace(tampered)
        try:
            with self.assertRaises(ValueError) as ctx:
                verify_raw_trace(tpath)
            self.assertIn("Odin OS initialization banner missing", str(ctx.exception))
        finally:
            os.remove(tpath)

    def test_09_missing_final_pass_banner(self):
        """Attack: Microkernel crashed before completing or final pass banner was omitted."""
        tampered = self.valid_trace_content.replace(
            "ALL 17 ADVERSARIAL INVARIANT TESTS PASSED WITH 100% HARDWARE ENFORCEMENT",
            "TESTS INCOMPLETE / CRASHED"
        )
        tpath = self._write_temp_trace(tampered)
        try:
            with self.assertRaises(ValueError) as ctx:
                verify_raw_trace(tpath)
            self.assertIn("Microkernel final pass banner missing", str(ctx.exception))
        finally:
            os.remove(tpath)

    def test_10_entire_synthetic_garbage_stream(self):
        """Attack: Completely fabricated synthetic stream with random data."""
        tpath = self._write_temp_trace("Random unformatted text and garbage bytes 0xDEADBEEF\n")
        try:
            with self.assertRaises(ValueError):
                verify_raw_trace(tpath)
        finally:
            os.remove(tpath)

if __name__ == "__main__":
    unittest.main()
