#!/usr/bin/env python3
"""
Odin OS Phase B.3.2: Authority Isolation & Mandatory Attacks Test Suite
Directly tests the Policy Decision Point (PDP) and Authority Signer against all required attack vectors
across both Mode A (Research Fixture) and Mode B (Independently Provisioned Authority).

Mandatory Attack & Verification Vectors:
1. Unauthorized target mutation (anchor outside allowed set).
2. Unauthorized operation (opcode outside allowed set).
3. Oversized mutation length (> max_mutation_length).
4. Excessive lease duration (> max_lease_cycles).
5. Unknown agent identity (default-deny enforcement).
6. Out-of-bounds offset range (exceeding permitted lease window).
7. Zero-length mutation request.
8. Tampering with approval result / signature verification.
9. Monotonic sequence allocation and state tracking across restarts.
10. Valid request produces canonically verifiable deed with matching public key.
11. Mode B Provisioned: Generates random CSPRNG key; fixture key CANNOT authenticate against Mode B root.
12. Mode B Fail-Closed: Missing or invalid key material raises SecurityError and halts.
"""

import sys
import os
import unittest
import struct
import hashlib
import tempfile
import secrets

# Ensure tools directory is in sys.path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
from pdp_authority_service import PolicyDecisionPoint, SecurityError, _DOMAIN_SEPARATOR, FIXTURE_ROOT_SEED

class TestAuthorityIsolation(unittest.TestCase):
    def setUp(self):
        # Create fresh temporary directory for sequence state persistence
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(self.temp_dir.name, "sequence_state.json")
        # Fresh Mode A PDP instance
        self.pdp_fixture = PolicyDecisionPoint(mode="fixture", sequence_state_file=self.state_file)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_unauthorized_target_anchor(self):
        """Attack 1: Agent requests mutation on unauthorized AST anchor."""
        approved, deed, receipt = self.pdp_fixture.evaluate_and_sign(
            agent_identity="agent:gemma-4",
            anchor_id=999, # Allowed is only [104]
            target_offset=0x40,
            target_length=0x10,
            operation=1
        )
        self.assertFalse(approved)
        self.assertIsNone(deed)
        self.assertEqual(receipt["decision"], "DENIED")
        self.assertEqual(receipt["denial_reason"], "UNAUTHORIZED_TARGET_ANCHOR")

    def test_02_unauthorized_operation(self):
        """Attack 2: Agent requests unauthorized operation opcode."""
        approved, deed, receipt = self.pdp_fixture.evaluate_and_sign(
            agent_identity="agent:gemma-4",
            anchor_id=104,
            target_offset=0x40,
            target_length=0x10,
            operation=0x99 # Allowed is only [1]
        )
        self.assertFalse(approved)
        self.assertIsNone(deed)
        self.assertEqual(receipt["decision"], "DENIED")
        self.assertEqual(receipt["denial_reason"], "UNAUTHORIZED_OPERATION")

    def test_03_oversized_mutation_length(self):
        """Attack 3: Agent requests mutation length exceeding policy maximum."""
        approved, deed, receipt = self.pdp_fixture.evaluate_and_sign(
            agent_identity="agent:gemma-4",
            anchor_id=104,
            target_offset=0x40,
            target_length=64, # Policy max is 32 bytes
            operation=1
        )
        self.assertFalse(approved)
        self.assertIsNone(deed)
        self.assertEqual(receipt["decision"], "DENIED")
        self.assertEqual(receipt["denial_reason"], "OVERSIZED_MUTATION_LENGTH")

    def test_04_excessive_lease_duration(self):
        """Attack 4: Agent requests lease cycles exceeding maximum allowed."""
        approved, deed, receipt = self.pdp_fixture.evaluate_and_sign(
            agent_identity="agent:gemma-4",
            anchor_id=104,
            target_offset=0x40,
            target_length=0x10,
            operation=1,
            lease_cycles=5000000 # Policy max is 1,000,000 cycles
        )
        self.assertFalse(approved)
        self.assertIsNone(deed)
        self.assertEqual(receipt["decision"], "DENIED")
        self.assertEqual(receipt["denial_reason"], "EXCESSIVE_LEASE_DURATION")

    def test_05_unknown_agent_identity(self):
        """Attack 5: Unregistered/rogue agent attempts to obtain authority grant."""
        approved, deed, receipt = self.pdp_fixture.evaluate_and_sign(
            agent_identity="agent:rogue-ai-infiltrator",
            anchor_id=104,
            target_offset=0x40,
            target_length=0x10,
            operation=1
        )
        self.assertFalse(approved)
        self.assertIsNone(deed)
        self.assertEqual(receipt["decision"], "DENIED")
        self.assertEqual(receipt["denial_reason"], "UNKNOWN_AGENT_IDENTITY")

    def test_06_out_of_bounds_offset_range(self):
        """Attack 6: Agent requests offset outside permitted lease window."""
        # 1. Below min offset (0x30 < 0x40)
        app1, d1, r1 = self.pdp_fixture.evaluate_and_sign(
            agent_identity="agent:gemma-4",
            anchor_id=104,
            target_offset=0x30,
            target_length=0x10,
            operation=1
        )
        self.assertFalse(app1)
        self.assertIsNone(d1)
        self.assertEqual(r1["denial_reason"], "OUT_OF_BOUNDS_LEASE_RANGE")

        # 2. Exceeding max offset (0x50 + 0x20 = 0x70 > 0x60)
        app2, d2, r2 = self.pdp_fixture.evaluate_and_sign(
            agent_identity="agent:gemma-4",
            anchor_id=104,
            target_offset=0x50,
            target_length=0x20,
            operation=1
        )
        self.assertFalse(app2)
        self.assertIsNone(d2)
        self.assertEqual(r2["denial_reason"], "OUT_OF_BOUNDS_LEASE_RANGE")

    def test_07_zero_length_mutation(self):
        """Attack 7: Agent requests degenerate zero-length mutation."""
        approved, deed, receipt = self.pdp_fixture.evaluate_and_sign(
            agent_identity="agent:gemma-4",
            anchor_id=104,
            target_offset=0x40,
            target_length=0,
            operation=1
        )
        self.assertFalse(approved)
        self.assertIsNone(deed)
        self.assertEqual(receipt["decision"], "DENIED")
        self.assertEqual(receipt["denial_reason"], "ZERO_LENGTH_MUTATION")

    def test_08_signature_cryptographic_verification(self):
        """Attack 8: Verification of deed signature and resistance to post-sign tampering."""
        import nacl.signing
        
        approved, deed, receipt = self.pdp_fixture.evaluate_and_sign(
            agent_identity="agent:gemma-4",
            anchor_id=104,
            target_offset=0x40,
            target_length=0x20,
            operation=1
        )
        self.assertTrue(approved)
        self.assertIsNotNone(deed)
        self.assertEqual(len(deed), 256)

        # Verify genuine signature
        vk = nacl.signing.VerifyKey(self.pdp_fixture.public_key_bytes)
        canonical_msg = _DOMAIN_SEPARATOR + deed[:156]
        sig = deed[156:220]
        
        # Genuine signature must verify
        vk.verify(canonical_msg, sig)

        # Attacker tampers with target_offset field (bytes 116..120)
        tampered_deed = bytearray(deed)
        tampered_deed[116] ^= 0xFF
        tampered_canonical = _DOMAIN_SEPARATOR + bytes(tampered_deed[:156])
        
        with self.assertRaises(Exception):
            vk.verify(tampered_canonical, sig)

    def test_09_monotonic_sequence_and_restart_persistence(self):
        """Attack 9: Monotonic sequence increment and persistence across PDP restarts."""
        app1, deed1, r1 = self.pdp_fixture.evaluate_and_sign(
            agent_identity="agent:gemma-4",
            anchor_id=104,
            target_offset=0x40,
            target_length=0x10
        )
        self.assertEqual(r1["allocated_sequence"], 1)

        # Simulate service restart: fresh PDP reading from sequence_state_file
        pdp_restarted = PolicyDecisionPoint(mode="fixture", sequence_state_file=self.state_file)
        app2, deed2, r2 = pdp_restarted.evaluate_and_sign(
            agent_identity="agent:gemma-4",
            anchor_id=104,
            target_offset=0x50,
            target_length=0x10
        )
        self.assertTrue(app2)
        # Sequence must NOT reset to 1; must monotonically continue to 2
        self.assertEqual(r2["allocated_sequence"], 2)

    def test_10_receipt_integrity(self):
        """Attack 10: Ensure audit receipt hash accurately binds the issued deed."""
        approved, deed, receipt = self.pdp_fixture.evaluate_and_sign(
            agent_identity="agent:gemma-4",
            anchor_id=104,
            target_offset=0x40,
            target_length=0x20
        )
        self.assertTrue(approved)
        expected_hash = hashlib.sha256(deed).hexdigest()
        self.assertEqual(receipt["deed_sha256"], expected_hash)

    def test_11_mode_b_provisioned_key_separation(self):
        """Attack 11: Mode B Provisioned key separation and mismatch detection."""
        import nacl.signing
        
        # Generate independent random 32-byte seed outside repository
        independent_seed = secrets.token_bytes(32)
        pdp_mode_b = PolicyDecisionPoint(mode="provisioned", seed=independent_seed)

        # Verify public key is distinct from Mode A fixture
        self.assertNotEqual(pdp_mode_b.public_key_bytes, self.pdp_fixture.public_key_bytes)

        # Sign deed with Mode B
        app_b, deed_b, r_b = pdp_mode_b.evaluate_and_sign(
            agent_identity="agent:gemma-4",
            anchor_id=104,
            target_offset=0x40,
            target_length=0x10
        )
        self.assertTrue(app_b)

        # Verification of Mode B deed against Mode A fixture public key MUST FAIL
        vk_fixture = nacl.signing.VerifyKey(self.pdp_fixture.public_key_bytes)
        canonical_b = _DOMAIN_SEPARATOR + deed_b[:156]
        sig_b = deed_b[156:220]
        with self.assertRaises(Exception):
            vk_fixture.verify(canonical_b, sig_b)

    def test_12_mode_b_fail_closed_on_missing_or_invalid_key(self):
        """Attack 12: Mode B fails closed when seed is missing or invalid."""
        # 1. Missing seed in Mode B raises SecurityError
        old_hex = os.environ.pop("ODIN_AUTHORITY_SEED_HEX", None)
        old_path = os.environ.pop("ODIN_AUTHORITY_SEED_PATH", None)
        try:
            with self.assertRaises(SecurityError):
                PolicyDecisionPoint(mode="provisioned")
        finally:
            if old_hex: os.environ["ODIN_AUTHORITY_SEED_HEX"] = old_hex
            if old_path: os.environ["ODIN_AUTHORITY_SEED_PATH"] = old_path

        # 2. Corrupt seed length raises SecurityError
        with self.assertRaises(SecurityError):
            PolicyDecisionPoint(mode="provisioned", seed=b"short_corrupt_seed")

if __name__ == "__main__":
    unittest.main()
