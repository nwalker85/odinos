#!/usr/bin/env python3
"""
Odin OS Phase B.3.1: Authority Isolation & Mandatory Attacks Test Suite
Directly tests the Policy Decision Point (PDP) and Authority Signer against all 10 required attack vectors.

Mandatory Attack Vectors:
1. Unauthorized target mutation (anchor outside allowed set).
2. Unauthorized operation (opcode outside allowed set).
3. Oversized mutation length (> max_mutation_length).
4. Excessive lease duration (> max_lease_cycles).
5. Unknown agent identity (default-deny enforcement).
6. Out-of-bounds offset range (exceeding permitted lease window).
7. Zero-length mutation request.
8. Tampering with approval result / signature verification.
9. Monotonic sequence allocation and state tracking.
10. Valid request produces canonically verifiable deed with matching public key.
"""

import sys
import os
import unittest
import struct
import hashlib

# Ensure tools directory is in sys.path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
from pdp_authority_service import PolicyDecisionPoint, _DOMAIN_SEPARATOR

class TestAuthorityIsolation(unittest.TestCase):
    def setUp(self):
        # Create fresh PDP instance for each test
        self.pdp = PolicyDecisionPoint()

    def test_01_unauthorized_target_anchor(self):
        """Attack 1: Agent requests mutation on unauthorized AST anchor."""
        approved, deed, receipt = self.pdp.evaluate_and_sign(
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
        approved, deed, receipt = self.pdp.evaluate_and_sign(
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
        approved, deed, receipt = self.pdp.evaluate_and_sign(
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
        approved, deed, receipt = self.pdp.evaluate_and_sign(
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
        approved, deed, receipt = self.pdp.evaluate_and_sign(
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
        app1, d1, r1 = self.pdp.evaluate_and_sign(
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
        app2, d2, r2 = self.pdp.evaluate_and_sign(
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
        approved, deed, receipt = self.pdp.evaluate_and_sign(
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
        
        approved, deed, receipt = self.pdp.evaluate_and_sign(
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
        vk = nacl.signing.VerifyKey(self.pdp.public_key_bytes)
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

    def test_09_monotonic_sequence_allocation(self):
        """Attack 9: Verification of strict monotonic sequence counter increment."""
        app1, deed1, r1 = self.pdp.evaluate_and_sign(
            agent_identity="agent:gemma-4",
            anchor_id=104,
            target_offset=0x40,
            target_length=0x10
        )
        app2, deed2, r2 = self.pdp.evaluate_and_sign(
            agent_identity="agent:gemma-4",
            anchor_id=104,
            target_offset=0x50,
            target_length=0x10
        )
        self.assertTrue(app1 and app2)
        self.assertEqual(r1["allocated_sequence"], 1)
        self.assertEqual(r2["allocated_sequence"], 2)

        # Sequence field in deed must match allocated sequence
        seq1 = struct.unpack_from("<I", deed1, 4)[0]
        seq2 = struct.unpack_from("<I", deed2, 4)[0]
        self.assertEqual(seq1, 1)
        self.assertEqual(seq2, 2)

    def test_10_receipt_integrity(self):
        """Attack 10: Ensure audit receipt hash accurately binds the issued deed."""
        approved, deed, receipt = self.pdp.evaluate_and_sign(
            agent_identity="agent:gemma-4",
            anchor_id=104,
            target_offset=0x40,
            target_length=0x20
        )
        self.assertTrue(approved)
        expected_hash = hashlib.sha256(deed).hexdigest()
        self.assertEqual(receipt["deed_sha256"], expected_hash)

if __name__ == "__main__":
    unittest.main()
