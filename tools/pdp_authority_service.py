#!/usr/bin/env python3
"""
Odin OS Phase B.3.1: Independent Policy Decision Point (PDP) & Authority Signer Service
Enforces strict separation between untrusted Agent Request and privileged Authority Grant.

Core Security Principles:
1. Agent Request != Authority Grant.
2. The agent and transport bridge DO NOT possess private signing keys.
3. Default-Deny Authorization: Only pre-authorized agents and bounded ranges are signed.
4. Monotonic Sequence Allocation: State survives inside the authority boundary.
5. Structured Authorization Denial: Failed requests produce zero usable signed capability.
"""

import sys
import os
import struct
import json
import hashlib
import time
from typing import Dict, Any, Tuple, Optional

# Isolated Root Authority Seed (Confined exclusively to this authority process)
_ROOT_SEED = b"odin_root_authority_seed_v2_key!"
_DOMAIN_SEPARATOR = b"ODIN_DEED_V2\x00\x00\x00\x00"

# Explicit Policy Specification
POLICY_REGISTRY = {
    "agent:gemma-4": {
        "description": "Local Gemma 4 Autonomous Agent Lease Policy",
        "allowed_anchors": [104],
        "allowed_offset_min": 0x40,
        "allowed_offset_max": 0x60,
        "max_mutation_length": 32,
        "max_lease_cycles": 1000000,
        "allowed_operations": [1] # OP_SPLICE
    },
    "agent:system-evaluator": {
        "description": "Baseline Test Suite Capability Policy",
        "allowed_anchors": [104, 105],
        "allowed_offset_min": 0x00,
        "allowed_offset_max": 0x10000,
        "max_mutation_length": 65536,
        "max_lease_cycles": 10000000,
        "allowed_operations": [1, 2, 3]
    }
}

class PolicyDecisionPoint:
    def __init__(self, seed: bytes = _ROOT_SEED):
        import nacl.signing
        self._signing_key = nacl.signing.SigningKey(seed)
        self.public_key_bytes = bytes(self._signing_key.verify_key.encode())
        self._current_sequence = 0
        self._audit_log = []

    def evaluate_and_sign(
        self,
        agent_identity: str,
        anchor_id: int,
        target_offset: int,
        target_length: int,
        operation: int = 1,
        lease_cycles: int = 1000000
    ) -> Tuple[bool, Optional[bytes], Dict[str, Any]]:
        """
        Independent Policy Decision Point (PDP) evaluation.
        Evaluates request against declarative policy before invoking cryptographic signing.
        """
        request_ts = time.time()
        
        # 1. Identity Check (Default Deny)
        if agent_identity not in POLICY_REGISTRY:
            receipt = self._emit_denial(agent_identity, "UNKNOWN_AGENT_IDENTITY", anchor_id, target_offset, target_length, request_ts)
            return False, None, receipt

        policy = POLICY_REGISTRY[agent_identity]

        # 2. Target Anchor Check
        if anchor_id not in policy["allowed_anchors"]:
            receipt = self._emit_denial(agent_identity, "UNAUTHORIZED_TARGET_ANCHOR", anchor_id, target_offset, target_length, request_ts)
            return False, None, receipt

        # 3. Target Range Bounds Check
        if target_length == 0:
            receipt = self._emit_denial(agent_identity, "ZERO_LENGTH_MUTATION", anchor_id, target_offset, target_length, request_ts)
            return False, None, receipt

        if target_length > policy["max_mutation_length"]:
            receipt = self._emit_denial(agent_identity, "OVERSIZED_MUTATION_LENGTH", anchor_id, target_offset, target_length, request_ts)
            return False, None, receipt

        if target_offset < policy["allowed_offset_min"] or (target_offset + target_length) > policy["allowed_offset_max"]:
            receipt = self._emit_denial(agent_identity, "OUT_OF_BOUNDS_LEASE_RANGE", anchor_id, target_offset, target_length, request_ts)
            return False, None, receipt

        # 4. Operation Permission Check
        if operation not in policy["allowed_operations"]:
            receipt = self._emit_denial(agent_identity, "UNAUTHORIZED_OPERATION", anchor_id, target_offset, target_length, request_ts)
            return False, None, receipt

        # 5. Lease Duration Check
        if lease_cycles > policy["max_lease_cycles"]:
            receipt = self._emit_denial(agent_identity, "EXCESSIVE_LEASE_DURATION", anchor_id, target_offset, target_length, request_ts)
            return False, None, receipt

        # Policy checks passed: Allocate monotonic sequence and construct canonical deed
        self._current_sequence += 1
        seq = self._current_sequence

        deed_bytes = self._construct_and_sign_canonical_deed(
            sequence=seq,
            anchor_id=anchor_id,
            offset=target_offset,
            length=target_length,
            operation=operation,
            lease_cycles=lease_cycles
        )

        receipt = {
            "decision": "APPROVED",
            "agent_identity": agent_identity,
            "anchor_id": anchor_id,
            "target_offset": target_offset,
            "target_length": target_length,
            "allocated_sequence": seq,
            "timestamp": request_ts,
            "deed_sha256": hashlib.sha256(deed_bytes).hexdigest()
        }
        self._audit_log.append(receipt)
        return True, deed_bytes, receipt

    def _emit_denial(self, agent_id: str, reason: str, anchor: int, offset: int, length: int, ts: float) -> Dict[str, Any]:
        denial = {
            "decision": "DENIED",
            "agent_identity": agent_id,
            "denial_reason": reason,
            "requested_anchor": anchor,
            "requested_offset": offset,
            "requested_length": length,
            "timestamp": ts
        }
        self._audit_log.append(denial)
        return denial

    def _construct_and_sign_canonical_deed(
        self,
        sequence: int,
        anchor_id: int,
        offset: int,
        length: int,
        operation: int,
        lease_cycles: int
    ) -> bytes:
        """
        Constructs and signs a 256-byte cache-line aligned TransitionDeed.
        """
        buf = bytearray(256)
        
        # 0x00..0x08: magic (2), version (1), flags (1), sequence (4)
        buf[0:2] = b"YG"
        buf[2] = 0x02 # Version 2
        buf[3] = (1 << 1) | (1 << 3) # FLAG_IS_MUTATION | FLAG_AST_STRICT
        struct.pack_into("<I", buf, 4, sequence)

        # 0x08..0x18: issuer_did (16 bytes)
        buf[8:24] = b"did:odin:root:01".ljust(16, b"\x00")
        
        # 0x18..0x28: target_entity_urn (16 bytes)
        buf[24:40] = b"urn:ast:kernel\x00\x00"[:16]

        # 0x28..0x48: prev_deed_hash (32 bytes)
        buf[40:72] = b"\xAA" * 32

        # 0x48..0x68: base_digest (32 bytes)
        buf[72:104] = b"\xBB" * 32

        # 0x68..0x70: lease_cycles (4), operation (1), esc_level (1), reserved (2)
        struct.pack_into("<IBBH", buf, 104, lease_cycles, operation, 0, 0)

        # 0x70..0x7C: target_ast_anchor_id (4), target_offset (4), target_length (4)
        struct.pack_into("<III", buf, 112, anchor_id, offset, length)

        # 0x7C..0x9C: new_state_digest (32 bytes)
        buf[124:156] = b"\xCC" * 32

        # Canonical Domain-Separated Message: 172 bytes
        canonical_msg = _DOMAIN_SEPARATOR + bytes(buf[:156])
        signed = self._signing_key.sign(canonical_msg)
        sig_bytes = signed.signature # 64 bytes

        # 0x9C..0xDC: signature (64 bytes)
        buf[156:220] = sig_bytes

        # 0xDC..0x100: padding (36 bytes) -> automatically zeroes
        return bytes(buf)

# Singleton Authority Instance for local service IPC
_authority_instance = None

def get_authority_service() -> PolicyDecisionPoint:
    global _authority_instance
    if _authority_instance is None:
        _authority_instance = PolicyDecisionPoint()
    return _authority_instance
