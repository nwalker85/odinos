#!/usr/bin/env python3
"""
Odin OS Phase B.3.2: Policy Decision Point (PDP) & Authority Signer Service

Implements two explicit authority modes:
- Mode A (Deterministic Research Fixture):
  Uses public, deliberately insecure test seed b"odin_root_authority_seed_v2_key!".
  Intended strictly for reproducible, deterministic test suites.
  NO CLAIM of private key secrecy or production resistance.
- Mode B (Independently Provisioned Authority):
  Loads a cryptographically secure random 32-byte Ed25519 seed from an external
  file (ODIN_AUTHORITY_SEED_PATH) or environment (ODIN_AUTHORITY_SEED_HEX).
  Never logged or serialized. Fails closed if missing or invalid.

Core Invariants:
1. Agent Request != Authority Grant.
2. The agent and transport bridge DO NOT possess private signing keys.
3. Default-Deny Authorization: Only pre-authorized agents and bounded ranges are signed.
4. Monotonic Sequence Allocation: State survives across evaluation turns.
5. Structured Authorization Denial: Failed requests produce zero usable signed capability.
"""

import sys
import os
import struct
import json
import hashlib
import time
import secrets
from typing import Dict, Any, Tuple, Optional

_DOMAIN_SEPARATOR = b"ODIN_DEED_V2\x00\x00\x00\x00"

# Mode A: Public Deterministic Research Fixture Seed (DELIBERATELY INSECURE)
FIXTURE_ROOT_SEED = b"odin_root_authority_seed_v2_key!"

# Declarative Policy Specification
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

class SecurityError(Exception):
    """Raised when cryptographic key material or authority boundaries are violated."""
    pass

class PolicyDecisionPoint:
    def __init__(
        self,
        mode: str = "fixture",
        seed: Optional[bytes] = None,
        sequence_state_file: Optional[str] = None
    ):
        """
        Initializes the Policy Decision Point.
        - mode="fixture": Uses public fixture seed for deterministic tests.
        - mode="provisioned": Requires valid seed or loads from ODIN_AUTHORITY_SEED_PATH / ODIN_AUTHORITY_SEED_HEX.
        """
        import nacl.signing

        self.mode = mode.lower()
        self.sequence_state_file = sequence_state_file
        
        if self.mode == "fixture":
            signing_seed = seed if seed is not None else FIXTURE_ROOT_SEED
        elif self.mode == "provisioned":
            if seed is not None:
                signing_seed = seed
            elif "ODIN_AUTHORITY_SEED_HEX" in os.environ:
                try:
                    signing_seed = bytes.fromhex(os.environ["ODIN_AUTHORITY_SEED_HEX"].strip())
                except Exception as e:
                    raise SecurityError(f"Mode B failure: Invalid hex in ODIN_AUTHORITY_SEED_HEX: {e}")
            elif "ODIN_AUTHORITY_SEED_PATH" in os.environ:
                path = os.environ["ODIN_AUTHORITY_SEED_PATH"]
                if not os.path.exists(path):
                    raise SecurityError(f"Mode B failure: Provisioned key file not found: {path}")
                try:
                    with open(path, "rb") as f:
                        signing_seed = f.read(32)
                except Exception as e:
                    raise SecurityError(f"Mode B failure: Unable to read provisioned key file: {e}")
            else:
                raise SecurityError(
                    "Mode B requires independent key provisioning via ODIN_AUTHORITY_SEED_PATH or ODIN_AUTHORITY_SEED_HEX."
                )
        else:
            raise ValueError(f"Unknown authority mode: {mode}")

        if len(signing_seed) != 32:
            raise SecurityError(f"Invalid seed length: expected 32 bytes, got {len(signing_seed)}")

        self._signing_key = nacl.signing.SigningKey(signing_seed)
        self.public_key_bytes = bytes(self._signing_key.verify_key.encode())
        self._current_sequence = self._load_sequence_state()
        self._audit_log = []

    def _load_sequence_state(self) -> int:
        if self.sequence_state_file and os.path.exists(self.sequence_state_file):
            try:
                with open(self.sequence_state_file, "r") as f:
                    data = json.load(f)
                    return int(data.get("last_sequence", 0))
            except Exception:
                return 0
        return 0

    def _persist_sequence_state(self, seq: int):
        if self.sequence_state_file:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(self.sequence_state_file)), exist_ok=True)
                with open(self.sequence_state_file, "w") as f:
                    json.dump({"last_sequence": seq, "timestamp": time.time()}, f)
            except Exception:
                pass

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
        Independent Policy Decision Point evaluation.
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

        # Allocate strictly monotonic sequence
        self._current_sequence += 1
        seq = self._current_sequence
        self._persist_sequence_state(seq)

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
            "authority_mode": self.mode,
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
            "authority_mode": self.mode,
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

# Singleton Authority Instance for local service IPC (Defaulting to Mode A Fixture)
_authority_instance = None

def get_authority_service(mode: str = "fixture") -> PolicyDecisionPoint:
    global _authority_instance
    if _authority_instance is None or _authority_instance.mode != mode:
        _authority_instance = PolicyDecisionPoint(mode=mode)
    return _authority_instance
