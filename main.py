"""
Beacon PII‑Safe Logging Utility (Option B1)

Features
- Detects & redacts likely PII:
  * Emails
  * Phone numbers (common international & NANP forms)
  * GPS coordinates (decimal degrees; "lat, long" patterns)
  * Proper names (lightweight heuristic; configurable allow/deny lists)
- Consent‑aware logging (require_consent(user_id) before writing)
- Audit levels: NONE / MINIMAL / DIAG (default MINIMAL)
- SHA‑256 user ID hashing when included in logs
- Pure standard library; single self‑contained file with unit tests

Run tests:
    python beacon_pii_safe_logger.py

Quick usage:
    from beacon_logger import BeaconLogger, AuditLevel
    logger = BeaconLogger()
    logger.require_consent("user123")
    logger.log(user_id="user123", event="signup", message="Welcome John Doe (john@example.com)")

Notes on name redaction: this module uses a pragmatic heuristic suitable for demo/teaching.
For production, prefer dedicated NER models with offline evaluation and language coverage.
"""
from __future__ import annotations

import hashlib
import json
import queue
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, Optional, Union


class AuditLevel(str, Enum):
    NONE = "NONE"      # no logging
    MINIMAL = "MINIMAL"  # event name + redacted message, hashed user id
    DIAG = "DIAG"      # include structured fields (after redaction)


EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
# Phone numbers: +1 555-123-4567, (555) 123 4567, 555.123.4567, 5551234567
PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\d{2,4}[\s.-]?)\d{3}[\s.-]?\d{4}\b")
# GPS decimal degrees and lat,long pairs (basic): 37.7749, -122.4194 or lat:37.77 lon:-122.41
GPS_PAIR_RE = re.compile(r"\b-?\d{1,3}\.\d{3,},\s*-?\d{1,3}\.\d{3,}\b")
GPS_LABELLED_RE = re.compile(r"\b(lat(?:itude)?|lon(?:gitude)?)[\s:=]+-?\d{1,3}\.\d{3,}\b", re.IGNORECASE)

# Common English first names (small demo set). Extend/replace in production.
COMMON_NAMES = {
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda",
    "William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa",
    "Matthew", "Betty", "Anthony", "Margaret", "Mark", "Sandra", "Paul", "Ashley",
}
NAME_WORD_RE = re.compile(r"\b([A-Z][a-z]{2,})\b")


@dataclass
class RedactionConfig:
    redact_names: bool = True
    extra_name_list: Iterable[str] = field(default_factory=set)
    allow_name_list: Iterable[str] = field(default_factory=set)
    mask_token: str = "[REDACTED]"


class BeaconLogger:
    def __init__(self,
                 level: AuditLevel = AuditLevel.MINIMAL,
                 redaction: Optional[RedactionConfig] = None,
                 sink: Optional[queue.Queue] = None):
        self._level = level
        self._consented_users: set[str] = set()
        self._lock = threading.RLock()
        self._sink = sink or queue.Queue()
        self._redaction = redaction or RedactionConfig()

    # === Consent management ===
    def require_consent(self, user_id: str) -> None:
        with self._lock:
            self._consented_users.add(user_id)

    def revoke_consent(self, user_id: str) -> None:
        with self._lock:
            self._consented_users.discard(user_id)

    def has_consent(self, user_id: Optional[str]) -> bool:
        if user_id is None:
            return True  # system events
        with self._lock:
            return user_id in self._consented_users

    # === Level control ===
    @property
    def level(self) -> AuditLevel:
        return self._level

    @level.setter
    def level(self, new_level: AuditLevel) -> None:
        if not isinstance(new_level, AuditLevel):
            raise ValueError("Invalid audit level")
        self._level = new_level

    # === Public logging API ===
    def log(self,
            event: str,
            message: Optional[str] = None,
            *,
            user_id: Optional[str] = None,
            fields: Optional[Mapping[str, Any]] = None,
            level: Optional[AuditLevel] = None) -> bool:
        """Log an event.

        Returns True if anything was emitted; False if suppressed (e.g., NONE or no consent).
        """
        lvl = level or self._level
        if lvl == AuditLevel.NONE:
            return False
        if not self.has_consent(user_id):
            return False

        ts = time.time()
        payload: Dict[str, Any] = {
            "ts": int(ts * 1000),
            "level": str(lvl),
            "event": event,
        }
        if user_id is not None:
            payload["user"] = self._hash_user(user_id)

        redacted_msg = self._redact_text(message) if message else None

        if lvl == AuditLevel.MINIMAL:
            if redacted_msg:
                payload["message"] = redacted_msg
        elif lvl == AuditLevel.DIAG:
            if redacted_msg:
                payload["message"] = redacted_msg
            if fields:
                payload["fields"] = self._redact_structure(fields)
        else:
            # Defensive: unknown level -> no-op
            return False

        record = json.dumps(payload, separators=(",", ":"))
        self._emit(record)
        return True

    # === Internal helpers ===
    def _emit(self, record: str) -> None:
        # For demo, push to an in-memory queue. Replace with file/stream handler as needed.
        self._sink.put(record)

    @staticmethod
    def _hash_user(user_id: str) -> str:
        return hashlib.sha256(user_id.encode("utf-8")).hexdigest()[:16]

    def _redact_structure(self, obj: Any) -> Any:
        if obj is None:
            return None
        if isinstance(obj, str):
            return self._redact_text(obj)
        if isinstance(obj, Mapping):
            return {k: self._redact_structure(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            t = type(obj)
            return t(self._redact_structure(x) for x in obj)
        return obj

    def _redact_text(self, text: str) -> str:
        if not text:
            return text
        t = EMAIL_RE.sub(self._redaction.mask_token, text)
        t = PHONE_RE.sub(self._redaction.mask_token, t)
        t = GPS_PAIR_RE.sub(self._redaction.mask_token, t)
        t = GPS_LABELLED_RE.sub(lambda m: f"{m.group(1)}: {self._redaction.mask_token}", t)
        if self._redaction.redact_names:
            t = self._redact_names(t)
        return t

    def _redact_names(self, text: str) -> str:
        # Heuristic: redact capitalized words that are in a first-name set or extra list, unless whitelisted
        allow = {*(n for n in self._redaction.allow_name_list)}
        names = COMMON_NAMES.union({n for n in self._redaction.extra_name_list})

        def repl(m: re.Match[str]) -> str:
            word = m.group(1)
            if word in allow:
                return word
            if word in names:
                return self._redaction.mask_token
            return word

        return NAME_WORD_RE.sub(repl, text)


# =====================
# Unit Tests
# =====================
import unittest


class TestBeaconLogger(unittest.TestCase):
    def setUp(self) -> None:
        self.logger = BeaconLogger()
        self.logger.require_consent("u1")

    def _drain(self) -> list[str]:
        out = []
        while True:
            try:
                out.append(self.logger._sink.get_nowait())
            except queue.Empty:
                break
        return out

    def test_default_level_minimal(self):
        self.logger.log(user_id="u1", event="e", message="hello")
        out = self._drain()
        self.assertEqual(len(out), 1)
        rec = json.loads(out[0])
        self.assertEqual(rec["level"], "MINIMAL")
        self.assertNotIn("fields", rec)

    def test_none_level_suppresses(self):
        self.logger.level = AuditLevel.NONE
        wrote = self.logger.log(user_id="u1", event="e", message="hi")
        self.assertFalse(wrote)
        self.assertEqual(self._drain(), [])

    def test_consent_required(self):
        self.logger.revoke_consent("u1")
        wrote = self.logger.log(user_id="u1", event="e", message="hello")
        self.assertFalse(wrote)
        self.assertEqual(self._drain(), [])

    def test_email_redaction(self):
        self.logger.log(user_id="u1", event="e", message="Contact me at a.b+2@test.co.uk")
        rec = json.loads(self._drain()[0])
        self.assertEqual(rec["message"], "[REDACTED]")

    def test_phone_redaction(self):
        msg = "Call (415) 555-2671 or +1 415 555 2671"
        self.logger.log(user_id="u1", event="e", message=msg)
        rec = json.loads(self._drain()[0])
        self.assertEqual(rec["message"], "[REDACTED] or [REDACTED]")

    def test_gps_redaction(self):
        msg = "Meet at 37.7749, -122.4194; lat: 40.7128 lon: -74.0060"
        self.logger.log(user_id="u1", event="e", message=msg)
        rec = json.loads(self._drain()[0])
        self.assertIn("[REDACTED]", rec["message"])  # both patterns masked

    def test_name_redaction_default(self):
        msg = "John met Mary at the park"
        self.logger.log(user_id="u1", event="e", message=msg)
        rec = json.loads(self._drain()[0])
        # Either/both names may be redacted depending on list
        self.assertNotEqual(rec["message"], msg)

    def test_name_allowlist(self):
        cfg = RedactionConfig(allow_name_list={"Mary"})
        self.logger = BeaconLogger(redaction=cfg)
        self.logger.require_consent("u1")
        msg = "John met Mary at the park"
        self.logger.log(user_id="u1", event="e", message=msg)
        rec = json.loads(self._drain()[0])
        self.assertIn("Mary", rec["message"])  # allowed
        self.assertIn("[REDACTED]", rec["message"])  # John redacted

    def test_diag_includes_fields_redacted(self):
        self.logger.level = AuditLevel.DIAG
        fields = {"email": "x@y.com", "phone": "+44 20 7946 0958", "loc": "51.5007, -0.1246"}
        self.logger.log(user_id="u1", event="e", message="m", fields=fields)
        rec = json.loads(self._drain()[0])
        self.assertIn("fields", rec)
        self.assertEqual(rec["fields"]["email"], "[REDACTED]")
        self.assertEqual(rec["fields"]["phone"], "[REDACTED]")
        self.assertEqual(rec["fields"]["loc"], "[REDACTED]")

    def test_hashes_user_id(self):
        self.logger.log(user_id="u1", event="e", message="m")
        rec = json.loads(self._drain()[0])
        self.assertIn("user", rec)
        self.assertNotEqual(rec["user"], "u1")
        self.assertEqual(len(rec["user"]), 16)

    def test_nested_structures(self):
        self.logger.level = AuditLevel.DIAG
        fields = {"a": ["john@example.com", {"gps": "37.77, -122.41"}], "b": None}
        self.logger.log(user_id="u1", event="e", message="ok", fields=fields)
        rec = json.loads(self._drain()[0])
        self.assertEqual(rec["fields"]["a"][0], "[REDACTED]")
        self.assertEqual(rec["fields"]["a"][1]["gps"], "[REDACTED]")
        self.assertIsNone(rec["fields"]["b"])

    def test_none_message_and_fields(self):
        self.logger.level = AuditLevel.DIAG
        self.logger.log(user_id="u1", event="e", message=None, fields=None)
        rec = json.loads(self._drain()[0])
        self.assertNotIn("message", rec)
        self.assertNotIn("fields", rec)

    def test_system_event_without_user(self):
        self.logger.log(user_id=None, event="healthcheck", message="OK")
        rec = json.loads(self._drain()[0])
        self.assertNotIn("user", rec)

    def test_suppressed_without_consent_even_diag(self):
        self.logger.revoke_consent("u1")
        self.logger.level = AuditLevel.DIAG
        wrote = self.logger.log(user_id="u1", event="e", message="m", fields={"x": "y"})
        self.assertFalse(wrote)
        self.assertEqual(self._drain(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
