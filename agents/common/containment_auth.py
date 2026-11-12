"""HMAC authentication for the node-local containment Redis protocol."""

import hashlib
import hmac
import json
from typing import Dict, Mapping

SIGNATURE_FIELD = "hmac_sha256"


def _canonical(fields: Mapping[str, object]) -> bytes:
    unsigned = {str(k): str(v) for k, v in fields.items() if k != SIGNATURE_FIELD}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sign_fields(fields: Mapping[str, object], key: str) -> Dict[str, str]:
    """Return string-valued fields with an HMAC-SHA256 signature."""
    if not isinstance(key, str) or not key:
        raise ValueError("containment HMAC key is missing")
    signed = {str(k): str(v) for k, v in fields.items() if k != SIGNATURE_FIELD}
    signed[SIGNATURE_FIELD] = hmac.new(key.encode("utf-8"), _canonical(signed), hashlib.sha256).hexdigest()
    return signed


def verify_fields(fields: Mapping[str, object], key: str) -> bool:
    """Verify an authenticated message without accepting missing, malformed, or bad signatures."""
    if not isinstance(key, str) or not key:
        return False
    supplied = fields.get(SIGNATURE_FIELD)
    if not isinstance(supplied, str) or len(supplied) != 64:
        return False
    expected = hmac.new(key.encode("utf-8"), _canonical(fields), hashlib.sha256).hexdigest()
    return hmac.compare_digest(supplied, expected)
