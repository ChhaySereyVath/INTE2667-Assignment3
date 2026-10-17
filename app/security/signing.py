"""Canonical JSON: one exact byte string for the same data (R14; KE06 adds signatures)."""
import json


def canonical_json(data):
    """One exact byte string for the same data: sorted keys, no spaces. Two machines
    that sign or hash the same record always get the same bytes."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
