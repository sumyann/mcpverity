"""Stable identity hashing for findings.

Used to key suppressions (a user's "this is a false positive, stop showing it
to me" decision) across repeated scans of the same server. Pulled out as its
own tiny module — no other engine code depends on it — so that anything
consuming MCPVerity as a library (e.g. a hosted UI with persisted suppressions)
can import the exact same hash function the engine itself uses internally,
with zero risk of the two drifting apart.
"""
SNIPPET_KEY_LEN = 120


def suppression_hash(rule_id: str, file_path: str, snippet: str) -> str:
    """Stable 16-char identifier for a finding's essence.

    Two findings hash identically iff they share a rule_id, file_path, and
    the first SNIPPET_KEY_LEN characters of their snippet — stable across
    re-scans even as unrelated parts of a file change.
    """
    import hashlib

    key = f"{rule_id}|{file_path}|{(snippet or '')[:SNIPPET_KEY_LEN]}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
