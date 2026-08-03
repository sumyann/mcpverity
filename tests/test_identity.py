from mcpverity.identity import suppression_hash


def test_suppression_hash_is_stable():
    a = suppression_hash("W003", "server.py", "API_KEY = 'sk-abc123'")
    b = suppression_hash("W003", "server.py", "API_KEY = 'sk-abc123'")
    assert a == b


def test_suppression_hash_changes_with_inputs():
    base = suppression_hash("W003", "server.py", "API_KEY = 'sk-abc123'")
    assert base != suppression_hash("W004", "server.py", "API_KEY = 'sk-abc123'")
    assert base != suppression_hash("W003", "other.py", "API_KEY = 'sk-abc123'")
    assert base != suppression_hash("W003", "server.py", "API_KEY = 'different'")


def test_suppression_hash_only_uses_first_120_chars_of_snippet():
    long_snippet = "x" * 200
    a = suppression_hash("W003", "server.py", long_snippet[:120] + "AAAA")
    b = suppression_hash("W003", "server.py", long_snippet[:120] + "BBBB")
    assert a == b
