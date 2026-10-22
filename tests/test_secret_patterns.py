"""W003 coverage for current credential formats, and redaction of each.

Fake tokens are assembled by concatenation so no scanner sees a complete
key in this file's source.
"""
import pytest

from mcpverity.rules.base import redact_secrets

A = "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z"
PEM = ("-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA" + A + "\n" + A + A
       + "\n-----END " + "RSA PRIVATE KEY-----")

# case -> (source, a fragment of the secret that must never be echoed[, label if different])
TRUE_POSITIVES = {
    "OpenAI project key": ('k = "sk-' + "proj-" + A + "_" + A + '"\n', "sk-" + "proj-" + A, "OpenAI project/service key"),
    "OpenAI service-account key": ('k = "sk-' + "svcacct-" + A + A + '"\n', A + A, "OpenAI project/service key"),
    "GitHub fine-grained token": ('t = "github' + "_pat_11ABCDEFG0" + A + "_" + A + '"\n', A),
    "Stripe live key": ('stripe.api_key = "sk' + "_live_" + A + '"\n', A),
    "Hugging Face token": ('HF = "hf' + "_" + A + 'xyz"\n', A),
    "Slack webhook URL": ('URL = "https://hooks.slack.com/services/' + "T0ABCDEFG/B0ABCDEFG/" + A[:24] + '"\n', A[:24]),
    "Private key block": ('KEY = """' + PEM + '"""\n', A),
    "JWT": ('T = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            + 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"\n', "SflKxwRJSMeKKF2QT4fw"),
    "Database URL with password": ('DB = "postgresql://admin:' + "S3cr3tPassw0rd" + '@db.internal:5432/app"\n',
                                   "S3cr3tPassw0rd"),
}

TRUE_NEGATIVES = {
    "dsn stock placeholder": 'DB = "postgresql://user:password@localhost:5432/app"\n',
    "dsn f-string": 'DB = f"postgresql://{user}:{pw}@{host}/app"\n',
    "dsn env template": 'DB = "postgres://app:${DB_PASSWORD}@db/app"\n',
    "dsn printf": 'DB = "mysql://%s:%s@%s/app" % (u, p, h)\n',
    "dsn without password": 'DB = "postgresql://localhost:5432/app"\n',
    "pem header check": 'if line.startswith("-----BEGIN ' + 'RSA PRIVATE KEY-----"):\n    pass\n',
}


def _w003(scan):
    return [f for f in scan.findings if f.rule_id == "W003"]


@pytest.mark.parametrize("case", TRUE_POSITIVES.keys())
def test_w003_detects_and_redacts(scan_files, case):
    src, secret_part, *label = TRUE_POSITIVES[case]
    label = label[0] if label else case
    hits = _w003(scan_files([{"path": "server.py", "content": src}]))
    assert [f.title for f in hits] == [f"Hardcoded secret: {label}"]
    for f in hits:
        assert secret_part not in f.snippet and secret_part not in f.message
        assert "REDACTED len=" in f.message


@pytest.mark.parametrize("src", TRUE_NEGATIVES.values(), ids=TRUE_NEGATIVES.keys())
def test_w003_ignores_placeholders(scan_files, src):
    assert _w003(scan_files([{"path": "server.py", "content": src}])) == []


def test_jwt_starts_at_lower_confidence(scan_files):
    (jwt,) = _w003(scan_files([{"path": "server.py", "content": TRUE_POSITIVES["JWT"][0]}]))
    (pg,) = _w003(scan_files([{"path": "server.py", "content": TRUE_POSITIVES["Database URL with password"][0]}]))
    assert jwt.confidence < pg.confidence


def test_unterminated_private_key_is_fully_redacted():
    # A snippet cut off mid-key still must not show the key body.
    cut = PEM.rsplit("\n", 1)[0]
    out = redact_secrets("x\n" + cut)
    assert A not in out and "REDACTED len=" in out
