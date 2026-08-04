# Security Policy

## Reporting a vulnerability in MCPVerity itself

If you find a security issue in MCPVerity's own code (not a false
negative/positive in its detections -- see below), please report it
privately via [GitHub Security Advisories](https://github.com/sumyann/mcpverity/security/advisories/new)
rather than opening a public issue.

Include:
- A description of the issue and its impact.
- Steps to reproduce (a minimal input file/repo is ideal).
- The MCPVerity version (`mcpverity version`) and Python version you're running.

We aim to acknowledge reports within 5 business days.

## Missed or incorrect detections are not security vulnerabilities in MCPVerity

If MCPVerity fails to flag a real risk (false negative) or flags something
that isn't one (false positive), that's a detection-quality bug, not a
security vulnerability in the tool -- please open a normal
[GitHub issue](https://github.com/sumyann/mcpverity/issues) instead, ideally with
a fixture per [CONTRIBUTING.md](./CONTRIBUTING.md#reporting-a-missed-or-incorrect-detection).

## Supported versions

Only the latest published release on PyPI receives security fixes. There is
no long-term-support branch at this time.
