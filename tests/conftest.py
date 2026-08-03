import asyncio

import pytest

from mcpverity.engine import run_scan


@pytest.fixture
def scan_files():
    """Run a scan over an in-memory file list and return the Scan object."""
    def _run(files, server_name="TEST", mode="paste", repo_url=None, enable_llm_check=False):
        return asyncio.run(run_scan(server_name, files, mode, repo_url, enable_llm_check))
    return _run
