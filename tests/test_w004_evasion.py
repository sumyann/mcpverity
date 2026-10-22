"""W004 must see through import aliases and simple call indirection.

Before the fix, every TRUE_POSITIVES case below produced no W004 finding:
the AST pass only matched calls written literally as `subprocess.run(...)`,
and a Python file that parsed never fell back to the regex signals.
"""
import pytest

TRUE_POSITIVES = {
    "import as": ("import subprocess as sp\nsp.run('ls', shell=True)\n", "shell=True subprocess"),
    "from import": ("from subprocess import run\nrun('ls')\n", "spawns subprocess"),
    "from import as": ("from os import system as s\ns('ls')\n", "invokes shell"),
    "star import": ("from os import *\nsystem('ls')\n", "invokes shell"),
    "getattr": ("import os\ngetattr(os, 'system')('ls')\n", "invokes shell"),
    "__import__": ("__import__('os').system('ls')\n", "invokes shell"),
    "importlib": ("import importlib\nimportlib.import_module('subprocess').Popen(['ls'])\n", "spawns subprocess"),
    "builtins.exec": ("import builtins\nbuiltins.exec('1')\n", "dynamic code evaluation"),
    "shutil alias": ("import shutil as sh\nsh.rmtree('/tmp/x')\n", "recursive filesystem delete"),
    "asyncio shell": ("import asyncio\nasyncio.create_subprocess_shell('ls')\n", "invokes shell"),
    "getoutput": ("import subprocess\nsubprocess.getoutput('ls')\n", "invokes shell"),
    "os.spawnlp": ("import os\nos.spawnlp(os.P_WAIT, 'ls', 'ls')\n", "spawns subprocess"),
    "pty.spawn": ("import pty\npty.spawn('/bin/sh')\n", "spawns subprocess"),
    "open /etc": ("data = open('/etc/shadow').read()\n", "reads sensitive filesystem path"),
    "chmod 777": ("import os\nos.chmod('/tmp/x', 0o777)\n", "sets world-writable permissions"),
}

TRUE_NEGATIVES = {
    "local function named run": "def run(x):\n    return x\nrun('ls')\n",
    "getattr on self": "class A:\n    def go(self):\n        getattr(self, 'system')('x')\n",
    "from-import of a lookalike": "from mylib import system\nsystem('ls')\n",
    "relative open": "open('notes.txt').read()\n",
    "chmod 644": "import os\nos.chmod('x', 0o644)\n",
}


def _w004(scan):
    return [f for f in scan.findings if f.rule_id == "W004"]


@pytest.mark.parametrize("src,label", TRUE_POSITIVES.values(), ids=TRUE_POSITIVES.keys())
def test_w004_resolves_aliases_and_indirection(scan_files, src, label):
    hits = _w004(scan_files([{"path": "server.py", "content": src}]))
    assert [f.title for f in hits] == [f"Over-privileged operation: {label}"]
    assert "ast" in hits[0].tags


@pytest.mark.parametrize("src", TRUE_NEGATIVES.values(), ids=TRUE_NEGATIVES.keys())
def test_w004_does_not_flag_lookalikes(scan_files, src):
    assert _w004(scan_files([{"path": "server.py", "content": src}])) == []


def test_w004_message_names_what_the_call_was_written_as(scan_files):
    scan = scan_files([{"path": "server.py", "content": "import subprocess as sp\nsp.Popen(['ls'])\n"}])
    (hit,) = _w004(scan)
    assert "`subprocess.Popen(...)` (written as `sp.Popen`)" in hit.message
    plain = scan_files([{"path": "server.py", "content": "import subprocess\nsubprocess.Popen(['ls'])\n"}])
    assert "written as" not in _w004(plain)[0].message
