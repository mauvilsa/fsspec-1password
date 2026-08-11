"""Shared fixtures – no real op executable required.

All calls to the op CLI are intercepted via unittest.mock so the tests run
in any environment regardless of whether 1Password CLI is installed.
"""

import io
import json
import re
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from fsspec_1password import _logging
from fsspec_1password._core import OnePasswordFileSystem

# ---------------------------------------------------------------------------
# Sample op CLI JSON responses
# ---------------------------------------------------------------------------

ITEM_JSON = json.dumps(
    {
        "id": "itemid1",
        "title": "GitHub",
        "fields": [
            {"id": "username", "label": "username", "value": "alice"},
            {"id": "password", "label": "password", "value": "s3cr3t"},
            {"id": "url", "label": "website", "value": "https://github.com"},
            # Field without a label – should be skipped
            {"id": "notesPlain", "label": "", "value": ""},
        ],
    }
)

ITEM_JSON_AWS = json.dumps(
    {
        "id": "itemid2",
        "title": "AWS",
        "fields": [
            {"id": "access_key", "label": "access_key", "value": "AKIAIOSFODNN7"},
        ],
    }
)

GITHUB_GET = ("item", "get", "GitHub", "--vault", "Personal", "--format=json")
AWS_GET = ("item", "get", "AWS", "--vault", "Work", "--format=json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def completed(stdout: str, returncode: int = 0) -> MagicMock:
    """Build a mock subprocess.CompletedProcess."""
    m = MagicMock(spec=subprocess.CompletedProcess)
    m.stdout = stdout
    m.returncode = returncode
    m.stderr = ""
    return m


def patch_run(responses: dict[tuple, str]):
    """Return a context manager that patches _run_op.

    `responses` maps tuples of CLI args to stdout strings.
    Signout calls always succeed with an empty string unless overridden.
    """

    def _fake_run(*args, **kwargs):
        key = tuple(args)
        if key in responses:
            return responses[key]
        if key == ("signout",):
            return ""
        raise KeyError(f"Unexpected op args: {args}")

    return patch("fsspec_1password._core._run_op", side_effect=_fake_run)


_RECORD_START = re.compile(r"^(?=\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} )", re.MULTILINE)


def records(console: io.StringIO) -> list[str]:
    """Split captured console output into individual records.

    A single record may span several lines (the caller stack at detail 3), so
    splitting on newlines is not enough – records start with a timestamp.
    """
    return [part.rstrip("\n") for part in _RECORD_START.split(console.getvalue()) if part.strip()]


def access_records(console: io.StringIO) -> list[str]:
    """Console records that report an access – excludes operational warnings."""
    return [r for r in records(console) if "op://" in r]


def json_lines(path) -> list[dict]:
    """Parse a JSON Lines log file."""
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def console(monkeypatch):
    """Capture the console sink in memory and disable the file sink.

    Handlers are built lazily against ``sys.stderr``, so patching stderr and
    resetting is enough to redirect them.  The file sink is off by default so
    that tests never touch the real home directory; tests that exercise it
    point OP_FSSPEC_AUDIT_LOG_FILE at a tmp_path.
    """
    monkeypatch.setenv("OP_FSSPEC_AUDIT_LOG_FILE", "none")
    monkeypatch.delenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", raising=False)
    monkeypatch.delenv("OP_FSSPEC_SIGNOUT", raising=False)
    monkeypatch.delenv("OP_FSSPEC_AUDIT_LOG_RUN_ID", raising=False)
    stream = io.StringIO()
    monkeypatch.setattr(sys, "stderr", stream)
    _logging.reset()
    yield stream
    _logging.reset()


@pytest.fixture
def fs():
    """Return a fresh OnePasswordFileSystem with op CLI fully mocked."""
    with patch("fsspec_1password._core.shutil.which", return_value="/usr/bin/op"):
        filesystem = OnePasswordFileSystem()
    # Bypass fsspec's instance cache so each test gets an independent object
    filesystem._item_cache = {}
    return filesystem
