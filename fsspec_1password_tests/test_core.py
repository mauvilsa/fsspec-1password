"""Tests for fsspec_1password.core – no real op executable required.

All calls to the op CLI are intercepted via unittest.mock so the tests run
in any environment regardless of whether 1Password CLI is installed.
"""

import io
import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

import fsspec_1password
from fsspec_1password.core import (
    OnePasswordFileSystem,
    _parse_path,
    _require_op,
    _run_op,
)

# ---------------------------------------------------------------------------
# Fixtures – sample op CLI JSON responses
# ---------------------------------------------------------------------------

VAULTS_JSON = json.dumps(
    [
        {"id": "vaultid1", "name": "Personal"},
        {"id": "vaultid2", "name": "Work"},
    ]
)

ITEMS_JSON = json.dumps(
    [
        {"id": "itemid1", "title": "GitHub"},
        {"id": "itemid2", "title": "AWS"},
    ]
)

ITEM_JSON = json.dumps(
    {
        "id": "itemid1",
        "title": "GitHub",
        "fields": [
            {"id": "username", "label": "username", "value": "alice"},
            {"id": "password", "label": "password", "value": "s3cr3t"},
            {"id": "url", "label": "website", "value": "https://github.com"},
            # Field without a label or value – should be skipped in ls
            {"id": "notesPlain", "label": "", "value": ""},
        ],
    }
)

FIELD_VALUE = "s3cr3t\n"


# ---------------------------------------------------------------------------
# Helper: build a mock CompletedProcess
# ---------------------------------------------------------------------------


def _completed(stdout: str, returncode: int = 0) -> MagicMock:
    m = MagicMock(spec=subprocess.CompletedProcess)
    m.stdout = stdout
    m.returncode = returncode
    m.stderr = ""
    return m


# ---------------------------------------------------------------------------
# _parse_path
# ---------------------------------------------------------------------------


class TestParsePath:
    def test_root(self):
        assert _parse_path("op://") == (None, None, None)

    def test_vault_only(self):
        assert _parse_path("op://Personal") == ("Personal", None, None)

    def test_vault_item(self):
        assert _parse_path("op://Personal/GitHub") == ("Personal", "GitHub", None)

    def test_vault_item_field(self):
        assert _parse_path("op://Personal/GitHub/password") == (
            "Personal",
            "GitHub",
            "password",
        )

    def test_trailing_slash_ignored(self):
        assert _parse_path("op://Personal/") == ("Personal", None, None)

    def test_no_scheme(self):
        # Path without op:// prefix – treated as raw path segments
        assert _parse_path("Personal/GitHub/password") == (
            "Personal",
            "GitHub",
            "password",
        )


# ---------------------------------------------------------------------------
# _require_op
# ---------------------------------------------------------------------------


class TestRequireOp:
    def test_op_found(self):
        with patch("fsspec_1password.core.shutil.which", return_value="/usr/bin/op"):
            path = _require_op()
        assert path == "/usr/bin/op"

    def test_op_not_found_raises_clear_error(self):
        with patch("fsspec_1password.core.shutil.which", return_value=None):
            with pytest.raises(RuntimeError) as exc_info:
                _require_op()
        msg = str(exc_info.value)
        assert "op" in msg
        assert "PATH" in msg
        assert "1Password" in msg

    def test_error_message_contains_install_url(self):
        with patch("fsspec_1password.core.shutil.which", return_value=None):
            with pytest.raises(RuntimeError) as exc_info:
                _require_op()
        assert "developer.1password.com" in str(exc_info.value)


# ---------------------------------------------------------------------------
# _run_op
# ---------------------------------------------------------------------------


class TestRunOp:
    def test_runs_correct_command(self):
        with (
            patch("fsspec_1password.core.shutil.which", return_value="/usr/bin/op"),
            patch("fsspec_1password.core.subprocess.run", return_value=_completed('{"ok": true}')) as mock_run,
        ):
            result = _run_op("vault", "list", "--format=json")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["/usr/bin/op", "vault", "list", "--format=json"]
        assert result == '{"ok": true}'

    def test_non_zero_exit_raises_permission_error(self):
        err = subprocess.CalledProcessError(1, "op", stderr="not signed in")
        with (
            patch("fsspec_1password.core.shutil.which", return_value="/usr/bin/op"),
            patch("fsspec_1password.core.subprocess.run", side_effect=err),
        ):
            with pytest.raises(PermissionError, match="not signed in"):
                _run_op("vault", "list")


# ---------------------------------------------------------------------------
# OnePasswordFileSystem – fixture that patches all CLI calls
# ---------------------------------------------------------------------------


@pytest.fixture
def fs():
    """Return a OnePasswordFileSystem with op CLI fully mocked."""
    with patch("fsspec_1password.core.shutil.which", return_value="/usr/bin/op"):
        filesystem = OnePasswordFileSystem()
    return filesystem


def _patch_run(responses: dict[tuple, str]):
    """Return a context manager that patches _run_op.

    `responses` maps tuples of CLI args (excluding the binary) to stdout.
    """

    def _fake_run(*args, **kwargs):
        key = tuple(args)
        if key in responses:
            return responses[key]
        raise KeyError(f"Unexpected op args: {args}")

    return patch("fsspec_1password.core._run_op", side_effect=_fake_run)


# ---------------------------------------------------------------------------
# ls – root (vaults)
# ---------------------------------------------------------------------------


class TestLsRoot:
    def test_returns_vault_names_as_directories(self, fs):
        with _patch_run({("vault", "list", "--format=json"): VAULTS_JSON}):
            entries = fs.ls("op://", detail=True)
        names = [e["name"] for e in entries]
        assert "op://Personal" in names
        assert "op://Work" in names
        for e in entries:
            assert e["type"] == "directory"

    def test_no_detail(self, fs):
        with _patch_run({("vault", "list", "--format=json"): VAULTS_JSON}):
            names = fs.ls("op://", detail=False)
        assert "op://Personal" in names

    def test_empty_vaults(self, fs):
        with _patch_run({("vault", "list", "--format=json"): "[]"}):
            entries = fs.ls("op://")
        assert entries == []


# ---------------------------------------------------------------------------
# ls – vault level (items)
# ---------------------------------------------------------------------------


class TestLsVault:
    def test_returns_items_as_directories(self, fs):
        with _patch_run({("item", "list", "--vault", "Personal", "--format=json"): ITEMS_JSON}):
            entries = fs.ls("op://Personal", detail=True)
        names = [e["name"] for e in entries]
        assert "op://Personal/GitHub" in names
        assert "op://Personal/AWS" in names
        for e in entries:
            assert e["type"] == "directory"

    def test_trailing_slash_ignored(self, fs):
        with _patch_run({("item", "list", "--vault", "Personal", "--format=json"): ITEMS_JSON}):
            entries = fs.ls("op://Personal/", detail=False)
        assert "op://Personal/GitHub" in entries


# ---------------------------------------------------------------------------
# ls – item level (fields)
# ---------------------------------------------------------------------------


class TestLsItem:
    def test_returns_fields_as_files(self, fs):
        with _patch_run({("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON}):
            entries = fs.ls("op://Personal/GitHub", detail=True)
        names = [e["name"] for e in entries]
        assert "op://Personal/GitHub/username" in names
        assert "op://Personal/GitHub/password" in names
        for e in entries:
            assert e["type"] == "file"

    def test_empty_label_fields_skipped(self, fs):
        with _patch_run({("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON}):
            entries = fs.ls("op://Personal/GitHub", detail=True)
        names = [e["name"] for e in entries]
        # Field with empty label should not appear
        assert not any(e.endswith("/") for e in names)
        assert "op://Personal/GitHub/" not in names

    def test_file_size_equals_value_length(self, fs):
        with _patch_run({("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON}):
            entries = fs.ls("op://Personal/GitHub", detail=True)
        by_name = {e["name"]: e for e in entries}
        assert by_name["op://Personal/GitHub/username"]["size"] == len(b"alice")
        assert by_name["op://Personal/GitHub/password"]["size"] == len(b"s3cr3t")

    def test_ls_field_raises_not_a_directory(self, fs):
        with pytest.raises(NotADirectoryError):
            fs.ls("op://Personal/GitHub/password")


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------


class TestInfo:
    def test_root_info(self, fs):
        info = fs.info("op://")
        assert info["type"] == "directory"

    def test_vault_info(self, fs):
        with _patch_run({("vault", "list", "--format=json"): VAULTS_JSON}):
            info = fs.info("op://Personal")
        assert info["type"] == "directory"
        assert "Personal" in info["name"]

    def test_vault_not_found(self, fs):
        with _patch_run({("vault", "list", "--format=json"): VAULTS_JSON}):
            with pytest.raises(FileNotFoundError):
                fs.info("op://DoesNotExist")

    def test_item_info(self, fs):
        with _patch_run({("item", "list", "--vault", "Personal", "--format=json"): ITEMS_JSON}):
            info = fs.info("op://Personal/GitHub")
        assert info["type"] == "directory"

    def test_item_not_found(self, fs):
        with _patch_run({("item", "list", "--vault", "Personal", "--format=json"): ITEMS_JSON}):
            with pytest.raises(FileNotFoundError):
                fs.info("op://Personal/NoSuchItem")

    def test_field_info(self, fs):
        with _patch_run({("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON}):
            info = fs.info("op://Personal/GitHub/password")
        assert info["type"] == "file"
        assert info["size"] == len(b"s3cr3t")

    def test_field_not_found(self, fs):
        with _patch_run({("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON}):
            with pytest.raises(FileNotFoundError):
                fs.info("op://Personal/GitHub/nonexistent_field")


# ---------------------------------------------------------------------------
# open / cat_file
# ---------------------------------------------------------------------------


class TestOpen:
    def test_read_field_value(self, fs):
        with _patch_run({("read", "op://Personal/GitHub/password"): FIELD_VALUE}):
            fobj = fs.open("op://Personal/GitHub/password", mode="rb")
        assert isinstance(fobj, io.IOBase)
        content = fobj.read()
        assert content == FIELD_VALUE.encode()

    def test_open_returns_bytes(self, fs):
        with _patch_run({("read", "op://Personal/GitHub/username"): "alice\n"}):
            with fs.open("op://Personal/GitHub/username") as f:
                data = f.read()
        assert data == b"alice\n"

    def test_write_mode_raises_permission_error(self, fs):
        with pytest.raises(PermissionError):
            fs.open("op://Personal/GitHub/password", mode="wb")

    def test_append_mode_raises_permission_error(self, fs):
        with pytest.raises(PermissionError):
            fs.open("op://Personal/GitHub/password", mode="ab")

    def test_open_directory_raises_is_a_directory(self, fs):
        with pytest.raises(IsADirectoryError):
            fs.open("op://Personal/GitHub")

    def test_open_vault_raises_is_a_directory(self, fs):
        with pytest.raises(IsADirectoryError):
            fs.open("op://Personal")


class TestCatFile:
    def test_returns_bytes(self, fs):
        with _patch_run({("read", "op://Personal/GitHub/password"): FIELD_VALUE}):
            data = fs.cat_file("op://Personal/GitHub/password")
        assert data == FIELD_VALUE.encode()

    def test_cat_directory_raises(self, fs):
        with pytest.raises(IsADirectoryError):
            fs.cat_file("op://Personal/GitHub")


# ---------------------------------------------------------------------------
# fsspec integration – protocol registration
# ---------------------------------------------------------------------------


class TestFsspecIntegration:
    def test_filesystem_registered_via_entry_point(self):
        """The op:// protocol should be resolvable via fsspec.filesystem()."""
        import fsspec

        with patch("fsspec_1password.core.shutil.which", return_value="/usr/bin/op"):
            fs_instance = fsspec.filesystem("op")
        assert isinstance(fs_instance, OnePasswordFileSystem)

    def test_op_protocol_attribute(self):
        assert OnePasswordFileSystem.protocol == "op"


# ---------------------------------------------------------------------------
# Error propagation – op CLI errors surface clearly
# ---------------------------------------------------------------------------


class TestCliErrors:
    def test_signed_out_error_surfaces_as_permission_error(self, fs):
        err = subprocess.CalledProcessError(1, "op", stderr="[ERROR] 2023/01/01 not signed in")
        with (
            patch("fsspec_1password.core.shutil.which", return_value="/usr/bin/op"),
            patch("fsspec_1password.core.subprocess.run", side_effect=err),
        ):
            with pytest.raises(PermissionError, match="not signed in"):
                fs.ls("op://")

    def test_op_missing_gives_runtime_error_on_ls(self):
        with patch("fsspec_1password.core.shutil.which", return_value=None):
            fs_no_op = OnePasswordFileSystem()
            with pytest.raises(RuntimeError, match="op"):
                fs_no_op.ls("op://")

    def test_op_missing_gives_runtime_error_on_open(self):
        with patch("fsspec_1password.core.shutil.which", return_value=None):
            fs_no_op = OnePasswordFileSystem()
            with pytest.raises(RuntimeError, match="PATH"):
                fs_no_op.open("op://Personal/GitHub/password")


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------


class TestVersion:
    def test_version_is_string(self):
        assert isinstance(fsspec_1password.__version__, str)

    def test_version_format(self):
        parts = fsspec_1password.__version__.split(".")
        assert len(parts) >= 2
