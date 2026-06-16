"""Tests for fsspec_1password._core – no real op executable required.

All calls to the op CLI are intercepted via unittest.mock so the tests run
in any environment regardless of whether 1Password CLI is installed.
"""

import io
import json
import logging
import subprocess
from unittest.mock import MagicMock, call, patch

import pytest

import fsspec_1password
from fsspec_1password._core import (
    OnePasswordFileSystem,
    _parse_path,
    _require_op,
    _run_op,
    logger,
)

# ---------------------------------------------------------------------------
# Fixtures – sample op CLI JSON responses
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
        with patch("fsspec_1password._core.shutil.which", return_value="/usr/bin/op"):
            path = _require_op()
        assert path == "/usr/bin/op"

    def test_op_not_found_raises_clear_error(self):
        with patch("fsspec_1password._core.shutil.which", return_value=None):
            with pytest.raises(RuntimeError) as exc_info:
                _require_op()
        msg = str(exc_info.value)
        assert "op" in msg
        assert "PATH" in msg
        assert "1Password" in msg

    def test_error_message_contains_install_url(self):
        with patch("fsspec_1password._core.shutil.which", return_value=None):
            with pytest.raises(RuntimeError) as exc_info:
                _require_op()
        assert "developer.1password.com" in str(exc_info.value)


# ---------------------------------------------------------------------------
# _run_op
# ---------------------------------------------------------------------------


class TestRunOp:
    def test_runs_correct_command(self):
        with (
            patch("fsspec_1password._core.shutil.which", return_value="/usr/bin/op"),
            patch("fsspec_1password._core.subprocess.run", return_value=_completed('{"ok": true}')) as mock_run,
        ):
            result = _run_op("vault", "list", "--format=json")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["/usr/bin/op", "vault", "list", "--format=json"]
        assert result == '{"ok": true}'

    def test_non_zero_exit_raises_permission_error(self):
        err = subprocess.CalledProcessError(1, "op", stderr="not signed in")
        with (
            patch("fsspec_1password._core.shutil.which", return_value="/usr/bin/op"),
            patch("fsspec_1password._core.subprocess.run", side_effect=err),
        ):
            with pytest.raises(PermissionError, match="not signed in"):
                _run_op("vault", "list")


# ---------------------------------------------------------------------------
# OnePasswordFileSystem – fixture that patches all CLI calls
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def logger_handlers():
    with patch.object(logger, "handlers", []):
        yield


@pytest.fixture
def fs():
    """Return a fresh OnePasswordFileSystem with op CLI fully mocked."""
    with patch("fsspec_1password._core.shutil.which", return_value="/usr/bin/op"):
        filesystem = OnePasswordFileSystem()
    # Bypass fsspec's instance cache so each test gets an independent object
    filesystem._item_cache = {}
    filesystem._access_warnings_emitted = set()
    return filesystem


def _patch_run(responses: dict[tuple, str]):
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


# ---------------------------------------------------------------------------
# ls – partial paths raise PermissionError
# ---------------------------------------------------------------------------


class TestLsPartialPaths:
    def test_root_raises_permission_error(self, fs):
        with pytest.raises(PermissionError, match="op://Vault/Item/Field"):
            fs.ls("op://")

    def test_vault_raises_permission_error(self, fs):
        with pytest.raises(PermissionError, match="op://Vault/Item/Field"):
            fs.ls("op://Personal")

    def test_item_raises_permission_error(self, fs):
        with pytest.raises(PermissionError, match="op://Vault/Item/Field"):
            fs.ls("op://Personal/GitHub")

    def test_field_raises_not_a_directory(self, fs):
        with pytest.raises(NotADirectoryError):
            fs.ls("op://Personal/GitHub/password")


# ---------------------------------------------------------------------------
# info – partial paths raise PermissionError; full field path works
# ---------------------------------------------------------------------------


class TestInfo:
    def test_root_raises_permission_error(self, fs):
        with pytest.raises(PermissionError, match="op://Vault/Item/Field"):
            fs.info("op://")

    def test_vault_raises_permission_error(self, fs):
        with pytest.raises(PermissionError, match="op://Vault/Item/Field"):
            fs.info("op://Personal")

    def test_item_raises_permission_error(self, fs):
        with pytest.raises(PermissionError, match="op://Vault/Item/Field"):
            fs.info("op://Personal/GitHub")

    def test_field_info(self, fs, caplog):
        with caplog.at_level(logging.WARNING, logger="fsspec_1password"):
            with _patch_run({("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON}):
                info = fs.info("op://Personal/GitHub/password")
        assert info["type"] == "file"
        assert info["size"] == len(b"s3cr3t")
        assert any("op://Personal/GitHub/password" in r.message for r in caplog.records)

    def test_field_not_found(self, fs, caplog):
        with caplog.at_level(logging.WARNING, logger="fsspec_1password"):
            with _patch_run({("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON}):
                with pytest.raises(FileNotFoundError):
                    fs.info("op://Personal/GitHub/nonexistent_field")
        assert any("op://Personal/GitHub/nonexistent_field" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# open / cat_file
# ---------------------------------------------------------------------------


class TestOpen:
    def test_read_field_value(self, fs, caplog):
        with caplog.at_level(logging.WARNING, logger="fsspec_1password"):
            with _patch_run({("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON}):
                fobj = fs.open("op://Personal/GitHub/password", mode="rb")
        assert isinstance(fobj, io.IOBase)
        content = fobj.read()
        assert content == b"s3cr3t"
        assert any("op://Personal/GitHub/password" in r.message for r in caplog.records)

    def test_open_returns_bytes(self, fs, caplog):
        with caplog.at_level(logging.WARNING, logger="fsspec_1password"):
            with _patch_run({("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON}):
                with fs.open("op://Personal/GitHub/username") as f:
                    data = f.read()
        assert data == b"alice"
        assert any("op://Personal/GitHub/username" in r.message for r in caplog.records)

    def test_write_mode_raises_permission_error(self, fs):
        with pytest.raises(PermissionError):
            fs.open("op://Personal/GitHub/password", mode="wb")

    def test_append_mode_raises_permission_error(self, fs):
        with pytest.raises(PermissionError):
            fs.open("op://Personal/GitHub/password", mode="ab")

    def test_open_item_raises_permission_error(self, fs):
        with pytest.raises(PermissionError, match="op://Vault/Item/Field"):
            fs.open("op://Personal/GitHub")

    def test_open_vault_raises_permission_error(self, fs):
        with pytest.raises(PermissionError, match="op://Vault/Item/Field"):
            fs.open("op://Personal")

    def test_open_root_raises_permission_error(self, fs):
        with pytest.raises(PermissionError, match="op://Vault/Item/Field"):
            fs.open("op://")


class TestCatFile:
    def test_returns_bytes(self, fs, caplog):
        with caplog.at_level(logging.WARNING, logger="fsspec_1password"):
            with _patch_run({("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON}):
                data = fs.cat_file("op://Personal/GitHub/password")
        assert data == b"s3cr3t"
        assert any("op://Personal/GitHub/password" in r.message for r in caplog.records)

    def test_cat_item_raises_permission_error(self, fs):
        with pytest.raises(PermissionError, match="op://Vault/Item/Field"):
            fs.cat_file("op://Personal/GitHub")


# ---------------------------------------------------------------------------
# Field caching – item fetched once, then signout, then served from cache
# ---------------------------------------------------------------------------


class TestFieldCaching:
    def test_item_loaded_once_for_multiple_fields(self, fs, caplog):
        """Reading two fields from the same item should only call op item get once."""
        with caplog.at_level(logging.WARNING, logger="fsspec_1password"):
            with _patch_run({("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON}) as mock_run:
                fs.cat_file("op://Personal/GitHub/username")
                fs.cat_file("op://Personal/GitHub/password")

        item_get_calls = [
            c
            for c in mock_run.call_args_list
            if c == call("item", "get", "GitHub", "--vault", "Personal", "--format=json")
        ]
        assert len(item_get_calls) == 1
        warned_urls = [r.message for r in caplog.records]
        assert any("op://Personal/GitHub/username" in m for m in warned_urls)
        assert any("op://Personal/GitHub/password" in m for m in warned_urls)

    def test_signout_called_after_item_load(self, fs, caplog):
        """op signout must be called exactly once after loading an item."""
        with caplog.at_level(logging.WARNING, logger="fsspec_1password"):
            with _patch_run({("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON}) as mock_run:
                fs.cat_file("op://Personal/GitHub/password")

        signout_calls = [c for c in mock_run.call_args_list if c == call("signout")]
        assert len(signout_calls) == 1
        assert any("op://Personal/GitHub/password" in r.message for r in caplog.records)

    def test_second_field_read_no_additional_op_calls(self, fs, caplog):
        """After the first field read, a second field read must not call op at all."""
        with caplog.at_level(logging.WARNING, logger="fsspec_1password"):
            with _patch_run({("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON}) as mock_run:
                fs.cat_file("op://Personal/GitHub/username")
                call_count_after_first = mock_run.call_count

                fs.cat_file("op://Personal/GitHub/password")
                call_count_after_second = mock_run.call_count

        assert call_count_after_second == call_count_after_first
        # warning logged for both accesses (cached and uncached)
        warned_urls = [r.message for r in caplog.records]
        assert any("op://Personal/GitHub/username" in m for m in warned_urls)
        assert any("op://Personal/GitHub/password" in m for m in warned_urls)

    def test_different_items_each_trigger_separate_op_and_signout(self, fs, caplog):
        """Two different items must each cause one op item get and one op signout."""
        with caplog.at_level(logging.WARNING, logger="fsspec_1password"):
            with _patch_run(
                {
                    ("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON,
                    ("item", "get", "AWS", "--vault", "Work", "--format=json"): ITEM_JSON_AWS,
                }
            ) as mock_run:
                fs.cat_file("op://Personal/GitHub/password")
                fs.cat_file("op://Work/AWS/access_key")

        signout_calls = [c for c in mock_run.call_args_list if c == call("signout")]
        assert len(signout_calls) == 2
        warned_urls = [r.message for r in caplog.records]
        assert any("op://Personal/GitHub/password" in m for m in warned_urls)
        assert any("op://Work/AWS/access_key" in m for m in warned_urls)

    def test_cached_field_values_are_correct(self, fs, caplog):
        with caplog.at_level(logging.WARNING, logger="fsspec_1password"):
            with _patch_run({("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON}):
                username = fs.cat_file("op://Personal/GitHub/username")
                password = fs.cat_file("op://Personal/GitHub/password")
                website = fs.cat_file("op://Personal/GitHub/website")

        assert username == b"alice"
        assert password == b"s3cr3t"
        assert website == b"https://github.com"
        warned_urls = [r.message for r in caplog.records]
        assert any("op://Personal/GitHub/username" in m for m in warned_urls)
        assert any("op://Personal/GitHub/password" in m for m in warned_urls)
        assert any("op://Personal/GitHub/website" in m for m in warned_urls)

    def test_field_not_in_item_raises_file_not_found(self, fs, caplog):
        with caplog.at_level(logging.WARNING, logger="fsspec_1password"):
            with _patch_run({("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON}):
                with pytest.raises(FileNotFoundError, match="nonexistent"):
                    fs.cat_file("op://Personal/GitHub/nonexistent")
        assert any("op://Personal/GitHub/nonexistent" in r.message for r in caplog.records)

    def test_signout_only_once_even_if_same_field_read_again(self, fs, caplog):
        """Re-reading the same field after caching must not trigger a second signout."""
        with caplog.at_level(logging.WARNING, logger="fsspec_1password"):
            with _patch_run({("item", "get", "GitHub", "--vault", "Personal", "--format=json"): ITEM_JSON}) as mock_run:
                fs.cat_file("op://Personal/GitHub/password")
                fs.cat_file("op://Personal/GitHub/password")

        signout_calls = [c for c in mock_run.call_args_list if c == call("signout")]
        assert len(signout_calls) == 1
        # warning logged only once
        password_warnings = [r for r in caplog.records if "op://Personal/GitHub/password" in r.message]
        assert len(password_warnings) == 1


# ---------------------------------------------------------------------------
# fsspec integration – protocol registration
# ---------------------------------------------------------------------------


class TestFsspecIntegration:
    def test_filesystem_registered_via_entry_point(self):
        """The op:// protocol should be resolvable via fsspec.filesystem()."""
        import fsspec

        with patch("fsspec_1password._core.shutil.which", return_value="/usr/bin/op"):
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
            patch("fsspec_1password._core.shutil.which", return_value="/usr/bin/op"),
            patch("fsspec_1password._core.subprocess.run", side_effect=err),
        ):
            with pytest.raises(PermissionError, match="not signed in"):
                fs.cat_file("op://Personal/GitHub/password")

    def test_op_missing_gives_runtime_error_on_open(self):
        with patch("fsspec_1password._core.shutil.which", return_value=None):
            fs_no_op = OnePasswordFileSystem()
            with pytest.raises(RuntimeError, match="PATH"):
                fs_no_op.open("op://Personal/GitHub/password")

    def test_op_missing_gives_runtime_error_on_cat(self):
        with patch("fsspec_1password._core.shutil.which", return_value=None):
            fs_no_op = OnePasswordFileSystem()
            with pytest.raises(RuntimeError, match="PATH"):
                fs_no_op.cat_file("op://Personal/GitHub/password")


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------


class TestVersion:
    def test_version_is_string(self):
        assert isinstance(fsspec_1password.__version__, str)

    def test_version_format(self):
        parts = fsspec_1password.__version__.split(".")
        assert len(parts) >= 2
