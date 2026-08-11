"""Tests for fsspec_1password._core – no real op executable required.

All calls to the op CLI are intercepted via unittest.mock so the tests run
in any environment regardless of whether 1Password CLI is installed.

Access logging is covered separately in test_logging.py.
"""

import io
import json
import subprocess
from unittest.mock import call, patch

import pytest

import fsspec_1password
from fsspec_1password._core import OnePasswordFileSystem, _parse_path, _require_op, _run_op

from .conftest import AWS_GET, GITHUB_GET, ITEM_JSON, ITEM_JSON_AWS, access_records, completed, patch_run

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
            patch("fsspec_1password._core.subprocess.run", return_value=completed('{"ok": true}')) as mock_run,
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

    def test_field_info(self, fs, console):
        with patch_run({GITHUB_GET: ITEM_JSON}):
            info = fs.info("op://Personal/GitHub/password")
        assert info["type"] == "file"
        assert info["size"] == len(b"s3cr3t")
        assert any("op://Personal/GitHub/password" in r for r in access_records(console))

    def test_field_not_found(self, fs, console):
        with patch_run({GITHUB_GET: ITEM_JSON}):
            with pytest.raises(FileNotFoundError):
                fs.info("op://Personal/GitHub/nonexistent_field")
        assert any("op://Personal/GitHub/nonexistent_field" in r for r in access_records(console))


# ---------------------------------------------------------------------------
# open / cat_file
# ---------------------------------------------------------------------------


class TestOpen:
    def test_read_field_value(self, fs, console):
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fobj = fs.open("op://Personal/GitHub/password", mode="rb")
        assert isinstance(fobj, io.IOBase)
        content = fobj.read()
        assert content == b"s3cr3t"
        assert any("op://Personal/GitHub/password" in r for r in access_records(console))

    def test_open_returns_bytes(self, fs, console):
        with patch_run({GITHUB_GET: ITEM_JSON}):
            with fs.open("op://Personal/GitHub/username") as f:
                data = f.read()
        assert data == b"alice"
        assert any("op://Personal/GitHub/username" in r for r in access_records(console))

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
    def test_returns_bytes(self, fs, console):
        with patch_run({GITHUB_GET: ITEM_JSON}):
            data = fs.cat_file("op://Personal/GitHub/password")
        assert data == b"s3cr3t"
        assert any("op://Personal/GitHub/password" in r for r in access_records(console))

    def test_cat_item_raises_permission_error(self, fs):
        with pytest.raises(PermissionError, match="op://Vault/Item/Field"):
            fs.cat_file("op://Personal/GitHub")


# ---------------------------------------------------------------------------
# Field caching – item fetched once, then signout, then served from cache
# ---------------------------------------------------------------------------


class TestFieldCaching:
    def test_item_loaded_once_for_multiple_fields(self, fs, console):
        """Reading two fields from the same item should only call op item get once."""
        with patch_run({GITHUB_GET: ITEM_JSON}) as mock_run:
            fs.cat_file("op://Personal/GitHub/username")
            fs.cat_file("op://Personal/GitHub/password")

        item_get_calls = [c for c in mock_run.call_args_list if c == call(*GITHUB_GET)]
        assert len(item_get_calls) == 1
        logged = access_records(console)
        assert any("op://Personal/GitHub/username" in r for r in logged)
        assert any("op://Personal/GitHub/password" in r for r in logged)

    def test_signout_called_after_item_load(self, fs):
        """op signout must be called exactly once after loading an item."""
        with patch_run({GITHUB_GET: ITEM_JSON}) as mock_run:
            fs.cat_file("op://Personal/GitHub/password")

        signout_calls = [c for c in mock_run.call_args_list if c == call("signout")]
        assert len(signout_calls) == 1

    def test_second_field_read_no_additional_op_calls(self, fs):
        """After the first field read, a second field read must not call op at all."""
        with patch_run({GITHUB_GET: ITEM_JSON}) as mock_run:
            fs.cat_file("op://Personal/GitHub/username")
            call_count_after_first = mock_run.call_count

            fs.cat_file("op://Personal/GitHub/password")
            call_count_after_second = mock_run.call_count

        assert call_count_after_second == call_count_after_first

    def test_different_items_each_trigger_separate_op_and_signout(self, fs, console):
        """Two different items must each cause one op item get and one op signout."""
        with patch_run({GITHUB_GET: ITEM_JSON, AWS_GET: ITEM_JSON_AWS}) as mock_run:
            fs.cat_file("op://Personal/GitHub/password")
            fs.cat_file("op://Work/AWS/access_key")

        signout_calls = [c for c in mock_run.call_args_list if c == call("signout")]
        assert len(signout_calls) == 2
        logged = access_records(console)
        assert any("op://Personal/GitHub/password" in r for r in logged)
        assert any("op://Work/AWS/access_key" in r for r in logged)

    def test_cached_field_values_are_correct(self, fs):
        with patch_run({GITHUB_GET: ITEM_JSON}):
            username = fs.cat_file("op://Personal/GitHub/username")
            password = fs.cat_file("op://Personal/GitHub/password")
            website = fs.cat_file("op://Personal/GitHub/website")

        assert username == b"alice"
        assert password == b"s3cr3t"
        assert website == b"https://github.com"

    def test_field_not_in_item_raises_file_not_found(self, fs, console):
        with patch_run({GITHUB_GET: ITEM_JSON}):
            with pytest.raises(FileNotFoundError, match="nonexistent"):
                fs.cat_file("op://Personal/GitHub/nonexistent")
        assert any("op://Personal/GitHub/nonexistent" in r for r in access_records(console))

    def test_signout_only_once_even_if_same_field_read_again(self, fs):
        """Re-reading the same field after caching must not trigger a second signout."""
        with patch_run({GITHUB_GET: ITEM_JSON}) as mock_run:
            fs.cat_file("op://Personal/GitHub/password")
            fs.cat_file("op://Personal/GitHub/password")

        signout_calls = [c for c in mock_run.call_args_list if c == call("signout")]
        assert len(signout_calls) == 1


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
# Signout on failure – signout must happen even when the item fetch fails
# ---------------------------------------------------------------------------


def _patch_run_item_get_failing(error: Exception, signout_error: Exception | None = None):
    """Patch _run_op so that `op item get` fails and `op signout` succeeds (or fails)."""

    def _fake_run(*args, **kwargs):
        if args[:2] == ("item", "get"):
            raise error
        if args == ("signout",):
            if signout_error is not None:
                raise signout_error
            return ""
        raise KeyError(f"Unexpected op args: {args}")

    return patch("fsspec_1password._core._run_op", side_effect=_fake_run)


class TestSignoutOnFailure:
    """Regression tests: a failed item fetch must still sign out.

    When the 1Password app itself requires a login (web page round trip), the
    `op item get` call fails with a permission error.  The user then completes
    the login, which leaves the CLI signed in.  Without a signout the next run
    reads the item with no authorisation prompt at all.
    """

    def test_signout_called_when_item_get_fails(self, fs):
        err = PermissionError("op CLI returned non-zero exit code 1: authorization prompt dismissed")
        with _patch_run_item_get_failing(err) as mock_run:
            with pytest.raises(PermissionError, match="authorization prompt dismissed"):
                fs.cat_file("op://Personal/GitHub/password")

        signout_calls = [c for c in mock_run.call_args_list if c == call("signout")]
        assert len(signout_calls) == 1

    def test_signout_called_when_item_json_is_invalid(self, fs):
        with patch_run({GITHUB_GET: "not json"}) as mock_run:
            with pytest.raises(json.JSONDecodeError):
                fs.cat_file("op://Personal/GitHub/password")

        signout_calls = [c for c in mock_run.call_args_list if c == call("signout")]
        assert len(signout_calls) == 1

    def test_failed_item_get_is_not_cached(self, fs):
        err = PermissionError("op CLI returned non-zero exit code 1: not signed in")
        with _patch_run_item_get_failing(err):
            with pytest.raises(PermissionError):
                fs.cat_file("op://Personal/GitHub/password")

        assert ("Personal", "GitHub") not in fs._item_cache

    def test_original_error_propagates_when_signout_also_fails(self, fs):
        """A failing signout must not mask the error that caused the failure."""
        err = PermissionError("op CLI returned non-zero exit code 1: not signed in")
        signout_err = PermissionError("op CLI returned non-zero exit code 1: signout failed")
        with _patch_run_item_get_failing(err, signout_error=signout_err):
            with pytest.raises(PermissionError, match="not signed in"):
                fs.cat_file("op://Personal/GitHub/password")

    def test_signout_failure_after_successful_fetch_still_raises(self, fs):
        """When the fetch succeeded, a failing signout must surface to the caller."""

        def _fake_run(*args, **kwargs):
            if args[:2] == ("item", "get"):
                return ITEM_JSON
            raise PermissionError("op CLI returned non-zero exit code 1: signout failed")

        with patch("fsspec_1password._core._run_op", side_effect=_fake_run):
            with pytest.raises(PermissionError, match="signout failed"):
                fs.cat_file("op://Personal/GitHub/password")

    def test_no_signout_on_failure_when_disabled(self, fs, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_SIGNOUT", "false")
        err = PermissionError("op CLI returned non-zero exit code 1: not signed in")
        with _patch_run_item_get_failing(err) as mock_run:
            with pytest.raises(PermissionError, match="not signed in"):
                fs.cat_file("op://Personal/GitHub/password")

        signout_calls = [c for c in mock_run.call_args_list if c == call("signout")]
        assert len(signout_calls) == 0

    def test_signout_on_failure_via_subprocess(self, fs):
        """End-to-end at the subprocess level: `op signout` is actually spawned."""
        item_get_error = subprocess.CalledProcessError(
            1, "op", stderr="[ERROR] 2024/01/01 you are not currently signed in"
        )
        calls = []

        def _fake_subprocess_run(cmd, **kwargs):
            calls.append(cmd)
            if "signout" in cmd:
                return completed("")
            raise item_get_error

        with (
            patch("fsspec_1password._core.shutil.which", return_value="/usr/bin/op"),
            patch("fsspec_1password._core.subprocess.run", side_effect=_fake_subprocess_run),
        ):
            with pytest.raises(PermissionError, match="not currently signed in"):
                fs.cat_file("op://Personal/GitHub/password")

        assert calls == [
            ["/usr/bin/op", "item", "get", "GitHub", "--vault", "Personal", "--format=json"],
            ["/usr/bin/op", "signout"],
        ]

    def test_op_missing_still_raises_runtime_error(self, fs):
        """With op absent the signout attempt must not mask the RuntimeError."""
        with patch("fsspec_1password._core.shutil.which", return_value=None):
            with pytest.raises(RuntimeError, match="PATH"):
                fs.cat_file("op://Personal/GitHub/password")


# ---------------------------------------------------------------------------
# Environment variable control: signout behavior
# ---------------------------------------------------------------------------


class TestSignoutControl:
    def test_signout_called_by_default(self, fs):
        """By default (no OP_FSSPEC_SIGNOUT), op signout should be called."""
        with patch_run({GITHUB_GET: ITEM_JSON}) as mock_run:
            fs.cat_file("op://Personal/GitHub/password")

        signout_calls = [c for c in mock_run.call_args_list if c == call("signout")]
        assert len(signout_calls) == 1

    @pytest.mark.parametrize("value", ["false", "FALSE", "False"])
    def test_signout_disabled(self, fs, monkeypatch, value):
        """Case-insensitive parsing: any spelling of false disables signout."""
        monkeypatch.setenv("OP_FSSPEC_SIGNOUT", value)
        with patch_run({GITHUB_GET: ITEM_JSON}) as mock_run:
            fs.cat_file("op://Personal/GitHub/password")

        signout_calls = [c for c in mock_run.call_args_list if c == call("signout")]
        assert len(signout_calls) == 0

    @pytest.mark.parametrize("value", ["true", "TRUE", "True"])
    def test_signout_enabled(self, fs, monkeypatch, value):
        monkeypatch.setenv("OP_FSSPEC_SIGNOUT", value)
        with patch_run({GITHUB_GET: ITEM_JSON}) as mock_run:
            fs.cat_file("op://Personal/GitHub/password")

        signout_calls = [c for c in mock_run.call_args_list if c == call("signout")]
        assert len(signout_calls) == 1

    @pytest.mark.parametrize("value", ["0", "1", "", "yes", "no"])
    def test_signout_rejects_invalid_values(self, fs, monkeypatch, value):
        monkeypatch.setenv("OP_FSSPEC_SIGNOUT", value)
        with pytest.raises(ValueError, match="OP_FSSPEC_SIGNOUT.*invalid.*true.*false"):
            with patch_run({GITHUB_GET: ITEM_JSON}):
                fs.cat_file("op://Personal/GitHub/password")


# ---------------------------------------------------------------------------
# Environment variable interaction
# ---------------------------------------------------------------------------


class TestEnvVarInteraction:
    def test_both_signout_and_logging_disabled(self, fs, console, monkeypatch):
        """Both signout and logging can be disabled simultaneously."""
        monkeypatch.setenv("OP_FSSPEC_SIGNOUT", "false")
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "0")
        with patch_run({GITHUB_GET: ITEM_JSON}) as mock_run:
            fs.cat_file("op://Personal/GitHub/password")

        signout_calls = [c for c in mock_run.call_args_list if c == call("signout")]
        assert len(signout_calls) == 0
        assert access_records(console) == []

    def test_both_signout_and_logging_enabled(self, fs, console, monkeypatch):
        """Both signout and full logging can be enabled explicitly."""
        monkeypatch.setenv("OP_FSSPEC_SIGNOUT", "true")
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "3")
        with patch_run({GITHUB_GET: ITEM_JSON}) as mock_run:
            fs.cat_file("op://Personal/GitHub/password")

        signout_calls = [c for c in mock_run.call_args_list if c == call("signout")]
        assert len(signout_calls) == 1
        assert any("op://Personal/GitHub/password" in r for r in access_records(console))

    def test_signout_with_item_only_logging(self, fs, console, monkeypatch):
        """Signout still happens when access logging is reduced to item level."""
        monkeypatch.setenv("OP_FSSPEC_SIGNOUT", "true")
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "1")
        with patch_run({GITHUB_GET: ITEM_JSON}) as mock_run:
            fs.cat_file("op://Personal/GitHub/password")

        signout_calls = [c for c in mock_run.call_args_list if c == call("signout")]
        assert len(signout_calls) == 1
        logged = access_records(console)
        assert len(logged) == 1
        assert "password" not in logged[0]


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------


class TestVersion:
    def test_version_is_string(self):
        assert isinstance(fsspec_1password.__version__, str)

    def test_version_format(self):
        parts = fsspec_1password.__version__.split(".")
        assert len(parts) >= 2
