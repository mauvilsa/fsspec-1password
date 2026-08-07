"""Tests for fsspec_1password._logging – the console and file access log sinks."""

import logging
import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from fsspec_1password import _logging
from fsspec_1password._logging import (
    DETAIL_CALLER,
    DETAIL_FIELD,
    DETAIL_ITEM,
    DETAIL_NONE,
    _audit_log_path,
    _console_log_detail,
    _get_caller,
    _run_id,
    access_logger,
    logger,
)

from .conftest import AWS_GET, GITHUB_GET, ITEM_JSON, ITEM_JSON_AWS, access_records, json_lines, patch_run, records


@pytest.fixture
def audit_log(tmp_path, monkeypatch):
    """Enable the file sink, pointed at a tmp_path."""
    path = tmp_path / "logs" / "audit.log"
    monkeypatch.setenv("OP_FSSPEC_AUDIT_LOG_FILE", str(path))
    _logging.reset()
    return path


def _fixed_caller(*frames):
    """Patch the caller inspection with a fixed stack (outermost first)."""
    return patch("fsspec_1password._logging._get_caller", return_value=list(frames))


# ---------------------------------------------------------------------------
# OP_FSSPEC_CONSOLE_LOG_DETAIL parsing
# ---------------------------------------------------------------------------


class TestAccessLogDetailParsing:
    def test_defaults_to_field_detail(self, monkeypatch):
        """The console default is 2 – item and field access, no caller."""
        monkeypatch.delenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", raising=False)
        assert _console_log_detail() == DETAIL_FIELD == 2

    @pytest.mark.parametrize("value,expected", [("0", 0), ("1", 1), ("2", 2), ("3", 3)])
    def test_valid_levels(self, monkeypatch, value, expected):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", value)
        assert _console_log_detail() == expected

    @pytest.mark.parametrize("value,expected", [(" 0 ", 0), ("\t2\n", 2)])
    def test_surrounding_whitespace_ignored(self, monkeypatch, value, expected):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", value)
        assert _console_log_detail() == expected

    @pytest.mark.parametrize("value", ["true", "false", "TRUE", "", "4", "-1", "abc", "1.0", "01"])
    def test_invalid_values_rejected(self, monkeypatch, value):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", value)
        with pytest.raises(ValueError, match="OP_FSSPEC_CONSOLE_LOG_DETAIL.*invalid.*0.*1.*2.*3"):
            _console_log_detail()

    @pytest.mark.parametrize("value", ["true", "false", "", "4"])
    def test_invalid_value_raises_on_access(self, fs, monkeypatch, value):
        """A bad value surfaces at the point of the read, not silently ignored."""
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", value)
        with pytest.raises(ValueError, match="OP_FSSPEC_CONSOLE_LOG_DETAIL.*invalid.*0.*1.*2.*3"):
            with patch_run({GITHUB_GET: ITEM_JSON}):
                fs.cat_file("op://Personal/GitHub/password")


# ---------------------------------------------------------------------------
# OP_FSSPEC_AUDIT_LOG_FILE path resolution
# ---------------------------------------------------------------------------


class TestLogFilePathResolution:
    def test_default_is_xdg_state_home(self, monkeypatch):
        monkeypatch.delenv("OP_FSSPEC_AUDIT_LOG_FILE", raising=False)
        monkeypatch.delenv("XDG_STATE_HOME", raising=False)
        assert _audit_log_path() == Path.home() / ".local" / "state" / "fsspec-1password" / "audit.log"

    def test_xdg_state_home_honoured(self, monkeypatch, tmp_path):
        monkeypatch.delenv("OP_FSSPEC_AUDIT_LOG_FILE", raising=False)
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
        assert _audit_log_path() == tmp_path / "fsspec-1password" / "audit.log"

    def test_relative_xdg_state_home_ignored(self, monkeypatch):
        """The XDG spec says a non-absolute value must be treated as unset."""
        monkeypatch.delenv("OP_FSSPEC_AUDIT_LOG_FILE", raising=False)
        monkeypatch.setenv("XDG_STATE_HOME", "relative/state")
        assert _audit_log_path() == Path.home() / ".local" / "state" / "fsspec-1password" / "audit.log"

    def test_explicit_path(self, monkeypatch, tmp_path):
        monkeypatch.setenv("OP_FSSPEC_AUDIT_LOG_FILE", str(tmp_path / "my.log"))
        assert _audit_log_path() == tmp_path / "my.log"

    def test_tilde_expanded(self, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_AUDIT_LOG_FILE", "~/audit.log")
        assert _audit_log_path() == Path.home() / "audit.log"

    @pytest.mark.parametrize("value", ["none", "NONE", " none ", "", "   "])
    def test_disabled_values(self, monkeypatch, value):
        monkeypatch.setenv("OP_FSSPEC_AUDIT_LOG_FILE", value)
        assert _audit_log_path() is None


# ---------------------------------------------------------------------------
# Console detail levels – strictly additive
# ---------------------------------------------------------------------------


class TestConsoleDetail0:
    def test_nothing_logged(self, fs, console, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "0")
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")
        assert records(console) == []

    def test_still_caches(self, fs, console, monkeypatch):
        """With logging off, caching must still work."""
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "0")
        with patch_run({GITHUB_GET: ITEM_JSON}) as mock_run:
            fs.cat_file("op://Personal/GitHub/username")
            after_first = mock_run.call_count
            fs.cat_file("op://Personal/GitHub/password")
            after_second = mock_run.call_count

        assert after_second == after_first
        assert records(console) == []


class TestConsoleDetail1:
    def test_logs_item_only(self, fs, console, monkeypatch):
        """Level 1 reports the item being cached – no field name, no caller."""
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "1")
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        assert len(records(console)) == 1
        (line,) = records(console)
        assert "'op://Personal/GitHub'" in line
        assert "CACHED" in line
        assert "password" not in line
        assert "ACCESS REQUESTED" not in line
        assert "\n" not in line

    def test_two_fields_of_same_item_log_once(self, fs, console, monkeypatch):
        """The item is fetched once, so it is reported once."""
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "1")
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/username")
            fs.cat_file("op://Personal/GitHub/password")

        assert len(records(console)) == 1

    def test_different_items_log_separately(self, fs, console, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "1")
        with patch_run({GITHUB_GET: ITEM_JSON, AWS_GET: ITEM_JSON_AWS}):
            fs.cat_file("op://Personal/GitHub/password")
            fs.cat_file("op://Work/AWS/access_key")

        lines = records(console)
        assert len(lines) == 2
        assert any("op://Personal/GitHub'" in line for line in lines)
        assert any("op://Work/AWS'" in line for line in lines)

    def test_missing_field_still_logs_item_only(self, fs, console, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "1")
        with patch_run({GITHUB_GET: ITEM_JSON}):
            with pytest.raises(FileNotFoundError):
                fs.cat_file("op://Personal/GitHub/nonexistent")

        assert len(records(console)) == 1
        assert "nonexistent" not in records(console)[0]


class TestConsoleDetail2:
    def test_adds_field_access_to_item_line(self, fs, console, monkeypatch):
        """Level 2 keeps the item line from level 1 and adds the field line."""
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "2")
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        lines = records(console)
        assert len(lines) == 2
        assert any("'op://Personal/GitHub/password' ACCESS REQUESTED" in line for line in lines)
        assert any("'op://Personal/GitHub'" in line and "CACHED" in line for line in lines)
        assert not any("ACCESS REQUESTED BY" in line for line in lines)

    def test_is_the_default(self, fs, console, monkeypatch):
        monkeypatch.delenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", raising=False)
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        lines = records(console)
        assert len(lines) == 2
        assert any("'op://Personal/GitHub/password' ACCESS REQUESTED" in line for line in lines)
        assert not any("ACCESS REQUESTED BY" in line for line in lines)

    def test_field_access_precedes_item_cached(self, fs, console, monkeypatch):
        """The field read is the cause of the fetch, so it is logged first."""
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "2")
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        lines = records(console)
        assert "ACCESS REQUESTED" in lines[0]
        assert "CACHED" in lines[1]

    def test_two_fields_log_separately_but_item_once(self, fs, console, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "2")
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/username")
            fs.cat_file("op://Personal/GitHub/password")

        lines = records(console)
        assert len([line for line in lines if "ACCESS REQUESTED" in line]) == 2
        assert len([line for line in lines if "CACHED" in line]) == 1

    def test_same_field_twice_logs_once(self, fs, console, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "2")
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")
            fs.cat_file("op://Personal/GitHub/password")

        assert len([line for line in records(console) if "ACCESS REQUESTED" in line]) == 1

    def test_caller_is_not_inspected(self, fs, console, monkeypatch):
        """Walking the stack is expensive – skip it when no sink needs it."""
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "2")
        with patch("fsspec_1password._logging._get_caller") as mock_caller:
            with patch_run({GITHUB_GET: ITEM_JSON}):
                fs.cat_file("op://Personal/GitHub/password")

        mock_caller.assert_not_called()


class TestConsoleDetail3:
    def test_adds_caller_to_field_line(self, fs, console, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "3")
        with _fixed_caller("my_app/main.py:main:3", "my_app/config.py:load:12"):
            with patch_run({GITHUB_GET: ITEM_JSON}):
                fs.cat_file("op://Personal/GitHub/password")

        lines = records(console)
        assert len(lines) == 2
        field_line = next(line for line in lines if "ACCESS REQUESTED" in line)
        assert "'op://Personal/GitHub/password' ACCESS REQUESTED BY:" in field_line
        assert "  my_app/main.py:main:3\n  -> my_app/config.py:load:12" in field_line

    def test_item_line_never_has_a_caller(self, fs, console, monkeypatch):
        """Caching is internal – there is no meaningful caller to attribute it to."""
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "3")
        with _fixed_caller("my_app/config.py:load:12"):
            with patch_run({GITHUB_GET: ITEM_JSON}):
                fs.cat_file("op://Personal/GitHub/password")

        item_line = next(line for line in records(console) if "CACHED" in line)
        assert "BY" not in item_line
        assert "my_app" not in item_line
        assert "\n" not in item_line

    def test_same_field_same_caller_logs_once(self, fs, console, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "3")
        with _fixed_caller("my_module.py:main:12"):
            with patch_run({GITHUB_GET: ITEM_JSON}):
                fs.cat_file("op://Personal/GitHub/password")
                fs.cat_file("op://Personal/GitHub/password")

        assert len([line for line in records(console) if "ACCESS REQUESTED" in line]) == 1

    def test_same_field_different_caller_logs_twice(self, fs, console, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "3")
        with patch("fsspec_1password._logging._get_caller", side_effect=[["a.py:main:1"], ["b.py:main:2"]]):
            with patch_run({GITHUB_GET: ITEM_JSON}):
                fs.cat_file("op://Personal/GitHub/password")
                fs.cat_file("op://Personal/GitHub/password")

        text = console.getvalue()
        assert len([line for line in records(console) if "ACCESS REQUESTED" in line]) == 2
        assert "a.py:main:1" in text
        assert "b.py:main:2" in text


class TestDetailLevelsAreAdditive:
    """Each level must be a superset of the one below it."""

    @pytest.mark.parametrize("detail", ["1", "2", "3"])
    def test_item_line_present_at_every_level_above_zero(self, fs, console, monkeypatch, detail):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", detail)
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        assert any("CACHED" in line for line in records(console))

    @pytest.mark.parametrize("detail", ["2", "3"])
    def test_field_line_present_at_level_2_and_above(self, fs, console, monkeypatch, detail):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", detail)
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        assert any("ACCESS REQUESTED" in line for line in records(console))


# ---------------------------------------------------------------------------
# The item event tracks the actual fetch, not every access
# ---------------------------------------------------------------------------


class TestItemCachedEvent:
    def test_not_emitted_when_served_from_cache(self, fs, console, monkeypatch):
        """One item line per op item get – i.e. per authorisation prompt."""
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "2")
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/username")
            fs.cat_file("op://Personal/GitHub/password")
            fs.cat_file("op://Personal/GitHub/website")

        assert len([line for line in records(console) if "CACHED" in line]) == 1

    def test_not_emitted_when_fetch_fails(self, fs, console, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "2")

        def _fake_run(*args, **kwargs):
            if args[:2] == ("item", "get"):
                raise PermissionError("op CLI returned non-zero exit code 1: not signed in")
            return ""

        with patch("fsspec_1password._core._run_op", side_effect=_fake_run):
            with pytest.raises(PermissionError):
                fs.cat_file("op://Personal/GitHub/password")

        assert not any("CACHED" in line for line in records(console))


# ---------------------------------------------------------------------------
# Failure events
# ---------------------------------------------------------------------------


class TestFailureEvents:
    def test_item_fetch_failure_logged(self, fs, console, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "1")

        def _fake_run(*args, **kwargs):
            if args[:2] == ("item", "get"):
                raise PermissionError("op CLI returned non-zero exit code 1: not signed in")
            return ""

        with patch("fsspec_1password._core._run_op", side_effect=_fake_run):
            with pytest.raises(PermissionError):
                fs.cat_file("op://Personal/GitHub/password")

        text = console.getvalue()
        assert "'op://Personal/GitHub' FETCH FAILED" in text
        assert "not signed in" in text

    def test_fetch_failures_are_not_deduplicated(self, fs, console, monkeypatch):
        """Each failed attempt is a separate event in time."""
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "1")

        def _fake_run(*args, **kwargs):
            if args[:2] == ("item", "get"):
                raise PermissionError("op CLI returned non-zero exit code 1: not signed in")
            return ""

        with patch("fsspec_1password._core._run_op", side_effect=_fake_run):
            for _ in range(2):
                with pytest.raises(PermissionError):
                    fs.cat_file("op://Personal/GitHub/password")

        assert len([line for line in records(console) if "FETCH FAILED" in line]) == 2

    def test_signout_failure_logged(self, fs, console, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "1")

        def _fake_run(*args, **kwargs):
            if args[:2] == ("item", "get"):
                raise PermissionError("op CLI returned non-zero exit code 1: not signed in")
            raise PermissionError("op CLI returned non-zero exit code 1: signout failed")

        with patch("fsspec_1password._core._run_op", side_effect=_fake_run):
            with pytest.raises(PermissionError, match="not signed in"):
                fs.cat_file("op://Personal/GitHub/password")

        assert "signout failed" in console.getvalue()

    @pytest.mark.parametrize("path", ["op://", "op://Personal", "op://Personal/GitHub"])
    def test_partial_path_logged_as_denied(self, fs, console, monkeypatch, path):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "1")
        with pytest.raises(PermissionError):
            fs.cat_file(path)

        text = console.getvalue()
        assert "ACCESS DENIED" in text
        assert path in text

    def test_denied_paths_deduplicated(self, fs, console, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "1")
        for _ in range(3):
            with pytest.raises(PermissionError):
                fs.cat_file("op://Personal/GitHub")

        assert len([line for line in records(console) if "ACCESS DENIED" in line]) == 1

    def test_denied_not_logged_at_level_0(self, fs, console, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "0")
        with pytest.raises(PermissionError):
            fs.cat_file("op://Personal/GitHub")

        assert records(console) == []


# ---------------------------------------------------------------------------
# File sink
# ---------------------------------------------------------------------------


class TestFileSink:
    def test_file_created_on_first_access(self, fs, audit_log):
        assert not audit_log.exists()
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")
        assert audit_log.exists()

    def test_import_alone_creates_nothing(self, tmp_path, monkeypatch):
        """Creating files in the home directory as an import side effect is invasive."""
        path = tmp_path / "logs" / "audit.log"
        monkeypatch.setenv("OP_FSSPEC_AUDIT_LOG_FILE", str(path))
        _logging.reset()
        assert not path.exists()
        assert not path.parent.exists()

    def test_nothing_written_without_an_access(self, fs, audit_log):
        """The run header is only written once there is something to record."""
        with pytest.raises(NotADirectoryError):
            fs.ls("op://Personal/GitHub/password")
        assert not audit_log.exists()

    def test_lines_are_valid_json(self, fs, audit_log):
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        entries = json_lines(audit_log)
        assert len(entries) >= 2
        assert all(isinstance(e, dict) for e in entries)

    def test_run_header_is_first(self, fs, audit_log):
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        header = json_lines(audit_log)[0]
        assert header["event"] == "run_start"
        assert header["pid"] == os.getpid()
        assert header["cwd"] == os.getcwd()
        assert isinstance(header["argv"], list)
        assert header["user"]
        assert header["host"]
        assert header["run"] == _run_id()

    def test_run_header_written_once(self, fs, audit_log):
        with patch_run({GITHUB_GET: ITEM_JSON, AWS_GET: ITEM_JSON_AWS}):
            fs.cat_file("op://Personal/GitHub/password")
            fs.cat_file("op://Work/AWS/access_key")

        assert len([e for e in json_lines(audit_log) if e["event"] == "run_start"]) == 1

    def test_every_line_carries_the_run_id(self, fs, audit_log):
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        entries = json_lines(audit_log)
        assert {e["run"] for e in entries} == {_run_id()}

    def test_run_id_can_be_overridden(self, fs, audit_log, monkeypatch):
        """Lets several processes of one job be correlated under a single id."""
        monkeypatch.setenv("OP_FSSPEC_AUDIT_LOG_RUN_ID", "my-pipeline-run")
        _logging.reset()
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        assert {e["run"] for e in json_lines(audit_log)} == {"my-pipeline-run"}

    def test_run_id_is_stable_within_a_process(self):
        assert _run_id() == _run_id()

    def test_records_are_structured(self, fs, audit_log):
        with _fixed_caller("my_app/main.py:main:3", "my_app/config.py:load:12"):
            with patch_run({GITHUB_GET: ITEM_JSON}):
                fs.cat_file("op://Personal/GitHub/password")

        entries = json_lines(audit_log)
        field = next(e for e in entries if e["event"] == "field_access")
        assert field["vault"] == "Personal"
        assert field["item"] == "GitHub"
        assert field["field"] == "password"
        assert field["caller"] == ["my_app/main.py:main:3", "my_app/config.py:load:12"]
        assert field["ts"].startswith("20")

        item = next(e for e in entries if e["event"] == "item_cached")
        assert item["vault"] == "Personal"
        assert item["item"] == "GitHub"
        assert "caller" not in item

    @pytest.mark.parametrize("detail", ["0", "1", "2", "3"])
    def test_always_full_detail_regardless_of_console(self, fs, audit_log, monkeypatch, detail):
        """The file is the audit trail – console verbosity must not weaken it."""
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", detail)
        with _fixed_caller("my_app/config.py:load:12"):
            with patch_run({GITHUB_GET: ITEM_JSON}):
                fs.cat_file("op://Personal/GitHub/password")

        events = [e["event"] for e in json_lines(audit_log)]
        assert "field_access" in events
        assert "item_cached" in events
        field = next(e for e in json_lines(audit_log) if e["event"] == "field_access")
        assert field["caller"] == ["my_app/config.py:load:12"]

    def test_caller_inspected_even_when_console_is_quiet(self, fs, audit_log, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "0")
        with patch("fsspec_1password._logging._get_caller", return_value=["x.py:f:1"]) as mock_caller:
            with patch_run({GITHUB_GET: ITEM_JSON}):
                fs.cat_file("op://Personal/GitHub/password")

        mock_caller.assert_called()

    def test_deduplication_is_per_sink(self, fs, audit_log, monkeypatch):
        """Console at detail 2 collapses two callers; the file must keep both."""
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "2")
        with patch("fsspec_1password._logging._get_caller", side_effect=[["a.py:main:1"], ["b.py:main:2"]]):
            with patch_run({GITHUB_GET: ITEM_JSON}):
                fs.cat_file("op://Personal/GitHub/password")
                fs.cat_file("op://Personal/GitHub/password")

        assert len([e for e in json_lines(audit_log) if e["event"] == "field_access"]) == 2

    def test_failures_recorded(self, fs, audit_log):
        def _fake_run(*args, **kwargs):
            if args[:2] == ("item", "get"):
                raise PermissionError("op CLI returned non-zero exit code 1: not signed in")
            return ""

        with patch("fsspec_1password._core._run_op", side_effect=_fake_run):
            with pytest.raises(PermissionError):
                fs.cat_file("op://Personal/GitHub/password")

        failure = next(e for e in json_lines(audit_log) if e["event"] == "item_fetch_failed")
        assert failure["vault"] == "Personal"
        assert "not signed in" in failure["error"]

    def test_directory_and_file_permissions_are_private(self, fs, audit_log):
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        assert stat.S_IMODE(audit_log.stat().st_mode) == 0o600
        assert stat.S_IMODE(audit_log.parent.stat().st_mode) == 0o700

    def test_pre_existing_wide_permissions_are_tightened(self, fs, audit_log):
        audit_log.parent.mkdir(parents=True)
        audit_log.write_text("")
        os.chmod(audit_log, 0o644)
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        assert stat.S_IMODE(audit_log.stat().st_mode) == 0o600

    def test_appends_to_existing_file(self, fs, audit_log):
        audit_log.parent.mkdir(parents=True)
        audit_log.write_text('{"event": "previous"}\n')
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        assert json_lines(audit_log)[0] == {"event": "previous"}

    def test_disabled_writes_nothing(self, fs, tmp_path, monkeypatch):
        path = tmp_path / "logs" / "audit.log"
        monkeypatch.setenv("OP_FSSPEC_AUDIT_LOG_FILE", "none")
        _logging.reset()
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        assert not path.exists()


class TestFileSinkRotation:
    def test_rotates_on_open_when_oversized(self, fs, audit_log, monkeypatch):
        monkeypatch.setattr(_logging, "_MAX_AUDIT_BYTES", 100)
        audit_log.parent.mkdir(parents=True)
        audit_log.write_text("x" * 200)

        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        assert audit_log.with_suffix(".log.1").read_text() == "x" * 200
        assert json_lines(audit_log)[0]["event"] == "run_start"

    def test_older_backups_shift_along(self, fs, audit_log, monkeypatch):
        monkeypatch.setattr(_logging, "_MAX_AUDIT_BYTES", 100)
        audit_log.parent.mkdir(parents=True)
        audit_log.write_text("current" + "x" * 200)
        audit_log.with_suffix(".log.1").write_text("older")

        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        assert audit_log.with_suffix(".log.2").read_text() == "older"
        assert audit_log.with_suffix(".log.1").read_text().startswith("current")

    def test_oldest_backup_discarded(self, fs, audit_log, monkeypatch):
        monkeypatch.setattr(_logging, "_MAX_AUDIT_BYTES", 100)
        monkeypatch.setattr(_logging, "_AUDIT_BACKUP_COUNT", 2)
        audit_log.parent.mkdir(parents=True)
        audit_log.write_text("x" * 200)
        audit_log.with_suffix(".log.1").write_text("one")
        audit_log.with_suffix(".log.2").write_text("two")

        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        assert audit_log.with_suffix(".log.2").read_text() == "one"
        assert not audit_log.with_suffix(".log.3").exists()

    def test_no_rotation_below_threshold(self, fs, audit_log, monkeypatch):
        monkeypatch.setattr(_logging, "_MAX_AUDIT_BYTES", 10_000)
        audit_log.parent.mkdir(parents=True)
        audit_log.write_text('{"event": "previous"}\n')

        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        assert not audit_log.with_suffix(".log.1").exists()


class TestFileSinkFailures:
    """A log file that cannot be written must never break reading a secret."""

    def test_unwritable_path_does_not_raise(self, fs, tmp_path, monkeypatch):
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")
        monkeypatch.setenv("OP_FSSPEC_AUDIT_LOG_FILE", str(blocker / "audit.log"))
        _logging.reset()

        with patch_run({GITHUB_GET: ITEM_JSON}):
            assert fs.cat_file("op://Personal/GitHub/password") == b"s3cr3t"

    def test_unwritable_path_warns_once(self, fs, console, tmp_path, monkeypatch):
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")
        monkeypatch.setenv("OP_FSSPEC_AUDIT_LOG_FILE", str(blocker / "audit.log"))
        _logging.reset()

        with patch_run({GITHUB_GET: ITEM_JSON, AWS_GET: ITEM_JSON_AWS}):
            fs.cat_file("op://Personal/GitHub/password")
            fs.cat_file("op://Work/AWS/access_key")

        warnings = [line for line in records(console) if "access log file" in line]
        assert len(warnings) == 1
        assert str(blocker / "audit.log") in warnings[0]

    def test_console_still_works_when_file_fails(self, fs, console, tmp_path, monkeypatch):
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")
        monkeypatch.setenv("OP_FSSPEC_AUDIT_LOG_FILE", str(blocker / "audit.log"))
        _logging.reset()

        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        assert any("'op://Personal/GitHub/password' ACCESS REQUESTED" in line for line in records(console))


# ---------------------------------------------------------------------------
# Secret values must never be logged
# ---------------------------------------------------------------------------


class TestNoSecretValues:
    @pytest.mark.parametrize("detail", ["0", "1", "2", "3"])
    def test_values_absent_from_both_sinks(self, fs, console, audit_log, monkeypatch, detail):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", detail)
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")
            fs.cat_file("op://Personal/GitHub/username")

        assert "s3cr3t" not in console.getvalue()
        assert "alice" not in console.getvalue()
        assert "s3cr3t" not in audit_log.read_text()
        assert "alice" not in audit_log.read_text()

    def test_debug_logging_does_not_leak_values(self, fs, console, audit_log, monkeypatch):
        """Even with the operational logger at DEBUG, values must not appear."""
        monkeypatch.setattr(logger, "level", logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)
        with patch("fsspec_1password._core.shutil.which", return_value="/usr/bin/op"):
            with patch("fsspec_1password._core.subprocess.run") as mock_run:
                mock_run.return_value.stdout = ITEM_JSON
                mock_run.return_value.returncode = 0
                fs.cat_file("op://Personal/GitHub/password")

        assert "s3cr3t" not in console.getvalue()
        assert "s3cr3t" not in audit_log.read_text()


# ---------------------------------------------------------------------------
# Logger wiring
# ---------------------------------------------------------------------------


class TestLoggerWiring:
    def test_loggers_do_not_propagate(self):
        """Propagation would double-print under any app calling basicConfig()."""
        assert logger.propagate is False
        assert access_logger.propagate is False

    def test_no_duplicate_output_with_root_handler(self, fs, console, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "2")
        root_handler = logging.StreamHandler(console)
        logging.getLogger().addHandler(root_handler)
        try:
            with patch_run({GITHUB_GET: ITEM_JSON}):
                fs.cat_file("op://Personal/GitHub/password")
        finally:
            logging.getLogger().removeHandler(root_handler)

        assert len([line for line in records(console) if "ACCESS REQUESTED" in line]) == 1

    def test_access_logger_is_separate_from_operational(self):
        assert access_logger.name == "fsspec_1password.access"
        assert access_logger is not logger

    def test_reset_removes_handlers_it_created(self, fs, console):
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")
        assert access_logger.handlers
        _logging.reset()
        assert access_logger.handlers == []

    def test_user_handlers_receive_readable_messages(self, fs, monkeypatch):
        """A plain handler attached by an application must show something useful."""
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "0")
        seen = []
        handler = logging.Handler()
        handler.emit = lambda record: seen.append(record.getMessage())
        access_logger.addHandler(handler)
        try:
            with _fixed_caller("my_app/config.py:load:12"):
                with patch_run({GITHUB_GET: ITEM_JSON}):
                    fs.cat_file("op://Personal/GitHub/password")
        finally:
            access_logger.removeHandler(handler)

        assert any("op://Personal/GitHub/password" in m for m in seen)

    def test_plain_records_pass_through_both_sinks(self, fs, console, audit_log):
        """A record an application logs to this logger must not break the sinks."""
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")
        access_logger.warning("something an application logged")

        assert "something an application logged" in console.getvalue()
        entry = next(e for e in json_lines(audit_log) if e["event"] == "message")
        assert entry["message"] == "something an application logged"
        assert entry["level"] == "WARNING"

    def test_no_handlers_created_when_everything_is_disabled(self, fs, monkeypatch):
        monkeypatch.setenv("OP_FSSPEC_CONSOLE_LOG_DETAIL", "0")
        monkeypatch.setenv("OP_FSSPEC_AUDIT_LOG_FILE", "none")
        _logging.reset()
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        assert access_logger.handlers == []


# ---------------------------------------------------------------------------
# Caller inspection
# ---------------------------------------------------------------------------


class TestGetCaller:
    def test_returns_frames_outermost_first(self):
        def inner():
            return _get_caller()

        def outer():
            return inner()

        frames = outer()
        assert isinstance(frames, list)
        assert all(isinstance(f, str) for f in frames)
        assert any(":inner:" in f for f in frames)
        assert any(":outer:" in f for f in frames)
        assert [i for i, f in enumerate(frames) if ":outer:" in f] < [i for i, f in enumerate(frames) if ":inner:" in f]

    def test_library_frames_excluded(self):
        frames = _get_caller()
        assert not any("fsspec_1password/_logging.py" in f for f in frames)

    @pytest.mark.parametrize("module", ["fsspec", "fsspec.core", "fsspec_1password", "fsspec_1password._core"])
    def test_internal_modules(self, module):
        assert _logging._is_internal(module) is True

    @pytest.mark.parametrize("module", ["fsspec_utils", "fsspecial.app", "my_app", "fsspec_1password_tests.x"])
    def test_caller_packages_merely_starting_with_fsspec_are_kept(self, module):
        """A user package whose name starts with 'fsspec' is still caller code."""
        assert _logging._is_internal(module) is False

    def test_unknown_when_no_external_frames(self):
        with patch("fsspec_1password._logging.inspect.stack", return_value=[]):
            assert _get_caller() == ["<unknown>"]


# ---------------------------------------------------------------------------
# Levels
# ---------------------------------------------------------------------------


class TestLevelConstants:
    def test_ordering(self):
        assert DETAIL_NONE < DETAIL_ITEM < DETAIL_FIELD < DETAIL_CALLER
        assert (DETAIL_NONE, DETAIL_ITEM, DETAIL_FIELD, DETAIL_CALLER) == (0, 1, 2, 3)


# ---------------------------------------------------------------------------
# Console formatting details
# ---------------------------------------------------------------------------


class TestConsoleFormat:
    def test_access_reported_at_warning_level(self, fs, console):
        """WARNING is deliberate: it makes access visible with no configuration."""
        with patch_run({GITHUB_GET: ITEM_JSON}):
            fs.cat_file("op://Personal/GitHub/password")

        assert access_records(console)
        assert all("WARNING" in line for line in access_records(console))
