"""Access logging for fsspec-1password.

Reading a secret is a security-relevant event, so it is recorded through two
independent sinks:

* **Console** (stderr) – human readable, verbosity controlled by
  ``OP_FSSPEC_CONSOLE_LOG_DETAIL`` (default ``2``).  This is what the person
  running the program sees.
* **File** – JSON Lines, *always* at full detail, at
  ``$XDG_STATE_HOME/fsspec-1password/audit.log`` (i.e.
  ``~/.local/state/fsspec-1password/audit.log``).  This is the audit trail;
  turning the console quiet must not weaken it.  Disable it explicitly with
  ``OP_FSSPEC_AUDIT_LOG_FILE=none``.

Each sink decides independently what to keep and how to render it: one record
is emitted per event carrying the full structured payload, and every handler
applies its own detail filter, its own deduplication and its own formatter.
That is why the same event can appear collapsed on the console and in full in
the file.

Field *values* are never written to any sink, at any detail level.

Detail levels are strictly additive – a higher number adds information, it
never removes any:

===== ================================================================
Level What is logged
===== ================================================================
0     nothing
1     items being fetched and cached
2     the above, plus each field access
3     the above, plus the code location that triggered the field access
===== ================================================================

Because logging is lazy, importing this module creates no files and installs
no handlers; both happen on the first access that is actually logged.
"""

import getpass
import inspect
import json
import logging
import os
import secrets
import socket
import sys
import threading
import time
from copy import copy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Detail levels
# ---------------------------------------------------------------------------

DETAIL_NONE = 0
DETAIL_ITEM = 1
DETAIL_FIELD = 2
DETAIL_CALLER = 3

_DETAIL_VALUES = {
    "0": DETAIL_NONE,
    "1": DETAIL_ITEM,
    "2": DETAIL_FIELD,
    "3": DETAIL_CALLER,
}

# Events, and the lowest detail level at which each becomes visible.
EVENT_ITEM_CACHED = "item_cached"
EVENT_ITEM_FETCH_FAILED = "item_fetch_failed"
EVENT_SIGNOUT_FAILED = "signout_failed"
EVENT_ACCESS_DENIED = "access_denied"
EVENT_FIELD_ACCESS = "field_access"

_EVENT_MIN_DETAIL = {
    EVENT_ITEM_CACHED: DETAIL_ITEM,
    EVENT_ITEM_FETCH_FAILED: DETAIL_ITEM,
    EVENT_SIGNOUT_FAILED: DETAIL_ITEM,
    EVENT_ACCESS_DENIED: DETAIL_ITEM,
    EVENT_FIELD_ACCESS: DETAIL_FIELD,
}

# Failures are events in time – repeating one is information, not noise.
_NEVER_DEDUPLICATED = frozenset({EVENT_ITEM_FETCH_FAILED, EVENT_SIGNOUT_FAILED})

_MAX_AUDIT_BYTES = 5 * 1024 * 1024
_AUDIT_BACKUP_COUNT = 3

# ---------------------------------------------------------------------------
# Loggers
# ---------------------------------------------------------------------------

#: Operational messages – the op commands being run, and problems with logging
#: itself.  Not the audit trail.
logger = logging.getLogger("fsspec_1password")

#: The audit trail: which secret was read, by whom, and when.
access_logger = logging.getLogger("fsspec_1password.access")

# Propagation is off on purpose.  These loggers install their own handlers so
# that access is visible without the application configuring logging at all;
# letting records propagate as well would print every access twice under any
# application that calls logging.basicConfig().  Applications that want these
# records in their own pipeline should add a handler to the logger directly.
_SINK_ATTRIBUTE = "_fsspec_1password_sink"

_lock = threading.RLock()
_handlers_ready = False
_audit_sink_failed = False
_run_id_value: str | None = None


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _console_log_detail() -> int:
    """Return how verbose the console access log should be.

    Controlled by OP_FSSPEC_CONSOLE_LOG_DETAIL. If not set, defaults to
    DETAIL_FIELD (2). This affects the console only – the file sink is
    always written at full detail.

    Raises:
        ValueError: If the env var is set to anything other than "0".."3".
    """
    value = os.environ.get("OP_FSSPEC_CONSOLE_LOG_DETAIL")
    if value is None:
        return DETAIL_FIELD
    detail = _DETAIL_VALUES.get(value.strip())
    if detail is None:
        raise ValueError(
            f"OP_FSSPEC_CONSOLE_LOG_DETAIL={value!r} is invalid. Must be '0' (nothing), '1' (items cached), "
            "'2' (items and field access) or '3' (items, field access and code location)."
        )
    return detail


def _audit_log_path() -> Path | None:
    """Return where the JSON Lines audit log is written, or None if disabled.

    Controlled by OP_FSSPEC_AUDIT_LOG_FILE: a path enables the file at that
    location, "none" (or an empty value) disables it.  When unset the XDG
    state directory is used, which is where the XDG Base Directory
    specification places logs.
    """
    value = os.environ.get("OP_FSSPEC_AUDIT_LOG_FILE")
    if value is not None:
        value = value.strip()
        if not value or value.lower() == "none":
            return None
        return Path(value).expanduser()

    state_home = os.environ.get("XDG_STATE_HOME", "").strip()
    # The XDG spec requires a non-absolute value to be treated as unset.
    base = Path(state_home) if state_home and Path(state_home).is_absolute() else Path.home() / ".local" / "state"
    return base / "fsspec-1password" / "audit.log"


def _run_id() -> str:
    """Return the identifier shared by every record from this process.

    A PID is close to useless after the fact – it is reused, and it says
    nothing about what ran.  A random per-process id ties a run's records
    together, and the run header line records what that run actually was.
    Set OP_FSSPEC_AUDIT_LOG_RUN_ID to correlate several processes of one job.
    """
    global _run_id_value
    with _lock:
        if _run_id_value is None:
            override = os.environ.get("OP_FSSPEC_AUDIT_LOG_RUN_ID", "").strip()
            _run_id_value = override or secrets.token_hex(4)
        return _run_id_value


#: Frames from these packages are the plumbing, not the caller to attribute to.
#: Matched exactly or as a package prefix – a user package merely *starting*
#: with "fsspec" is caller code and must stay visible in the audit trail.
_INTERNAL_PACKAGES = ("fsspec", "fsspec_1password")


def _is_internal(module: str) -> bool:
    return module in _INTERNAL_PACKAGES or module.startswith(tuple(f"{p}." for p in _INTERNAL_PACKAGES))


def _get_caller() -> list[str]:
    """Return the call chain that reached the library, outermost frame first.

    ``inspect.stack()`` defaults to reading a line of source for every frame,
    which is far more expensive than the frame data itself – ``stack(0)`` skips
    that.
    """
    frames = []
    for frame_info in inspect.stack(0):
        module = frame_info.frame.f_globals.get("__name__", "")
        if not module or _is_internal(module):
            continue
        path = "/".join(frame_info.filename.split("/")[-len(module.split(".")) :])
        frames.append(f"{path}:{frame_info.function}:{frame_info.lineno}")
    frames.reverse()
    return frames or ["<unknown>"]


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _url(fields: dict) -> str:
    parts = [fields.get("vault"), fields.get("item"), fields.get("field")]
    return "op://" + "/".join(p for p in parts if p)


def _render(event: str, fields: dict, detail: int) -> str:
    """Render an event as console text at the given detail level."""
    if event == EVENT_FIELD_ACCESS:
        caller = fields.get("caller")
        if detail >= DETAIL_CALLER and caller:
            return f"'{_url(fields)}' ACCESS REQUESTED BY:\n  " + "\n  -> ".join(caller)
        return f"'{_url(fields)}' ACCESS REQUESTED"
    if event == EVENT_ITEM_CACHED:
        return f"'{_url(fields)}' FETCHED AND CACHED"
    if event == EVENT_ITEM_FETCH_FAILED:
        return f"'{_url(fields)}' FETCH FAILED: {fields.get('error')}"
    if event == EVENT_SIGNOUT_FAILED:
        return f"op signout did not succeed: {fields.get('error')}"
    if event == EVENT_ACCESS_DENIED:
        return f"'{fields.get('path')}' ACCESS DENIED: {fields.get('reason')}"
    return f"{event}: {fields}"


def _dedup_key(event: str, fields: dict, detail: int) -> tuple | None:
    """Return the identity of an event at a given detail, or None to never dedup.

    The key is exactly as coarse as the rendering: two accesses that produce
    the same line collapse into one, and they stop collapsing as soon as the
    detail level makes them distinguishable.
    """
    if event in _NEVER_DEDUPLICATED:
        return None
    if event == EVENT_FIELD_ACCESS:
        key = (event, fields.get("vault"), fields.get("item"), fields.get("field"))
        if detail >= DETAIL_CALLER:
            return key + (tuple(fields.get("caller") or ()),)
        return key
    if event == EVENT_ITEM_CACHED:
        return (event, fields.get("vault"), fields.get("item"))
    if event == EVENT_ACCESS_DENIED:
        return (event, fields.get("path"))
    return (event,)


def _timestamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _event_of(record: logging.LogRecord) -> tuple[str, dict] | None:
    """Return the event and payload a record carries, or None if it has neither.

    Records logged to this logger by an application carry neither and are
    passed through untouched.
    """
    event = getattr(record, "op_event", None)
    if event is None:
        return None
    return event, getattr(record, "op_fields", {})


# ---------------------------------------------------------------------------
# Filters and formatters – one set per sink
# ---------------------------------------------------------------------------


class _DetailFilter(logging.Filter):
    """Drop records that are below this sink's detail level."""

    def __init__(self, detail: Callable[[], int]) -> None:
        super().__init__()
        self._detail = detail

    def filter(self, record: logging.LogRecord) -> bool:
        carried = _event_of(record)
        if carried is None:
            return True
        return _EVENT_MIN_DETAIL.get(carried[0], DETAIL_ITEM) <= self._detail()


class _DedupFilter(logging.Filter):
    """Emit each distinct event once per sink, at that sink's detail level."""

    def __init__(self, detail: Callable[[], int]) -> None:
        super().__init__()
        self._detail = detail
        self._seen: set[tuple] = set()

    def filter(self, record: logging.LogRecord) -> bool:
        carried = _event_of(record)
        if carried is None:
            return True
        key = _dedup_key(carried[0], carried[1], self._detail())
        if key is None:
            return True
        if key in self._seen:
            return False
        self._seen.add(key)
        return True


class _ConsoleFormatter(logging.Formatter):
    """Render an event as human readable text at this sink's detail level."""

    def __init__(self, detail: Callable[[], int]) -> None:
        super().__init__(fmt="%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        self._detail = detail

    def format(self, record: logging.LogRecord) -> str:
        carried = _event_of(record)
        if carried is not None:
            # Copy: the same record is handed to every handler, each of which
            # renders it its own way.
            record = copy(record)
            record.msg = _render(carried[0], carried[1], self._detail())
            record.args = ()
        return super().format(record)


class _JsonLinesFormatter(logging.Formatter):
    """Render an event as one JSON object per line.

    Structured output keeps the audit log machine readable and keeps a record
    on a single line even when it carries a whole call stack – which matters
    because several processes append to the same file.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {"ts": _timestamp(record.created), "run": _run_id()}
        carried = _event_of(record)
        if carried is None:
            payload.update(event="message", level=record.levelname, message=record.getMessage())
        else:
            payload["event"] = carried[0]
            payload.update(carried[1])
        return json.dumps(payload, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Handler setup
# ---------------------------------------------------------------------------


def _mark(handler: logging.Handler) -> logging.Handler:
    setattr(handler, _SINK_ATTRIBUTE, True)
    return handler


def _setup_operational_logger() -> None:
    logger.setLevel(logging.WARNING)
    logger.propagate = False
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt="%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(_mark(handler))


def _run_header() -> str:
    """Describe the process, so a run id can be resolved to what ran."""
    try:
        user = getpass.getuser()
    except Exception:  # pragma: no cover - no passwd entry and no env vars
        user = "<unknown>"
    try:
        host = socket.gethostname()
    except Exception:  # pragma: no cover - unusual host configuration
        host = "<unknown>"
    return json.dumps(
        {
            "ts": _timestamp(time.time()),
            "run": _run_id(),
            "event": "run_start",
            "pid": os.getpid(),
            "user": user,
            "host": host,
            "cwd": os.getcwd(),
            "argv": list(sys.argv),
        },
        ensure_ascii=False,
        default=str,
    )


def _rotate(path: Path) -> None:
    """Rotate the log if it has grown too large, before it is opened.

    Rotating only at open time keeps concurrent writers safe: appends from
    several processes interleave harmlessly, but a rotation performed while
    others are writing does not.
    """
    try:
        if not path.exists() or path.stat().st_size < _MAX_AUDIT_BYTES:
            return
        oldest = path.with_name(f"{path.name}.{_AUDIT_BACKUP_COUNT}")
        if oldest.exists():
            oldest.unlink()
        for index in range(_AUDIT_BACKUP_COUNT - 1, 0, -1):
            backup = path.with_name(f"{path.name}.{index}")
            if backup.exists():
                backup.replace(path.with_name(f"{path.name}.{index + 1}"))
        path.replace(path.with_name(f"{path.name}.1"))
    except OSError:  # pragma: no cover - rotation is best effort
        pass


def _build_audit_handler(path: Path) -> logging.Handler:
    """Open the audit log, creating it private to the user."""
    path.parent.mkdir(parents=True, exist_ok=True)
    _chmod(path.parent, 0o700)
    _rotate(path)
    # Create with restrictive permissions before anything is written to it.
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600))
    _chmod(path, 0o600)
    with open(path, "a", encoding="utf-8") as stream:
        stream.write(_run_header() + "\n")

    handler = logging.FileHandler(path, mode="a", encoding="utf-8")
    handler.setFormatter(_JsonLinesFormatter())
    handler.addFilter(_DetailFilter(lambda: DETAIL_CALLER))
    handler.addFilter(_DedupFilter(lambda: DETAIL_CALLER))
    return _mark(handler)


def _chmod(path: Path, mode: int) -> None:
    """Tighten permissions, tolerating filesystems that do not support it."""
    try:
        os.chmod(path, mode)
    except OSError:  # pragma: no cover - e.g. Windows or an exotic filesystem
        pass


def _ensure_handlers() -> None:
    """Install the sinks, once, on first use."""
    global _handlers_ready, _audit_sink_failed
    with _lock:
        if _handlers_ready:
            return
        _handlers_ready = True

        access_logger.setLevel(logging.WARNING)
        access_logger.propagate = False

        console = logging.StreamHandler()
        console.setFormatter(_ConsoleFormatter(_console_log_detail))
        console.addFilter(_DetailFilter(_console_log_detail))
        console.addFilter(_DedupFilter(_console_log_detail))
        access_logger.addHandler(_mark(console))

        path = _audit_log_path()
        if path is None:
            return
        try:
            access_logger.addHandler(_build_audit_handler(path))
        except Exception as exc:
            # A log that cannot be written must never stop a secret being read.
            _audit_sink_failed = True
            logger.warning("Could not open the access log file '%s', logging to the console only: %s", path, exc)


def reset() -> None:
    """Tear down the sinks so that configuration changes take effect.

    Handlers capture their configuration – and ``sys.stderr`` – when they are
    built.  Call this after changing any OP_FSSPEC_* logging variable within a
    running process.  Deduplication state is discarded too, so events already
    reported will be reported again.
    """
    global _handlers_ready, _audit_sink_failed, _run_id_value
    with _lock:
        for target in (logger, access_logger):
            for handler in list(target.handlers):
                if getattr(handler, _SINK_ATTRIBUTE, False):
                    target.removeHandler(handler)
                    handler.close()
        _handlers_ready = False
        _audit_sink_failed = False
        _run_id_value = None
        _setup_operational_logger()


# ---------------------------------------------------------------------------
# Emitting
# ---------------------------------------------------------------------------


def _foreign_handlers() -> bool:
    """True if an application attached its own handler to the access logger."""
    return any(not getattr(h, _SINK_ATTRIBUTE, False) for h in access_logger.handlers)


def _effective_detail() -> int:
    """The highest detail any sink will use – below this, nothing is computed.

    Always calls :func:`_console_log_detail` so that a malformed
    OP_FSSPEC_CONSOLE_LOG_DETAIL is reported at the point of the access rather
    than silently ignored.
    """
    detail = _console_log_detail()
    if _foreign_handlers():
        return DETAIL_CALLER
    if _audit_log_path() is not None and not _audit_sink_failed:
        return DETAIL_CALLER
    return detail


def _emit(event: str, **fields: Any) -> None:
    detail = _effective_detail()
    if _EVENT_MIN_DETAIL[event] > detail:
        return
    if event == EVENT_FIELD_ACCESS and detail >= DETAIL_CALLER:
        fields["caller"] = _get_caller()
    _ensure_handlers()
    # The rendered message is what a handler attached by an application sees;
    # our own sinks re-render from op_fields at their own detail level.
    access_logger.warning(
        "%s",
        _render(event, fields, DETAIL_CALLER),
        extra={"op_event": event, "op_fields": fields},
    )


def log_field_access(vault: str, item: str, field: str) -> None:
    """Record that a field value was asked for.

    Emitted *before* the value is looked up, so that a read still leaves a
    trace when it goes on to fail – a denied authorisation, a field that does
    not exist, or a process killed while the prompt was open.  The outcome is
    reported separately, which is why this event is rendered as a request
    rather than as a completed access.
    """
    _emit(EVENT_FIELD_ACCESS, vault=vault, item=item, field=field)


def log_item_cached(vault: str, item: str) -> None:
    """Record that an item was fetched and cached.

    This is the internal event behind an access: it maps one to one onto an
    ``op item get`` call, and therefore onto one authorisation prompt.  It has
    no caller – it is triggered by the cache, not by application code.
    """
    _emit(EVENT_ITEM_CACHED, vault=vault, item=item)


def log_item_fetch_failed(vault: str, item: str, error: BaseException) -> None:
    """Record a failed attempt to fetch an item."""
    _emit(EVENT_ITEM_FETCH_FAILED, vault=vault, item=item, error=str(error))


def log_signout_failed(error: BaseException) -> None:
    """Record that op signout did not succeed – the CLI may still be signed in."""
    _emit(EVENT_SIGNOUT_FAILED, error=str(error))


def log_access_denied(path: str, reason: str) -> None:
    """Record a rejected read – an attempt to reach something not readable."""
    _emit(EVENT_ACCESS_DENIED, path=path, reason=reason)


_setup_operational_logger()
