"""fsspec filesystem implementation for 1Password entries via the op CLI.

Only full ``op://Vault/Item/Field`` or ``op://Vault/Item/Section/Field`` paths
are supported for reading. Accessing ``op://``, ``op://Vault``, or
``op://Vault/Item`` raises a ``PermissionError`` – this filesystem is designed
to read specific secrets, not to facilitate exploration of entire accounts and
vaults.

When a field is first read the entire ``op://Vault/Item`` is fetched via
``op item get`` and all its fields are cached.  ``op signout`` is then run
immediately – also when the fetch failed – so that each item access requires
exactly one user authorisation.  Subsequent reads of any field belonging to the
same item are served from the in-memory cache without any CLI interaction.

Environment variables:
  OP_FSSPEC_SIGNOUT: Set to "true" or "false" (case-insensitive) to control
                      whether op signout is called after item fetch.
                      If not set, defaults to true. Any other value raises ValueError.
  OP_FSSPEC_ACCESS_LOG_DETAIL: How much detail the access log emitted at WARNING
                      level includes:
                        "0" nothing is logged;
                        "1" item access only, e.g. 'op://Vault/Item';
                        "2" item and field access, e.g. 'op://Vault/Item/Field';
                        "3" item and field access plus the code location that
                            triggered it.
                      If not set, defaults to "3". Any other value raises ValueError.
"""

import inspect
import io
import json
import logging
import os
import shutil
import subprocess
from typing import Any

from fsspec.spec import AbstractFileSystem

logger = logging.getLogger("fsspec_1password")
logger.setLevel(logging.WARNING)
handler = logging.StreamHandler()
handler.setLevel(logging.WARNING)
handler.setFormatter(logging.Formatter(fmt="%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(handler)

_PARTIAL_PATH_ERROR = (
    "fsspec-1password only supports reading specific fields. Use op://Vault/Item/Field to access a secret."
)

# OP_FSSPEC_ACCESS_LOG_DETAIL levels, from least to most detailed
ACCESS_LOG_NONE = 0
ACCESS_LOG_ITEM = 1
ACCESS_LOG_FIELD = 2
ACCESS_LOG_CALLER = 3

_ACCESS_LOG_DETAILS = {
    "0": ACCESS_LOG_NONE,
    "1": ACCESS_LOG_ITEM,
    "2": ACCESS_LOG_FIELD,
    "3": ACCESS_LOG_CALLER,
}


def _parse_bool_env(value: str | None) -> bool:
    """Strictly parse a boolean environment variable value.

    Args:
        value: Environment variable value (non-None).

    Returns:
        True for "true" (case-insensitive), False for "false" (case-insensitive).

    Raises:
        ValueError: If value is not "true" or "false" (case-insensitive).
    """
    value_lower = value.lower().strip()
    if value_lower == "true":
        return True
    if value_lower == "false":
        return False
    raise ValueError(f"Invalid boolean value: {value!r}. Expected 'true' or 'false' (case-insensitive).")


def _should_signout() -> bool:
    """Check if op signout should be called after item fetch.

    Controlled by OP_FSSPEC_SIGNOUT env var. If not set, defaults to True.
    Must be "true" or "false" (case-insensitive) if set.
    """
    value = os.environ.get("OP_FSSPEC_SIGNOUT")
    if value is None:
        return True
    try:
        return _parse_bool_env(value)
    except ValueError:
        raise ValueError(
            f"OP_FSSPEC_SIGNOUT={value!r} is invalid. Must be 'true' or 'false' (case-insensitive)."
        ) from None


def _access_log_detail() -> int:
    """Return how verbose the access log should be.

    Controlled by OP_FSSPEC_ACCESS_LOG_DETAIL env var. If not set, defaults to
    ACCESS_LOG_CALLER (3), i.e. the most detailed level.

    Returns:
        ACCESS_LOG_NONE (0): nothing is logged.
        ACCESS_LOG_ITEM (1): item access only, without the field name.
        ACCESS_LOG_FIELD (2): item and field access.
        ACCESS_LOG_CALLER (3): item and field access plus the calling code location.

    Raises:
        ValueError: If the env var is set to anything other than "0", "1", "2" or "3".
    """
    value = os.environ.get("OP_FSSPEC_ACCESS_LOG_DETAIL")
    if value is None:
        return ACCESS_LOG_CALLER
    level = _ACCESS_LOG_DETAILS.get(value.strip())
    if level is None:
        raise ValueError(
            f"OP_FSSPEC_ACCESS_LOG_DETAIL={value!r} is invalid. Must be '0' (no logging), '1' (item access), "
            "'2' (item and field access) or '3' (item and field access with code location)."
        )
    return level


def _get_caller() -> str:
    caller = None
    for frame_info in inspect.stack():
        module = frame_info.frame.f_globals.get("__name__", "")
        if not module or module.startswith("fsspec"):
            continue
        path = "/".join(frame_info.filename.split("/")[-len(module.split(".")) :])
        location = f"{path}:{frame_info.function}:{frame_info.lineno}"
        caller = f"{location}" + ("\n  -> " + caller if caller else "")
    return "  " + (caller or "<unknown>")


def _require_op() -> str:
    """Return the path to the op executable, raising a clear error if absent."""
    op_path = shutil.which("op")
    if op_path is None:
        raise RuntimeError(
            "The '1Password CLI' executable 'op' was not found in PATH. "
            "Please install it from https://developer.1password.com/docs/cli/get-started/ "
            "and make sure it is available in your PATH before using the op:// protocol."
        )
    return op_path


def _run_op(*args: str, **kwargs: Any) -> str:
    """Run an op CLI command and return its stdout as a string."""
    op_path = _require_op()
    cmd = [op_path, *args]
    logger.debug("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else ""
        raise PermissionError(f"op CLI returned non-zero exit code {exc.returncode}: {stderr}") from exc
    return result.stdout


def _parse_path(path: str) -> tuple[str | None, str | None, str | None]:
    """Parse an op:// path into (vault, item, field) triple.

    Returns None for each component that is absent.
    """
    stripped = path
    for prefix in ("op://", "op:/"):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix) :]
            break
    stripped = stripped.strip("/")

    if not stripped:
        return None, None, None

    parts = stripped.split("/", 2)
    vault = parts[0] if len(parts) > 0 and parts[0] else None
    item = parts[1] if len(parts) > 1 and parts[1] else None
    field = parts[2] if len(parts) > 2 and parts[2] else None
    return vault, item, field


class OnePasswordFileSystem(AbstractFileSystem):
    """Read-only fsspec filesystem backed by the 1Password op CLI.

    Every "file" in this filesystem corresponds to a single 1Password field
    value.  Only full ``op://Vault/Item/Field`` URIs are supported.

    URI structure
    -------------
    ``op://Vault/Item/Field``  – field; ``open`` / ``cat`` returns the value

    Caching
    -------
    On the first access to any field of an item the entire item is fetched
    with ``op item get`` and all its fields are stored in an in-memory cache.
    ``op signout`` is then called immediately – including when the fetch
    failed – so each item requires exactly one user authorisation.  Repeated
    reads of any field of the same item are served from the cache with no
    further CLI calls.

    Authentication
    --------------
    Authentication is handled transparently by the op CLI (biometric, session
    token, service-account token, …).  Refer to the 1Password CLI documentation
    for details: https://developer.1password.com/docs/cli/
    """

    protocol = "op"
    root_marker = ""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._item_cache: dict[tuple[str, str], dict[str, str]] = {}
        self._access_warnings_emitted: set[tuple] = set()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_item_to_cache(self, vault: str, item: str) -> None:
        """Fetch an entire item, cache all its fields, then optionally sign out.

        The signout also runs when the fetch fails.  A failing fetch can itself
        leave the CLI signed in – e.g. when the 1Password app requires a login
        and the user completes it after the fetch already errored out – so
        skipping the signout would let the next run read the item without any
        authorisation prompt.

        Whether to call op signout is controlled by OP_FSSPEC_SIGNOUT env var.
        """
        fetch_failed = True
        try:
            raw = _run_op("item", "get", item, "--vault", vault, "--format=json")
            item_data = json.loads(raw)
            fields: dict[str, str] = {}
            for f in item_data.get("fields", []):
                label = f.get("label") or f.get("id", "")
                if label:
                    section = f.get("section", {}).get("label")
                    if section:
                        label = f"{section}/{label}"
                    fields[label] = f.get("value", "") or ""
            for u in item_data.get("urls", []):
                label = u.get("label")
                if label:
                    fields[label] = u.get("href", "") or ""
            self._item_cache[(vault, item)] = fields
            fetch_failed = False
        finally:
            self._signout(suppress_errors=fetch_failed)

    def _signout(self, suppress_errors: bool = False) -> None:
        """Run ``op signout`` unless disabled via OP_FSSPEC_SIGNOUT.

        When ``suppress_errors`` is true, failures are logged instead of raised
        so that they do not mask the error that is already propagating.
        """
        try:
            if _should_signout():
                _run_op("signout")
        except Exception as exc:
            if not suppress_errors:
                raise
            logger.warning("op signout after a failed item fetch did not succeed: %s", exc)

    def _log_access(self, vault: str, item: str, field: str) -> None:
        """Log an access at the verbosity given by OP_FSSPEC_ACCESS_LOG_DETAIL.

        Each distinct log entry is emitted only once, so the deduplication key
        is as coarse as the level: per item for level 1, per field for level 2
        and per field-and-caller for level 3.
        """
        level = _access_log_detail()
        if level == ACCESS_LOG_NONE:
            return

        if level == ACCESS_LOG_ITEM:
            key: tuple = (level, vault, item)
            message, args = "'op://%s/%s' ACCESSED", (vault, item)
        else:
            url = f"op://{vault}/{item}/{field}"
            if level == ACCESS_LOG_FIELD:
                key = (level, url)
                message, args = "'%s' ACCESSED", (url,)
            else:
                caller = _get_caller()
                key = (level, url, caller)
                message, args = "'%s' ACCESSED BY:\n%s", (url, caller)

        if key not in self._access_warnings_emitted:
            logger.warning(message, *args)
            self._access_warnings_emitted.add(key)

    def _get_cached_field(self, vault: str, item: str, field: str) -> str:
        """Return a field value, loading the item cache if necessary.

        Field access is logged (controlled by OP_FSSPEC_ACCESS_LOG_DETAIL env var).
        """
        self._log_access(vault, item, field)
        if (vault, item) not in self._item_cache:
            self._load_item_to_cache(vault, item)
        fields = self._item_cache[(vault, item)]
        if field not in fields:
            raise FileNotFoundError(f"Field '{field}' not found in 'op://{vault}/{item}'")
        return fields[field]

    # ------------------------------------------------------------------
    # fsspec AbstractFileSystem interface
    # ------------------------------------------------------------------

    def ls(self, path: str, detail: bool = True, **kwargs: Any) -> list:
        vault, item, field = _parse_path(path)

        if field is None:
            raise PermissionError(_PARTIAL_PATH_ERROR)

        # A field is a file, not a directory
        raise NotADirectoryError(f"op://{vault}/{item}/{field} is a file, not a directory")

    def info(self, path: str, **kwargs: Any) -> dict:
        vault, item, field = _parse_path(path)

        if field is None:
            raise PermissionError(_PARTIAL_PATH_ERROR)

        value = self._get_cached_field(vault, item, field)
        size = len(value.encode()) if isinstance(value, str) else len(value or b"")
        return {"name": f"op://{vault}/{item}/{field}", "type": "file", "size": size}

    def _open(
        self,
        path: str,
        mode: str = "rb",
        **kwargs: Any,
    ):
        if "w" in mode or "a" in mode:
            raise PermissionError("OnePasswordFileSystem is read-only")

        vault, item, field = _parse_path(path)
        if vault is None or item is None or field is None:
            raise PermissionError(_PARTIAL_PATH_ERROR)

        value = self._get_cached_field(vault, item, field)
        return io.BytesIO(value.encode() if isinstance(value, str) else value)

    def cat_file(self, path: str, **kwargs: Any) -> bytes:
        vault, item, field = _parse_path(path)
        if vault is None or item is None or field is None:
            raise PermissionError(_PARTIAL_PATH_ERROR)
        value = self._get_cached_field(vault, item, field)
        return value.encode() if isinstance(value, str) else value
