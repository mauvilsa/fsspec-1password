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

Every access is logged, to the console and to an audit file – see
``fsspec_1password._logging`` for the sinks and their configuration.

Environment variables:
  OP_FSSPEC_SIGNOUT: Set to "true" or "false" (case-insensitive) to control
                      whether op signout is called after item fetch.
                      If not set, defaults to true. Any other value raises ValueError.
  OP_FSSPEC_CONSOLE_LOG_DETAIL: How much detail the console access log includes.
                      Higher levels add information, they never remove any:
                        "0" nothing is logged;
                        "1" items being fetched and cached, e.g. 'op://Vault/Item';
                        "2" the above plus each field access, e.g.
                            'op://Vault/Item/Field';
                        "3" the above plus the code location that triggered
                            the field access.
                      If not set, defaults to "2". Any other value raises ValueError.
                      This affects the console only – the audit file is always
                      written at full detail.
  OP_FSSPEC_AUDIT_LOG_FILE: Where the JSON Lines audit log is written.
                      Defaults to $XDG_STATE_HOME/fsspec-1password/audit.log,
                      i.e. ~/.local/state/fsspec-1password/audit.log.
                      Set to "none" to disable it.
  OP_FSSPEC_AUDIT_LOG_RUN_ID: Identifier shared by every record from this process.
                      Defaults to a random per-process value. Set it to
                      correlate several processes of the same job.
"""

import io
import json
import os
import shutil
import subprocess
from typing import Any, NoReturn

from fsspec.spec import AbstractFileSystem

from ._logging import (
    log_access_denied,
    log_field_access,
    log_item_cached,
    log_item_fetch_failed,
    log_signout_failed,
    logger,
)

_PARTIAL_PATH_ERROR = (
    "fsspec-1password only supports reading specific fields. Use op://Vault/Item/Field to access a secret."
)


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
            # Logged before the signout attempt: the item is cached and
            # readable at this point, whether or not the signout succeeds.
            log_item_cached(vault, item)
        except Exception as exc:
            log_item_fetch_failed(vault, item, exc)
            raise
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
            log_signout_failed(exc)

    def _get_cached_field(self, vault: str, item: str, field: str) -> str:
        """Return a field value, loading the item cache if necessary.

        The access is logged before the value is looked up, so that a read of a
        field that turns out not to exist is recorded too.
        """
        log_field_access(vault, item, field)
        if (vault, item) not in self._item_cache:
            self._load_item_to_cache(vault, item)
        fields = self._item_cache[(vault, item)]
        if field not in fields:
            raise FileNotFoundError(f"Field '{field}' not found in 'op://{vault}/{item}'")
        return fields[field]

    # ------------------------------------------------------------------
    # fsspec AbstractFileSystem interface
    # ------------------------------------------------------------------

    def _deny_partial_path(self, path: str) -> NoReturn:
        """Reject – and record – a read of anything short of a full field path."""
        log_access_denied(path, _PARTIAL_PATH_ERROR)
        raise PermissionError(_PARTIAL_PATH_ERROR)

    def ls(self, path: str, detail: bool = True, **kwargs: Any) -> list:
        vault, item, field = _parse_path(path)

        if field is None:
            self._deny_partial_path(path)

        # A field is a file, not a directory
        raise NotADirectoryError(f"op://{vault}/{item}/{field} is a file, not a directory")

    def info(self, path: str, **kwargs: Any) -> dict:
        vault, item, field = _parse_path(path)

        if field is None:
            self._deny_partial_path(path)

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
            self._deny_partial_path(path)

        value = self._get_cached_field(vault, item, field)
        return io.BytesIO(value.encode() if isinstance(value, str) else value)

    def cat_file(self, path: str, **kwargs: Any) -> bytes:
        vault, item, field = _parse_path(path)
        if vault is None or item is None or field is None:
            self._deny_partial_path(path)
        value = self._get_cached_field(vault, item, field)
        return value.encode() if isinstance(value, str) else value
