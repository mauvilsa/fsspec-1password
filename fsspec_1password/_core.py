"""fsspec filesystem implementation for 1Password entries via the op CLI.

Only full ``op://Vault/Item/Field`` or ``op://Vault/Item/Section/Field`` paths
are supported for reading. Accessing ``op://``, ``op://Vault``, or
``op://Vault/Item`` raises a ``PermissionError`` – this filesystem is designed
to read specific secrets, not to facilitate exploration of entire accounts and
vaults.

When a field is first read the entire ``op://Vault/Item`` is fetched via
``op item get`` and all its fields are cached.  ``op signout`` is then run
immediately so that each item access requires exactly one user authorisation.
Subsequent reads of any field belonging to the same item are served from the
in-memory cache without any CLI interaction.
"""

import inspect
import io
import json
import logging
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
    ``op signout`` is then called immediately, so each item requires exactly
    one user authorisation.  Repeated reads of any field of the same item
    are served from the cache with no further CLI calls.

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
        self._access_warnings_emitted = set()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_item_to_cache(self, vault: str, item: str) -> None:
        """Fetch an entire item, cache all its fields, then sign out."""
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
        _run_op("signout")

    def _get_cached_field(self, vault: str, item: str, field: str) -> str:
        """Return a field value, loading the item cache if necessary."""
        caller = _get_caller()
        url = f"op://{vault}/{item}/{field}"
        if (url, caller) not in self._access_warnings_emitted:
            logger.warning("'%s' ACCESSED BY:\n%s", url, caller)
            self._access_warnings_emitted.add((url, caller))
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
