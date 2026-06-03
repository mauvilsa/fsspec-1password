"""fsspec filesystem implementation for 1Password entries via the op CLI.

Paths follow the op:// URI scheme:
    op://              -> root, listing all vaults
    op://Vault         -> a vault, listing items
    op://Vault/Item    -> an item, listing fields
    op://Vault/Item/Field -> a field (readable as a file)
"""

import io
import json
import logging
import shutil
import subprocess
from typing import Any

from fsspec.spec import AbstractFileSystem

logger = logging.getLogger("fsspec_1password")


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
    # Strip leading "op://" and any trailing slashes
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
    value.  Directories are vaults (top level) and items (second level).

    URI structure
    -------------
    ``op://``                  – root; ``ls`` returns vault names
    ``op://Vault``             – vault; ``ls`` returns item names
    ``op://Vault/Item``        – item; ``ls`` returns field names
    ``op://Vault/Item/Field``  – field; ``open`` / ``cat`` returns the value

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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _list_vaults(self) -> list[dict]:
        raw = _run_op("vault", "list", "--format=json")
        return json.loads(raw)

    def _list_items(self, vault: str) -> list[dict]:
        raw = _run_op("item", "list", "--vault", vault, "--format=json")
        return json.loads(raw)

    def _get_item(self, vault: str, item: str) -> dict:
        raw = _run_op("item", "get", item, "--vault", vault, "--format=json")
        return json.loads(raw)

    def _read_field(self, vault: str, item: str, field: str) -> bytes:
        value = _run_op("read", f"op://{vault}/{item}/{field}")
        return value.encode()

    # ------------------------------------------------------------------
    # fsspec AbstractFileSystem interface
    # ------------------------------------------------------------------

    def ls(self, path: str, detail: bool = True, **kwargs: Any) -> list:
        vault, item, field = _parse_path(path)

        if vault is None:
            # Root – list vaults
            vaults = self._list_vaults()
            entries = []
            for v in vaults:
                name = v.get("name", v.get("id", ""))
                entries.append(
                    {
                        "name": f"op://{name}",
                        "type": "directory",
                        "size": 0,
                    }
                )
            return entries if detail else [e["name"] for e in entries]

        if item is None:
            # Vault level – list items
            items = self._list_items(vault)
            entries = []
            for it in items:
                name = it.get("title", it.get("id", ""))
                entries.append(
                    {
                        "name": f"op://{vault}/{name}",
                        "type": "directory",
                        "size": 0,
                    }
                )
            return entries if detail else [e["name"] for e in entries]

        if field is None:
            # Item level – list fields
            item_data = self._get_item(vault, item)
            entries = []
            for f in item_data.get("fields", []):
                label = f.get("label") or f.get("id", "")
                if not label:
                    continue
                value = f.get("value", "")
                size = len(value.encode()) if isinstance(value, str) else len(value or b"")
                entries.append(
                    {
                        "name": f"op://{vault}/{item}/{label}",
                        "type": "file",
                        "size": size,
                    }
                )
            return entries if detail else [e["name"] for e in entries]

        # Field level – a field is a file, not a directory
        raise NotADirectoryError(f"op://{vault}/{item}/{field} is a file, not a directory")

    def info(self, path: str, **kwargs: Any) -> dict:
        vault, item, field = _parse_path(path)

        if vault is None:
            return {"name": "op://", "type": "directory", "size": 0}

        if item is None:
            # Validate vault exists by listing vaults
            vaults = self._list_vaults()
            names = {v.get("name", v.get("id", "")) for v in vaults}
            if vault not in names:
                raise FileNotFoundError(f"Vault not found: {vault}")
            return {"name": f"op://{vault}", "type": "directory", "size": 0}

        if field is None:
            # Validate item exists
            items = self._list_items(vault)
            titles = {it.get("title", it.get("id", "")) for it in items}
            if item not in titles:
                raise FileNotFoundError(f"Item not found: op://{vault}/{item}")
            return {"name": f"op://{vault}/{item}", "type": "directory", "size": 0}

        # Field – get size from item data
        item_data = self._get_item(vault, item)
        for f in item_data.get("fields", []):
            label = f.get("label") or f.get("id", "")
            if label == field:
                value = f.get("value", "")
                size = len(value.encode()) if isinstance(value, str) else len(value or b"")
                return {"name": f"op://{vault}/{item}/{field}", "type": "file", "size": size}
        raise FileNotFoundError(f"Field not found: op://{vault}/{item}/{field}")

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
            raise IsADirectoryError(f"op://{vault}/{item} is a directory, not a file")

        data = self._read_field(vault, item, field)
        return io.BytesIO(data)

    def cat_file(self, path: str, **kwargs: Any) -> bytes:
        vault, item, field = _parse_path(path)
        if vault is None or item is None or field is None:
            raise IsADirectoryError(f"Path is a directory, not a file: {path}")
        return self._read_field(vault, item, field)
