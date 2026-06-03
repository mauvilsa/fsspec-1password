# fsspec-1password

An [fsspec](https://filesystem-spec.readthedocs.io/) filesystem implementation for [1Password](https://1password.com/) entries, backed by the [1Password CLI (`op`)](https://developer.1password.com/docs/cli/).

## Overview

`fsspec-1password` exposes your 1Password vaults, items, and fields as a read-only virtual filesystem under the `op://` protocol.  Any tool or library that speaks fsspec can transparently read secret values straight from 1Password – no files on disk, no environment variable juggling.

```
op://                        ← root (list all vaults)
op://Vault                   ← vault directory (list items)
op://Vault/Item              ← item directory (list fields)
op://Vault/Item/Field        ← field file (read secret value)
```

## Requirements

* Python ≥ 3.10
* [fsspec](https://pypi.org/project/fsspec/) ≥ 2022.1.0
* The [1Password CLI (`op`)](https://developer.1password.com/docs/cli/get-started/) must be installed and available in `PATH`.

> **If `op` is not in `PATH`** a clear `RuntimeError` is raised immediately:
>
> ```
> RuntimeError: The '1Password CLI' executable 'op' was not found in PATH.
> Please install it from https://developer.1password.com/docs/cli/get-started/
> and make sure it is available in your PATH before using the op:// protocol.
> ```

## Installation

```bash
pip install fsspec-1password
```

## Quick start

### Direct usage

```python
import fsspec_1password  # registers the op:// protocol with fsspec

fs = fsspec_1password.OnePasswordFileSystem()

# List all vaults
fs.ls("op://")
# [{'name': 'op://Personal', 'type': 'directory', 'size': 0}, ...]

# List items in a vault
fs.ls("op://Personal")
# [{'name': 'op://Personal/GitHub', 'type': 'directory', 'size': 0}, ...]

# List fields of an item
fs.ls("op://Personal/GitHub")
# [{'name': 'op://Personal/GitHub/username', 'type': 'file', 'size': 5}, ...]

# Read a field value
secret = fs.cat_file("op://Personal/GitHub/password")
# b's3cr3t'

with fs.open("op://Personal/GitHub/password") as f:
    secret = f.read()
# b's3cr3t'
```

### Via fsspec

```python
import fsspec

with fsspec.open("op://Personal/GitHub/password") as f:
    secret = f.read()
```

### Use with other libraries

Any library that accepts an fsspec-compatible path works out of the box:

```python
import pandas as pd

# Read a CSV stored as a 1Password secure note
df = pd.read_csv("op://Work/MySecretCSV/content", storage_options={})
```

## Authentication

Authentication is handled entirely by the `op` CLI.  Depending on your setup this may be:

* **Biometric** (Touch ID / Windows Hello) – automatic after initial sign-in.
* **Session token** – set `OP_SESSION_<account>` in the environment.
* **Service-account token** – set `OP_SERVICE_ACCOUNT_TOKEN` in the environment.

Refer to the [1Password CLI documentation](https://developer.1password.com/docs/cli/) for full details.

## URI scheme

| Path | Description |
|------|-------------|
| `op://` | Root – directory listing returns all vaults |
| `op://Vault` | Vault – directory listing returns all items |
| `op://Vault/Item` | Item – directory listing returns all fields |
| `op://Vault/Item/Field` | Field – readable file containing the secret value |

`Vault`, `Item`, and `Field` refer to the **title/label** of the object, matching how you would address them with `op read op://Vault/Item/Field`.

## Development

```bash
git clone https://github.com/mauvilsa/fsspec-1password
cd fsspec-1password
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# Run tests (no real op executable required)
pytest

# Run with coverage
pytest --cov --cov-report=html
```

### Running pre-commit hooks

```bash
pre-commit install
pre-commit run --all-files
```

### Bumping the version

```bash
bump2version patch   # or minor / major
```

## License

MIT – see [LICENSE](LICENSE).
