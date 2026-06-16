# fsspec-1password

An [fsspec](https://filesystem-spec.readthedocs.io/) filesystem implementation for [1Password](https://1password.com/) entries, backed by the [1Password CLI (`op`)](https://developer.1password.com/docs/cli/).

## Overview

`fsspec-1password` lets you read individual 1Password field values through the `op://` protocol.  Any tool or library that speaks fsspec can transparently read secret values straight from 1Password – no files on disk, no environment variable juggling.

> **Scope:** Only full `op://Vault/Item/Field` or `op://Vault/Item/Section/Field` URIs are supported.  Accessing `op://`, `op://Vault`, or `op://Vault/Item` raises a `PermissionError` – this library is designed to read specific secrets, not to browse entire accounts or vaults.

### Caching and sign-out

When a field is first read, the entire `op://Vault/Item` is fetched in a single `op item get` call and all its fields are cached in memory.  `op signout` is then called immediately.  This means:

* Each item access triggers **exactly one** user authorisation prompt.
* Subsequent reads of any field from the same item are served from the cache – no further `op` calls, no additional prompts.
* Accessing a field from a **different** item requires a new authorisation.

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

# Read a field value (triggers op authorisation the first time)
secret = fs.cat_file("op://Personal/GitHub/password")
# b's3cr3t'

# Reading another field from the same item uses the cache – no extra prompt
username = fs.cat_file("op://Personal/GitHub/username")
# b'alice'

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
