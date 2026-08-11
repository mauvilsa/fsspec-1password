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
* `op signout` is called even when the fetch fails, so a failure cannot leave the CLI signed in.

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

## Configuration

### Environment variables

The behavior of `fsspec-1password` can be controlled via environment variables:

#### `OP_FSSPEC_SIGNOUT` (default: enabled)

Controls whether `op signout` is called immediately after fetching an item.

* **Enabled (default):** When not set, each field access triggers exactly one authorization prompt.  Sessions are terminated immediately after the item is fetched.
* **Disabled:** Set to `false` (case-insensitive). Sessions remain active and expire after ~10 minutes.  This can be useful if you're accessing multiple items frequently and want to avoid repeated authorization prompts.

Valid values: `true` or `false` (case-insensitive). Any other value raises `ValueError`.

Example – disable automatic signout:
```bash
export OP_FSSPEC_SIGNOUT=false
python my_script.py
```

#### `OP_FSSPEC_CONSOLE_LOG_DETAIL` (default: `2`)

Controls how much detail the **console** access log includes.  Levels are additive – a higher number adds information, it never removes any.

| Level | What is logged |
| ----- | -------------- |
| `0` | Nothing |
| `1` | Items being fetched and cached |
| `2` (default) | The above, plus each field access |
| `3` | The above, plus the code location that triggered the field access |

```
2026-08-07 08:42:25 WARNING 'op://Personal/GitHub/password' ACCESS REQUESTED BY:   <- level 2 (3 adds the caller)
  my_app/main.py:main:8
  -> my_app/config.py:load:17
2026-08-07 08:42:25 WARNING 'op://Personal/GitHub' FETCHED AND CACHED              <- level 1
```

The two lines report different things.  The **field** line is the access – one per field your code reads, written *before* the value is looked up so that a read still leaves a trace when it goes on to fail.  That is why it says `ACCESS REQUESTED` rather than `ACCESSED`: at the moment the line is written the secret has been asked for, not yet handed over.  If it fails, the reason follows on its own line (`FETCH FAILED`, or a `FileNotFoundError` for an unknown field); a request with no failure after it succeeded.

The **item** line is the internal caching event: it appears once per `op item get`, and therefore once per authorisation prompt.  It never carries a caller, because it is triggered by the cache rather than by your code.  Unlike the field line it is written *after* the fact, so it is past tense.

Each distinct entry is logged only once, and the deduplication is exactly as coarse as the rendering: at level `2` a field is logged once no matter how many places read it, at level `3` once per field-and-caller combination.  Failed fetches and sign-outs are never deduplicated.

Valid values: `0`, `1`, `2` or `3`. Any other value raises `ValueError`.

This affects the console only.  **The audit file below is always written at full detail** – quietening the console does not weaken the audit trail.

```bash
export OP_FSSPEC_CONSOLE_LOG_DETAIL=1   # only report which items were unlocked
export OP_FSSPEC_CONSOLE_LOG_DETAIL=0   # silence the console entirely
```

#### `OP_FSSPEC_AUDIT_LOG_FILE` (default: `~/.local/state/fsspec-1password/audit.log`)

Every access is also appended to a log file, always at full detail.  The default location follows the [XDG Base Directory specification](https://specifications.freedesktop.org/basedir-spec/latest/), which places logs under `$XDG_STATE_HOME` (`~/.local/state` when unset).  The directory is created with mode `0700` and the file with `0600`.

Set the variable to another path to move it, or to `none` to disable file logging:

```bash
export OP_FSSPEC_AUDIT_LOG_FILE=/var/log/my-app/1password-audit.log
export OP_FSSPEC_AUDIT_LOG_FILE=none
```

Nothing is created on import – the file appears on the first access that is actually logged.  If it cannot be written (read-only home, no permission, …) a single warning is printed and the console log continues to work; a log that cannot be written never stops a secret from being read.

The file is rotated when it exceeds 5 MB, keeping 3 backups (`audit.log.1` … `audit.log.3`).  Rotation happens when the file is opened, so several processes appending concurrently cannot corrupt each other.

**Field values are never written to any log, at any detail level.**

#### `OP_FSSPEC_AUDIT_LOG_RUN_ID` (default: a random per-process value)

Several processes may write to the same log file, so every record carries a run id saying which run produced it.  A PID would not help here – it is reused, and it says nothing about what ran – so each process gets a random id and writes one `run_start` header line resolving that id to the user, host, working directory and command line.

Set this variable to give several processes of the same job a shared id:

```bash
export OP_FSSPEC_AUDIT_LOG_RUN_ID="nightly-etl-$(date +%F)"
```

### Reading the audit log

The file is [JSON Lines](https://jsonlines.org/) – one JSON object per line – so that a record stays on a single line even when it carries a whole call stack, and so it can be queried directly.  `jq` reads this format natively, no flags needed:

```jsonl
{"ts":"2026-08-07T06:42:25.306Z","run":"628df3a7","event":"run_start","pid":30531,"user":"alice","host":"laptop","cwd":"/srv/etl","argv":["python","etl.py"]}
{"ts":"2026-08-07T06:42:25.307Z","run":"628df3a7","event":"field_access","vault":"Personal","item":"GitHub","field":"password","caller":["etl.py:<module>:26","etl.py:load_config:21"]}
{"ts":"2026-08-07T06:42:25.307Z","run":"628df3a7","event":"item_cached","vault":"Personal","item":"GitHub"}
```

Turn the whole log into readable lines:

```bash
jq -r '"\(.ts) [\(.run)] \(
  if   .event == "field_access" then "READ    op://\(.vault)/\(.item)/\(.field)  \(.caller | join(" -> "))"
  elif .event == "item_cached"  then "FETCH   op://\(.vault)/\(.item)"
  elif .event == "run_start"    then "RUN     \(.user)@\(.host) \(.argv | join(" "))"
  else "\(.event | ascii_upcase) \(.path // "op://\(.vault)/\(.item)") \(.reason // .error // "")" end)"' \
  ~/.local/state/fsspec-1password/audit.log
```

```
2026-08-07T06:42:25.306Z [628df3a7] RUN     alice@laptop python etl.py
2026-08-07T06:42:25.307Z [628df3a7] READ    op://Personal/GitHub/password  etl.py:<module>:26 -> etl.py:load_config:21
2026-08-07T06:42:25.307Z [628df3a7] FETCH   op://Personal/GitHub
```

Which secrets were read, and from where:

```bash
jq -r 'select(.event=="field_access") | "op://\(.vault)/\(.item)/\(.field)\t\(.caller[-1])"' \
  ~/.local/state/fsspec-1password/audit.log | sort | uniq -c | sort -rn
```

Resolve a run id back to the process it came from:

```bash
jq -r 'select(.event=="run_start") | "\(.run)  \(.ts)  \(.user)@\(.host)  \(.argv|join(" "))"' \
  ~/.local/state/fsspec-1password/audit.log
```

Everything that failed – rejected paths, failed fetches, failed sign-outs:

```bash
jq -c 'select(.event | test("failed|denied"))' ~/.local/state/fsspec-1password/audit.log
```

### Routing the logs into your own logging

Access records go to the `fsspec_1password.access` logger, operational messages to `fsspec_1password`.  Neither propagates to the root logger – they install their own handlers so that access is visible even when the application does not configure logging at all, and propagating as well would print every access twice under anything that calls `logging.basicConfig()`.

To feed the records into your own pipeline, attach a handler to the logger directly.  Records carry the event name and its fields as `op_event` and `op_fields` attributes:

```python
import logging

handler = logging.FileHandler("/var/log/my-app/secrets.log")
logging.getLogger("fsspec_1password.access").addHandler(handler)
```

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
