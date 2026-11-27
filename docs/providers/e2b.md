# E2B: `run e2b`

**Status:** Stable target. Last validated: pending. [All providers](README.md)

`run e2b` creates one E2B sandbox from the default `base` CPU template, probes it and deletes it by the ID its create
returned (PRV-8).

## Prerequisites

- An installed `sandprobe`, and a clone of this repository for the SDK lock file.
- An E2B account and API key.
- Python 3.11 or later, with the pinned `e2b==2.63.0` SDK in a virtual environment. Sandprobe never installs it for
  you:

  ```sh
  python3 -m venv ~/.venvs/sandprobe-e2b
  ~/.venvs/sandprobe-e2b/bin/pip install --require-hashes --only-binary=:all: -r internal/host/e2b-requirements.lock
  ```

## Credentials

| Name | What it is |
|-|-|
| `SANDPROBE_E2B_KEY_FILE` or `-e2b-key-file` | Your API key in a regular file only you can read. If you name a file that can't be read, Sandprobe doesn't fall back to the variable below. |
| `E2B_API_KEY` | The API key, when no key file is named. |
| `SANDPROBE_E2B_PYTHON` or `-e2b-python` | The Python in that virtual environment. Defaults to `python3`. |

The key stays on your machine. It never enters the sandbox, a command line, a journal, a report or an error.

## Run it

```sh
export SANDPROBE_E2B_KEY_FILE=~/.config/sandprobe/e2b.key
export SANDPROBE_E2B_PYTHON=~/.venvs/sandprobe-e2b/bin/python
sandprobe plan e2b
sandprobe run e2b -y
```

The sandbox has no injected secrets, volumes or previews, a 900-second timeout, and internet access on, as E2B's
default. The probe runs as the template's normal user. A sandbox that can't be confirmed deleted keeps its journal,
and the run exits 7.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | Each would contact an E2B-owned endpoint: metadata, a proxy, the host over vsock, a Kubernetes API. PRV-8 excludes them. |
| PER-5 | No reset: pause and resume aren't one, and the sandbox has no run-owned persistent storage. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

## Terms and consent

PRV-8 records E2B's terms as reviewed on 12 Nov 2026. [E2B's terms](https://e2b.dev/terms), Prohibited Conduct 7,
prohibit testing "the vulnerability of any part of the Services", and the clauses beside it restrict interference
and circumvention. [E2B's security page](https://e2b.dev/security) gives no affirmative permission for research. A
live run needs your own recorded authorization for this bounded scope. Sandprobe never presents it as E2B's
permission.

## What the score can and can't reach

- Persistence rests on PER-1 to PER-4. Whether anything survives a reset isn't tested.
- This is exec mode: one command run in a default sandbox, not an agent's own workload.

### Canary and Cloud access (0.3.0)

Test traffic goes to the hosted canary at `control.pub.probe.ac0.dev` by default. It keeps the box's public address,
with the run's nonces, for the run's lifetime (at most 30 minutes), and your machine's public address in a rate
counter for at most an hour, both in memory only. To use a canary you run, name it with
`-canary-url <url> -canary-pin <pin>`, or with `-canary <state file>` for one from `deploy/canary.sh`. Cloud access
is not applicable here: PRV-8 excludes E2B's own metadata and Kubernetes endpoints under Sandprobe's reviewed scope
for it, so the box holds no cloud identity of yours to check. Cloud access is never green, the score is out of
five, and a line under the score says why. A credential of yours put into the box is still caught under Secrets.
