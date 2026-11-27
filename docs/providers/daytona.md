# Daytona: `run daytona`

**Status:** Stable target. Last validated: pending. [All providers](README.md)

`run daytona` creates one Daytona sandbox from the default prebuilt CPU snapshot, probes it and deletes it by the ID
its create returned (PRV-12).

## Prerequisites

- An installed `sandprobe`, and a clone of this repository for the SDK lock file.
- A Daytona account and API key. The key is scoped to an organization.
- Python with the pinned `daytona==0.198.0` SDK in a virtual environment. Sandprobe never installs it for you:

  ```sh
  python3 -m venv ~/.venvs/sandprobe-daytona
  ~/.venvs/sandprobe-daytona/bin/pip install --require-hashes --only-binary=:all: -r internal/host/daytona-requirements.lock
  ```

## Credentials

| Name | What it is |
|-|-|
| `SANDPROBE_DAYTONA_KEY_FILE` or `-daytona-key-file` | Your API key in a regular file only you can read. If you name a file that can't be read, Sandprobe doesn't fall back to the variable below. |
| `DAYTONA_API_KEY` | The API key, when no key file is named. |
| `SANDPROBE_DAYTONA_PYTHON` or `-daytona-python` | The Python in that virtual environment. Defaults to `python3`. |

The key stays on your machine. It never enters the sandbox, a command line, a journal, a report or an error.

## Run it

```sh
export SANDPROBE_DAYTONA_KEY_FILE=~/.config/sandprobe/daytona.key
export SANDPROBE_DAYTONA_PYTHON=~/.venvs/sandprobe-daytona/bin/python
sandprobe plan daytona
sandprobe run daytona -y
```

The sandbox is private, in the US, with no secrets, volumes or public previews. It stops after 15 idle minutes as a
cost backstop; that isn't deletion. A sandbox that can't be confirmed deleted keeps its journal, and the run exits 7.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-7 | PRV-12 excludes metadata, configured-proxy and Kubernetes API checks that would contact Daytona-owned endpoints. |
| AMP-6 | PRV-12 excludes host-vsock probing. The current implementation only checks device presence and makes no connection; approval alone does not implement a host-connectivity test. |
| PER-5 | No reset, and no run-owned storage that survives one. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

## Terms and consent

PRV-12 records Daytona's terms as reviewed on 13 Nov 2026. [Daytona's terms of service](https://www.daytona.io/terms-of-service),
section 8, bar vulnerability testing without written permission. Daytona's
[acceptable use policy](https://www.daytona.io/docs/en/acceptable-use/) permits targeted testing of systems you own or
are authorized to test, without notice, but defers to the terms of service where they conflict, and treats testing
Daytona itself as a separate matter. A live run needs your own informed authorization. Sandprobe never presents it as
a waiver from Daytona.

## What the score can and can't reach

- Persistence rests on PER-1 to PER-4. Whether anything survives a reset isn't tested.
- Before creating anything, the key's API access is checked, but that check doesn't return the organization. The
  organization is pinned from the create's own answer.

These are the native `run daytona` defaults. The managed model workload has a separate, explicit storage and
network contract; see [measurement gaps](../measurement-gaps.md) and
the [managed workload documentation](../../experiments/daytona-agent/README.md).

### Canary and Cloud access (0.3.0)

Test traffic goes to the hosted canary at `control.pub.probe.ac0.dev` by default. It keeps the box's public address,
with the run's nonces, for the run's lifetime (at most 30 minutes), and your machine's public address in a rate
counter for at most an hour, both in memory only. To use a canary you run, name it with
`-canary-url <url> -canary-pin <pin>`, or with `-canary <state file>` for one from `deploy/canary.sh`. Cloud access
is not applicable here: PRV-12 excludes Daytona's own metadata and Kubernetes endpoints under Sandprobe's reviewed
scope for it, so the box holds no cloud identity of yours to check. Cloud access is never green, the score is out of
five, and a line under the score says why. A credential of yours put into the box is still caught under Secrets.
