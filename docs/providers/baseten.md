# Baseten: `run baseten`

**Status:** Beta. Last validated: pending. [All providers](README.md)

`run baseten` creates one Baseten Sandbox from the built-in base image, on CPU with the default memory, probes it and
deletes it (PRV-6).

Its known gaps:

- Baseten addresses sandboxes by name, and a name can be reused once a sandbox ends. Sandprobe binds every call to the
  create's own name, URL, creation time and external ID, and checks them first, but that can't make a call atomic.
  The report states the remaining race.
- Suspend and resume isn't a reset, so PER-5 can't run.

## Prerequisites

- An installed `sandprobe`. You don't need a clone of this repository.
- A Baseten personal API key, or a full-access team key.

## Credentials

| Name | What it is |
|-|-|
| `SANDPROBE_BASETEN_KEY_FILE` or `-baseten-key-file` | Your API key in a regular file only you can read. If you name a file that can't be read, Sandprobe doesn't fall back to the variable below. |
| `BASETEN_API_KEY` | The API key, when no key file is named. |
| `BASETEN_TEAM_ID` or `-baseten-team` | The team. Required when the key reaches several teams. |
| `BASETEN_REGION` or `-baseten-region` | Optional. Empty uses Baseten's default. |

The key is exchanged for an access token scoped to the sandbox API. Neither one is sent into the sandbox, or written
to a report, a journal, a command line or an error.

## Run it

```sh
export SANDPROBE_BASETEN_KEY_FILE=~/.config/sandprobe/baseten.key
sandprobe plan baseten
sandprobe run baseten -y
sandprobe run baseten -keep-sandbox -y                       # keep it for inspection, deleted one hour after creation
sandprobe cleanup baseten -baseten-state <journal> -y        # delete a kept or unconfirmed sandbox from its journal
```

The sandbox has a random name, no secrets, previews or volumes, and a 15-minute delete expiry as a backstop. A
sandbox that can't be confirmed deleted keeps its journal, and the run exits 7.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | PRV-6's scope sends no request to Baseten's metadata, proxy, vsock or Kubernetes API. |
| PER-5 | Suspend and resume preserves state and isn't a reset, and the run creates no volume. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

## Terms and consent

PRV-6 records Baseten's terms as reviewed on 11 Nov 2026. [Baseten's terms](https://www.baseten.co/terms-and-conditions),
section 4.3, restrict attempts to "gain unauthorized access" and use to "build a competing product or service". No
affirmative permission for research was found. A live run needs your own authorization, and reasonable spend.
Sandprobe never presents it as Baseten's permission.

## What the score can and can't reach

- Persistence rests on PER-1 to PER-4. Whether anything survives a reset isn't tested.
- The run covers a CPU sandbox and the canary only: no unrelated workloads and no requests to Baseten's own control
  endpoints.

### Canary and Cloud access (0.3.0)

Test traffic goes to the hosted canary at `control.pub.probe.ac0.dev` by default. It keeps the box's public address,
with the run's nonces, for the run's lifetime (at most 30 minutes), and your machine's public address in a rate
counter for at most an hour, both in memory only. To use a canary you run, name it with
`-canary-url <url> -canary-pin <pin>`, or with `-canary <state file>` for one from `deploy/canary.sh`. Cloud access is
not applicable here: PRV-6 excludes Baseten's own metadata and Kubernetes endpoints under Sandprobe's reviewed scope
for it, so the box holds no cloud identity of yours to check. Cloud access is never green, the score is out of five,
and a line under the score says why. A credential of yours put into the box is still caught under Secrets.
