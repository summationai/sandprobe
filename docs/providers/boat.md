# Boat: `run boat`

**Status:** Experimental. Last validated: pending.
[All providers](README.md)

`run boat` creates one small CPU VM from Boat's base environment, in your personal wallet, probes it and deletes it
permanently by the ID its create returned (PRV-11).

**Before you run this:** a live run needs the operator's informed authorization, never a claimed provider-written
approval (PRV-11). Boat's terms restrict probing its security controls (see below).

## Prerequisites

- An installed `sandprobe`. You don't need a clone of this repository.
- A Boat account and API key.

## Credentials

| Name | What it is |
|-|-|
| `SANDPROBE_BOAT_KEY_FILE` or `-boat-key-file` | Your API key in a regular file only you can read. |
| `BOAT_API_KEY` | The API key, when no key file is named. |

The key stays on your machine. It never enters the VM, a command line, a journal, a report or an error.

## Run it

```sh
export SANDPROBE_BOAT_KEY_FILE=~/.config/sandprobe/boat.key
sandprobe plan boat
sandprobe run boat -y
```

The VM has `noEnv=true`, no snapshots, monitoring, previews or volumes, and a 15-minute auto-archive as a backstop;
archiving isn't deletion. Delete is permanent, and counts only once Boat reports the deletion complete and the
sandbox answers "not found". A VM that can't be confirmed deleted keeps its journal, and the run exits 7.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | Each would contact a Boat-owned endpoint: metadata, a proxy, the host over vsock, a Kubernetes API. PRV-11 excludes them under Boat's terms. |
| PER-5 | No reset, and no run-owned storage that survives one. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

## Terms and consent

PRV-11 records [Boat's terms](https://boat.dev/terms) as reviewed on 13 Nov 2026. TOS-10 says "You may not probe,
bypass, disable, reverse engineer" its security and access controls. TOS-6 bars "unauthorized vulnerability scanning,
intrusion, exploitation, or network abuse". TOS-3 supports testing workloads. A run makes no exploit, bypass,
privileged action or provider-control request: it observes permissions in the guest and sends markers to the canary.
PRV-11: a live run needs the operator's informed authorization, never a claimed provider-written approval. Sandprobe
never presents a run as Boat's permission or waiver.

## What the score can and can't reach

- Persistence rests on PER-1 to PER-4. Whether anything survives a reset isn't tested.
- Boat can keep showing the base environment's label after `noEnv`. Sandprobe treats that label as neither proof of
  secrets nor proof of none: secrets are judged by what the probe can open.

### Canary and Cloud access (0.3.0)

Test traffic goes to the hosted canary at `control.pub.probe.ac0.dev` by default. It keeps the box's public address,
with the run's nonces, for the run's lifetime (at most 30 minutes), and your machine's public address in a rate
counter for at most an hour, both in memory only. To use a canary you run, name it with
`-canary-url <url> -canary-pin <pin>`, or with `-canary <state file>` for one from `deploy/canary.sh`. Cloud access
is not applicable here: PRV-11 excludes Boat's own metadata and Kubernetes endpoints under Sandprobe's reviewed scope
for it, so the box holds no cloud identity of yours to check. Cloud access is never green, the score is out of five,
and a line under the score says why. A credential of yours put into the box is still caught under Secrets.
