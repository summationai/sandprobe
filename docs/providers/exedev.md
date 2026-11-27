# exe.dev: `run exe.dev`

**Status:** Experimental. Last validated: pending.
[All providers](README.md)

`run exe.dev` creates one standalone Ubuntu 24.04 VM, 2 vCPU and 4 GB, with egress on and no integrations, probes it
and deletes it (PRV-13). [docs/EXEDEV.md](../EXEDEV.md) has the adapter's full contract.

**Before you run this:** a live run needs the operator's own clearance for this bounded run, never represented as
provider-written permission (PRV-13). Its terms bar benchmarking the service (see below).

## Prerequisites

- An installed `sandprobe`. You don't need a clone of this repository.
- An exe.dev account, and an expiring API token scoped to the tag `sandprobe`. Ideally restrict it to the commands
  `help`, `whoami`, `new`, `ls`, `stat`, `ssh` and `rm`.

## Credentials

| Name | What it is |
|-|-|
| `SANDPROBE_EXEDEV_KEY_FILE` or `-exedev-key-file` | The token in a regular file only you can read, at most 8 KiB. There is no environment variable for the token itself. |

The token stays on your machine. It never enters the VM, a command line, a journal, a report or an error.

## Run it

```sh
export SANDPROBE_EXEDEV_KEY_FILE=~/.config/sandprobe/exedev.token
sandprobe plan exe.dev
sandprobe run exe.dev -y
sandprobe cleanup exe.dev -exedev-state <journal> -y     # reconcile a VM a run couldn't confirm deleted
```

exe.dev's create API sets no expiry. If your machine crashes mid-run, the VM keeps costing money until you run
`cleanup` from its journal. A VM that can't be confirmed deleted keeps its journal, and the run exits 7.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | Each would send a request from the guest to exe.dev's metadata, a proxy, the host over vsock or a Kubernetes API. PRV-13 excludes them. |
| PER-5 | No reset, and no resettable storage. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

## Terms and consent

PRV-13 records [exe.dev's terms of service](https://exe.dev/docs/terms-of-service) as checked on 17 Nov 2026. Section
2.2 bars use "for benchmarking or competitive analysis of the Service". PRV-13: a live run needs the operator's own
clearance for this bounded run, never represented as provider-written permission.

## What the score can and can't reach

- Persistence rests on PER-1 to PER-4. Whether anything survives a reset isn't tested.
- exe.dev addresses a VM by name, with no immutable ID or conditional delete. Under PRV-13's reviewed exception,
  Sandprobe pins the name its create returned, with the VM's creation time, region and run tags, and checks them
  before every call. That can't make a call atomic, and the report states the remaining race.
- This is the Ubuntu, no-integration configuration, not exe.dev's default agent image.

### Canary and Cloud access (0.3.0)

Test traffic goes to the hosted canary at `control.pub.probe.ac0.dev` by default. It keeps the box's public address,
with the run's nonces, for the run's lifetime (at most 30 minutes), and your machine's public address in a rate
counter for at most an hour, both in memory only. To use a canary you run, name it with
`-canary-url <url> -canary-pin <pin>`, or with `-canary <state file>` for one from `deploy/canary.sh`. Cloud access is
not applicable here: PRV-13 excludes exe.dev's own metadata and Kubernetes endpoints under Sandprobe's reviewed scope
for it, so the box holds no cloud identity of yours to check. Cloud access is never green, the score is out of five,
and a line under the score says why. A credential of yours put into the box is still caught under Secrets.
