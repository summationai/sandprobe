# Vercel Sandbox: `run vercel`

**Status:** Stable target. Last validated: pending. [All providers](README.md)

`run vercel` creates one Vercel Sandbox from the built-in universal image, in a team and project you name, probes it
and cleans it up (PRV-9).

## Prerequisites

- An installed `sandprobe`.
- A Vercel Pro or Enterprise team: Vercel's testing policy covers those plans. Sandprobe checks that the project
  belongs to the team, not which plan the team is on, so confirm that yourself.
- A project for the test. Sandprobe never modifies an existing project. To make a dedicated empty one, use the helper
  in a clone of this repository. It writes a private journal first, makes one request, never retries, and never
  deletes the project:

  ```sh
  python3 deploy/vercel-project.py --key-file ~/.config/sandprobe/vercel.key --team team_... \
    --state ~/.config/sandprobe/vercel-project.state
  ```

## Credentials

| Name | What it is |
|-|-|
| `SANDPROBE_VERCEL_KEY_FILE` or `-vercel-key-file` | Your token in a regular file only you can read. If you name a file that can't be read, Sandprobe doesn't fall back to the variable below. |
| `VERCEL_TOKEN` | The token, when no key file is named. |
| `VERCEL_TEAM_ID` or `-vercel-team` | Required. The team, `team_...`. |
| `VERCEL_PROJECT_ID` or `-vercel-project` | Required. The test project, `prj_...`. |

The token stays on your machine. It never enters the sandbox, a command line, a journal, a report or an error.

## Run it

```sh
export SANDPROBE_VERCEL_KEY_FILE=~/.config/sandprobe/vercel.key VERCEL_TEAM_ID=team_... VERCEL_PROJECT_ID=prj_...
sandprobe plan vercel
sandprobe run vercel -y
```

The sandbox has two CPU cores, `persistent=false`, a 15-minute timeout, and no injected secrets, ports or mounts.
The probe runs as the image's ordinary user, with `sudo=false`. Cleanup stops the session by its ID, then deletes the
sandbox's record by name. A sandbox that can't be confirmed gone keeps its journal, and the run exits 7.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | Each would reach Vercel's own platform: metadata, a proxy, the host over vsock, a Kubernetes API. Vercel's testing policy rules the platform out, so PRV-9 excludes them. |
| PER-5 | No reset, and no run-owned storage that survives one. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

## Terms and consent

PRV-9 records Vercel's policies. Vercel's [penetration testing policy](https://vercel.com/kb/guide/penetration-testing-on-vercel)
permits Pro and Enterprise customers to test their own applications, and says they "must not target the underlying
hosting infrastructure and platform". Vercel's [acceptable use policy](https://vercel.com/legal/acceptable-use-policy)
(reviewed 13 Nov 2026) says "You may conduct benchmark tests of a service", with an exception for AI services, and
asks that a public disclosure give enough detail to reproduce the test. A run uses CPU compute only, with no AI or
model calls. Neither policy is Vercel's approval of a run, and Sandprobe never presents it as one.

## What the score can and can't reach

- Persistence rests on PER-1 to PER-4. Whether anything survives a reset isn't tested.
- The record is deleted by name. Sandprobe checks the name's identity first, but the race between that check and the
  delete can't be closed, and the report says so.

### Canary and Cloud access (0.3.0)

Test traffic goes to the hosted canary at `control.pub.probe.ac0.dev` by default. It keeps the box's public address,
with the run's nonces, for the run's lifetime (at most 30 minutes), and your machine's public address in a rate
counter for at most an hour, both in memory only. To use a canary you run, name it with
`-canary-url <url> -canary-pin <pin>`, or with `-canary <state file>` for one from `deploy/canary.sh`. Cloud access is
not applicable here: PRV-9 excludes Vercel's own metadata and Kubernetes endpoints under Sandprobe's reviewed scope
for it, so the box holds no cloud identity of yours to check. Cloud access is never green, the score is out of five,
and a line under the score says why. A credential of yours put into the box is still caught under Secrets.
