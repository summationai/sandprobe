# Fly Sprites: `run sprites`

**Status:** Stable target. Last validated: pending. [All providers](README.md)

`run sprites` creates one sprite with default settings in your Sprites org, checkpoints it, probes it, restores the
checkpoint to test what survives a reset, and destroys it (the Sprites PRV row in SPEC.md).

## Prerequisites

- An installed `sandprobe`. You don't need a clone of this repository.
- The `sprite` CLI: `curl https://sprites.dev/install.sh | bash`.
- A Sprites org.

## Credentials

Sandprobe keeps a Sprites login of its own, under `~/.config/sandprobe/sprites`, so your own sprite configuration is
never touched. When there's none, `sandprobe providers` prints the command that makes it:

```sh
HOME=~/.config/sandprobe/sprites sprite auth setup --token <your token>
```

| Name | What it is |
|-|-|
| `SANDPROBE_SPRITES_ORG` or `-org` | The org for the throwaway sprite. Needed only when that login holds several orgs. |

## Run it

```sh
sandprobe plan sprites
sandprobe run sprites -y
sandprobe run sprites -setup ./my-agent-setup.sh -y
```

`-setup <file>` grades your own sprite configuration, not only the default one. Your script runs once in the new
sprite, as its default user, before the checkpoint, so the reset restores the configured box. If it leaves an
executable `/usr/local/bin/agent-exec`, every probe call runs through it, the way your agent's commands do (SPR-1,
SPR-2). Nothing the script prints is kept.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | Each would contact a Fly-owned endpoint: metadata, a proxy, the host over vsock, a Kubernetes API. Fly's acceptable use policy prohibits security testing, so the Sprites row keeps every check's traffic inside your own sprite and on its way to the canary. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

PER-5 runs: Sandprobe restores the checkpoint it took before the probe, then looks for its markers.

## Terms and consent

The Sprites row records Fly's terms as read on 20 Nov 2026. Fly's
[acceptable use policy](https://fly.io/legal/acceptable-use-policy/) lists "Security testing (network or application
scanning, phishing, or penetration testing)" among prohibited uses. Sandprobe's position, in that row, is that it
isn't security testing of Fly: it checks, from inside your own sprite, that you can safely use it as an agent
sandbox. That is why the four checks above are excluded. The host still uses Fly's API to create, checkpoint,
restore and destroy the sprite. Read the policy yourself and decide whether your run fits it.

## What the score can and can't reach

- PER-5's roots (`/`, `/tmp` and `/var/lib/docker`) have no provider identity, so PER-5 can find something or stay
  unknown, but never prove that nothing survives.
- Sprites reaches a sprite only by name. Before each call, Sandprobe checks that the name still answers with the ID
  its create returned. The race between that check and the call can't be closed, and the report says so.

### Canary and Cloud access (0.3.0)

Test traffic goes to the hosted canary at `control.pub.probe.ac0.dev` by default. It keeps the box's public address,
with the run's nonces, for the run's lifetime (at most 30 minutes), and your machine's public address in a rate
counter for at most an hour, both in memory only. To use a canary you run, name it with
`-canary-url <url> -canary-pin <pin>`, or with `-canary <state file>` for one from `deploy/canary.sh`. Cloud access
is not applicable here: the Sprites row excludes Fly's own metadata and Kubernetes endpoints under Sandprobe's
reviewed scope for it, so the box holds no cloud identity of yours to check. Cloud access is never green, the score
is out of five, and a line under the score says why. A credential of yours put into the box is still caught under
Secrets.
