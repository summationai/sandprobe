# Local Docker: `run docker`

**Status:** Stable target. Last validated: pending. [All providers](README.md)

`run docker` grades a throwaway container made from a local image, on your own machine. No provider is involved
(PRV-14).

## Prerequisites

- An installed `sandprobe`. You don't need a clone of this repository.
- Docker, running.
- The image, already on this machine. Nothing is pulled.

## Credentials

None.

## Run it

```sh
sandprobe plan docker my-agent-image -as agent
sandprobe run docker my-agent-image -as agent -y
sandprobe run docker my-agent-image -as agent -y -- --read-only --cap-drop ALL --network none
```

Everything after `--` goes to `docker run` unchanged, so pass the options your agent's sandbox really uses. `--rm` is
refused: Sandprobe does its own teardown. `-as` names the agent's user; without it, the run uses the container's own
user, else root.

The run creates a bridge network, a canary container and the container under test, and deletes each by the ID Docker
returned. If any of it can't be confirmed gone, the run says so, names its ID and exits 7.

### What runs in the container

Your image's own entrypoint, command and health check don't run. Sandprobe starts the container with its own idle
process as the entrypoint: the probe it bind-mounts, in a mode that only waits. It also passes `--no-healthcheck`,
unless you name a health option yourself (DKR-1). So an image whose entrypoint exits without a task or a terminal, as
most agent images' does, needs no wrapper and no keep-alive. SEC-2 and SEC-5 don't count the idle
process, once Docker's own record confirms it is PID 1 of the container's PID namespace (DKR-2). With `--init` or
`--pid` that can't be confirmed, so they count it.

To run a process of your own, such as the agent's dev server, pass `--entrypoint` after `--`. It starts with no
arguments, the image's health check stays on, the plan and the report say so, and SEC-2 and SEC-5 count them like
any other process:

```sh
sandprobe run docker sandprobe-demo/vibe -as agent -y -- --entrypoint /opt/app/entry.sh
```

If the container stops before or while the probe runs, the run says what stopped, with its exit code as Docker
recorded it, and gives a command to run instead (DKR-3).

With `--read-only`, Sandprobe adds a 16 MB tmpfs at `/opt/sandprobe/scratch` for the probe's own scratch, so a
read-only root with no writable `/tmp` still runs. The plan and the report name it as Sandprobe's addition, and no
check counts it (DKR-4).

## What's skipped, and why

No check is excluded for a provider. Only the skips every run has apply:

| Check | Why |
|-|-|
| EGR-6 | Contacting public upload sites isn't approved, on any run. |
| PER-5 | Always skipped on `run docker`: nothing it creates can outlive the container (DKR-5). |
| EGR-3 | Skipped when the agent's environment names no proxy, or names a local one you didn't approve with `-allow-local-proxy`. |
| AMP-6 | Skipped when the container has no vsock device. |

## Terms and consent

No provider's terms apply. The image and the machine are yours.

## What the score can and can't reach

- PER-5 is skipped on every `run docker`, so storage that outlives the container isn't tested (DKR-5). Its reset
  would recreate the container, which marks only a persistent volume Sandprobe created for the run, and `run docker`
  creates none: a named volume in your options is yours and is never marked, and an image's `VOLUME` gets a fresh
  anonymous volume on every create, so no marker could survive in it. With nothing to mark, no marker is placed and
  the container is never reset.
- Egress is measured to a canary on a network Sandprobe made, with the box's resolver pointed at it. A receipt proves
  the box can send data to an address it was given, not that it reaches the internet. If your options name a network
  (`--network none`, say), the box keeps that network instead.

### Canary and Cloud access (0.3.0)

`run docker` always starts its own canary container on your machine, and refuses `-canary`, `-canary-url` and
`-canary-pin`. The canary's test traffic stays on your machine. Cloud access is tested: SEC-4 asks the cloud metadata
addresses `sandprobe plan docker` lists which identity the box has, and AMP-7 makes a TLS handshake, with no request,
to a Kubernetes API the box names. The score is out of six.
