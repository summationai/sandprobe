# Cloudflare Sandbox: `run cloudflare`

**Status:** Stable target. Last validated: pending. [All providers](README.md)

`run cloudflare` creates one container through a dedicated, authenticated controller Worker that you deploy for the
run, probes it and destroys it (PRV-10). It uses the built-in `cloudflare/debian-trixie` image on the smallest `lite`
instance, with Internet access on.

## Prerequisites

- An installed `sandprobe`, and a clone of this repository for the controller in
  [`deploy/cloudflare`](../../deploy/cloudflare/README.md).
- Node and npm, to bundle the controller with its pinned Wrangler, and Python 3 for its helper.
- A Cloudflare account that already has a `workers.dev` subdomain and Containers access. The helper never buys a plan
  or changes account-wide settings.

## Credentials

| Name | What it is |
|-|-|
| A token file for `manage.py --key-file` | An account-scoped token with Workers Scripts Write, Workers Containers Write and Account Settings Read, in a file only you can read. Only the helper reads it. |
| `SANDPROBE_CLOUDFLARE_SETUP` or `-cloudflare-setup` | The private journal `manage.py up` writes: mode 0600, in a directory only you can write. It holds the controller's one-run capability, so never commit or print it. |

The management token never enters the Worker or the container.

## Run it

Bundle the controller, deploy it, run, then remove it. [`deploy/cloudflare/README.md`](../../deploy/cloudflare/README.md)
has the full steps:

```sh
(cd deploy/cloudflare && npm ci --ignore-scripts && WRANGLER_SEND_METRICS=false npm run check)
python3 deploy/cloudflare/manage.py preflight --key-file <token file> --account <account ID>
python3 deploy/cloudflare/manage.py up --key-file <token file> --account <account ID> \
  --state <private dir>/cloudflare-run.state --bundle /tmp/sandprobe-cloudflare-bundle/worker.js
sandprobe plan cloudflare -cloudflare-setup <private dir>/cloudflare-run.state
sandprobe run cloudflare -cloudflare-setup <private dir>/cloudflare-run.state -y
python3 deploy/cloudflare/manage.py down --key-file <token file> --account <account ID> \
  --state <private dir>/cloudflare-run.state
```

Each controller allows exactly one create. The container has a 15-minute hard expiry and a 2-minute inactivity
limit as backstops. Run `manage.py down` after every run: it removes the Worker and its resources by their recorded
IDs.

## What's skipped, and why

| Check | Why |
|-|-|
| SEC-4, EGR-3, AMP-6, AMP-7 | Each would contact a Cloudflare-owned endpoint: metadata, a proxy, the host over vsock, a Kubernetes API. Cloudflare's testing policy excludes provider destinations, so PRV-10 excludes them. |
| PER-5 | No reset, pause or persistent storage. |
| EGR-6 | Contacting public upload sites isn't approved, on any run. |

## Terms and consent

PRV-10 records Cloudflare's terms as reviewed on 13 Nov 2026. Cloudflare's
[Self-Serve Agreement](https://www.cloudflare.com/terms/), section 2.2.2, says: "You are permitted to perform
benchmark tests of our Services." A disclosure must let others reproduce the test, and section 2.7 prohibits abusive
or malicious use. Cloudflare's [testing policy](https://developers.cloudflare.com/fundamentals/reference/scans-penetration/)
limits testing to your own assets, forbids exploiting findings, and excludes provider destinations outside its bug
bounty's scope. Sandprobe claims no approval from Cloudflare.

## What the score can and can't reach

- Persistence rests on PER-1 to PER-4. Whether anything survives a reset isn't tested.
- This is one declared configuration, run in exec mode. Native exec inherits only `PATH`, not the image's full
  environment, so the report describes this configuration, not every Cloudflare sandbox.
- The Worker's name can be reused, so its removal has a check-to-delete race, which the report states.

### Canary and Cloud access (0.3.0)

Test traffic goes to the hosted canary at `control.pub.probe.ac0.dev` by default. It keeps the box's public address,
with the run's nonces, for the run's lifetime (at most 30 minutes), and your machine's public address in a rate
counter for at most an hour, both in memory only. To use a canary you run, name it with
`-canary-url <url> -canary-pin <pin>`, or with `-canary <state file>` for one from `deploy/canary.sh`. Cloud access
is not applicable here: PRV-10 excludes Cloudflare's own metadata and Kubernetes endpoints under Sandprobe's
reviewed scope for it, so the box holds no cloud identity of yours to check. Cloud access is never green, the score
is out of five, and a line under the score says why. A credential of yours put into the box is still caught under
Secrets.
