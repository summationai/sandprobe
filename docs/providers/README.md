# Where Sandprobe runs

This page is the single source for each provider's status. Each provider's own page has its setup, the exact command,
what it skips and why, its terms, and what the score can and can't reach there.

"Last validated" is the date of the latest live check recorded on the provider's own page, which says what ran.
"Pending" means its page records none yet.

- **Stable target:** meant to be fully supported.
- **Beta:** works, with known gaps that its page names.
- **Experimental:** the provider's terms restrict testing, so a live run needs the operator's own authorization or
  clearance, never represented as provider-written permission. Each page quotes its PRV row.

| Provider | Status | Run | Setup | Checks | Last validated |
|-|-|-|-|-|-|
| [Any box with a shell](exec.md) | Stable target | `sandprobe run exec -as <user> -y -- <command>` | None. Your own command reaches the box. | Off by default: SEC-4, EGR-3, AMP-6, AMP-7 (PRV-15). SEC-4, EGR-3 and AMP-7 would contact your provider's own endpoints; AMP-6 only checks for a vsock device and connects to nothing. PER-5 skipped: an existing box is never reset. | pending |
| [Local Docker](docker.md) | Stable target | `sandprobe run docker <image> -as <user> -y` | Docker, with the image already local | No provider exclusions. PER-5 skipped: nothing a run creates outlives the container (DKR-5). | pending |
| [Kubernetes](kubernetes.md) | Stable target | `sandprobe run kubernetes -as <user> -y` | `kubectl`; `SANDPROBE_KUBE_CONTEXT` (required), `SANDPROBE_KUBE_NAMESPACE`, `SANDPROBE_KUBE_IMAGE`, `SANDPROBE_KUBE_OVERRIDES` | Off by default: SEC-4, EGR-3, AMP-6, AMP-7, since whoever hosts the cluster has terms the recipe can't know (PRV-16). PER-5 skipped: the recipe has no reset. | 25 Nov 2026 |
| [Your own recipe](recipe.md) | Beta: on `main`, not yet in a release; run end to end on local Docker only | `sandprobe run -recipe <file> -as <user> -y` | A recipe file of your own, which is host code that runs with your credentials, and the settings its `sp_ready` checks | Always off: SEC-4, EGR-3, AMP-6, AMP-7, since Sandprobe hasn't reviewed your recipe or your provider's terms (RCP-4); only `-provider-endpoints` turns one on. PER-5 skipped: recipe resets aren't built. | pending |
| [E2B](e2b.md) | Stable target | `sandprobe run e2b -y` | `SANDPROBE_E2B_KEY_FILE` or `E2B_API_KEY`; `SANDPROBE_E2B_PYTHON` | Skips SEC-4, EGR-3, AMP-6, AMP-7: E2B-owned endpoints (PRV-8). PER-5 skipped: no reset. | pending |
| [Daytona](daytona.md) | Stable target | `sandprobe run daytona -y` | `SANDPROBE_DAYTONA_KEY_FILE` or `DAYTONA_API_KEY`; `SANDPROBE_DAYTONA_PYTHON` | Skips SEC-4, EGR-3, AMP-6, AMP-7: Daytona-owned endpoints (PRV-12). PER-5 skipped: no reset. | pending |
| [Vercel Sandbox](vercel.md) | Stable target | `sandprobe run vercel -y` | `SANDPROBE_VERCEL_KEY_FILE` or `VERCEL_TOKEN`; `VERCEL_TEAM_ID`; `VERCEL_PROJECT_ID` | Skips SEC-4, EGR-3, AMP-6, AMP-7: Vercel's platform is out of scope (PRV-9). PER-5 skipped: no reset. | pending |
| [Cloudflare Sandbox](cloudflare.md) | Stable target | `sandprobe run cloudflare -y` | `SANDPROBE_CLOUDFLARE_SETUP`: the journal `deploy/cloudflare/manage.py up` writes | Skips SEC-4, EGR-3, AMP-6, AMP-7: Cloudflare-owned endpoints (PRV-10). PER-5 skipped: no reset. | pending |
| [Fly Sprites](sprites.md) | Stable target | `sandprobe run sprites -y` | The `sprite` CLI, logged in under `~/.config/sandprobe/sprites`; `SANDPROBE_SPRITES_ORG` if that login holds several orgs | Skips SEC-4, EGR-3, AMP-6, AMP-7: Fly-owned endpoints (the Sprites PRV row). Runs PER-5 through a checkpoint and restore. | pending |
| [AWS Nitro on EKS](aws-nitro.md) | Stable target | `sandprobe run aws-nitro -variant isolated -y` | The cluster `deploy/eks.sh up` makes, with `PROFILE` set to your AWS CLI profile; `kubectl` | No provider exclusions, so SEC-4 and AMP-7 run. PER-5 skipped: the pod has no persistent volume. | 25 Nov 2026, `isolated` |
| [Modal](modal.md) | Beta | `sandprobe run modal -y` | `SANDPROBE_MODAL_WORKSPACE`, and Modal's own login (`modal setup`, or `MODAL_TOKEN_ID` and `MODAL_TOKEN_SECRET`) | Skips SEC-4, EGR-3, AMP-6, AMP-7: Modal-owned endpoints (PRV-5). PER-5 skipped: no reset. | 25 Nov 2026 |
| [Docker Sandboxes](docker-sandboxes.md) | Beta: `run exec`, no adapter | `sandprobe run exec -as agent -y -- sbx exec -i <sandbox> sh` | Docker's `sbx`, signed in, and a local sandbox | Off by default: SEC-4, EGR-3, AMP-6, AMP-7 (PRV-15). PER-5 skipped: an existing box is never reset. In the one validated run, Exfiltration stayed unproven through Docker's proxy. | 25 Nov 2026 |
| [GKE Agent Sandbox](gke-agent-sandbox.md) | Beta: `run exec`, no adapter; 0.3.8 or later | `sandprobe run exec -as <uid> -y -- kubectl exec -i <pod> -c <container> -- sh` | `kubectl` and a running Sandbox | Off by default: SEC-4, EGR-3, AMP-6, AMP-7 (PRV-15). PER-5 skipped: an existing box is never reset. AMP-3 unknown when the pod's status has no NoNewPrivs line, as in the run checked. | 25 Nov 2026 |
| [Baseten](baseten.md) | Beta | `sandprobe run baseten -y` | `SANDPROBE_BASETEN_KEY_FILE` or `BASETEN_API_KEY`; `BASETEN_TEAM_ID` when the key reaches several teams; `BASETEN_REGION` (optional) | Skips SEC-4, EGR-3, AMP-6, AMP-7: Baseten-owned endpoints (PRV-6). PER-5 skipped: suspend and resume isn't a reset. | pending |
| [Boat](boat.md) | Experimental: a live run needs the operator's informed authorization, never a claimed provider-written approval (PRV-11; [Boat's terms](https://boat.dev/terms)) | `sandprobe run boat -y` | `SANDPROBE_BOAT_KEY_FILE` or `BOAT_API_KEY` | Skips SEC-4, EGR-3, AMP-6, AMP-7: Boat-owned endpoints (PRV-11). PER-5 skipped: no reset. | pending |
| [exe.dev](exedev.md) | Experimental: a live run needs the operator's own clearance for this bounded run, never represented as provider-written permission (PRV-13; [exe.dev's terms](https://exe.dev/docs/terms-of-service)) | `sandprobe run exe.dev -y` | `SANDPROBE_EXEDEV_KEY_FILE` (a key file only) | Skips SEC-4, EGR-3, AMP-6, AMP-7: exe.dev's own endpoints (PRV-13). PER-5 skipped: no reset. | pending |

Every check a row doesn't skip runs. Every run also has these skips. Each is listed in the report with its reason,
and none counts as a pass (GRD-3):

- EGR-6 (upload sites such as GitHub, npm, PyPI or S3), since contacting them isn't approved;
- EGR-3 when the agent's environment names no proxy, or names a local one you didn't approve with `-allow-local-proxy`;
- AMP-6 when the box has no vsock device.

Run `sandprobe providers` to see which of these are ready on your machine, and what to set up for the rest. Run
`sandprobe plan <provider>` to see what a run would create, contact, mark and delete. Nothing is created until you
approve the plan.

Read your provider's terms before you run anything. Sandprobe never presents a run as the provider's permission.
The rules behind each row are its PRV row in [SPEC.md](../../SPEC.md).

This page shows coverage only. It holds no grades, scores or results of any provider's real boxes.
