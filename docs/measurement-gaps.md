# Interpreting measurement gaps

Sandprobe measures a provider configuration running a workload. A score is not an execution count or a certificate
that every feature was tested. Retain the source revision, workload contract, raw results, exclusions and cleanup
evidence when comparing configurations. Recomputing a saved report with newer scoring code is an offline analysis,
not a fresh measurement.

| Result or gap | Meaning | What can improve the evidence |
|---|---|---|
| `pass`, `finding`, verified `absent` | A conclusive result under that check's proof rules | Preserve the supporting evidence and measurement scope. |
| `not_found` | A find-only check found no exposure; containment is unproven | A supported stronger measurement, if one exists; never relabel as a pass. |
| `unknown` | The evidence does not decide the check | Inspect the recorded reason and attempts before changing code or rerunning. A check may have run and remained inconclusive. |
| `skipped` | The host did not select the check | Resolve the actual gate: permitted scope, required feature, lifecycle support or implementation. |
| `scoped_out` | A selected check reports that its defined discovery found no applicable target | Inspect the stated discovery scope. This is not proof that every possible custom target is absent. |

The managed Nitro and Daytona workloads deliberately exclude provider endpoints. Preserve those exclusions until
the provider terms and assessment scope permit a specific measurement. Do not assume a feature is absent because
its check was excluded; an exclusion can mask a separate feature or implementation prerequisite.

| Check | Prerequisites and current limitations |
|---|---|
| SEC-4 | Requires permitted metadata-endpoint scope. A configured cloud identity or its absence is a separate fact. |
| EGR-3 | Requires an actual configured workload proxy, permitted scope and, for a local proxy, explicit local-proxy approval. Installing a proxy solely to exercise this check changes the configuration. |
| AMP-6 | Host connectivity is not implemented. The handler checks `/dev/vsock` presence, but never connects; a present device yields unknown. A missing device or an exclusion can prevent selection. Neither approval nor device presence alone completes the measurement. |
| AMP-7 | Requires a Kubernetes API target named by the workload environment and permitted scope. This check makes a TLS handshake, not an authenticated permissions assessment. |
| AMP-8.blk | Uses sysfs names mapped to `/dev/<name>`, plus explicitly declared custom paths under EVD-13. An existing workload device can be declared with `run exec -block-device-path`; this never attaches a device or reads device data. Do not add a device just to reduce exclusions. |
| PER-5 | Requires a supported reset, run-owned storage and a safely identifiable run-owned marker. For the default regular-file marker, an inode mismatch remains unknown and unread. EVD-15 adds an explicit host-API `symlink-v1` alternative: only the run-owned link's bounded metadata is checked, never its target or file contents. Unsupported link operations stay unknown. A claimed persistent volume alone does not prove marker survival. |

For network checks, a connected socket followed by a TLS reset or HTTP error, without an independent canary
receipt, proves neither delivery nor a refusal. A new protocol must be supported by the deployed canary and
explicitly selected under EVD-10. `canary check -require-http-marker-v1` checks that prerequisite without creating
a sandbox or proving guest delivery. Repeating the same unsupported exchange does not add proof.

Keep workload success, security findings, measurement completeness and cleanup as separate conclusions. Change
the workload configuration only for a workload or security requirement, and compare the changed configuration
explicitly against its baseline.

EVD-18 also offers explicit `empty-file-v1` metadata markers for filesystems that reject symbolic links.
It creates an empty regular file in a distinct run-owned namespace and rechecks only its pinned type, zero size
and stable name during measurement. The run token is in the name; no file contents are read. Retained metadata
is a persistence finding, not a pass or a claim of regular-file content identity. There is no automatic fallback;
the selected mechanism remains visible in the plan and comparisons. If no marker can be placed, Sandprobe records
the placement failure and avoids an unnecessary reset. Incomplete resets may report a bounded host-stage label;
provider error messages and credentials are never used as that label.

The optional Daytona organization-default policy readback is separate from the standard 28 checks. EVD-19 uses
Daytona's documented sandbox-ID organization read after fresh run ownership verification, rather than an
account-level organization read. A response is observed only with the matching organization and a strict boolean;
a rejected or unverifiable response remains unknown. It never proves effective network enforcement.
Managed raw-evidence artifacts have a separate compatibility boundary from public reports. New collectors write
`sandprobe.managed-evidence/2`, including optional reset-stage diagnostics. Use a matching new reader. A reader
from 0.3.4 or earlier doesn't check the version: it refuses an envelope that carries a reset stage, but its Nitro replay
drops the `schema` field and accepts a version2 envelope with no stage as if it were unversioned. Historical unversioned envelopes are legacy version1
and remain replayable without the new diagnostic. This does not change OUT-1 or authenticate saved evidence.

## Generate a gap plan

```sh
sandprobe gaps /path/to/legacy-standard-report.json -o json
sandprobe gaps /path/to/legacy-standard-report.json /path/to/measurement-prerequisites.json -o json
```

This is offline structural analysis, not a fresh assessment or authentication of either saved input. It lists
scope, feature and implementation prerequisites independently, plus the proof needed for inconclusive rows.
For example, an excluded AMP-6 still needs an implemented host-connectivity measurement even if the survey
reports a vsock device. A scope exclusion does not establish that a proxy or Kubernetes target exists.

Managed Nitro and Daytona collectors now write `measurement-prerequisites.json` from their existing original-agent
survey. The separate private artifact contains fixed labels and run/probe bindings, without environment values,
proxy credentials or target addresses. No extra provider requests are made. A write failure warns with a fixed
message and leaves the standard assessment intact. The report and managed-evidence schemas are unchanged.
Old assessments do not have this file: omit it, and the plan says **not recorded**, never absent. Do not reconstruct
an excluded prerequisite from an empty manifest target: the host deliberately removed that target before probing.
A mismatched, edited, partial or unsupported sidecar is refused. A structurally matching file is still unauthenticated.

`gaps` adds no endpoint opt-in, network exception, device or privilege. Its exit status follows the saved assessment:
0 for a valid complete assessment, 5 for a valid incomplete assessment, and 2 for unsupported/unsafe inputs.
Successful generation does not mean that every check ran, or that the gaps can all be closed on the current provider.

## Timeboxed work dispositions

New `gaps` output declares `sandprobe.measurement-gaps/2` and assigns each inconclusive row one disposition.
This is a work plan layered over the original result, not a new grade or proof. Version1 consumers need to accept
the new version explicitly; the saved report and prerequisite schemas do not change.

| Disposition | Work rule |
|---|---|
| `policy` | Keep the exclusion/opt-out. Do not implement around it or enable an endpoint to improve the count. |
| `not_applicable` | The defined discovery or a recognized feature/lifecycle gate supplies no target in this configuration. Do not install a proxy, attach a device or fabricate reset support. |
| `unprovable` | The current find-only or route measurement cannot decide the negative from silence, a reset or an unsigned error. Repeated runs are not work items. |
| `bridgeable` | A specific configuration/prerequisite repair or bounded investigation may improve evidence. The label promises neither a fix nor permission. Require fresh proof before changing the result. |

Explicit scope exclusions take priority when they hide another prerequisite. For example, an excluded vsock check
remains policy even though connectivity implementation is also missing. The plan retains both requirements.
The absence of a recorded prerequisite is not evidence that the feature is absent.

SEC-5 with effective or permitted CAP_SETUID/CAP_SETGID is a bridgeable configuration candidate. Remove unnecessary
capabilities in an explicit workload configuration, then test again. The existing Nitro `reference-open` profile
already drops all capabilities; the managed Nitro and Daytona workloads also request zero capabilities. Keep
these hardened runs distinct from the native documented-default Nitro run. A zero capability mask does not replace
full process-target coverage, eligible refusals or the positive/negative controls. Bounding-only capabilities do not
mean the agent currently holds them. Never promote a prior unknown or not-found result because settings changed.

A useful end-of-day handoff records the source/configuration cohort, every row's disposition, any synthetic bug
reproduction, checks performed and unresolved dependencies. Report improvements only from new measured evidence.
