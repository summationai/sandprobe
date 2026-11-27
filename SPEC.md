# Sandprobe

This is Sandprobe's specification. Every behavior traces to a rule ID here, and the code and tests cite those IDs.

Sandprobe answers one question about an AI agent's sandbox: what could a hijacked agent reach? A small read-only probe
runs inside the box, as the agent, through the same path the agent's own commands take. In about a minute it checks
four things: readable secrets, ways out, persistence that survives a reset, and amplifiers such as sudo, capabilities
and control sockets. It chains a readable secret and a proven way out into one finding, scores the box out of six for the
checks it ran, and gives a fix for each finding. It never reads a secret's value. Platform teams, their security leads,
and agents themselves (Claude Code, Codex) run it from one CLI. Its core rule is no false passes: a check passes only on
a negative proof, never because something failed quietly. Where no trustworthy negative proof exists, the check can
only find, and the report says what it could not prove. The promise has a stated boundary (SBX-10): it covers faults,
misconfiguration and wrappers, not a box that deliberately deceives the probe.

Sources: earlier internal sandbox checks, the AWS Nitro Sandboxes launch (9 Nov 2026) and its EC2 and EKS docs, and
independent security and code reviews of each change.

## At a glance

```
 host: a laptop, CI, or an agent's shell                    the box under test
 ┌────────────────────────────────────────────┐             ┌───────────────────────────────────┐
 │ sandprobe (Go, Charm TUI)                  │ create by   │ the agent's exec path             │
 │  ├ picker, access check, plan       UX     │ immutable   │  └ sandprobe-probe (static Go,    │
 │  ├ manifest: checks, nonce, box ID  GRD-5  │ ID, copy,   │     digest known to the host)     │
 │  ├ provider adapters                PRV    ├────────────▶│     observations only, no grade   │
 │  ├ reset, then storage-root recheck TWN-3  │ run as the  │                                   │
 │  ├ grader                           GRD    │ agent       │                                   │
 │  └ TUI · HTML · JSON                OUT    │◀────────────┤                                   │
 └───────────────┬────────────────────────────┘ observations└────────────────┬──────────────────┘
                 │ liveness before and after; receipts for the nonce          │ attempts carrying the nonce
                 └───────────────────────────────────▶ canary.<our domain> ◀──┘
                                                         TLS echo with a pinned key, TCP and UDP ports,
                                                         the authoritative name server for <nonce>.dns.*
```

The probe observes; only the host grades, and the host trusts nothing the box returns (GRD-5). Receipts reach the
host from the canary, never through the box.

## Local robustness extension, 16 November 2026

This bounded extension supersedes only the blanket exclusion of user-invoked offline comparison below. It adds no hosted service, scheduler, periodic provider probing, alert delivery or independent attestation; live provider runs are unchanged.

- **JON-1 Strict framing.** Protocol JSON is one bounded value, depth at most64, with no trailing data. Duplicate object member names, including case aliases which Go would map to the same field, are rejected before decoding. Case-distinct object names are conservatively rejected; arrays retain case-sensitive values. No raw malformed data/member names are echoed. Unknown-field rules on existing protocols remain strict. Preserve valid canonical existing messages and saved-run shapes.
- **JON-2 Every boundary and tests.** Apply JON-1 to host observation parsing and every probe stdin mode, with the existing1MiB byte bound checked before parsing (not a truncated reader accepted as EOF). Reject unsupported/extra probe arguments. Add duplicate/alias/nesting/trailing/oversize/fuzz regressions. CI runs build/vet/unit tests on Linux without cloud/provider credentials; no live provider tests or new paid resources.
- **ANL-1 Saved report input.** Offline analysis accepts only explicitly named report files opened with no-follow/nonblocking semantics and fstat-verified regular descriptors under an8MiB max+1 read bound and JON-1 framing. A supported schema, exactly the version its fields need (AGT-6), canonical known catalog IDs/results, unique checks, required grade/run/manifest fields and consistency between selected/skipped/check/unknown/completeness metadata are required. Missing/contradictory evidence is an error or incomplete, never a clean result. A `run exec` report's declared provider (PRV-17) is the person's word as recorded, but what it excludes comes from this binary's own table, never from the report: a name the table lacks, one on a report that isn't `run exec`, or skip kinds that differ from that name's entry are refused. A report's `run.recipe` (RCP-4) is read only whole: present exactly when `run.provider` is `recipe` and exactly when the report declares `sandprobe/7` (AGT-6), with `own` true, `sha256` exactly 64 lowercase hex digits and `run.box.created_by_sandprobe` true; a record on any other report, a `recipe` report without one, or any other shape is refused. Fixed errors do not echo file contents. Negative results must be legal for their catalog kind and include exported proof metadata; grade counts/findings must agree with checks where derivable. A `sandprobe/1` to `sandprobe/5` report still carries GRD-1's letter, checked as before (one of A, B, C, D or F on a valid run, empty on an invalid one); a `sandprobe/6` report carries no `letter` in any form (AGT-6). A saved letter is never printed, never copied into any output (the page `-out` re-renders included) and never an input to success/regression decisions. Analysis structurally validates exported reports, does not re-verify raw observations or canary receipts, and cannot authenticate or attest to an edited report. Every offline rendering of a saved report (`scorecard` in text, JSON and the page `-out` re-renders, `profile`, `assess`, `compare`, `fix`) says so plainly: structurally checked only, its observations and receipts not re-verified, and an edited report can't be told apart.
- **ANL-2 Coverage profile.** Five fixed areas are egress(EGR), secrets(SEC-1/2/3/5), privilege(AMP-1/2/3/8.sys/8.blk), persistence(PER), provider reach(SEC-4/AMP-4/5/6/7). SEC-3 stays aggregate secrets; no image/provider attribution is inferred. Each catalog check requires an explicit area mapping; an unmapped future check blocks offline analysis until classified. Counts distinguish findings, negative proofs, find-only no-finding, absent/out-of-scope, unknown, excluded and missing catalog coverage. No profile labels a wall secure/Held or reports the saved letter (GRD-1): its JSON is `sandprobe.profile/2`, which is `sandprobe.profile/1` without `reported_grade_unverified`. Invalid reports have no assessed area. Terminal output escapes untrusted identifiers, including Unicode format controls (Cf), bidi overrides/isolates, zero-width format characters and BOM as visible code points; JSON labels reported data as unauthenticated and self-observed.
- **CMP-1 Local comparison.** Compare two structurally validated reports by known check IDs/results/severities and declared scope/identity, never a saved letter or prose heuristics. The report version is not compared, so a `sandprobe/6` report against an older one of the same run reads unchanged. Flag new/worse findings and loss of coverage separately; removed/skipped/unknown checks cannot look like an improvement. Compare per-check scope/route, kind/evidence class, selected/skipped targets and recorded identity/config; unrecorded configuration remains unknown. Provider/mode/context differences are explicit, and unequal `run.recipe` records (RCP-4), one present on one side only included, are a `declared_configuration` change, since different host code made and deleted the boxes; no-observed-change is conditional on matched coverage/context and means only the summarized fields, not equivalent security or an attestation. Ignore ephemeral runIDs/timestamps/nonces/receipt destinations when comparing observations. Keep invalid/incomplete inputs visible. Exit precedence is input/usage2, invalid/incomplete or unmatched context5, observed regression6, then assessed/no observed regression0. Automated gates must reject every nonzero exit and inspect both findings and context fields, rather than gate only on exit6. No network, file writes, schedules or notifications.
- **CMP-2 Progress between two runs (24 November 2026).** A fix loop runs, applies fixes, runs again and compares, so `compare` also says what got better, without weakening CMP-1. From two valid reports (GRD-5) that ANL-1 accepts, check by check in catalog order:
  - **Got better:** a check that was a finding (any severity) or `unknown` in the before report and ends `pass` or `absent` in the after report: a result backed by proof, a negative proof (TWN-1) or a verified absence (TWN-2).
  - **No longer applies:** a check that was a finding or `unknown` and ends `scoped_out`. This is a separate list. It is never listed as better, since `scoped_out` is never a pass (KND-1): its discovery rule found nothing left for the check to apply to.
  - **No longer found, but not proven:** a finding in the before report that ends `not_found` or `unknown` in the after report. This is a separate list. It is never listed as better and never counted as better: `not_found` is never a pass (KND-2), and `unknown` proves nothing. A finding that ends `unknown` is also CMP-1's coverage loss, and leaves the after run incomplete, so the pair exits 5. A finding that ends skipped or missing is coverage loss only, as before.
  - Nothing else is listed in these lists. A finding whose severity drops but stays a finding, `unknown` to `not_found`, and a check clean in both reports are in neither list.
  - **Score:** `Score: <before> → <after>`, each `<score>/<of>` from SCR-2's score of its own report, the same numbers `scorecard` shows. The line appears only when both runs are valid. Otherwise the line says which report's run is invalid, so it has no score (GRD-5). An incomplete run keeps its score, as on its scorecard, and CMP-1's incomplete line stays.
  - **Identity:** when the recorded identity differs, the setup-differs line stays. A second line says that the agent's identity (its user, group, capabilities or privilege settings) differs. It says that this is expected when the fix was to change the agent's user or drop its privileges, and that the two reports still measured different identities. The warning and exit 5 stay.
  - **Words:** each listed check is named by its category and question (SCR-3), as `Secrets › <question>`, from fixed catalog text, never from report text. Never `Secrets: <question>`: FBK-4 reads that shape as a credential key, and wrapping would break it. Got worse and No longer tested come first, then Got better (`none` when empty), then "No longer applies (nothing left for it to check)" and the not-proven list (each only when it has a check), then the score. There is no "better" verdict: CMP-1's verdict lines are unchanged. Every line keeps UX-9: it wraps within 80 display columns, a list item's later lines indented under its text, and under a C or POSIX locale the bullet is `*`, the separator `>` and the arrow `->`.
  - **JSON:** `-o json` adds `got_better`, `no_longer_applicable` and `no_longer_found_not_proven` (check IDs in catalog order, `[]` when none and when either run is invalid), and `score_before` and `score_after` (`{"score": n, "of": m}` for a valid run, `null` for an invalid one). Every existing field keeps its name and meaning, and the schema stays `sandprobe.compare/1`. The change is additive, and needs no bump. AGT-6 makes a new OUT-1 field breaking because Sandprobe reads saved reports back with readers that refuse unknown fields (ANL-1, JON-1). Nothing in Sandprobe reads `sandprobe.compare/1` back, and CMP-1 tells gates to use the exit code and the findings and context fields, which don't change. The scorecard's JSON gained `green_not_proven` (SCR-2) the same way.
  - **Exit codes and gates:** unchanged. CMP-1's precedence (2, then 5, then 6, then 0) comes from the same fields as before, and nothing in this rule reads them. A complete pair with matched context and anything worse still exits 6. An incomplete or unmatched pair exits 5, whatever got worse or better. Better never outranks worse or incomplete.
- **QCK-1 Local quick observation.** A separate Linux quick entrypoint runs as the current identity with no network, provider APIs, external commands/sudo, socket connection, secret-value read, filesystem mutation, process memory/environment opens or persistence marker. The interface is `sandprobe-probe-linux-ARCH -quick [absolute-path ...]`; JSON-only output escapes untrusted strings. It reports own-identity metadata from at most64KiB of explicitly allowed proc status, at most256 environment names and metadata for at most32 explicitly declared absolute paths of at most1024 bytes each. No recursive traversal or symlink following; terminal strings are escaped. Output is capped at256KiB and the entrypoint has a five-second deadline; blocking filesystems may prevent graceful completion, so no result is inferred from timeout. Consumers must discard output on every nonzero exit and require complete JSON even on exit0; the watchdog may interrupt stdout and leave partial JSON with exit5. It reports permission metadata only; inaccessible/malformed observations stay unknown. It assigns no A–F grade or negative containment pass and labels egress/reset/sudo/process/provider-boundary coverage untested. It is not host-shipped attestation, a complete baseline, a comparison input or proof of secret disclosure. No fallback from quick data to sandprobe/1 report.
- **QCK-2 Tests and packaging.** Exercise quick mode only on synthetic fixtures/disposable owned local Linux containers, including missing proc/permissions/symlinks/caps/error cases. Package static Linux amd64/arm64 binaries with checksums and explicit build/version metadata; no unsigned remote installer or publication/release is implied. Existing full-provider flows and their selected checks stay unchanged.

## Scorecard headline, 19 November 2026

The scorecard is a simpler headline: six categories, each green or red (or not applicable, SCR-2), a score out of
the categories that apply, and every other detail in an appendix. This changes presentation only. The grader, the
letter and every saved report stay as they are, and OUT-1 gains only SCR-2's skip kinds in its manifest, in reports
that declare `sandprobe/2` (AGT-6); the scorecard is computed from a report's checks when it is shown, never written into one.
Since `sandprobe/6` (AGT-6) no generic output carries the letter (GRD-1), and every new report declares that version, or `sandprobe/7` when it carries `run.recipe`.

- **SCR-1 Six categories.** Every catalog check belongs to exactly one category, each asked as a question:
  Secrets, "can it read keys and tokens?" (SEC-1, SEC-2, SEC-3, SEC-5); Exfiltration, "can data leave the box?"
  (EGR-1 to EGR-6, each EGR-5 port); Containment, "can it reach past the box to the host?" (AMP-4, AMP-5, AMP-6,
  AMP-8.sys, AMP-8.blk); Privilege, "can it become root?" (AMP-1, AMP-2, AMP-3); Cloud access, "can it use your cloud
  identity?" (SEC-4, AMP-7): a cloud identity the person owns, meaning their own cloud roles, the metadata service of
  their own cloud, and their own Kubernetes API, never a hosted provider's own infrastructure; Persistence, "can it leave something for the next session?" (PER-1 to PER-5).
  This refines ANL-2's five areas without changing them: provider reach splits into Containment and Cloud access,
  and AMP-8 moves from privilege to Containment. An unmapped check fails the tests. Chains have no category; the
  checks they join already turn their own categories red.
- **SCR-6 Executed check counts.** The HTML category's tests-run counter counts recorded checks except
  skipped and scoped-out results. A missing row is not executed. An unknown is counted as executed/inconclusive,
  never as a pass; not-found is executed without a negative proof. Scope discovery alone is not an executed
  access test. These counters do not change SCR-2's score or SCR-5's proof coverage.
  Tests: `internal/report/fix_test.go` `TestHTMLExecutedCountsExcludeScopeOnlyResults`.
- **SCR-2 Green needs proof.** A category is green only when at least one of its checks was tested (any result but
  skipped), none is unknown, and none has a finding above Info. Anything else is red, and
  its reason says which: found, couldn't prove, or not tested. When every unknown in a category comes from HCN-5's
  no-canary choice, the reason reads "not tested: run without a canary" (a host reason, never a box string), and the
  category stays red.
  A category is not applicable only when every one of its checks was skipped and each skip's kind is `provider_terms`:
  a native adapter's PRV row excludes that provider-owned endpoint under Sandprobe's reviewed scope for that provider
  (PRV-5), or, on `run exec`, the PRV row of the provider the operator declared with `-provider` does (PRV-17). The
  kind's wire name stays `provider_terms`, but what it means is that reviewed scope, which rests on the provider's
  terms for some providers and on the project owner's own rules of engagement for others (Modal's, PRV-5), never on a
  claim about the provider's terms alone. In
  practice that is Cloud access (SEC-4 and AMP-7) on a hosted provider. That scope limits what Sandprobe measures,
  not whether a risk exists, so this rests on SCR-1's narrowed contract: on a hosted sandbox the metadata service and
  any Kubernetes API belong to the provider, and the box holds no cloud identity of the person's that these checks
  could reach. A credential of the person's own injected into the box (an environment variable, a key file) is still
  Secrets' to catch (SEC-1, SEC-3), never Cloud access's. The row reads "Not applicable: this box holds no cloud
  identity of yours that Sandprobe checks here; Sandprobe's reviewed scope for <name> excludes these provider-owned
  endpoints", fixed text in which `<name>` is the PRV-row key (never a box string), and the line beside the score
  reads "Cloud access isn't counted: Sandprobe's reviewed scope for <name> excludes these provider-owned endpoints
  (<reasons>)", with that provider's exclusion reasons from this binary's own PRV rows, never the report's text. The
  row carries `<name>` as `scope` in the card's JSON; a saved card from before it reads "for the provider" in its
  place. For PRV-17's declared provider, the row and the line each also say "The operator declared the provider as
  <name>; Sandprobe did not verify it".
  A kind is never taken on the report's word: the scorecard derives each
  check's kind from this binary's own policy for the provider the run names (a native adapter's PRV-row exclusions are
  `provider_terms`; `run exec`'s, a shipped recipe's and a person's own recipe's (`recipe`, RCP-4) defaults are `opt_in`,
  except that on a `run exec` report whose
  manifest declares a provider (PRV-17) the checks that provider's PRV row excludes are `provider_terms`; any other
  provider has none), uses it
  only when the manifest records the same, and ANL-1 refuses a saved report whose recorded kinds disagree with it, so
  editing `SkipKinds` alone changes nothing. Only the host writes a kind, and only for a check it excluded
  under GRD-3's provider-endpoint gate (`SkipKinds` in the manifest, never in the probe's input); a skip without one
  (a report from before this rule, a survey-driven skip such as "no vsock device", the managed workload runners'
  exclusions) is plain "Not tested". The managed workload runners record no kind, so their exposure cards (SCR-4)
  stay out of six: the Nitro runner's exclusions are RUN-8's audit scope, not a provider's terms, and the Daytona
  workload runner, though it uses PRV-12's exclusions, keeps the common Nitro and Daytona ranking and the deploy
  runners' six-category check; `run daytona` itself reads out of five. Nothing the box returns, no unknown, and no `-no-canary` run makes a category
  not applicable: HCN-5's checks stay unknown, so their category stays "not tested: run without a canary", red, and
  the run incomplete. PRV-15's and RCP-4's default exclusions (`run exec`, `run kubernetes`) are kind `opt_in`, since
  the person may lift them, and on a Kubernetes cluster Cloud access is the category that matters most: when none of
  a category's checks was tested and its skips are `opt_in`, it stays red, and the reason reads "Not tested: opt in
  with -provider-endpoints SEC-4,AMP-7 if your provider's terms allow", naming those checks from the catalog
  (PRV-15's opt-in). The score is the number of green categories out of the
  applicable ones. A not-applicable row is never green and never counted as passed: it leaves the denominator, so a
  run with one reads at most 5/5 and is never shown or serialized as 6/6. Coverage still counts its checks as
  skipped (SCR-5), so the card keeps the unmeasured endpoints visible. No finding, count or completeness changes: GRD-3's skips already never touch GRD-1 or
  GRD-2. `compare` reports a changed set of `provider_terms` skips, or a changed PRV-17 declared provider, as a
  changed setup (CMP-1's declared configuration), so a newly not-applicable category is never read as like-for-like,
  and a check that goes from
  tested to skipped stays coverage loss. An `opt_in` skip and one with no kind both read "Not tested", so a report
  from before this rule and a new `opt_in` one of the same box compare as a matched pair.
  A green row that rests on a check with no finding but no negative proof says so in one line ("not proven: DNS"),
  since that is KND-2's not proven, never a refusal; a check whose findings are only ever Info is left out of it. When
  a green row has no conclusive check at all (SCR-5's `Conclusive == 0`: every check tested in it ended `not_found` or
  `scoped_out`, with no `pass`, no `absent` and no finding), the card sets `green_not_proven: true` on that row, and
  OUT-2's page, the terminal and workload exposure tables mark it as unproven (`none found · unproven`, dashed, on the page,
  where category states read `exposed`, `clear`, `none found · unproven` or `not applicable`; `◌ GREEN · NOT PROVEN` in the
  terminal; `Green · not proven` in workload exposure tables) rather than plain green; it still counts toward the score. An
  Info finding is a completed observation (SCR-5), so a green row with one, or with any `pass` or `absent`, stays plain
  "Green" with its "not proven" line. The label only ever weakens a green: a row with an unknown, a finding above Info
  or no tested check stays red, a not-applicable row stays not applicable, and an invalid run has no rows.
  Old `sandprobe.workload-exposure/1` rows may omit this display flag: validate their coverage first and derive the
  rendered flag from that coverage. A supplied true flag that contradicts coverage, sits on a row that isn't green, or
  comes without coverage is rejected; an omitted or false flag never suppresses the rendered label and never becomes
  additional proof (SCR-5). An invalid run (GRD-5) has no score. A full score therefore means
  no finding above Info and nothing unknown in the categories it counts, and is still bounded by GRD-4 and SBX-10.
- **SCR-5 Exposure and measurement coverage are separate.** Preserve SCR-2's RC
  score, but attach deterministic catalog-wide coverage to every valid scorecard.
  Partition each category's checks into proven pass/absence, findings (including
  Info), unproven not-found, unknown, scoped-out, skipped and missing. Only
  pass/absence, finding and not-found results contribute usable-result coverage;
  unknown, scoped-out, skipped and missing entries do not. An unknown check may
  have executed but stayed inconclusive. Complete coverage
  requires a pass/absence or finding for every check; a finding is a completed
  observation, never a security pass. List all gaps by fixed catalog ID. State
  category/check usable-result and completion counts beside the score in JSON,
  terminal and HTML, including workload scorecards. A green category and a full
  score never imply complete coverage, and coverage still counts all six categories,
  a not-applicable one's checks as skipped (SCR-2). New derived display annotations must not become
  required fields for existing `sandprobe.workload-exposure/1` records with valid coverage. Derive display
  distinctions from validated coverage; never invent proof for a legacy record. Test:
  `internal/report/scorecard_coverage_test.go` `TestSavedExposureCoverageWithoutNewDisplayFields`.
  Invalid runs claim no coverage; historical
  scorecards without coverage remain readable and never gain an invented complete
  status. Derive coverage only from graded checks and grading unknowns, never a
  provider flag, supplied counter, workload pass or configuration declaration.
  This adds no network checks, credential reads or provider-infrastructure probes,
  changes no scope exclusion, and changes no RC exposure verdict. Only synthetic
  public fixtures enter tests; private saved runs and accounts remain outside git.
- **SCR-3 Headline first, details in the appendix.** OUT-2's page, the terminal summary after a run, and the offline
  `sandprobe scorecard <report.json>` lead with the score and the six rows: name, question, green, green · not proven,
  red or not applicable (SCR-2), and a short reason built only from catalog IDs and titles, never from box strings (a
  not-applicable row's reason is the host's own skip reason). GRD-4's statement stays beside the score.
  On OUT-2's page a single hairline scorecard sheet comes first. Its specification bar names what is being tested (a
  plain-English sandbox service or runtime label the page chooses from `run.provider` and any PRV-17 declared provider,
  beside the box's name; a provider the page doesn't recognize reads "Sandbox · provider not recognized", never the
  report's own string) and the run's facts: the observed Linux user ID when recorded, when it ran, the probe's version, and
  that the probe ran in-box and is not attested (SBX-10, fixed text, never read from the report). `run.mode`, the
  probe's launch path, isn't among them. Below the specification bar, the sheet splits between the score — the largest
  thing on the page, with its clear-category count and breakdown — and a two-tone headline: one plain sentence per chain
  with its severity (GRD's lead sentence when there is no chain), any incomplete status ("Incomplete: n checks
  unknown"), not-counted category notice, grader notes, GRD-4's statement, and a hairline result ledger giving the
  failures by severity, the passes and the unknowns; an invalid run shows its invalid notice ("Invalid run: no score",
  with the reason) and no score, ledger or category matrix. Directly under the split, the six categories sit in a 3×2
  hairline matrix, each giving its state (`exposed`, `clear`, `none found · unproven` dashed, or `not applicable`), question,
  reason, "x/y run" and tabular links to its checks. Neither OUT-2's page (its title included, which carries
  the score instead) nor the terminal prints a letter grade, and OUT-1's JSON carries none (`sandprobe/6`, AGT-6). The JSON the page
  embeds carries none either: a page re-rendered from an older report (`-out`) embeds it as a `sandprobe/6` report, the
  same document without its `letter` (AGT-6), so the embedded JSON still reads under ANL-1; the page's footer names that version.
  Below the sheet, "What to fix" lists every test exactly once on hairline ledger rows. Fail (a finding above Info; an
  indicator carries an explicit `· exposure sign, not confirmed` note, never a confirmation) groups by severity, critical, high,
  medium and low, each chain's sentence first in its own severity with its fix and links to the checks it joins.
  Unknown follows as its own group, dashed, never folded in with the passes. Pass (a refusal or an absence only, per
  rule 1, explained from the catalog), Info, N/A (nothing in scope to test), No finding (which proves nothing, and whose
  line names no observation the result doesn't guarantee) and
  Skipped / Not run (with its reason) fold behind one accordion, "Other checks". Each row gives its result, the test as a plain
  question, what was seen in plain English, the fix when it failed, its check ID and its category. Every count on the
  page (the ledger, each group, the fold, the contents rail) counts the rows the page shows, never a typed number, and
  so equals the grade's counts. On a wide screen a contents rail links the scorecard, each group with its count, and
  the numbered run-detail chapters; under 900px it goes away. A canary receipt is described from the catalog, never
  from the grader's evidence text. Numbered `Run details` chapters (`01 Sandbox map`, `02 How this check ran` with
  decoded capabilities, `no_new_privs` and `seccomp`, where a capability mask or `no_new_privs` that is missing, malformed
  or out of range reads "unknown", and so does a seccomp mode other than 0, 1 or 2. The report carries the seccomp
  mode as a plain number, so one the probe never reported can't be told from 0: both read "no filter reported (0)",
  never "disabled" and never "unknown", and `03 Scope & limits` with SBX-10's boundary and collapsible
  category coverage) follow below. The terminal keeps one appendix line
  pointing at the page, and `compare`'s text names each changed check by its category and question (its JSON and exit
  codes are unchanged). `scorecard` reads one saved report under ANL-1's input rules, makes no network call, writes
  the re-rendered page only inside the `-out` directory (named from the report's provider and run ID only when both
  are plain names, else `sandprobe-report.html`, and never through a symlink already there), escapes every control
  character of the report's text before it reaches a terminal, and exits as `profile` does (5 when invalid or
  incomplete).

## Auxiliary workload architecture, 19 November 2026

- **ARC-1 Image-compatible scheduling.** Receiver and control pods explicitly select kubernetes.io/arch=amd64,
  matching the tested linux/amd64 image in both local-build and CI-image modes. The agent's dedicated NodePool
  already selects amd64. This changes scheduling only; retain existing identity, network and cleanup controls.
  Test both auxiliary pod types in experiments/eks-agent/test_runner.py before live provisioning.

## Auto Mode DNS and execution diagnostics, 19 November 2026

- **GAT-3 Identity token lifetime.** Require the exact intended projected-token audience and path, but
  validate requested expiration as an integer from3600 through86400 seconds rather than exactly86400.
  The observed EKS admission value86360 is shorter than the prior one-day maximum; the one-hour minimum
  covers this bounded task's45-minute active deadline. Reject booleans, nonintegers, missing/extra fields,
  changed audiences/paths and values outside the range. Do not read token contents or grant a security pass.
  Replay credential-free, normalized live structural metadata offline through the existing exact guard;
  test lower/upper bounds and rejection cases before another run.

- **CLI-1 Supported client skew.** Pin the managed evaluation cluster to Kubernetes1.37 and check the
  local kubectl client before any cloud create. Require major1 and minor36..38, following the Kubernetes
  one-minor client/server skew policy (https://kubernetes.io/releases/version-skew-policy/). Record only
  canonical major/minor metadata. Reject missing, malformed or unsupported versions; explicitly pass the
  pinned server version to the cluster helper and verify the described cluster version. Do not replace
  the operator's global client; use a checksum-verified official binary in a task-specific tool cache.
- **CMD-1 Safe kubectl failure categories.** Preserve only fixed categories for recognizable kubectl
  authentication-exec failures, API unavailability or request timeouts, without exporting their raw error
  text. Unknown errors remain command_failed. This adds diagnostics, not mutation retries, credential
  fallback or a security pass. Test supported/unsupported skew, pre-create rejection, explicit helper
  version binding and error classification without exposing synthetic private error details.

- **GAT-2 Nitro runtime placement.** The live isolated-sandbox RuntimeClass declares the scheduling selector
  eks.amazonaws.com/nitro-sandbox=true; Kubernetes adds it to the submitted Pod. Explicitly include that
  exact selector together with the dedicated karpenter.sh/nodepool selector in the submitted task and
  expected returned structure. Reject missing, changed or extra selector entries. Preserve the dedicated
  node and DefaultDeny checks; do not accept arbitrary RuntimeClass additions. Persist specific guard
  rejection categories only from an explicit source-literal allowlist, never raw external error text.
  Test both required entries, unexpected additions and allowlisted versus external failure messages.

- **GAT-1 Readiness and diagnostics.** Before releasing model execution, journal fixed configuration,
  structure, environment, token-metadata, node and image guard stages. Retry only idempotent host reads
  (Kubernetes GET projections/templates/scalars and the fixed token os.stat command) up to3 attempts,
  with1-second pauses, and only for the existing sanitized command_failed category. Never retry mutations,
  host-release creation or model calls. Every required check must still return its exact expected result;
  exhausted retries fail closed and retain the guard stage. This does not establish the cause of the
  previous generic gate failure or turn missing evidence into a pass.
- **CLN-1 Update-in-progress teardown.** After checking the journaled cluster ownership marker, retry
  DeleteCluster only for ResourceInUseException explicitly reporting an update in progress. Bound this
  wait to60 attempts with the existing10-second interval and recheck ownership before each attempt.
  Other errors and exhausted waits retain state and fail with fixed messages. Existing caller deadline,
  cluster-deleted wait, exact node inventory and role cleanup guards remain in force. Test transient,
  persistent and unrelated errors with a fake AWS CLI; no new cluster is implied by these fixes.

- **IDN-1 Association idempotency.** CreatePodIdentityAssociation requires a33..126-character client request
  token (confirmed by the run-owned InvalidParameterException audit event). Derive a deterministic64-character
  SHA256 hex token from a fixed operation domain plus the16-character run ID, retain identical inputs on
  retry, and keep it distinct across runs. This token is an operation identifier, never an AWS credential.
- **IDN-2 Cluster-owned association cleanup.** An association belongs to its exact cluster. If a create did
  not return an association ID, never guess an association to delete. Defer that unresolved child while
  deleting the journaled cluster through its existing identity guards; after that parent is confirmed gone,
  mark the child deleted_with_cluster. A retained parent must leave the child unresolved and cleanup failed.
  On cleanup retry with a previously deleted parent, independently re-confirm that exact cluster name is
  absent before resolving the unknown association; an existing/replacement cluster or API error fails closed.
  Tests cover token bounds/determinism/operation use and parent success/failure/retry with an unknown child.

- **DNS-1 Auto Mode resolver.** For an AWS-described IPv4 Auto Mode cluster, derive its node-local
  CoreDNS address as serviceIpv4Cidr network address plus10, as documented at
  https://docs.aws.amazon.com/eks/latest/userguide/auto-net-pol.html (Determining the CoreDNS IP address).
  Require computeConfig.enabled=true and a canonical RFC1918 service CIDR with AWS-supported /12..24
  prefix. Allow only that resolver /32 on TCP/UDP53. Do not require a kube-dns Service, install a new DNS
  addon or broaden network access. Missing/malformed cluster metadata fails closed. Non-Auto Mode is unsupported.
- **RUN-7 Execution diagnostics.** Persist fixed stage labels before image preparation, cluster creation,
  node configuration, registry publication/validation, DNS selection and task setup/execution. On failure
  preserve only the stage and a fixed failure category; never subprocess/SDK output, credential contents
  or raw exception text. Export stage/category in incomplete reports after managed cleanup. Missing evidence
  still cannot earn a pass. Tests cover canonical/invalid CIDRs, missing Auto Mode flag, exact DNS /32 and
  failure-stage retention. This repairs setup/observability only; live runs require user authorization.

## Verified CI image transport, 19 November 2026

- **IMG-6 Current-main availability.** Build and retain the verified image artifact on every main push,
  including documentation-only commits, because daemonless preflight requires the exact clean HEAD SHA.
  Keep pull-request path filtering, private one-day retention, pinned actions, offline-only validation and
  no cloud credentials/live tests in CI. Do not weaken source matching or accept an ancestor/dispatch
  artifact as a fallback. Verify the resulting main-push artifact and read-only preflight after merge;
  runtime code and the completed live result remain unchanged.

- **IMG-1 Daemonless option.** Add an explicit --image-run-id mode using gh and Skopeo instead of a local
  Docker daemon. Pin all GitHub API requests to github.com regardless of GH_HOST. Accept only a successful
  completed push-to-main run of this repository's networked-agent
  workflow whose exact source SHA matches the clean local checkout. No fork/PR/dispatch run, arbitrary URL,
  image tag or external repository is accepted. This changes image transport only, not the sandbox/model scope.
- **IMG-2 Artifact provenance.** CI exports its tested linux/amd64 image as a Docker archive with a bounded
  manifest containing source SHA, successful run attempt, image/config digest, archive SHA256 and size.
  Bind the exact immutable artifact ID/name to that run/attempt, with the API's outer ZIP digest and size.
  Stream with compressed/unpacked byte and deadline limits; do not use generic ZIP extraction.
  Upload privately with one-day retention only on main pushes. Before any cloud create, download the exact expected artifact, reject extra/
  symlink/nonregular files, bound archive size to512MiB, verify source/hash/size and read the single image's
  bounded config without extracting layers. Config bytes must match the recorded image ID and linux/amd64.
  This is authenticated CI provenance and integrity checking, not hardware attestation or a security grade.
- **IMG-3 Registry and cleanup.** Copy only that verified archive into the run-owned ECR repository. Pipe the
  normal ECR login password directly to Skopeo with an explicit private per-run auth file; never expose its
  value, use a global credential store or forward operator credentials into CI/the workload. Remove the auth
  file after push on success/failure and remove the per-run image download during managed cleanup. Preserve
  exact ECR lifecycle guards and all model/account/approval/pod/measurement requirements.
- **IMG-4 Tests.** Cover run metadata mismatch/fork/event/failure, malformed/oversized archives, config/source/
  archive digest/platform mismatch and nonregular/extra paths. CI verifies an archive of the actual tested
  image before upload. A missing/expired/mismatched artifact fails before creating paid resources. Existing
  local Docker build mode remains supported. Map to experiments/eks-agent/test_image_artifact.py and test_runner.py.
- **IMG-5 Darwin transport.** macOS Skopeo cannot repeatedly open a shared-offset /dev/fd archive.
  On Darwin only, use the exact archive pathname beneath the run's owner-only0700 directories, retaining
  its verified read-only descriptor. Before and after each source operation require an owner-matching
  regular0400 single-link file, matching path/descriptor identity, size/timestamps and approved archive hash.
  These detect changes within a trusted host-user boundary, not immutability against a malicious same-UID
  host process. Linux retains descriptor transport. Before scheduling any workload, inspect the destination
  manifest at the returned ECR digest and require its config digest to match the verified CI image ID.
  Mismatch fails closed into managed cleanup. Test transport selection, replacement/symlink/content changes
  and destination-config mismatch; also exercise the actual archive with local Darwin Skopeo before retrying.

## Lightweight Bedrock model compatibility, 19 November 2026

- **MOD-4 Native response contract.** For exactly mistral.ministral-3-3b-instruct, request Converse
  outputConfig.textFormat JSON Schema with one required solution.py string and additionalProperties=false.
  Preserve strict local response/source validation, size bounds, nine checks, two-call/2048-token limits
  and all credential/network policy restrictions. No unstructured or alternate-endpoint fallback. Other
  supported models retain their request shape. Set the fixed client read timeout to120 seconds to cover
  AWS's documented initial grammar compilation of up to90 seconds; retries remain disabled. Follow
  https://docs.aws.amazon.com/bedrock/latest/userguide/structured-output.html and the model's AWS card.
- **MOD-5 Failure-stage metadata.** A failed guest task may report only a strict failure object with
  schema sandprobe.agent-task-failure/1 and one fixed stage: client_initialization, model_request,
  response_format, artifact_write, functional_checks or execution. Never serialize exception text,
  credentials, model responses or generated source as diagnostics. Historical failed task=null remains
  accepted. These are untrusted guest diagnostics, never a security pass or a provider grade. Test API
  request-schema compatibility, model-specific selection, failure privacy and malformed stage objects.

- **MOD-1 Model choice.** The coding workload does not require Claude or Codex. Add the explicitly supported
  direct regional model mistral.ministral-3-3b-instruct alongside the existing Claude model syntax. Preserve
  one exact foundation-model IAM resource and all existing account, agreement, region, identity, endpoint and
  lifecycle checks. Do not allow inference-profile/ARN/wildcard IDs or automatically subscribe to a model.
- **MOD-2 Response framing.** Accept one bounded JSON response either directly or inside one exact whole-response
  json code fence (or unlabelled code fence). No leading/trailing prose, multiple values, duplicate/extra keys,
  arbitrary language fences or source-only fallback. The same solution.py key, source digest binding and fixed
  functional checks apply. A format/model failure stays a workload failure, never a security pass.
- **MOD-3 Scope and tests.** A live run is one managed disposable run with the small already-enabled model and
  existing call/token bounds, and needs the operator's recorded approval, which is not an independent AWS Support
  verification. Unit tests cover allowed model/exact IAM scope, rejected IDs and direct/fenced/malformed responses.
  Existing Linux coding and receiver calibration remains required before merging and running. Retries after a
  failed setup are serial, of the same model/task/account profile, each cleaned up before the next. Preserve call/
  token/deadline/resource limits, with no security-probe expansion.

## Managed networked-agent evaluation, 19 November 2026

This implements the previously prepared profile. AWS testing-approval requirements remain; authorization to
implement or merge is not proof of third-party approval. No CI job uses cloud credentials.

- **RUN-1 Managed lifecycle.** Add a Python runner with preflight, run and cleanup commands. Live preflight
  requires a caller-recorded AWS EKS testing-approval reference, the exact disposable account the operator names,
  an already-enabled regional on-demand Claude model/agreement, Docker and working CLI tools. No subscriptions,
  inference-profile fallback, additional accounts/regions or production resources. A private locked journal records
  resource intent before create and create-returned identities immediately afterward. Require no-follow regular
  files owned by the caller, private modes, atomic durable writes and a private exclusive lock. Unknown create outcomes are
  retained for reconciliation, never silently cleared or deleted by a guessed name. Delegate the dedicated cluster
  lifecycle to deploy/eks.sh using a unique journal. Every failure enters bounded cleanup; incomplete cleanup is
  explicit, retained and makes the evaluation incomplete. Do not print subprocess output/errors or credentials.
- **RUN-2 Scoped resources.** Create a run-owned ECR repository/task image, IAM role with exact cluster/ns/SA
  Pod Identity trust and one-model permission, association, fresh namespaces and Kubernetes resources. Use
  create-only requests and UID-preconditioned deletes. Check RoleId, association ID and ECR creation fingerprint/
  tags before teardown; disclose name-addressed API residual races. Configure a new NodeClass/NodePool with
  DefaultDeny and force the agent onto it; enable the network-policy controller before task scheduling. Verify
  host-resolved model addresses and actual cluster DNS, image digest and narrow returned pod fields. No broad
  environment/credential-object dumps. The workload's Pod Identity mount is intentional and checked by presence.
- **RUN-3 Representative coding task.** Supersede NET-1's three-record aggregation with a small synthetic
  coding project: Claude returns only a bounded JSON solution.py, the sandbox runs fixed functional tests, and
  may request one bounded repair if they fail. Compare exact bounded results against independent expected
  cases outside the generated module interpreter; missing completion/output or exit0 alone cannot pass. Only the predetermined Python test command runs, never model
  shell commands; no generated code runs on the host. Output is at most16KiB per response,2048tokens/call,
  two requests/process, five seconds/test attempt and a bounded Job. Kill/reap the generated process group
  on every completion/timeout; detached descendants remain a risk until container teardown, so do not use
  same-container negative measurements to certify containment. Child output is captured/discarded rather
  than logged; the child receives a minimal environment without SDK credentials. The intended Pod Identity file
  is still in the same sandbox, so this is not a credential-separation claim. Report task success, attempted model
  calls, functional-test result and artifact digest; failure is visible independently of security assessment.
  In host-controller mode, the one repair receives the validated failing case IDs
  and their shipped public synthetic inputs/expected outputs. Construct this
  feedback from trusted CASES, never candidate stdout, exception text or guest
  strings. Do not change the nine cases, first prompt, model or two-request cap.
  Failure to validate feedback stops repair; it cannot become a pass.
  Both host-controller runners may explicitly select the shipped Ministral 3B
  default or Ministral 8B through `--model`. Reject other IDs before provisioning.
  Preserve the same first prompt, cases, structured JSON, token/request limits
  and network/security intent. Record the selected model in the managed intent,
  workload result and identity policy hash; compare runs using the same selection.
  Selection never subscribes to a model, accepts an agreement or falls back.

- **RUN-4 Controlled measurements.** Use only run-owned synthetic fixtures: an agent-owned writable workspace,
  a root-owned unreadable synthetic file built into the task image, an image-root write attempt at a dedicated
  nonexistent fixture path, own identity/capability metadata and a run-owned TCP receiver with a known nonce.
  A separate control must reach that exact receiver before and after the agent's attempt. Use distinct
  host-issued nonces for agent and controls and host-fetched exact-run receiver receipts. A receiver-recorded
  agent nonce is a policy violation. Explicit permission/refusal errors with healthy controls are a bounded refusal;
  timeout, missing/malformed control or arbitrary errors remain inconclusive. No host escape, provider metadata,
  credential discovery, real secret reads, other-process inspection or arbitrary destination probing is added.
- **RUN-5 Versioned scoped assessment.** Emit sandprobe.agent-evaluation/1 with source/run/config identity,
  independently visible workload status, fixed required properties and passed/failed/inconclusive outcomes.
  This is a configuration/workload assessment, not a provider-wide letter, attestation or a host/hypervisor test.
  Required security properties include bounded observed identity, synthetic protected-file refusal, writable
  workspace, image-root write refusal and controlled receiver egress denial. Any observed security violation
  produces scoped F with uncertainty retained only when supported by host-collected receiver evidence;
  workload failure alone produces no security letter. Guest measurements share a trust boundary with generated
  code and are self-reported/inconclusive, even when they claim a refusal. This version cannot assign A.
  A requires a future independently protected measurement channel and calibration, not guest success flags.
  Bind evidence to exact run/pod/image/config/nonces; reject missing/duplicate/unknown properties and forged
  cleanup or receiver claims. Cleanup status comes only from the host lifecycle, not workload output. DNS is
  intentionally allowed, other destinations and reset/cross-tenant/hypervisor protections remain unassessed and
  listed. Do not reinterpret old reports or change legacy grades/gates. Calibrate this fixed policy on independent
  allowed/refused/unknown/forged-input and broken-control cases before live use; a timeout can never earn A.
- **RUN-8 Same-workload standard grading.** The managed Nitro runner holds the original workload
  container alive after its bounded model/file/test task, including a reported task failure. It runs the
  shipped Linux probe as the same uid in that same namespace/pod UID/image/configuration, before stopping
  the Job. No replacement pod or process-topology change may improve the score. A host-only bridge binds
  the recorded cluster endpoint, run label, original Job UID and pod UID, image digest and configuration
  digest before upload. Endpoint, namespace, original Job/pod UID, image/configuration and zero-restart guards apply to every upload/probe invocation. Report the normal
  `host.Execute` / `grade.GradeBytes` / `report.Build` result without altered thresholds, alongside the
  separately reported workload outcome. Missing evidence remains unknown under the standard grader;
  A is never a target achieved by hiding necessary workload access. This grades a tested configuration,
  not every configuration offered by a provider.
  A separate calibration receiver is managed by `deploy/canary.sh` in the private run folder with fresh `agent-<runID>.probe.ac0.dev` DNS, with durable exact-ID
  state and pre-create intents; unresolved outcomes retain the deployment and block address release; existing canaries/DNS are never adopted. Its control and health evidence use the existing SSM
  adapter. Standard collection uses MEAS-5's shared hosted canary and signed receipts;
  the owned receiver supplies only independent calibration. The workload policy is unchanged for grading:
  model TLS and declared DNS remain available, with Pod Identity only in guest-controller mode
  (RUN-17 removes it in host-controller mode). Neither canary nor receiver is added to the allowlist.
  Check traffic uses these declared measurement destinations, with approved model-host TLS measured
  under MEAS-6/7. SEC-4, AMP-6, AMP-7 and EGR-3 are explicitly excluded from this
  defensive configuration-audit scope to avoid provider-owned endpoints; PER-5 remains skipped because
  no reset is performed. Exclusions are printed, never counted as negative proofs. Native DNS canary
  receipts may demonstrate the risk of permitted DNS, and the unchanged grader may return F.
  Workload readiness and grading have finite deadlines inside the Job deadline. Any bridge/collection
  failure is reported as missing standard assessment and cannot fall back to a reassuring custom grade.
  Cleanup still executes on all paths and independently covers the run-owned canary, releasing it only after the probe cluster is confirmed gone. Standard reports
  initially record cleanup pending; the host records final cleanup separately, never claiming it early.
  Tests: namespace/UID/Job/image/config/endpoint binding rejection; same-pod grading ordering and task-failure
  handling; standard grading artifacts and honest failure reporting; durable canary state and cleanup.

- **RUN-6 Tests and rollout.** Unit-test lifecycle failures/unknown creates, exact-identity cleanup, restrictive
  manifests/trust, functional task/repair/error budgets and assessment uncertainty. Execute known-good and
  deliberately-broken synthetic local containers plus controlled receiver tests in credential-free Linux CI.
  Stub model replies are labeled and never become live model/Nitro results. Map to experiments/eks-agent/test_*.py
  and .github/workflows/networked-agent.yml. Independent security and code reviews cover spec and code before
  merging; run data is credential-scanned and kept internal. No unattended continuous provider probing.

## Network-enabled agent reference preparation, 19 November 2026

The workload is a useful network-enabled task rather than total network isolation. This extension prepares
artifacts and local tests; it does not authorize a live EKS security assessment or assign a replacement grade.

- **NET-1 Usable workload.** Prepare a non-root Nitro Job whose task process calls Claude through Bedrock Converse once,
  asks it to aggregate fixed nonsecret records, independently verifies the returned JSON totals, and writes the
  result in ephemeral `/workspace`. Bound model output to128tokens/4096bytes, connection5s/read45s and
  Job180s; disable SDK model retries, Job retries/restarts and parallel execution. The future live runner must
  enforce a run budget; one call per process is not a global exactly-once guarantee under Job replacement. Reject duplicate/extra JSON
  keys, trailing values, booleans/floats and wrong totals. No generated commands are executed.
  A model failure, malformed response,
  incorrect totals or missing output fails the task; no synthetic answer substitutes for a failed live call.
- **NET-2 Scoped connectivity.** Keep networking enabled. A namespace-scoped default-deny policy allows only
  pinned, host-resolved Bedrock runtime IPv4 addresses on443, the recorded cluster DNS address or kube-system CoreDNS pods on53 TCP/UDP,
  and the documented Pod Identity credential surrogate169.254.170.23 on80. Fix the SDK endpoint to
  bedrock-runtime.us-west-2.amazonaws.com with certificate verification and no custom proxy/endpoint fallback.
  Record caller-supplied addresses as unverified; the live runner must verify and record hostname/IP provenance.
  DNS queries are permitted and can
  carry information; this is not a no-exfiltration profile. DNS or endpoint-address changes require regenerating
  the plan, never falling back to unrestricted egress. These Kubernetes rules need a live enabled/enforcing
  network-policy controller and startup enforcement; rendered configuration alone proves nothing about enforcement.
- **NET-3 Identity and isolation.** Use a new run-owned service account and a dedicated Pod Identity role with
  only bedrock:InvokeModel on one exact regional foundation-model ARN, with trust scoped to the exact cluster,
  namespace and service account. Require pre-enabled model access/agreement and direct regional on-demand
  support. Do not subscribe, broaden IAM or switch to cross-region inference to make it work.
  Never inject operator credentials.
  The intended workload-role credential is authorized access, not an unexpected credential leak. Disable ordinary
  Kubernetes API-token automount. The sole credential-use exception is SDK protocol use of its own injected
  Pod Identity token/credentials, without logging/export. Require the expected injection and only the SDK
  container-credential provider; disable environment/shared-file/instance-metadata credential fallback.
  Keep UID/GID10001, no privilege escalation, dropALL, read-only root,
  RuntimeDefault seccomp, no host namespaces/mounts, fixed limits and ephemeral tmp/workspace. Use a pinned
  image containing the task and locked SDK dependencies. No runtime package install, shell/model-code execution,
  secret-value logging or broad credential inspection. Errors use fixed messages.
- **NET-4 Plan and lifecycle.** Render Kubernetes manifests and a proposed model IAM permission policy to stdout only.
  Require a fresh run-owned namespace and absence of additive allow policies before live deployment.
  Rendering performs no API calls or deployments. Reject unsafe names, mutable image references, broad model
  selectors, private/link-local/malformed Bedrock addresses, wildcard resources and absent endpoint/DNS context.
  The deployment must use the existing dedicated Sandprobe EKS lifecycle, track every extra IAM/Pod Identity
  resource by create-returned ID, and confirm UID-checked cleanup. Until that managed runner and AWS testing
  authorization are available, do not apply the manifests, create resources or describe this preparation as live-tested.
- **NET-5 Evidence and grading.** Require successful model/file work plus independently controlled allowed and
  forbidden tests. A healthy receiver plus timeout alone is not negative proof; require trustworthy refusal/deny
  evidence or report inconclusive. Test only our disposable resources and synthetic data. Do not contact arbitrary
  forbidden external services or probe AWS control endpoints. A model failure cannot be hidden behind good
  security results. Preserve all legacy grades and explain their context limitations; do not assign A from
  manifests, IAM intent, unavailable tests or mocked model replies. Further protected-resource/reset measurements
  and grading calibration remain required.
- **NET-6 Offline tests.** Test render validation, exact egress/identity/resource configuration, scoped IAM,
  and workload success/error/wrong-answer cases using a stub SDK. A CI-only local container check uses the
  same pinned image and a stub model, no cloud credentials or external traffic. Stub success is explicitly not a
  live model result or Nitro security pass. Map to experiments/eks-agent/test_profile.py and test_task.py.

## Workload-aware grading, 20 November 2026

Repeatedly reproducing the legacy F is not the goal: the benchmark
must distinguish permitted workload capabilities from violations of the sandbox's boundary.

- **WGR-1 Fixed benchmark contract.** The host declares `networked-coding-v1` BEFORE the
  workload is released (and remains immutable through the probe), bound to the original box UID, immutable image, configuration digest and run.
  Its boundary is the verified private agent container. Its own processes, ephemeral
  `/workspace` writes and the exact one-model identity projection are permitted capabilities,
  not proof of access to another principal. Root/capabilities remain a failed configuration
  requirement, not by themselves proof of a VM/host escape. Required direct canary TCP
  routes443/22/80/8080 are forbidden; DNS resolver access is allowed but explicitly broad
  DNS is a residual-exposure warning. This profile cannot earn A while that exposure exists.
  The fixed protected resource is the image's root-owned0400 synthetic marker
  `/opt/sandprobe/protected-marker`, outside the allowed workspace. Existence/ownership
  and private-container/identity context must be verified by the host gate, not inferred
  from an arbitrary path, UID or a user-supplied saved report. An unconstrained caller may
  not allowlist arbitrary secrets, drop required controls or edit policy after observations.
- **WGR-2 Structured evidence.** Preserve all target records and twin results on local
  finding observations as well as passes. This retains the distinction between readable
  intended credentials and a protected resource; never parse prose to assign trust roles.
  Add the fixed protected marker to SEC-3's pre-run plan. File-open evidence carries
  pinned FD device/inode metadata; expected identity and protected-fixture attribution
  requires the exact frozen match. Mixed finding proofs still validate every refusal
  errno, absence and both twins, so permitted positives cannot mask instrumentation faults. A missing file, missing target,
  broken allowed/refused twin, malformed proof or unsupported ownership context is unknown,
  never a protection pass. Credential contents are never read; only openability is tested.
  Expected identity paths are only the exact verified token projection and its pre-release
  canonical alias, bound by device/inode and verified read-only projection. Directory or
  timestamp-pattern allowlists are forbidden; a rotated/unbound alias stays unknown. Unexpected readable credential paths remain unattributed/unknown,
  not silently permitted and not automatically called protected-secret theft.
- **WGR-3 Versioned conditional configuration grade.** This is a fixed-workload
  configuration-conformance benchmark under SBX-10's honest host-shipped probe assumption,
  not a measured containment/attestation grade against actively malicious same-UID code.
  Every output prominently separates `configuration_grade` from
  `security_assurance: not_established_against_active_guest_tampering`. A/B never mean
  safe deployment or verified resistance to forged in-guest observations. A/B require
  successful workload and all valid required proofs and host/IAM/fixture guards. This
  deliberately does not upgrade RUN-5's self-reports into security assurance.
  Implement the host's workload grade in Go beside the legacy
  grader, not in a Python exception list. Revalidate the underlying observations/manifest
  and normal canary evidence; ignore any supplied legacy letter. Grade the strongest proven
  violation: F only protected synthetic-resource access plus forbidden canary delivery;
  D protected-resource access or proven forbidden canary delivery alone;
  F describes combined synthetic exposures, never proof secret contents were read/exfiltrated; C a failed required
  privilege/write guardrail or required evidence missing; B all required negative proofs
  with the explicitly permitted broad-DNS exposure; A requires all required proofs and no
  such exposure, and is unavailable in this initial broad-DNS profile. Missing evidence
  caps a better result at C but never hides D/F. Successful workload execution is reported
  separately and required for an acceptable benchmark outcome. A failed/missing workload
  cannot produce an acceptable A/B outcome. All grades name their profile, coverage and
  assumptions; none certifies host/hypervisor isolation or an entire provider.
  Required controls are marker access refusal; AMP-2/3 (non-root, zero effective/permitted/inheritable/bounding/ambient capabilities, and no-new-privileges),
  PER-2 (PATH integrity), AMP-8.sys (kernel write permissions), and four direct TCP routes.
  Writable ephemeral home/config files and agent-owned process access are reported as
  allowed capabilities. Names-only SEC-1 indicators do not establish stolen secrets.
  Unattributed control sockets, privilege amplifiers or unrecognized credential surfaces
  require explicit review/unknown coverage; they cannot disappear into an A/B grade.
  Every catalog row is explicit: required controls as above; SEC-1 names are indicators
  (unknown unrecognized names need review); SEC-2/5 and AMP-5 concern the verified private
  agent container's own processes/services; PER-1/3/4 are permitted only for home/workspace
  targets, otherwise review; SEC-3 permits only the bound identity projection while requiring
  the protected fixture; EGR-1 is permitted broad-DNS exposure; AMP-1/4/8.blk are review
  surfaces when found, with absent/scoped-out results disclosed. SEC-4, EGR-3/4/6,
  EGR-5.53u, PER-5 and AMP-6/7 are outside this fixed baseline and explicitly listed as
  not assessed; their observations remain visible. Nothing implies untested provider
  boundaries held. Unknown required/context/review evidence prevents conformant A/B.
- **WGR-4 Host verification and output.** Before releasing the workload and again before
  grading, verify the exact role's only inline policy equals the single-model policy and
  no attached/extra inline policies exist. This verifies requested identity configuration,
  not all effective AWS permissions, resource-policy grants or organizational controls. Bind the protected marker's expected owner/mode
  and nonempty regular-file device/inode metadata to the verified image. The primary managed result is
  the versioned workload assessment, with legacy raw findings/letter retained separately
  for diagnosis. Never rewrite historical F reports as authenticated new grades. Saved-run
  replay is explicitly retrospective/unauthenticated and cannot establish a live A/B.
- **WGR-5 Calibration before another provider run.** Test a permitted own-process/identity/
  workspace case without F; protected-resource exposure with/without forbidden egress;
  allowed DNS versus forbidden TCP; root configuration mismatch without assumed escape;
  missing/absent/forged marker/twin/identity/nonce/coverage; workload failure; unchanged
  legacy grading; and immutable pre-run contract. Use synthetic, credential-free fixtures.
  Complete independent spec/code/security review and offline calibration first. No new
  provider-wide claims or cloud reruns are justified just to reproduce the old letter.

- **WGR-6 Report-format compatibility watch.** A credential-free, offline report compatibility check runs
  against a retained collection of a recorded managed run. That collection is a real provider's, so the check runs
  where the operators keep their records, not in this repository's CI. Rebuild the report with
  the current formatter, validate the literal JSON keys/types consumed by the managed
  collector, preserve the frozen contract/raw evidence bindings, then feed the serialized
  result through the current workload finalizer. It must retain conditional configuration B,
  separate legacy F and the assurance/input-verification labels for that fixture. No live
  cloud/provider calls, model calls or raw credential inputs are used. Layout, colors and
  incidental HTML wording are not pinned by this guard. Intentional protocol changes need
  an explicit consumer/schema migration; silently dropping context or reintroducing a
  single misleading headline grade fails CI. This is a persistent PR regression check,
  not a claim of continuous human review or a guarantee against every possible conflict.

- **WGR-7 Portable workload identity declaration.** A second-provider run must not
  fabricate an EKS identity projection or change the benchmark after observing its
  results. The existing version1 contract remains Nitro-only with its exact UID/GID10001
  and token bindings. A version2 contract may declare `provider=daytona`,
  `identity_mode=host_controller_no_guest_credentials`, and frozen positive non-root
  `agent_uid`/`agent_gid` values. The model controller stays outside the guest; model
  management credentials are not injected into the sandbox. This is a distinct agent
  deployment pattern and is disclosed beside any comparison with in-guest Nitro inference.
  Version2 requires empty token path/device/inode fields, the same immutable image digest,
  run/box/configuration/identity-policy and protected-fixture bindings, and all existing
  host-verification flags. The identity-policy digest binds the host's pre-run no-guest-
  credentials declaration; it is not an IAM-policy verification or attestation.
  Provider/mode/UID/GID are forbidden in version1, and unsupported provider/mode/schema,
  root principals, missing image digest or mixed token modes are rejected. A changed
  observed UID/GID is a guardrail failure. Zero capabilities (all five sets), seccomp,
  no-new-privileges, protected-resource proof, required route proofs, workload success
  and all other WGR-3 coverage rules remain unchanged. No version2 credential path is
  implicitly permitted; credential-shaped AWS variable names become review/unknown
  rather than inheriting Nitro's intended-identity allowance. Image public-key name
  GPG_KEY remains an indicator, with no secret-content claim. Missing native provider
  verification or required evidence prevents A/B; no historical report is upgraded.
  This change only adds offline contract/grader support. A separate reviewed managed
  runner, scoped account access and cleanup verification are required before live use.

- **WGR-8 Native snapshot evidence gaps.** Version2 may bind a Daytona snapshot UUID
  in `snapshot_id` while `image` is empty and `image_content_verified=false`. This
  records the selected native artifact honestly when the API exposes only mutable
  tagged registry references. It never substitutes a hash of a tag/name for an image
  digest. A required `image-content-binding` control remains unknown, preventing A/B.
  Verified version2 image content requires an actual OCI digest and the explicit
  verification flag; version1 keeps its existing exact digest requirement and rejects
  both portable-only wire fields. All other version2 contract, proof, grading and
  assurance rules remain unchanged. Snapshot identity does not establish image bytes.
- **RUN-10 Managed Daytona workload.** One own disposable Daytona workload/configuration
  run, with an owner-only key file. Use the pinned SDK and original-ID/creation/organization/run-label lifecycle guards,
  one create with no automatic retry, fixed US CPU snapshot resolved by UUID before
  create, private ephemeral sandbox, no secrets/volumes and15-minute idle stop.
  Read back the selected snapshot and network allow list before/after execution.
  Management API credentials stay on the host. Trusted management setup may run as
  root solely to prepare root-owned synthetic fixtures and launch the workload as
  UID/GID10001 with empty capability sets and no-new-privileges via setpriv. Never
  attempt to acquire privileges from the agent principal. Provider-default seccomp
  and filesystem configuration are measured, not invented. Missing native configuration
  verification stays unknown. The API's `public=false` alone is not proof of a private
  process namespace; do not set the corresponding host-verification flag from it.
  Freeze and sync the contract before the first model request. Model calls use the
  existing fixed regional Bedrock Ministral3B on the host (maximum2 calls), while the
  identical CSV task and9 independent cases run only inside the original sandbox.
  A TLS handshake to the fixed regional model hostname verifies intended guest network
  connectivity separately; no guest model credential is injected. This external-controller
  deployment pattern differs from Nitro's in-guest inference and must remain explicit.
  The workload and probe use the same principal/wrapper and unchanged network policy.
  Scope the existing probe to guest configuration, owned synthetic fixtures and our
  run-owned canary. Exclude metadata/proxy/vsock/Kubernetes/public-upload checks and
  reset persistence; no provider-control request, exploit, real secret read or other
  tenant. A dedicated canary is created and cleaned only by the existing managed script
  with its own state/domain and a strict optional `SANDPROBE_CANARY_NAME` namespace
  (`sandprobe-canary-` plus the16hex run ID), never an existing operator canary.
  The existing default namespace and guard remain unchanged for other callers. The operator's fixed AWS
  account (`SANDPROBE_AWS_ACCOUNT`), region and profile (`SANDPROBE_AWS_PROFILE`, and `PROFILE` for the deploy
  scripts; neither has a default) guards apply to canary and model calls.
  A new managed wrapper journals intent before provisioning, retains ambiguous creates,
  guarantees bounded cleanup on ordinary failures/signals, and offers cleanup recovery
  by recorded IDs. Verify original sandbox absence/terminal state and canary/DNS cleanup.
  Export raw observations, contract, workload, legacy diagnostics and our primary workload
  assessment after a credential scan; do not substitute the six-category generic score (SCR-1).
  Exit5 retains incomplete execution/assessment/cleanup; D/F exits6; exit0 requires
  passing benchmark requirements and confirmed cleanup, not a security certification.
  Scope: targeted own guest configuration/functional tests and owned-canary traffic only;
  PRV-12's exclusions stay in force. Nothing here is a provider waiver or permission to test
  Daytona's infrastructure.

- **RUN-11 Preparation diagnostics and reviewed retry.** A preparation that returns no
  workload/probe assessment is retained as a failure record, never called a graded run.
  The native API represents mutually exclusive network modes with nullable booleans:
  an exact nonempty requested IPv4 allow list may coexist with an unset `networkBlockAll`.
  Reject explicit block-all, different/missing allow lists and unexpected domain filters;
  do not require an explicit false for the unused mode. This verifies configuration only.
  Persist fixed host execution stages, create-attempt status, safe error categories,
  provider-call success metadata and boolean native-policy comparisons on every exit,
  before cleanup where applicable. Never persist command text, arbitrary SDK errors,
  environment values or credentials. Split root preparation into fixed observable steps.
  A positive completed host status stating create was never attempted may resolve an
  absent journal; missing journal/status after a launch remains ambiguous and retains
  the receiver. Interrupted processes cannot fabricate a completed no-create status.
  One reviewed preparation retry is permitted after the prior attempt's confirmed cleanup.
  It is a bounded continuation of the still-unrun workload, not an automatic SDK retry
  or additional security-testing scope. The guest TLS check connects to one frozen model endpoint IP while still
  verifying the fixed regional hostname, avoiding a second resolver selecting a
  different address outside the declared allow list. Stop after any completed workload/assessment,
  retain every attempt and all existing original-ID/cleanup/probe-exclusion rules.

- **RUN-12 Verify manager prerequisites and model client before provisioning.** A
  preparation that stops at the guest prerequisite gate must not infer which prerequisite failed.
  Record source-fixed, typed readiness metadata (actual manager UID/GID and executable
  availability) before enforcing prerequisites. The API's requested user is not a
  measurement of the toolbox process UID. Trusted management may use the image's
  intentionally configured noninteractive guest administrator path (`/usr/bin/sudo -n`)
  when its SDK process is not root, only to perform setup and invoke the existing
  privilege-drop wrapper. Confirm that path actually runs as UID0 first; refuse it
  when the manager already has the benchmark agent UID10001. This is normal authenticated
  administration of our own guest, never an agent privilege-acquisition test. All
  workload/model-generated code and the probe still run as10001 with the same clean
  environment, dropped groups/capabilities and no-new-privileges. No sudo from the
  agent principal, root-generated workload execution or weakened grading is allowed.
  The installed AWS CLI lacks the native response-schema request field. Use the exact
  existing hash-locked Nitro boto3/botocore model client in a separate host interpreter,
  verify its version/request shape offline before receiver creation, and bind its STS
  account to the fixed experiment account before any model call. Preserve fixed region,
  model, timeouts, maximum2 requests and disabled SDK retries; no subscriptions or
  provider/region fallback. A finite final preparation continuation after
  cleaned, ungraded failures is permitted to complete a still-unrun benchmark.
  Stop on any further prerequisite failure, completed assessment or cleanup uncertainty;
  preserve all attempts. New prerequisites are checked before provisioning where possible.

- **RUN-13 Offline repair after the final bounded attempt.** EGR-6 is never passed
  as a provider exclusion, which Execute rejects: Plan already skips unapproved public-upload
  checks. A repair never reuses a staging file made0444 after the first upload, which a
  non-root manager can't replace. Use fresh, unpredictable,
  strictly validated staging paths for each solution upload. Staging belongs to trusted
  management, not necessarily root. Agent workspace writes retain UID10001 and all
  existing ownership/no-follow/link-count checks. Exercise consecutive uploads with a
  nonroot filesystem principal and the exact collector options offline.

- **RUN-14 Renewed Daytona workload continuation.** A continuation may fix issues and
  rerun until the same model workload used for Nitro can be evaluated on Daytona,
  within provider terms and scope restrictions. Preserve the identical prompt/parser/nine cases,
  fixed regional model and maximum2 requests per attempt. Each managed invocation
  retains a fresh run ID and original-ID ownership journal; do not retry ambiguous
  creates or continue while cleanup is uncertain. After a runner failure, retain
  evidence, correct the spec/code with independent code/security review and offline
  validation, and use a new clean reviewed source commit for the next attempt.
  No weakening of workload checks, required controls or grading is permitted.
  All existing endpoint exclusions, agent/management role separation and cleanup
  verification remain. Stop on a completed workload/assessment, suspected provider
  vulnerability or uncertain cleanup; no repetition to obtain a better grade.

- **MEAS-5 Shared public canary for managed workloads.** Nitro and Daytona's standard
  collectors use the same HCN-5 hosted URL and shipped control-key pin as the CLI.
  Verify signed status and reserve one slot before collection; a failure stops the
  assessment without an operator-canary fallback. Release the slot under a fresh,
  bounded cleanup context even after cancellation, and report an unconfirmed release.
  State HCN-4's retention in the managed guides. The separately bound run-owned
  receiver remains only for its independent A/C delivery controls and restricted
  receiver test: a shared public canary cannot establish reachability to that receiver.
  Its original-ID cleanup remains mandatory. Do not delete the shared hosted service
  or another run's resources. No idle dedicated receiver is retained after a run.

- **MEAS-7 Frozen workload TLS endpoint bindings.** The generic EGR-6 collector may
  receive a host-frozen address for a selected approved name. In the existing target
  list, the canonical form is `<approved-name>=<literal-public-IP>`; bare approved
  names retain MEAS-6's guest resolution. Validate every name/address and duplicate
  before any DNS lookup or dial. A binding is measurement input, not guest DNS proof.
  Managed adapters bind the exact model endpoint address already resolved by the host
  and frozen in the verified workload network configuration; they do not broaden it.
  Use the same hostname for SNI and WebPKI verification, one literal-address443 dial,
  the existing shared deadline and no HTTP/upload/proxy. Failed TLS remains unknown.
  Preserve the binding in the frozen manifest. No report fields or score rules change;
  readers that do not support bound targets may reject them, never downgrade them into
  an unbound negative proof. Host-only resolution does not demonstrate guest DNS.

- **MEAS-6 Bounded workload-host TLS measurement.** EGR-6 is implemented generically,
  independent of the provider adapter. An explicit `upload_hosts` request selects
  one to four distinct exact names from the shipped workload/dependency list:
  `github.com`, `raw.githubusercontent.com`, `pypi.org`, `files.pythonhosted.org`,
  `api.anthropic.com`, `api.openai.com`, `bedrock-runtime.us-west-2.amazonaws.com`.
  No URLs, arbitrary hosts, IP literals, provider-control endpoints or wildcard
  selection are accepted. Both managed runners expose the same explicit list.
  Default remains off; a no-canary run refuses this selection. Validate before surveying or creating a sandbox; the frozen
  manifest records the selected names in `Targets["EGR-6"]`. The probe independently
  validates the list, resolves each name once, rejects empty, excessive or non-public
  answers, and dials at most one of those literal public addresses on TCP443 (preferring IPv4, as the managed workloads do), using
  the original name for SNI and WebPKI verification. It uses no environment proxy,
  sends no HTTP request or application data, follows no redirect, and shares one
  three-second DNS/connect/TLS budget per name. A verified handshake is only the
  existing Medium indicator of a reachable upload-capable service, never proof that
  an upload works or an assurance failure for an intended workload dependency.
  If no verified handshake is observed, the result is unknown with a fixed reason,
  never a pass, absence or inferred network refusal. A partial finding names only
  verified hosts and retains the number of unproven destinations. Tests contact
  only local TLS fixtures; production cannot opt into private destinations.

- **SCR-4 Workload exposure headline.** The six-category scorecard (SCR-1)
  is the common exposure ranking for Nitro and Daytona workload runs. Compute it from
  the same standard observations and proofs using SCR-2, never from a supplied
  letter or workload-context permission override. Retain a separate versioned
  exposure-scorecard artifact, make it the headline of new workload HTML, and
  include it in the managed evaluation. Keep the existing workload configuration
  assessment, completeness, unknowns, not-proven observations and assurance limits
  visible alongside it. A numeric score cannot waive missing proof, certify a
  provider or become an A–F conversion. Unchanged legacy rendering entry points
  preserve historical output. Shared summary recomputation and the native Daytona
  runner must use identical score rules. Existing exit/cleanup gates remain.
  Managed runners print a sanitized human completion notice on stderr, keeping
  stdout JSON and saved report schemas unchanged. Distinguish a completed RC
  assessment with gaps from an unavailable assessment, unverified workload or
  unconfirmed cleanup; exit5 alone does not establish a failed execution or an
  unsafe provider. A valid score never upgrades missing coverage.
- **SCR-7 A saved workload card is rebuilt, never trusted.** A `sandprobe.workload-exposure/1` card is unauthenticated
  input, so no string or verdict it stores reaches output on its own word. One function, `buildRow`, makes every
  scorecard row from its checks' outcomes: `Score` calls it for a graded report, and the card validator calls it for a
  saved card. A card is accepted only when each stored row equals, as a whole, a row `buildRow` makes from the least
  the card can't forge against itself: the category, this binary's PRV-row table, and the row's own check lists and
  coverage. The page then renders the rows it built, never the stored ones. In order:
  - **Validate first, build second.** Before any row is built, the card's coverage partition is checked: each
    category's groups hold only its own checks, each once, and together exactly its checks, and each row's `found`,
    `unknown` and `unproven` together hold at most as many. Every check is a linear pass over what the card supplies,
    so a forged list, a check repeated 10,000 times say, costs that pass and is refused with no row built.
  - **Invariants.** Each of `found`, `unknown` and `unproven` holds only the category's own checks, once each,
    in catalog order, and the three are disjoint. A found check is one that can be found above Info, and an unproven
    one is find-only, as is every check coverage records `unproven`. A not-applicable row lists nothing, and its
    coverage records no finding. A green row has no found or unknown check. A coverage finding the row doesn't list as
    found must be Info by evidence, since only an Info finding leaves a row green: a check whose findings are only
    ever Info (EGR-4) needs none; a check with both Info and higher variants (SEC-3) is Info only when this process's
    own grading graded it so. `WorkloadExposureScore` keeps that grading beside the card, unexported and never
    serialized, so a card read from a file carries no severity evidence, and an unlisted SEC-3 finding on it fails
    closed: the card is refused, never read as green. Any other finding the row leaves unlisted is refused. No row
    carries `declared_provider` (PRV-17).
  - **Outcomes from coverage.** Each check's outcome is its coverage group's: proven and scoped out are clean,
    unproven is not found, unknown and missing are themselves. A finding is Info only when the row doesn't list it and
    it is Info by that same evidence, and found otherwise. A skipped check may be plain, opt-in when it is a
    provider endpoint, or excluded by the PRV-row scope the row names (its `scope`, or for a 0.3.0 card the one key its
    `terms` pin) when that key's entry excludes it. A skipped check's kind changes a row in two ways only: the row is
    not applicable when every check is excluded and none was tested, and the opt-in reason names the opt-in subset in
    catalog order. So no combination is enumerated. At most three outcome maps are built: every skipped check plain;
    every one excluded, when the scope's entry excludes each; and the one opt-in subset the stored reason names, read
    with a bound of the category's size, when each check it names is a skipped provider endpoint of the category.
    Each is built with and without HCN-5's no-canary choice. A card therefore costs at most 6 builds per row, 36 for
    the six categories, whatever it holds, and the stored row must equal one of them. Without coverage, two maps are
    built, as below.
  - **Not applicable only under Score's own condition**, which lives in `buildRow`: no check of the category was
    tested and every one was excluded by the row's PRV-row scope. A provider whose entry excludes only some of a
    category's checks never makes that category not applicable, in today's form or in 0.3.0's.
  - **Historical forms.** A card from 0.3.0 may carry a not-applicable row with no `scope`, exactly 0.3.0's reason
    ("Not applicable: this box holds no cloud identity of yours that Sandprobe checks here; the provider's own
    endpoints weren't tested (their terms)"), and `terms` equal to exactly one key's reasons; it renders in today's
    wording under that key, and may omit the green-not-proven flag, which is then derived from its coverage. A card
    from 0.2.1 has no coverage. It is held to the same invariants, its own lists fix their checks' outcomes and the
    rest are taken as all clean or all missing, and it may carry no not-applicable row, `scope`, `terms`, opt-in reason
    or green-not-proven flag, since 0.2.1 wrote none. Every other form is refused.
  - **Totals from the built rows.** The score counts the built green rows and `of` the categories not built not
    applicable; a card whose own totals or coverage counters differ is refused. `verification` is empty or ANL-1's
    fixed label.

  The saved-report checks (ANL-1, `compare`, `profile`, `assess`, `fix`) were audited for the same pattern: none
  expands combinations, each loop is linear in a file ANL-1 bounds at 8 MiB, and a repeated ID fails at its first
  repeat.

  What remains the card's word is its evidence: which checks it records in which coverage group, and, for a 0.2.1
  card, its lists. Changing that evidence can change the built row, as a different result would; it can never make
  the page show a row its own evidence doesn't produce.

- **RUN-22 Functional failure diagnostics.** Keep the same prompt, two-request cap,
  nine functional cases and success criterion. The shared checker may report only
  fixed failure kinds, whether all outputs were checked, matched-case count and
  fixed failed-case numbers. Never emit source, candidate outputs, module names,
  exception text or stderr. Distinguish absent complete outputs (setup/dependency/
  syntax/memory/child/deadline/format failures) from complete mismatched outputs.
  Both host controllers validate the exact diagnostic shape and its consistency
  with the existing verification result before storing a private, digest-bound
  per-attempt artifact. Missing or contradictory diagnostics cannot produce success.
  Preserve the legacy boolean checker API and task/report schemas.

- **RUN-21 Owned receiver pinned TLS client.** Replace the deployment's external
  OpenSSL network/parse pipeline with one native TLS handshake to the original
  receiver's literal IP. Verify its exact SHA-256 SPKI pin obtained through SSM,
  retaining the self-signed receiver trust model and health SNI. Require TLS1.2
  or newer, a single five-second connect/handshake budget, no proxy, DNS lookup,
  HTTP or application request, and no additional TLS-close write budget. Emit
  only fixed verified/invalid/pin-mismatch/unproven results. Only verified with
  successful command completion passes setup. Keep plain-port checks and cleanup.
  This changes receiver setup only; EGR-6 still requires WebPKI verification.

- **RUN-20 Receiver readiness diagnostics.** During managed receiver creation,
  record source-defined internal/TLS/plain-port readiness stages in its private
  deployment journal. A failed TLS client command, pin mismatch or unproven health reply
  remains a deployment failure. Never store command output, certificates, payloads
  or stderr in these markers. Manual status stays read-only, no additional network
  attempts are introduced, and exact-ID cleanup is unchanged.

- **RUN-19 Managed failure diagnostics.** Preserve fixed worker-preparation,
  intended-model TLS and controller step codes in the private status, without
  exception text, model output or provider stderr. A newly created private worker
  cache may inherit setgid from a Kubernetes fsGroup workspace: normalize only that
  new directory to `0700` through an owned, no-follow directory descriptor. Refuse an
  already-existing unsafe cache; never silently repair it. Record the validated owned-home
  metadata before and after the workload and only changed contract field names
  when the frozen binding differs. A mismatch still stops grading. EGR-6 may
  report fixed DNS/answer/connect/TLS failure counts; failures remain unknown,
  with the same approved destinations, public-address checks and traffic budget.

- **RUN-18 Shared initial workload environment.** The two host-controller profiles
  start workload commands and the probe with the same explicit environment from
  `internal/host/workload_environment.json`, through `env -i`. Do not clear variables
  only for measurement. Nitro's long-lived container process uses this same prefix;
  the original Job/pod command is rechecked before every bound probe, and the host
  bridge accepts the clean-environment binding only with RUN-17's schema3 contract.
  A legacy guest-identity contract cannot request it. Daytona retains its existing
  clean-environment behavior but shares the policy source. No user or provider
  credential, proxy, or incidental image variable is passed through. Keep PATH,
  protected HOME, private cache, locale, no-bytecode and the probe twin; this does
  not change runtime identity/capability/network guards or skip any check.

- **RUN-17 Host-controller workload parity.** Managed Nitro may explicitly select
  `--controller host --model-python <pinned interpreter>` to match Daytona's
  `host_controller_no_guest_credentials` deployment pattern. Preserve the legacy
  guest-controller default and its schema1 identity contract. The host mode uses
  the same prompt/parser, fixed regional Ministral model, at most two requests and
  nine sandbox-executed functional cases as Daytona. Generated code never executes
  on the controller. Perform the pinned model SDK/account preflight before any paid
  create. Create no model IAM role or Pod Identity association; verify no association,
  credential environment entry, token projection or extra mount before model release
  and after the task. Host mode removes the unused Pod Identity metadata egress allowance;
  it retains only the fixed model IPs on443 and the declared DNS endpoint. Keep the original pod/container ID, image digest, network policy,
  non-root/capability/seccomp/no-new-privileges guards and independent receiver controls.
  Root-owned verification tools are built into the pinned read-only image. Only the
  solution is uploaded, atomically under the agent's workspace; verify its digest
  inside the same sandbox with the shared worker. Before model requests the worker
  checks immutable tool metadata and a private writable cache. CI executes it inside
  a network-disabled, read-only, non-root container. Model/parser children receive no
  DNS credential or endpoint/retry override. A host-controller contract declares
  `sandprobe.workload-contract/3`, bound to `aws-nitro`, uid/gid10001, the protected
  fixture/home and verified image; it contains no guest token fields. Its report
  declares `sandprobe/3` so older readers refuse the new contract semantics by version.
  This does not turn provider endpoint exclusions or absent reset evidence into tests.

- **RUN-23 Persistent storage assessment.** A separately selected host-controller
  profile may use a run-owned persistent workspace to exercise TWN-3's recreate
  model. Keep the same model, nine-case workload, agent identity, protected home,
  network policy and capability restrictions; label it separately from ephemeral
  results. Declare the storage configuration before workload execution. Nitro creates
  encrypted EBS explicitly, records its returned ID before a static Auto Mode PV
  may reference it, and Daytona uses a newly created
  volume; neither may adopt existing storage. Record create-returned immutable IDs
  durably before mounting. Recreate only the original run-owned box, preserve the
  same volume ID, mount path and subpath, and use the existing PER-5 marker/recheck
  engine. Stop/start is not a reset. Preserve all uncertainty and independently
  confirm deletion of every original/replacement box and volume. A rendered plan
  is intent only and cannot enable live assessment until ownership, configuration
  readbacks, reset and recovery/cleanup paths are implemented and tested.
  An unknown external-volume create is not resolved by matching names or tags.
  EBS cleanup waits for independent original-cluster absence and no attachments;
  neither cluster teardown nor a successful volume DELETE alone proves it gone.
  Managed Daytona selects this profile explicitly. Its assessment and recovery
  take one exclusive run-folder lock, and recovery accounts for every recorded
  original/replacement consumer before the receiver may be released. Record box,
  storage and receiver confirmation separately; aggregate cleanup requires all.
  `persistent-artifacts` keeps the coding workspace/cache ephemeral and mounts
  native persistent storage separately at `/persist`. Before model release, the
  agent must write/read back a bounded synthetic artifact there; after the same
  nine-case workload it writes a bounded result summary. Neither operation changes
  mount ownership or permissions. PER-5 marks/rechecks that storage through the
  existing reset engine. Do not require object-backed storage to support private
  POSIX coding-workspace semantics. Keep the older workspace variant labelled
  separately. Exact-ID terminal `deleted` volume metadata confirms cleanup only
  with its original recorded birth and organization, even if the provider renamed
  the tombstone; active volume names still match. Never resend DELETE while a
  matching volume is already deleting, and never count the request itself as proof.
  Nitro binds the original namespace, claim, PV and storage-class UIDs and the
  exact EBS handle/zone before every persistent-profile invocation. A reset job
  comes from the host-rendered original manifest, checked against its frozen
  configuration hash; rename it and recompute its hash without changing workload
  or security intent. Do not clone runtime environment values from the API.
  The artifact profile binds the separate artifacts claim and `/persist` mount;
  readbacks reject redirected claims, subpaths, propagation and extra mounts.
  Managed Nitro selects `persistent-artifacts` only with the host controller.
  Use the documented ReadWriteOncePod mode. Bind the explicit encrypted EBS
  volume to the recorded receiver node's zone before scheduling, retain local
  workspace/cache, and run the same bounded artifact program as Daytona before
  model release and after the nine-case workload. The child reset journal is
  exclusive, private, durable and bound to a parent nonce and original identities.
  Delete the original Job with its UID precondition and confirm its Job/Pod gone
  before creating exactly one replacement from the hash-bound host manifest.
  Record the replacement Job UID before discovery; an unknown create is retained
  as unknown. The replacement must pass image, principal, configuration and same
  storage readbacks before PER-5 recheck. Read the replacement's actual security
  context as well: non-root UID/GID10001, read-only root, no privilege escalation,
  no capabilities, RuntimeDefault seccomp, no host namespaces/sidecars and no
  service-account token mount. The environment hash alone is not that readback.
  Never repeat the model workload during
  reset. Import child reset state in finally, including failed/timed-out grading,
  and stop both known Jobs before the final receiver control. Dedicated cluster
  deletion covers unknown Kubernetes children; independently delete the original
  EBS ID only after confirmed original-cluster absence and no attachments.

- **RUN-24 Rejected Daytona replacement recovery.** An ID-less consumer remains
  unresolved by default. A trusted management audit may resolve a rejected create
  only after its 110-second transport budget plus ten seconds have elapsed: one
  organization-bound sandbox-create event must record HTTP400, no target ID, and
  the original request's exact random name, nonce, snapshot, network allowlist and
  volume binding. Bound its timestamp to the journaled create window. Require an
  independently authenticated, complete exact-name lookup with no matching object;
  any object with that name, pagination, missing audit or contradictory event
  blocks recovery. Never adopt or delete an object found by that lookup. Persist
  a digest of the matched refusal evidence on the original volume consumer,
  separately from a deleted consumer: no invented sandbox ID or deletion proof.
  Only then may exact-ID volume cleanup proceed. Retain the failed create journal,
  never retry the create, and leave failed reset/recheck evidence unknown. No raw
  audit body, error message, key metadata or unrelated event leaves the adapter.

- **RUN-15 Protected startup configuration, writable project.** Improve the
  configuration shared by the Nitro and Daytona workload runs: HOME points to an
  owner-root0555 directory under the owned /opt/sandprobe fixture, with protected
  ancestors. Project writes and cache writes remain available under /workspace;
  temporary files remain available under /tmp. The real workload, generated-code
  verifier and static probe use the same declared HOME. The host checks owned-home
  metadata/identity before and after the workload. Do not weaken mandatory checks,
  hide writable paths, remove required model identity or change prompt/nine cases.
  Record the changed execution configuration and validate both refusal of startup
  writes and successful project/cache writes with the unchanged functional task.
  This improves a configuration surface, not reset persistence or host isolation.
  A live evaluation runs one fresh managed workload/assessment per provider,
  serially, from the exact clean merged source. Retain scorecard scores, unknown/not-proven
  checks, separate workload conformance and all cleanup results. Use the existing
  scripts, original-ID journals, fixed account/region/model and request budgets;
  endpoint exclusions stay unchanged.
  Stop each line after the completed assessment, unexpected protected delivery or
  cleanup uncertainty. Do not repeat a completed run to obtain a higher score.

- **RUN-16 Isolated receiver lifecycle and pre-create proof.** Nitro must use the
  same per-run receiver namespace pattern as Daytona, never adopt or delete an
  existing shared receiver. Before delegate startup, durably bind an outcome
  record to run, nonce, exact delegate digest and original state path. The delegate
  must durably mark mutation possible before its first cloud mutation; failure to
  write that barrier prevents mutation. Only the supervisor, after child completion
  and verified absence of create-capable descendants, including normal/error
  exits, may seal a terminal outcome. A completed direct child alone is insufficient;
  uncertain descendant quiescence leaves the outcome nonterminal. Process-group
  checks rely on the reviewed trusted non-detaching delegate and host toolchain;
  they are not arbitrary hostile descendant-tree containment. Serialized barriers
  reject late updates after terminal sealing. Teardown for new outcome-bearing
  records requires bound terminal quiescence proof; legacy recovery stays separate. A bound
  terminal failure in the pre-create phase proves no cloud create; missing,
  malformed, nonterminal, mismatched or mutation-entered records stay ambiguous.
  Lost create responses never become no-create proof. Preserve legacy original-ID
  cleanup and all namespace/tag/birth guards. Test rejection, interruption around
  the barrier, lost responses, malformed records and existing-receiver preservation.
  A failed run whose exact source shows the following can support a separate trusted-host
  retrospective reconciliation (an operator-only tool, outside the public tree): its only
  cloud intent is canary creation; every mutation follows durable delegate-state
  initialization; the quiescent original worker's private directory contains
  neither that state nor a teardown archive, with no external removal/rollback.
  Record `reconciled_no_cloud_create`, original failure, source/evidence and the
  trusted-host assumptions. Do not label it deleted or independently inventoried
  cloud absence, and do not generalize absent journals into cleanup passes. The
  existing receiver merely corroborates a guard-refusal hypothesis. No completed
  grade is repeated to improve scores.

- **EVD-1 Portable evidence coverage.** The published scorecard (SCR-1, https://probe.ac0.app/)
  describes six exposure questions: Secrets, Exfiltration, Containment, Privilege,
  Cloud access and Persistence. Keep these categories in the workload evidence view,
  without substituting that view for the SCR score or changing WGR's grade. Export
  a separate versioned evidence-coverage record and opt-in HTML view that distinguishes
  findings, permitted exposures, unknowns and unassessed controls. Context guards stay
  separate from the six categories. Group related unknowns by the actual missing
  measurement: image binding, private-process context and its dependent controls,
  identity/fixture guards, network proof and final receiver collection. Name evidence
  source and next measurement. Missing adapter evidence is not proof the provider
  lacks the feature, and no unavailable/unimplemented check earns a pass. The same
  diagnostic is available to Nitro and Daytona; historical assessments and wire
  contracts are unchanged. The view makes no numeric score or security assurance claim.
- **EVD-2 Preserve exchange diagnostics.** A TCP connection is not successful
  marker delivery. Retain optional, fixed-enum application stage/outcome metadata
  when the canary exchange runs, including TLS handshake, marker send and reply
  receive failures. Never retain response bodies, raw errors or credentials.
  Existing kernel refusal and host receipt requirements remain authoritative:
  completed exchange does not independently prove delivery, and failed exchange
  or silence never proves blocking. Malformed diagnostic fields cannot change a
  verdict or become report-controlled prose. Older records need no new fields.
- **EVD-7 Local SDK failures are not provider evidence.** If a Daytona SDK subprocess cannot start
  because its interpreter is missing, unresolvable or not executable, return a fixed local-runtime failure
  and label the host call `local_sdk_unavailable`. Never echo interpreter paths, keys or raw OS errors.
  Preserve provider/transport failures as separate generic failures. Record one SDK call per invocation;
  logging must not duplicate exec operations. No local runtime failure is a security result or cleanup proof.
  Tests: `internal/host/daytona_test.go` `TestDaytonaLocalSDKUnavailable`,
  `TestDaytonaCommandRecordsOneCall`.
- **EVD-8 Workload preparation diagnostics.** Retain a fixed failure stage for local source reads,
  artifact upload, worker execution or worker-ready parsing, plus EVD-7's bounded SDK/local failure category
  when execution fails. An artifact name is one of the source-fixed workload basenames, never a path.
  Do not emit file contents, guest responses, errors or credentials. Preparation failures consume no model
  request and cannot become successful workloads or security passes. Test the real workload controller
  boundary with credential-free upload/exec faults and malformed responses before invoking any model.
- **EVD-9 HTTP marker foundation.** The existing canary TCP/80 listener may additionally accept a canonical
  HTTP/1.1 GET for `/sandprobe/v1/echo/<nonce>` with the matching nonce.canary.<domain> Host and
  Connection: close. Accept at most 2048 bytes, no body, query, authentication, upgrade, transfer coding or
  unrecognized headers. Bounded conventional forwarding headers are ignored; receipts use the socket peer,
  never a supplied forwarding address. Other ports retain the legacy protocol; legacy nonce/health traffic keeps its 64-byte bound.
  A valid request records only the already-armed nonce at the existing tcp/80 scope and returns a fixed,
  length-delimited text acknowledgement. Never forward a request, redirect, log request text or echo headers.
  Shared request/ack helpers reject malformed hosts, framing, wrong nonces, extra bytes and HTTP errors without
  emitting response text. Even HTTP200 with the right acknowledgement is exchange completion only: the host's
  independent receipt is still required for delivery; no receipt or HTTP error proves no denial. This first
  stage changes no probe requests, default canary selection, grading, plan or evidence schema. Explicit client
  selection/capability and calibration must be reviewed before the new exchange is used for assessment.
- **EVD-10 Explicit HTTP marker selection.** TCP/80 may use `tcp80-http-marker-v1` only when explicitly
  selected and the existing trusted canary control verifies that capability for the same boot pin. A separate
  `protocols` control operation advertises it; legacy status/arm/query answers omit the new field. Default
  requests remain legacy, and unsupported/unverified capability stops the assessment before check traffic.
  The declared protocol is copied from host options to the manifest and probe input; unknown protocols and
  no-canary combinations are rejected. Only EGR-5.80 changes payload: no new destination, port, proxy, retry,
  TLS setting or provider-endpoint permission. Kernel refusal and independent host receipt rules stay unchanged.
  Reports carrying the field declare `sandprobe/4`; old reports keep their minimum schema, and comparisons
  report a changed measurement configuration. Both managed bridges can declare the generic protocol; no
  successful exchange or HTTP error independently becomes a pass or finding.
  `canary check -require-http-marker-v1` verifies capability without reserving slots or testing guest delivery.
  Managed Nitro and Daytona runners selecting HTTP must invoke that signed capability preflight before
  creating any paid receiver or provider resource. They build the checker from the same clean source as the
  managed collector. Unavailable capability stops setup with a fixed error, without a retry or legacy fallback;
  the collector still rechecks capability immediately before assessment. Preflight success is not delivery proof.
- **EVD-19 Sandbox-bound organization readback.** EVD-11's optional Daytona configuration read uses the
  pinned SDK's `GET /sandbox/{sandboxId}/organization`, after the existing fresh original-ID, run-label,
  creation-time and organization checks. The sandbox ID is the verified create-returned ID, never a name,
  guessed ID or guest input. Require the returned organization ID to match that fresh binding and the network
  setting to be a real boolean. Make exactly one bounded read; never retry through account-level organization
  APIs, list organizations, fetch credentials or change policy. Endpoint authentication, permission, transport,
  schema and identity failures retain EVD-14's fixed unknown labels. The host-only artifact keeps its existing
  organization-default/configuration-only scope and schema; this is neither per-connection denial proof nor
  one of the 28 standard check outcomes.
- **EVD-23 Bounded coverage dispositions.** Gap plans add one work disposition per inconclusive row:
  `policy`, `not_applicable`, `unprovable`, or `bridgeable`, with source-fixed basis and exact category totals.
  This adds fields to the separate output, so new plans declare `sandprobe.measurement-gaps/2`; report and
  prerequisite schemas stay unchanged. Explicit exclusions and opt-outs take priority over missing features or
  unimplemented measurements. A source-fixed feature-absence skip or scoped-out discovery is not applicable;
  do not infer feature absence from a target removed by an exclusion. Find-only no-finding outcomes and
  connected exchanges without decisive delivery/denial proof are unprovable under the current measurement.
  Recognized host canary/calibration failures remain bridgeable investigation candidates. Other unknowns need
  bounded investigation; the label promises no fix or authorization. SEC-2/SEC-5 with reported held process-access
  capabilities is a bridgeable configuration candidate: drop unnecessary capabilities in an explicit new
  configuration, then collect a real full negative proof. A drop alone changes no result. Policy/NA/unprovable rows
  are not work items for a timeboxed coverage effort. Dispositions never alter score, kind, result or conclusive count.
- **EVD-22 Measurement prerequisites and gap plans.** Managed collectors may persist a separate
  `sandprobe.measurement-prerequisites/1` sidecar from the existing original-agent survey. It records only
  source-fixed proxy configuration, Kubernetes-target presence and vsock-device presence labels, bound to the
  frozen run ID, nonce, box ID and probe digest. No extra survey, provider call, address, proxy credential or
  environment value is collected. Survey absence is an error, never a negative prerequisite result. Write it
  privately, without following or replacing an existing destination; failure emits only a fixed diagnostic and
  must not discard the standard assessment. It is guest-reported prerequisite context, never isolation proof.
  Offline `gaps <report.json> [<prerequisites.json>]` emits a separate versioned gap plan from a structurally
  valid saved report and, optionally, a strict matching sidecar. Missing sidecars mean not recorded, never absent.
  Exclusion scope, missing features and unimplemented measurement remain independent requirements; notably
  AMP-6 is unimplemented even with a device. Not-found and unknown results retain their proof limitations.
  Reject invalid assessments, malformed/mismatched sidecars and unsupported enums. Emit only catalog check IDs,
  result enums and source-fixed guidance, never arbitrary reasons, paths, addresses or SDK text. Neither saved
  input is authenticated by offline analysis. No grades, outcomes, selection, exclusions or workload settings change.
- **EVD-21 Bounded collection-failure diagnostics.** A host collection that stops before a report may retain
  a source-fixed failure stage and its error chain for classification. Never serialize an arbitrary error string,
  guest output or SDK response. Stage extraction returns only a closed label or `unknown`. Managed Daytona
  keeps a failed collection separate from the completed functional workload: a versioned
  `sandprobe.collection-failure/1` sidecar records the collection stage and bounded failure category, with
  `assessment_available=false`. This file is not a report, grade, negative proof or permission to retry an
  ambiguous provider operation. Nested known SDK status/guard and timeout/transport/schema errors keep their fixed category through host
  wrapping. No collection selection, probe, grading, provider calls or cleanup rule changes.
- **EVD-20 Versioned managed evidence.** New managed collectors wrap raw evidence in
  `schema: sandprobe.managed-evidence/2` for `standard-evidence.json` and the Nitro bridge's collection
  response. This version explicitly includes EVD-18's optional host reset failure stage. The public OUT-1
  report schema is independent and unchanged. Unversioned historical managed envelopes are legacy version1;
  they remain readable when they lack the new stage. An unknown, null or incompatible version is rejected,
  never retried or downgraded. Live Nitro collection requires version2. Retrospective finalization carries
  the evidence version into its strict Go request; an unversioned/version1 request containing a nonempty
  failure stage is rejected before grading. Empty diagnostics retain legacy replay compatibility. Readers
  from 0.3.4 and earlier don't check the version, so it is no boundary for them: their strict Go decoder refuses an
  envelope that carries a failure stage, but their Nitro replay unwraps the envelope, drops `schema`, and finalizes
  a version2 envelope with no stage as if it were unversioned. Use the collector's matching new reader. A version is a format
  declaration, never authentication, freshness, attestation or positive security evidence.
- **EVD-11 Organization network-policy readback.** The managed Daytona collector may make one bounded
  native organization read using only the organization ID freshly verified against its own sandbox's
  create-returned identity, run label and creation time. No organization list, default-organization inference,
  other-organization retry or policy mutation is permitted. The returned organization ID must match exactly
  and `sandbox_limited_network_egress` must be an actual boolean; absent/null/string values remain unknown.
  A separate versioned organization-default policy artifact records observed true/false or a fixed unavailable
  reason, never organization identifiers or raw SDK text. Permission, binding and schema failures do not stop
  the workload. This is configuration readback, not per-flow denial proof or full effective-policy/tier proof;
  it changes no guest observation, pass/fail, exposure score or configuration eligibility requirement.
- **EVD-17 Workload score provider context.** RC recomputation from workload evidence must preserve the provider
  named by a structurally valid, host-frozen workload contract, after the standard evidence grades valid. Never
  infer a provider from guest prose or treat an invalid contract as scope evidence. Without a provider declaration,
  retain the historical unqualified context. This preserves SCR-2 applicability and native exclusion provenance;
  it adds no measured result and changes no scoring rule. Saved source artifacts remain unchanged when recomputed.
- **EVD-16 Native exclusion provenance in managed reports.** The managed Daytona collector uses the same
  PRV-12 exclusion map as the native adapter and must preserve its `provider_terms` kind in the frozen manifest.
  This selects no additional check, changes no observation, and gives skipped checks no measured or conclusive
  credit. SCR-2's existing provider policy decides category applicability; this does not turn exclusions into
  passes or change the scoring algorithm. Do not assign provider-terms provenance to an operator's narrower
  assessment exclusion merely because it names a provider endpoint.
- **EVD-15 Metadata-only persistence marker.** The host may explicitly choose `symlink-v1` for PER-5 instead
  of the default regular file. The frozen planned path is `<root>/.sandprobe-link-<run id>`, distinct from the
  regular-file namespace. After pinning and verifying the surveyed root, create exclusively a symbolic link
  whose target text is exactly the public run ID. Never follow it or open its target. Pin the link itself with
  `O_PATH|O_NOFOLLOW`, verify its type, and read only its bounded link text with `readlinkat(fd, "", ...)`.
  The name must still identify that pinned link after the metadata read. A matching link after a proven reset
  shows persistence of run-owned metadata even if the filesystem renumbered its inode; this is not proof of
  regular-file contents or stable inode identity. A different target, other type, replacement during measurement,
  unsupported syscall/filesystem or unreadable metadata stays unknown. There is no fallback to reading contents.
  Absence remains find-only `not_found`, never a pass. Preserve native reset/volume binding and every planned root.
  Regular-file markers retain their exact inode/length guards. Existing wire fields keep their meaning (marker
  payload length and placement inode); the distinct planned namespace freezes the selected mechanism. Old graders
  reject the new namespace rather than treating it as a regular-file proof. Defaults remain regular-file markers.
  Both managed runners may select it explicitly with `--persistence-marker symlink-v1` for a persistent profile;
  they freeze the selection in the run intent/journal and forward it to the generic host option. Invalid selectors
  or an ephemeral profile are rejected before resource creation. Cleanup needs no measurement selector. A resumed
  journal must not change its recorded marker mechanism; older journals mean regular-file markers.
- **EVD-18 Portable metadata retention marker.** An explicit `empty-file-v1` PER-5 mode uses an exclusively
  created empty regular file at `<root>/.sandprobe-empty-<run id>`. The public run token is carried by its unique
  name, not file contents. Verify the surveyed root before creation and the created empty regular object before
  confirming placement; a close failure leaves placement unknown. After reset, pin the entry with `O_PATH` and
  `O_NOFOLLOW`, require a regular file of size zero, and verify the name still identifies that same pinned object.
  Never reopen it for reading or inspect contents. Matching metadata proves retention of a run-owned namespace
  marker; it does not prove regular-file contents or original inode identity. An inode change across reset is
  allowed only for this explicit metadata protocol. Nonempty, wrong-type, inaccessible or concurrently replaced
  entries stay unknown and unread. Missing markers stay find-only, never pass. There is no automatic fallback.
  The existing native reset/volume proof and regular-file content guards remain unchanged. Both managed runners
  freeze and forward this generic selector like `symlink-v1`. If no planned marker was placed, do not reset or
  create a replacement merely to obtain an already-inconclusive result; retain all placement gaps in the reason.
  Host-only reset evidence may additionally retain a closed, fixed failure-stage label. It is diagnostic only,
  never a provider error string or positive proof; unknown labels are ignored and successful reset evidence clears it.
- **EVD-14 Bounded policy-readback diagnostics.** EVD-11's optional organization read may report only fixed
  failure categories: authentication, permission, endpoint availability, rate limit, request rejection, service
  availability, timeout, transport or response-schema failure; other errors retain `readback_unavailable`.
  No exception text, response body, URL, headers, organization data or credentials enter the artifact. Binding
  must still be verified before the single exact-ID read; no retries, fallback endpoint, policy mutation or
  grading change. Every failure remains unknown with no inferred policy value or enforcement claim.
- **EVD-12 Typed block-device permission evidence.** AMP-8.blk may test only a resolved block-device node
  pinned with `O_PATH`; regular files, character devices, other types and paths that cannot be pinned remain
  unknown, never a block-device finding or negative proof. Read permission uses
  `faccessat2(fd, "", R_OK, AT_EMPTY_PATH|AT_EACCESS)` on that pinned object, never an I/O open. Its regular-file
  permission twins use the same syscall. Unsupported syscall/flags remain unknown without a path-based fallback.
  Re-resolving the reported path after the permission call must identify the same pinned block-device inode;
  observed removal, replacement or retargeting makes the measurement unknown. This does not broaden discovery:
  the existing `/sys/class/block` to `/dev/<name>` mapping still misses custom or nested device-node paths.
- **EVD-13 Declared block-device paths.** A host may freeze up to 32 distinct, canonical absolute Linux
  paths (at most 4095 printable ASCII bytes each) as AMP-8.blk targets before execution. `run exec` exposes
  this through repeatable `-block-device-path`; its plan lists every path. These supplement, never replace,
  sysfs-name discovery. An empty discovery cannot scope out a declared target: each must receive EVD-12's
  typed, pinned metadata-only permission measurement. Missing, wrong-type or unmeasurable targets stay unknown.
  The grader rejects scoped-out evidence when any target was declared. This adds no device, grants no permission,
  performs no device I/O, and makes no claim of exhaustive discovery outside the declared and sysfs paths.
- **EVD-3 Credential-file portability.** Reuse the independently reviewed
  SEC-3 correction (SBX-2): when an owned regular file's read-only reopen fails
  solely with EPERM while requesting O_NOATIME, retry that same pinned descriptor
  without O_NOATIME. Only the retry's result counts. Open and close unread; do not
  touch original path resolution or weaken real EACCES/EPERM denials. Keep unrelated
  Docker lifecycle changes out of this correction.
- **EVD-4 Bounded validation of the accuracy changes.** One fresh managed Daytona
  workload/configuration validation may follow the reviewed accuracy changes once they
  pass CI and merge. Preserve the same model/prompt/nine cases,
  principal, endpoint exclusions, fixed account/region and cleanup guards. Retain
  exchange diagnostics, coverage and original observations. This is measurement
  validation, not a retry to improve the letter. Stop after a completed assessment,
  cleanup uncertainty or suspected provider issue. Do not enable metadata/proxy,
  host/other-tenant or newly disallowed checks merely because the public page lists
  their category. Missing evidence stays unknown; provider documentation is not a
  substitute for measured isolation or authorization.

- **EVD-5 Configuration evidence parity.** Retain a provider-independent, versioned
  configuration evidence artifact before model execution, bound to managed run,
  original box and frozen configuration hash. Distinguish image runtime-status
  readback from snapshot metadata and private-container configuration readback from
  API visibility. Nitro may record its existing control-plane guards; Daytona must
  record runtime image/private-process evidence as unavailable with fixed reasons.
  A tagged or digest-shaped snapshot reference is not runtime-image verification.
  Runtime image identity must parse as an exact supported OCI digest identity;
  substring matches, suffixes, malformed or unrelated identities fail the Nitro
  execution guard. Shared cross-language fixtures cover canonical and deceptive
  identities. Keep historical grades, grading thresholds and existing scope
  unchanged. The artifact is host configuration evidence, not attestation; missing
  provider support stays unknown. No cloud run is needed for this offline change.

- **EVD-6 Bounded network failure classification.** Shared marker clients may retain
  fixed labels for exact HTTP403/407 status lines and other HTTP status classes (1xx through5xx),
  connection reset, broken pipe and non-TLS record failures. Read at most256bytes;
  do not retain response text, headers, bodies, certificates or raw error strings.
  The labels identify observed protocol behavior, never provider attribution or an
  authenticated policy denial. Keep the historical `http_other_status` label valid when loading older
  records. A status class is diagnostic only, including2xx: it is not the nonce acknowledgement.
  Preserve pinned TLS, nonce acknowledgement, kernel
  refusal and host receipt rules. These diagnostics cannot alter any verdict,
  complete an unknown, or create an additional request/target. Historical records
  remain unchanged. Verify real probe paths against owned local fixtures and run
  a grading-invariance regression over all accepted labels. No live run is needed.

- **MEAS-1 Shared receiver measurement.** Measurement definitions, nonce protocol,
  calibration ordering, evidence validation and grading are provider-independent.
  Provider adapters supply original resource identity, the existing agent execution
  path, receiver transport/control access and confirmed shutdown. The core contains
  no provider-name grading branches. A host-only receiver binding (managed run,
  original box, receiver identity/key pin, owned endpoint, scope and three unique
  nonces) is hashed into the workload declaration before the first model request.
  Only the middle nonce and the owned endpoint/pin enter the guest; positive-control
  nonces remain host-only until evidence is published. Missing adapter support is
  explicit unknown evidence, never a pass or a claim that the provider lacks it.
- **MEAS-2 Calibrated final collection.** Arm a separate run-owned receiver session,
  send and verify a host-side positive control, invoke the shipped receiver attempt
  through the same agent path without changing workload/network configuration, and
  collect a second host control and final receipts only after original-ID guest
  shutdown is confirmed. Bind all control answers to receiver identity, pin, run and
  nonce/protocol/port; overload, failed collection or missing controls remain unknown.
  Grade a versioned `receiver-calibration` record against the pre-workload hash and
  original box. A bound middle-nonce receipt remains positive evidence even if guest
  output is invalid; stop and preserve restricted evidence on unexpected delivery.
  No middle delivery observed is not_found, never a refusal/pass. Public and private
  endpoint scope remain explicit; no public target is called a private-cluster test.
  Legacy `private-receiver` records and historical grades remain unchanged.
- **MEAS-3 Shared exchange validation.** Bound canary reply reads to256bytes and
  require the expected nonce acknowledgement before describing a completed exchange.
  Retain fixed `unexpected_reply` diagnostics without response text. TLS key pinning
  and host receipt/kernel refusal requirements remain. Wrong replies and silence do
  not prove denial, and guest acknowledgement does not replace host delivery evidence.
- **MEAS-4 Adapter integration and validation.** Integrate the shared engine first
  with the existing Daytona owned sandbox and managed canary. SSM and Docker receiver
  transports implement the same interface; generic fixtures exercise replay, changed
  receiver/box, failed controls, missing shutdown, invalid guest output and positive
  delivery. Stop/delete the original Daytona guest before final receiver collection,
  retain the cleanup proof and let recovery reuse recorded IDs. Do not change allow
  lists, agent privilege, image/process verification flags, model or nine-case task.
  After reviewed changes pass CI and merge, one fresh managed Daytona
  workload/assessment may run; retain
  every result and verify sandbox/receiver cleanup. Do not retry a completed grade.
  Unavailable image-content/private-process evidence and inconclusive network checks
  stay unknown; documentation or a tag is not runtime verification. No new metadata,
  provider-control, host/other-tenant or reset probes are authorized by this change.

## Pre-run boundary context, 19 November 2026

This is the first prerequisite for a future versioned boundary assessment. It does not replace legacy grades.

- **BND-1 Host declaration.** Before the full probe runs, opt-in AWS reference variants record a structured
  `sandprobe.boundary-contract/1` object in the host manifest, not probe stdin. Record the fixed file-workload
  profile `aws-reference-file-v1`, requested pinned image, Kubernetes-reported imageID (at most256bytes),
  requested UID/GID10001, network expectation
  (`unrestricted` or `deny-canary-six-routes`), reset model `none`, and protected-resource attribution
  `unestablished`. Derive the network expectation from the selected reference variant and imageID from the
  same REF-3-verified pod. The network field is the operator's reference-test requirement, not a provider promise or
  evidence that it is enforced. Configuration and imageID are API-reported, not attested. Do not infer protected
  principals from a UID, PID, path, or legacy finding; the current reference workload has no protected fixture.
- **BND-2 Validation and scope.** Accept only this initial fixed workload, supported version, pinned reference
  image, bounded digest-bearing imageID and exact identity/reset/attribution/enumeration values. Reject malformed
  declarations before executing the probe, without echoing their contents. Parsing inherits JON-1 strict
  framing and unknown-field rejection. Copy declarations into the manifest
  by value. The declaration neither changes probe selection nor suppresses findings, validates observations,
  establishes negative proof, or affects legacy letters and gates. Old/default runs carry no declaration and
  none is reconstructed for saved runs. Absence is missing context, never proof of containment.
- **BND-3 Offline use.** ANL-1 validates any recorded declaration and rejects unsupported/malformed versions.
  Offline assessment exports it as declared context only, with an explicit unauthenticated/non-attribution limit.
  Comparison reports any declaration change, including addition/removal, as a context change. Matching declared
  context alone does not establish matching enforcement, protected-role attribution, or equivalent security.
- **BND-4 Remaining calibration.** Before a new overall grade, add independently executed synthetic resources
  with known agent-owned/protected roles and allowed/refused counterparts, bind observations to those exact
  resources, and calibrate false-negative and false-positive cases. Ordinary same-user process access must not
  be relabeled protected-secret theft; unrelated harmless-marker delivery must not be relabeled secret theft.
  Missing protected-role or reset evidence stays inconclusive. BND-1 does not satisfy these measurements.
- **BND-5 Tests.** Validate malformed/version/image/identity/policy declarations, old-report compatibility,
  pre-execution rejection, immutable plan copy, pair differences and changed/missing offline context. Map to
  `internal/obs/boundary_test.go`, `internal/host/boundary_test.go`,
  `internal/analysis/boundary_test.go` and `cmd/sandprobe/nitro_reference_test.go`.

## Single-provider grading calibration, 18 November 2026

One-provider investigation and calibration come before more provider runs. AWS's saved open-network
and network-isolated runs are the first case study. This extension adds a narrow
retrospective assessment, not an alternative overall sandbox verdict or a declaration of provider-policy compliance.

- **CAL-1 Fixed question.** `sandprobe assess <report.json> canary-egress-deny-v1 [-o json]` asks whether the saved
  results satisfy a hypothetical requirement to deny six specific agent-to-canary routes: EGR-1 (resolver DNS),
  EGR-2 (direct HTTPS), EGR-5.22, EGR-5.80, EGR-5.8080 (direct TCP), EGR-5.53u (direct UDP). All six are mandatory;
  the caller cannot drop an inconvenient route. This is not a claim that a provider promised this policy, nor a test
  of arbitrary destinations, proxies, host isolation, actual secret exfiltration or all egress.
- **CAL-2 Evidence and uncertainty.** Use ANL-1 loading/validation, then check each required route's catalog kind,
  selection, exported proof/result consistency and expected scope port/route. Require a nonempty valid destination
  IP matching the manifest endpoint and a recorded per-check nonce. A saved two-sided `pass` with
  canary proof is `reported_refusal`; a saved proof-class `finding` with canary proof is `reported_delivery`.
  Inputs rejected by ANL-1 remain input errors. Otherwise missing, unknown, skipped, absent, scoped-out, find-only
  not_found, wrong scope or missing proof is `inconclusive`,
  never a refusal. Invalid runs assess no route. No new security pass is established: raw observations, canary
  receipts, health controls and operator configuration cannot be reverified from this offline result.
- **CAL-3 Bounded outcome.** Output version `sandprobe.assessment/2`, fixed profile ID, source provider/run ID,
  unauthenticated/retrospective verification label, six route rows, counts, five-area ANL-2 coverage, and the saved
  report's highest-severity finding IDs (`highest_severity_finding_ids_unverified`), by the severities it saved, not regraded.
  `sandprobe.assessment/1` also gave the saved letter in its coverage and named those IDs
  `reported_grade_driver_ids_unverified`; removing one field and renaming another is breaking, so the version changed. Outcome is `reported_violation` if any delivery is reported,
  otherwise `inconclusive`. Current DNS and UDP checks are find-only, so this profile cannot establish all six
  refusals from any currently legal report. The four direct TCP routes also have a separate fixed summary; it
  does not remove the DNS/UDP requirements or change the overall outcome. Uncertainty remains
  visible even alongside a violation. No overall grade, certification, provider ranking or CI security gate is produced.
  The command exits 2 on input/usage error, 5 for invalid/incomplete source or any inconclusive required route,
  6 for reported delivery with otherwise complete source/route coverage. Exit 0 is deliberately unreachable under
  the current catalog; there is no fabricated successful fixture or silent exclusion of DNS/UDP. Every nonzero
  exit must be treated as not meeting the complete assessment requirements.
- **CAL-4 Interpretation.** Keep image/guest capability observations separate from proven boundary crossings.
  Report UID when recorded, without treating guest root alone as host escape. State that process/file openability
  plus independent marker delivery does not prove secret contents were exfiltrated. Writable startup files alone
  do not prove reset survival. Preserve all findings and unknowns, do not infer process ownership/trust roles from
  path names, and do not retrospectively invent image, namespace or policy context. Old grades, `run -min`, existing
  report formats and gate semantics remain unchanged.
- **CAL-5 Calibration.** Add deterministic replay tests on saved open-versus-refused reports (`test/reports`: the same
  local Docker box with every route out, and with every route refused by its own firewall), synthetic four-TCP-refused,
  delivery, unknown, invalid, omitted route, absent, wrong proof/scope, missing identity and unrelated incompleteness
  cases. Forged six-pass reports are rejected. DNS/UDP silence stays inconclusive, guest root never overrides a route refusal, and a delivery never gets
  hidden by other unknowns. Test CLI output/exit behavior and safe escaping. These are offline interpretation tests,
  not new live runs or proof that the probe's underlying controls work on an untested provider. Any later live
  calibration must still obey the provider's terms, bounded spend, owned disposable resources and verified cleanup.
  Replays of a real provider's saved reports, which check that this interpretation still reads a recorded provider
  report the same way, run where the operators keep those records, not in this repository.

Tests: CAL-1–5 map to `internal/analysis/assessment_test.go` and `cmd/sandprobe/assessment_test.go`.

- **CAL-6 Executed controls.** A separate, bounded Linux CI calibration job runs the actual Linux probe, host
  grader and run-owned local Docker canary against four existing synthetic fixtures: clean, holes,
  net-canary-down and broken-arch. Assert all four subtests actually execute and pass; missing/skipped controls
  fail the job. Expected legacy outcomes are clean A (with find-only/no-finding coverage distinct from refusals),
  holes F, unavailable canary incomplete with no egress refusal, and unexecutable probe no grade. This does not
  change grade rules or demonstrate a live provider result. Run no cloud/provider APIs or production resources.
  Bound the job and Go test deadlines; retain the test harness's exact-container-ID cleanup. Publish only a fixed
  synthetic-control summary with grades/coverage, not probe documents, secret values or provider evidence.
  Keep Go stderr separate from the JSON event stream. Failed controls may publish fixed reason codes,
  allowlisted control names and known check-ID hints; never raw output/error text. A nonzero Go command must
  not publish a successful summary even if its event stream appears complete. `TestFixtures/clean`'s
  `expectClean` and `TestFixtures/net-canary-down`'s `expectCanaryUnknown` own the finer coverage/no-refusal
  assertions; the summary parser verifies execution, grade and completeness.

Tests: CAL-6 maps to `test/calibration.sh`, `test/calibration_summary.py` and `test/calibration_summary_test.py`.

- **REF-1 Paired reference configuration.** Add opt-in AWS Nitro variants `reference-open` and
  `reference-network-isolated`. Use the same fixed public Amazon Linux multi-architecture image digest, command,
  UID/GID10001, fsGroup10001, capabilities drop ALL, no privilege escalation, RuntimeDefault seccomp, read-only
  root, no service-account-token automount and no service links. Only the existing network-isolated annotation
  differs between the pair. Keep both old variants unchanged. These are operator-hardened reference setups,
  never relabeled provider defaults or evidence that an existing provider grade improved.
- **REF-2 Scripted workload.** A fixed shell task writes/transforms/checksums nonsecret text in a run-owned
  ephemeral `/workspace`, then creates a completion marker and sleeps. This is a deterministic file-work task,
  not an LLM/coding-agent evaluation. Writable `/tmp` and `/workspace` emptyDir volumes are each capped64Mi;
  CPU1/memory1Gi limits remain. No external service, credential, persistent volume, host mount, privileged helper
  or additional Kubernetes resource. Readiness requires task completion; allow at most15minutes for scheduling,
  then bound reference readiness to two minutes, within the existing30minute run deadline.
- **REF-3 Check and record configuration.** Before upload/probing, verify the ready pod's API-reported UID and
  fixed security/runtime/image/workspace fields against the requested profile. Explicitly verify hostNetwork,
  hostPID, hostIPC and container privileged are false. Reject API-injected env/envFrom using presence only,
  without retrieving their values. Query only fixed nonsecret fields,
  never the whole Pod JSON, env values or credential objects. Reject a missing/mismatching field, extra container,
  init/ephemeral container, mount option, emptyDir medium, lifecycle hook, startup/liveness probe, volume device,
  capability or volume. Record the API-reported immutable imageID, fixed profile
  and requested security settings in existing escaped report notes. API-reported configuration is not kernel
  enforcement attestation; the probe's actual identity/capability results and all findings remain authoritative
  within SBX-10's limits. No skip, severity change, identity override or promised passing grade is introduced.
  Offline comparison compares only CLI-written reference context notes with the exact `REF-2: ` or `REF-3: `
  prefix, treating their contents as opaque data. Changed reference image/profile metadata remains a context
  change. Grader/lifecycle notes (including CHN-2) must not become configuration changes or mask regression exit6.
  Unrelated Pod annotations must not cause a missing network-isolated annotation to print a mismatching placeholder.
- **REF-4 Lifecycle and scope.** Preserve existing create/UID-check/upload/probe/delete and bounded cleanup.
  Reference verification errors take the same cleanup path. Plans disclose the reference setup and file task
  before approval. Preparing variants or CI checks authorizes no live EKS run.
- **REF-5 Tests.** Assert fixed manifests and pair equivalence except network annotation, old-variant behavior,
  command safety/readiness/resources, accepted API snapshot, missing/mutated fields and wrong UID rejection,
  safe notes and cleanup on verification errors. Unit tests use a fake kubectl only; unsupported runtime behavior
  remains unvalidated until an authorized live run. Map to `internal/host/nitro_reference_test.go` and
  `cmd/sandprobe/nitro_reference_test.go`. A gated CI check executes the exact task in the pinned public image
  as non-root with local Docker, no network and ephemeral scratch. It verifies completion, checksum and exact-ID
  cleanup; it validates task/tool availability, not Nitro enforcement. Map to `internal/host/nitro_reference_docker_test.go`.

## Any sandbox, 20 November 2026

Sandprobe works with any sandbox, starting with the top 20, without the canary becoming a hurdle: a hosted, anonymous
canary is the default. The canary's side of
HCN-1 to HCN-4 is built (`internal/canary`, `internal/canarycontrol`), and so are the host's client
(`host.HTTPSCanary`), PRV-15's `run exec`, and the hosted canary itself (HCN-7: deployed 21 Nov 2026 at
`pub.probe.ac0.dev`, verified end to end with `run exec` through `docker exec`), HCN-5's choice of canary for every run, including native adapters (22 Nov 2026), and `-no-canary`, and RCP's
runner with its first shipped recipe, Kubernetes (PRV-16), and PRV-15's `-provider-endpoints` for `run exec` and
shipped recipes, and RCP-4's `-recipe <file>` for a person's own recipe (24 Nov 2026). Recipe resets aren't built yet.
Each piece needs AGENTS rule 2's two reviews before it lands. Where a rule below amends an existing
one, the amended text lands in place only after review.

- **HCN-1 Public control.** The canary may serve SBX-11's control operations (status, arm, query, disarm, and
  HCN-3's reserve) over HTTPS as well as through SSM and `docker exec`. The control listener shares port 443 and is
  chosen by SNI: the control name (`control.<our domain>` for the hosted canary) gets a WebPKI certificate and the
  JSON API under `/v1`; every other name gets today's pinned-key echo, unchanged. WebPKI only protects the run secret
  in transit; it doesn't prove the canary answered, since a CA-authorized proxy, an enterprise interception root or a
  redirected name can terminate TLS. Trust rests on a control key instead: an ECDSA key the canary's deployment makes
  on its own instance and never exports, kept across restarts. Its pin (SHA-256 of the public key) ships in each
  sandprobe release for the hosted canary, at most two at once for a rotation; a self-hosted canary's pin is given
  with `-canary-url`. Every request carries a fresh 32-byte host challenge. The control key signs one transcript: the
  label `sandprobe-control-v1`, the request's method and path, the request body's length and its exact bytes, then
  the answer body's exact bytes. The signature and the key travel in response headers, outside the signed answer, so
  nothing signed contains its own signature. Both sides parse JSON under JON-1 (strictjson: duplicate or
  case-ambiguous keys and unknown fields refused), and the host parses only answer bytes that verified. The host
  accepts an answer only when that signature verifies under a pinned key, so anything on the path can relay or drop an answer but never forge or replay one;
  a dropped or altered answer fails the request, which leaves the run unknown. The receipt key's pin is trusted only
  as a verified status answer carries it; health and EGR-2 keep checking it. The status answer also names the
  canary's receipt address and domain, signed like everything else, and the host sends the box's traffic and its own
  health checks only there, never to what DNS returns for the control name: a redirected name could otherwise put a
  relay in front of the box that forwards genuine control and health but drops the box's attempts, and turn a signed
  zero-receipt answer into a clean negative. A redirect, an unverified answer, or one
  over 16 KB fails the request; every request is bounded to 5 seconds. The control path takes only `application/json`
  and refuses a request a browser marks as cross-origin, so a web page can't spend anonymous slots through its
  visitors.
- **HCN-2 The run secret.** On the public path the host makes 32 random bytes per run, reserves and arms with their
  SHA-256, and presents the secret itself on every query and disarm; the canary compares digests in constant time. The secret
  never enters the box, a report or a log. Arm refuses a run ID or a nonce already armed (as today). Without the
  secret, query and disarm are refused, so a box that knows its run ID and nonces cannot reset or read its run. The
  arm's answer carries a run generation the canary draws at random; every query answer repeats it, and the host
  requires it unchanged, so a run re-armed by anything that learned the secret on the path is never read as clean.
  A failure to draw randomness, on either side, aborts the run.
- **HCN-3 Shared bounds.** On the public path: at most 256 runs armed at once; per control source address at most 4
  runs at once and 30 arms an hour; a lifetime of at most 1,800 s. A source is the caller's connection address (never
  a header), an IPv6 one counted as its /64; at most 50,000 sources are tracked, and a new one past that is told the
  canary is busy. Receipt-port caps rise to fit many boxes behind
  one provider's NAT. Every cap hit and kernel drop still marks the runs armed at the time overloaded, and an
  overloaded run gives no network negative (SBX-11): a shared canary under load makes results unknown, never a pass,
  and the report names the cause. Before creating any box, the host reserves a slot (`reserve`, with the secret's
  SHA-256 and the run's lifetime). A reservation counts against every bound above the moment it's made, so concurrent
  callers can't overbook the canary, and only an arm carrying the same SHA-256, before the reservation's lifetime
  ends, can use it; the per-hour count is of reservations. A refused reservation stops the run before any box is
  created. An arm that still fails (an expired reservation, a malformed run) stops the run before the probe runs: the
  box is deleted as usual, nothing is graded, and the report names the cause.
- **HCN-4 Retention.** The public canary holds receipts (with each box's source address) only for an armed run's
  lifetime, and per-source rate counters for at most an hour, in memory. It writes no access log and stores nothing.
  Reports are never uploaded (OUT-3).
- **HCN-5 Which canary, and consent.** In precedence, for every run but `run docker`: `-canary <state file>` (an
  operator canary from `deploy/canary.sh`, reached over SSM), used only when named: a `canary-*.state` file is never
  picked up on its own, since a forgotten one would send a run to a canary that may be gone; `-canary-url <https URL>`
  with its `-canary-pin` (a self-hosted public canary, `sandprobe canary serve`); otherwise the
  hosted canary at `control.pub.probe.ac0.dev`, under the
  control key each release pins (two during a rotation). A pin given without its URL is refused before any of this, never set aside for
  another canary. The command line always beats the environment: once any of `-canary`, `-canary-url`, `-canary-pin`
  or `-no-canary` is given as a flag, the `SANDPROBE_CANARY`, `SANDPROBE_CANARY_URL` and `SANDPROBE_CANARY_PIN` values
  are all set aside, so the flags name the whole choice and a stale value in the environment can never outrank them;
  with no canary flag, those values stand in for the flags. `run docker` always uses PRV-14's local canary: it refuses
  `-canary`, `-canary-url` and `-canary-pin` given as flags with a usage error before anything runs, and never reads
  their environment values. The native adapters (Sprites, AWS Nitro, Baseten, E2B, Vercel, Cloudflare, Daytona, Boat and
  exe.dev) choose the same way as `run exec` and recipes, under the same guarantees: after approval, and before the
  box is created (for `run exec`, before anything runs in it), a public canary must give its signed status under the
  pin and reserve the run's slot (HCN-1, HCN-3), and an operator canary must answer its status over SSM; either
  failing stops the run with nothing created. A public canary's slots are given back when the run ends, under their
  own budget, even after Ctrl-C or a cleanup that used all of its own. Where a provider's PRV row says "our canary", it means the canary the plan names.
  The plan names
  the canary and who runs it before approval (AGT-3). When the canary is a public one, the hosted canary or one
  `-canary-url` names, the plan also states HCN-4's retention of both addresses it sees, in one sentence shared by
  every plan: the box's public address, with the run's nonces, for the run's lifetime, at most 30 minutes; and the
  public address of the machine running Sandprobe, in a rate counter for at most an hour; both in memory only, with
  no access log and nothing stored. `plan`, `providers` and a run that isn't approved ask no canary anything. With `-no-canary`, EGR-1 to EGR-5 are
  unknown with the reason "run without a canary", never skipped: GRD-3's skips don't make a run incomplete, so
  skipping them could leave the run complete (KND-2 already lets the find-only ones end unknown). The run is incomplete (GRD-2),
  and the plan's `-no-canary` line says so: "the exfiltration checks aren't tested (the run ends incomplete)".
  The probe is never asked for them and gets no canary address, nonce or domain; the host arms nothing and asks no
  canary anything; the grader refuses an outcome the box returns for one (GRD-5), and gives each the host's reason
  whatever the box sent. A check excluded for another reason (PRV-15's provider endpoints) keeps that skip. Before
  approval, the plan says that no test traffic goes to any canary. When `-provider-endpoints` also turns checks on
  (PRV-15), the same line names each connection they still make: SEC-4's metadata addresses, from the catalog list the
  probe dials (UX-4), and AMP-7's TCP and TLS handshake, with no request, to the Kubernetes API the box's environment
  names. It names nothing for AMP-6, which only checks for a vsock device and connects to nothing (AMP-6's row); its
  attestation line says so. EGR-3 carries its nonce to a canary, so under `-no-canary` it never runs: the plan says
  so, names no proxy for it, and its local-proxy line reads excluded. The plan's destinations are exactly the ones the
  probe's input lets it contact. The help says the same in short. `-no-canary` is for `run exec`, a shipped recipe (`run
  kubernetes`), a person's own recipe (`run -recipe`) and their plans only, and is refused with any canary flag.
- **HCN-8 Private maintenance.** The existing private Unix control socket supports `maintenance`, `drain`
  and `resume`. Their answers alone carry `maintenance {draining, active_runs, reservations}` after expired
  entries are purged; they carry no run names, sources, nonces, secrets or receipt contents. `drain` atomically
  refuses new public reservations and private arms. Already reserved public runs may still arm, and existing
  receipt collection, health, query and disarm continue unchanged. Zero runs without `draining=true` is not
  restart clearance. The public HTTPS handler cannot invoke these operations or see their metadata; legacy
  answers omit the field. These controls are process-local and idempotent. `-start-drained` applies the gate
  before listeners start; an operator explicitly resumes after verification. A restart still loses receipts
  and changes the receipt boot pin: preserve the persistent public control key, check the private drained/zero
  state immediately before stopping, and retain a verified rollback binary. An older deployment lacking these
  controls requires a separately coordinated bootstrap window; this feature does not prove it is idle.
- **HCN-7 Deploying the hosted canary.** `deploy/canary.sh` with `PUBLIC=1` deploys it beside an operator canary,
  never in its place: its own domain (`pub.probe.ac0.dev` by default; `up` refuses a domain that already has records),
  namespace and state file (not `canary-*.state`, an operator canary's name, which a run uses only when `-canary`
  names it), a t4g.small, and an extra DNS-only `control.<domain>` record that `down` deletes with the
  rest. The non-public deployment is byte for byte unchanged. Its service makes the control key on first start in its
  own state directory and starts only once `canary.sh` has given it, over SSM, the Elastic IP it signs (HCN-1).
  `status` records the control pin on first sight and fails if it ever changes, then asks for the signed status from
  outside, as any host would. `sandprobe canary check` is that question: it asks twice, prints only what the second
  signed answer says after the client confirmed it names the first one's address and domain, reserves nothing, and its
  `-tls-insecure`, for a canary whose certificate comes from Let's Encrypt's staging service (`ACME_STAGING=1`), skips
  WebPKI for that check only, since a status carries no secret and trust rests on the pin. It asks the canary a run
  would use, chosen by HCN-5's precedence with no network call: with nothing named, by flag or environment, the hosted
  canary under the pin this release ships; `-canary-url` with its `-canary-pin` asks the canary they name. Its output
  says which canary answered, at which control URL. It keeps HCN-5's refusals: a URL without its pin, or a pin without
  its URL, is refused before anything is asked, and so is an operator canary (`-canary` or `SANDPROBE_CANARY`), which
  answers only over SSM and is checked by `deploy/canary.sh status`. `-tls-insecure` needs `-canary-url`: the hosted
  canary's certificate is a WebPKI one.
- **HCN-6 Shared receivers.** A receiver binding (MEAS-1) on a hosted canary has scope `shared_public_endpoint`; its
  `ReceiverID` is its first pinned control key (HCN-1), which names the deployment across restarts (not built yet:
  until receiver sessions reserve their own slot and carry this scope, a public canary isn't a receiver); its cleanup is the disarm only, since the receiver is
  not the run's to delete. Every other MEAS-1 and MEAS-2 requirement is unchanged.
- **PRV-15 Any box by command.** `sandprobe run exec [-as <user>] -y -- <command>` probes an existing box through the
  person's own command, which must start a POSIX `sh` in the box on the agent's path with stdin attached. The host
  runs it without a shell, arguments as given, under the run's deadline. Its checks are non-mutating; its transport
  makes one bounded, transient scratch write (the probe and its input). Each invocation writes one script to stdin:
  a start marker with a fresh random token (output outside the markers is ignored); a scratch directory at an exact
  absolute path the host fixes before the first upload and passes as a literal, never a variable, to every
  invocation, the preflight included (`<dir>/sandprobe-<24 hex>`, where `<dir>` is `/tmp` unless the person names
  another absolute directory with `-scratch`; the preflight reports the box's own temporary directory so a run that
  can't write `/tmp` can say which to name), made with mode 700, and the run stops if it already exists; a random owner token the host made for this box,
  written into it right after that exclusive `mkdir`; an exit and signal trap that removes it only while it carries
  that token; the probe decoded from a base64 heredoc (no
  `base64` in the box stops the run); the probe's run framed between markers. For the main run, the shell instead replaces itself
  with the probe in wrapper mode, which prints the markers, starts the run and removes the scratch (LNC-1, LNC-2). The
  script uses only `sh`, `mkdir`,
  `base64`, `chmod` and `rm`: upload plumbing run by the host's script, not by the probe, so SBX-5's rule for the
  probe holds. The digest the probe reports for its own executable must equal the shipped one (SBX-5). After each
  invocation, a separate one removes the path only if it carries that owner token, and confirms it gone; a path
  without the token isn't Sandprobe's and is never removed, only reported. If the host can't confirm its own path
  gone, the report names the path and a command that removes it only if it still carries the token (PRV-1).
  - **The user is bound before any check.** One invocation first asks only the box's machine type (`uname -m`, run
    by the wrapper through a command that must exit 0) to choose which shipped probe to upload: no probe runs, no
    check, no file is written. The next is identity only: the probe runs with `-whoami
    [<name>]`, resolves the requested name to a numeric uid inside the box, reports its own real, effective,
    saved-set and filesystem uids (the kernel's `Uid:` line) and its temporary directory, and runs no check. If
    `-as` was given and any of the four differs, nothing else runs. Every later invocation passes that uid
    (`-expect-uid`), and the probe refuses at startup, before the survey or any check, unless all four of its uids
    equal it. Without `-as` the preflight's uid is bound the same way, and the report says
    the user is unconfirmed as the agent's.
  - The box is an existing box (PRV-1): non-mutating checks only, GRD-3's existing-box skips, no reset, and the
    boundary is the person's attestation (PRV-2, UX-4). The launch mode is `exec` (SBX-4).
  - The provider isn't identified, so SEC-4, EGR-3, AMP-6 and AMP-7, the checks that contact a provider-owned
    endpoint, are excluded by default, as kind `opt_in` (SCR-2), unless the person names the provider with `-provider`,
    when that provider's PRV row decides the ones it excludes (PRV-17) (Sandprobe checks the person's own box and
    sends only to the
    canary). `-provider-endpoints <IDs>` selects named ones only (for example `SEC-4,AMP-7`), each one the person
    attests their provider's terms allow on their own account; the plan lists each with that attestation before
    approval (AGT-3), and the report records it beside the check. Nothing selects them all at once.
    - The value is a comma-separated list of those four IDs, each named once, exactly as the catalog spells it. An
      empty value, an empty item, `all`, `*`, a duplicate or any other ID is refused before the plan exists, and so is
      the flag anywhere but `run exec`, a shipped recipe or a person's own (RCP-4) and their plans: `run docker` already runs these
      checks, and a native adapter's PRV row decides them (PRV-5). It has no environment default, so an attestation is
      typed for each run.
    - A selected check leaves the exclusions and runs as it does for a provider whose rules allow it, under every
      other gate: nothing is contacted before approval; SEC-4 asks for role listings only, never a credential document;
      AMP-7 is a TCP and TLS handshake to the API the agent's environment names, no request; EGR-3 goes only through
      the proxy the agent's environment names, a local one only with `-allow-local-proxy`; AMP-6 stays skipped on
      `run exec`, since an existing box gets no vsock connects (PRV-1), and on a recipe's throwaway box follows its own
      gate. The checks left out keep their `opt_in` skip (SCR-2).
    - The host records the attested IDs in the manifest (`Attested`, never in the probe's input), and each one's report
      row carries a fixed `attestation` sentence, never text from the command line; such a report declares
      `sandprobe/6` (`sandprobe/2` before the letter left OUT-1, AGT-6), and the reader accepts attestations only where this policy allows them. The grader (GRD-5) and ANL-1 refuse an attestation on a check that isn't a provider
      endpoint, is named twice, or still carries a skip kind, and ANL-1 also refuses one where this binary's own policy
      for the run's provider isn't `opt_in` (SCR-2): only `run exec`, shipped recipes and a person's own recipe take an
      attestation.
    - Every attested check keeps its report row, with its attestation, whether or not the run is valid, since the
      check may already have contacted its endpoint: an invalid run (GRD-5) grades nothing, so its row reads unknown,
      "not graded: the run is invalid", while the grade lists no unknowns. ANL-1 requires a row for every attested check
      in valid and invalid reports alike, and every row of an invalid report is a skip or an attested check exactly
      not graded: unknown, with that reason, and no evidence, severity, proof or scope. The
      page lists each attestation and its result in its appendix for every run.
- **RCP-1 Recipes.** A recipe is a POSIX shell file with a `# sandprobe-recipe: v1` header (provider, docs, terms with
  the quoted clause, exclusions, `addressed-by: id` or `name`) and the functions `sp_ready`, `sp_create`, `sp_shell`,
  `sp_delete` and `sp_gone`, and optionally `sp_checkpoint` and `sp_restore`, or `sp_recreate`, and `sp_whois` for a
  name-addressed provider. A shipped recipe may also define `sp_wait`: the host calls it once, after the create's ID is
  on disk (RCP-2) and before the first `sp_shell`, and it returns once the box takes `sp_shell` or fails with the
  recipe's own message. The host gives it 90 seconds whatever its commands do, and runs it in its own process group:
  at that limit, or on a cancel, the whole group is killed before the cleanup starts. It may run only a command that does nothing (`sh -c :`) in the box, by the name check RCP-2
  requires. A person's own recipe's `sp_wait` is never called. A header value is printable ASCII, at most 400 characters, since plans and reports show
  it; a recipe with any other is refused. The host calls one function per `sh` invocation, under the run's deadline. `sp_shell`
  keeps PRV-15's contract. Each call is `sh -c` over the recipe's bytes as read once (at most 64 KiB, never read
  again from disk) followed by the function's name, with stdin from `/dev/null` except `sp_shell`'s, which carries
  PRV-15's script; its output is bounded. Its stderr goes to `/dev/null`, since kubectl and an exec plugin write
  there and it can carry a credential (AGENTS rule 3); the person sees only what the recipe writes to fd 3, a pipe
  the host opens before the recipe starts and drains itself, so the text has no file and no name. It is bounded where
  it is written, not only where it is shown: the host keeps the first 4 KiB and discards the rest as it arrives, so a
  recipe that floods fd 3 grows nothing on disk or in memory, and a child left holding the pipe delays the call by at
  most a second. What is shown or recorded of it, in an error or in the report's cleanup outcome, is its last 300
  characters as printable ASCII only: a newline or tab becomes a space and every other byte is dropped, so no
  control, C1 or Unicode format character and no invalid UTF-8 reaches a terminal or a report. A recipe runs every child command with fd 3 closed, so no tool can
  write a message as the recipe. A recipe
  takes its settings from the person's environment, under `SANDPROBE_` names its header lists (`env:`), never from
  flags. `sp_ready` checks them, which may mean read-only calls to the provider before approval (so `plan` and
  `providers` make them too), and prints one line naming where boxes will be made; the plan shows it before
  approval, and the host passes it back as `SANDPROBE_TARGET` to every later call, so a recipe refuses a call whose
  target no longer matches. The host sets `SANDPROBE_BOX`, `SANDPROBE_NAME` and `SANDPROBE_TARGET` itself, and the
  person's own values for them never reach a recipe.
- **RCP-2 Identity and deletion.** The box ID is `sp_create`'s whole stdout: exactly one line matching
  `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`, or the run stops with the create's outcome reported. The host passes the ID
  and a fresh `sandprobe-<12 hex>` name in the environment (`SANDPROBE_BOX`, `SANDPROBE_NAME`), never in command
  text. Delete and gone use only that ID (PRV-1). `sp_gone` exits 0 only on the provider's positive "not found" or
  terminal deleted state, 1 while the box exists, 2 when it can't tell; anything but 0 is not gone (KND) and the run
  exits 7 naming the ID (OUT-4). A
  name-addressed recipe runs `sp_whois` before each call and the call is made only if it answers the recorded ID; the
  remaining race is reported (PRV-1). A create that returns no ID leaves its name recorded, reported, never deleted.
  Recorded means on disk (AGENTS rule 8): before `sp_create`, the host writes the recipe, its SHA-256, the target and
  the name to `~/.config/sandprobe/recipe-<recipe>-<name>.state` (mode 600), and nothing is created if it can't; the
  ID is added once returned, and if it can't be, nothing runs in the box and it's deleted by that ID; the file is
  removed only when `sp_gone` says 0, and is named in the error otherwise. For a person's own recipe (RCP-4)
  `<recipe>` is `own-` and the first 12 hex digits of the file's SHA-256, never any part of its path, and the record
  also holds the file's absolute path; no shipped recipe is named `recipe` or begins `own-`.
  The name and that path go to stderr before the create, even with `-o json`. The cleanup's budgets start when it
  does (the scratch removal, then five minutes for the delete), so a run that used all of its own still asks for the
  delete.
  Every shipped recipe must address an immutable ID, or a reviewed name exception, and its review checks it. A
  person's own recipe may be `addressed-by: name`: the host runs the same `sp_whois` guard, before each `sp_shell` and
  before `sp_delete`, and reports the same race, with no review behind either, as its plan says of the whole file.
  `sp_gone` still runs after a mismatch, to verify that the recorded ID is absent.
  A recipe run's `provider_calls` (PRV-3) list `sp_create`, `sp_delete` and the last `sp_gone`, each as
  `<recipe> recipe sha256:<64 hex> <function>`, where `<recipe>` is a shipped recipe's name, or `own` for a person's
  own, with its exit code and the create-returned ID, and nothing the recipe printed. `sp_shell`'s invocations
  aren't listed, as `run exec`'s aren't.
- **RCP-3 Reset.** PER-5 runs only through a recipe's TWN-3 reset: `sp_checkpoint` and `sp_restore` (restore in
  place) or `sp_recreate` (recreate). A recipe with neither skips PER-5 under its GRD-3 gate; PER-1 to PER-4 run
  either way. Resets aren't built yet: none of the three is ever called, PER-5 is skipped, and the plan and report
  of a recipe that defines one say so.
- **RCP-4 Shipped and own recipes.** A recipe in `recipes/` is a provider adapter: it has a PRV row citing the
  provider's terms (PRV-5) and its exclusions, and gets the two reviews. Its exclusions default to PRV-15's four;
  its reviewed PRV row may select any of them, citing what allows it. A provider whose terms require written consent
  for testing gets no shipped recipe until that consent is recorded; `sandprobe providers` lists it with the reason.
  A shipped recipe's exclusions are lifted the same way: `-provider-endpoints` may name only checks its header
  excludes, each under the person's PRV-15 attestation.
  `sandprobe run -recipe <file>` runs a person's own recipe with the default exclusions, which only PRV-15's per-check
  `-provider-endpoints` attestation lifts; its plan shows the file's SHA-256 and says Sandprobe hasn't reviewed that
  provider's terms. A person's own recipe is trusted host code: it runs with the person's own credentials and
  permissions, and the plan says so. Built: the shipped recipes (`run kubernetes`), and `-recipe <file>` (24 Nov
  2026), which these points settle:
  - **The command.** `sandprobe plan -recipe <file>` and `sandprobe run -recipe <file> [-as <user>] -y` name no
    provider: the file takes its place. A provider beside `-recipe`, or `-recipe` on any other command, is a usage
    error. Every other flag does what it does for a shipped recipe: `-as`, `-scratch`, `-out`, `-min`, `-theme`,
    `-o json`, the canary flags, `-no-canary`, `-provider-endpoints` and `-allow-local-proxy` work, and what a
    shipped recipe refuses stays refused, `-provider` (PRV-17) and anything after `--` among them. Approval is
    AGT-3's. `sandprobe providers` lists no own recipe.
  - **The file.** It is opened once, without following a symlink at the path's last component and without blocking,
    and what was opened must be a regular file of at most 64 KiB, read through that bound (ANL-1's care for a
    file a person names). Anything else is one fixed usage error. Its header and functions are checked as a shipped
    recipe's are (RCP-1), and no error echoes anything from the file but a header key's own name, lowercase letters
    and hyphens, cut to 32 characters. Its SHA-256 is over the bytes read, the only bytes
    any call runs.
  - **The exclusions** are all four of PRV-15's, whatever the header's `exclusions:` line says: a line naming fewer,
    or no line, drops none, and one naming any other check is refused as for any recipe. Each skip's kind is
    `opt_in` (SCR-2), since nobody reviewed any terms, and its reason quotes nothing from the header.
  - **The provider.** The header's `provider:` line is the recipe's own word. The plan and the report's residual
    show it as that. It is never matched against the providers Sandprobe has reviewed, so it makes no skip
    `provider_terms` and no category not applicable. The `terms:` line is required and the `docs:` line optional,
    as for any recipe, and no plan or report shows either.
  - **The plan** (UX-4) shows what a shipped recipe's does, and first: the file's path as given; its full SHA-256;
    that it is the person's own recipe, which Sandprobe hasn't reviewed; the provider it names, and that Sandprobe
    hasn't reviewed that provider's terms; that it is trusted host code, run on this machine with the person's own
    credentials and permissions; `sp_ready`'s line naming where the box will be made; and the four exclusions.
    `sp_ready` is part of that code and runs before any plan exists (RCP-1), so `plan -recipe` and an unapproved
    `run -recipe` run it too: naming the file is what allows that, and the plan says it already ran. Before that
    first execution, once the flags are sound, the host writes one line to stderr, in text and with `-o json` alike,
    naming the file as given and its full SHA-256, so the bytes about to run are on record even if the recipe then
    hangs or misbehaves. The plan also
    says the delete and the gone answer are the recipe's own `sp_delete` and `sp_gone`: each is given the
    create-returned ID, with the name and the target that every call gets, and is required to act only on that ID.
    Sandprobe can't enforce what code nobody reviewed does with them, and the plan, the residual and the docs say
    so instead of saying the recipe gets only the ID.
  - **The report.** `run.provider` is `recipe`: the way the box was reached, as `exec` is, never a provider's
    name, and this binary's own policy for it is the four `opt_in` defaults (SCR-2). `run.box.created_by_sandprobe`
    is true. `run.recipe` is the record a reader relies on: `{"own": true, "sha256": "<64 lowercase hex>"}`, the
    SHA-256 of the bytes that ran and the fact that the recipe is the person's own, with no path and no header
    text. Only a run through a person's own recipe writes it: a shipped recipe's run carries none, so `own` is
    never false. ANL-1 reads it only whole: present exactly when `run.provider` is `recipe`, exactly when the
    report declares `sandprobe/7`, `own` true, the digest exactly 64 lowercase hex digits, and the box created by Sandprobe; a record on
    any other report, a `recipe` report without one, or any other shape is refused. `provider_calls` carries the
    same SHA-256 (RCP-2): a successful create is exactly `own recipe sha256:<64 hex> sp_create`, with `id` equal
    to `run.box.provider_id`. The residual names it too, with the header's provider as the recipe's own word, and
    says the deletion rests on the recipe's `sp_gone`. In a report a run writes the three agree; ANL-1 checks only
    the record. The file's path is in no report. A report with the record declares `sandprobe/7` (AGT-6).
    `compare` treats unequal records as a changed setup (CMP-1).
- **PRV-16 Kubernetes, by recipe.** `sandprobe run kubernetes [-as <user>] -y` makes one throwaway pod in the
  person's own cluster through `recipes/kubernetes.sh` and `kubectl`. Settings: `SANDPROBE_KUBE_CONTEXT` (required:
  the kubeconfig's current context is never used, since a kubeconfig often also holds production clusters),
  `SANDPROBE_KUBE_NAMESPACE` (default `default`, checked as a lowercase DNS label with its characters spelled out,
  since a range like `a-z` follows the locale), `SANDPROBE_KUBE_IMAGE` (default the debian image pinned by digest in
  test/probe.sh) and `SANDPROBE_KUBE_OVERRIDES` (the path of a file holding a JSON merge patch over the generated pod:
  the agent's securityContext, service account, runtime class and so on. kubectl reads it through `--patch-file`, so
  its contents, an env value say, never sit on a command line, and `sp_ready` refuses a value that isn't a readable
  file, inline JSON included). The recipe runs with the person's environment, so kubectl finds the context in the
  kubeconfig its own `KUBECONFIG` names, else in `~/.kube/config`. Every kubectl call names the context, and every
  call to the cluster the
  namespace. `sp_ready` checks that `create pods`, `get pods`, `delete pods` and `create pods/exec` are allowed there
  (`kubectl auth can-i`) and names the context, its API server, the namespace, and a SHA-256 of the context's cluster
  and context entries (CA, proxy, TLS server name, skip-verify, cluster and user names), shown as 12 hex digits and
  never the entries themselves; every later call refuses if any of that has changed, so a kubeconfig edit can't
  redirect it mid-run. An API server URL with a user, query or fragment part could carry a credential, so it is
  refused and never printed; of any other only the origin (scheme, host, port) is shown, since a proxy's path can
  carry one too, while the hash covers the whole URL. The create sets the fresh name, the namespace, an
  `app.kubernetes.io/managed-by=sandprobe` label and `activeDeadlineSeconds: 3600` over the overrides (so a pod whose
  cleanup never came stops on its own), dry-runs the result and creates nothing unless it is exactly
  `v1/Pod/<namespace>/<name>`, and is a create, never an apply, so it can't adopt a pod that exists; the ID is the
  UID it returned. `sp_wait` then waits for the pod to take exec (`sh -c :`,
  12 tries, 5 seconds apart, under RCP-1's 90 seconds), since a new node's kubelet serves exec only once its serving certificate is issued. Only
  kubectl's "error dialing backend" is retried; its message is matched, never shown. Each try is made only while the
  name still holds that UID, by a lookup that succeeded. Any other failure stops the run with the recipe's own message, and the pod is deleted.
  The pod is name-addressed: `sp_whois` prints the UID now holding the name; `sp_delete` is the
  API's DELETE with that UID as its precondition and a one-second grace period, so it can delete no other pod and
  doesn't wait on the overrides' grace; `sp_gone` is 0 when the name is absent or held by another UID, 1 while
  ours holds it, 2 when kubectl fails or the target changed. `kubectl exec -i` reaches the box, and the report states
  the race left between `sp_whois` and each call (RCP-2). There is no reset, so PER-5 is skipped (RCP-3). Terms:
  Kubernetes is Apache-2.0 software and the cluster is the person's (no provider terms beyond the licence and the
  infrastructure's owner); whoever hosts it (EKS, GKE, AKS) has terms the recipe
  can't know, so PRV-15's four provider-endpoint checks stay excluded (RCP-4) unless the person attests one with
  `-provider-endpoints`: on EKS, say, `SEC-4,AMP-7` then lists the node's or pod's role and reaches the cluster's API. The maintainers' own live runs of it use a
  local kind cluster with its own kubeconfig file, or the cluster `deploy/eks.sh` makes (25 Nov 2026), with the
  kubeconfig that script writes, and no other cluster or kubeconfig. On that EKS cluster they keep the AWS Nitro
  row's terms and scope and the four default exclusions.

Amendments these need, after review:

- "Not in v1": applied in place with the canary's side of HCN.
- OUT-3: "our canary" becomes "the canary the plan names (HCN-5)".
- PRV-5 and AGENTS rule 5: Summation's own runs keep the full rule (terms read and quoted in a PRV row before any
  probe). A person running Sandprobe on their own account reads their own provider's terms: the defaults keep every
  check off provider-owned endpoints, and only the person's per-check attestation (PRV-15) turns one on.
- GRD-3: applied in place with PRV-15's `run exec`.
- SCR-2: applied in place with HCN-5's `-no-canary`.
- PRV-2: for Summation's own runs, "the org or account the operator names" is one the project owner designates;
  anyone else's run creates boxes only in the account the person is logged into, under the person's attestation.
- SBX-11: applied in place with the canary's side of HCN.
- AGENTS rule 9: the maintainers' live-test holds govern Summation's own live runs, not people running Sandprobe on
  their own accounts.
- Tests: a row for each rule above, including the false-pass cases (re-arm, disarm or query without the secret, a
  duplicate nonce, a flood, a canary restart, an `-as` mismatch, a malformed or multi-line create ID, a gone check
  that fails), and these: redirected DNS plus an installed interception root never yields a clean network negative
  (HCN-1); a replayed or re-signed answer, or a changed generation, is refused (HCN-1, HCN-2); the effective user
  changed between the preflight, the survey and the full run means no network or provider-bound check runs
  (PRV-15); a killed invocation leaves no scratch path unreported (PRV-15).

## Not in v1

Sandprobe v1 is a one-shot check, run on demand: one run, one box, one JSON report and one HTML report, and the CLI
exits. A user who wants a re-check runs it again. Out of scope for v1, and nothing built leans toward it:

- No watch mode, no scheduled or periodic re-checks, and nothing left running after a run but the canary below: no
  daemon or agent in the box (the probe and its scratch directory are removed, SBX-1) and none on the host.
- No history service across runs: no run database or trends. The local robustness extension above explicitly permits
  user-invoked offline comparison of saved reports; it does not add scheduled collection. The TUI keeps its palette choice (UX-8).
- No paging, alerts or notifications.
- No hosted service or dashboard: reports are written locally and uploaded nowhere (OUT-3). The one hosted piece is
  the canary (HCN), which holds receipts, never reports.
- No OpenTelemetry exporter or metrics stream: OUT-1's mapping onto OpenTelemetry names is documentation for later.
- No paid-tier features.
- The Modal proof of concept (its own section) compares setups and runs a sidecar beside the box. It is built only
  with `-tags poc` and never ships.

The canary is the one thing that keeps running between runs, because a way out can't be proven without an endpoint
outside the box (SBX-11). It keeps receipts in memory only for runs the host has armed, bounded, and gone within an hour
at most, and drops everything else. Nothing is stored durably, nothing is kept per user beyond HCN-4's in-memory rate
counters, and no history across runs is shown anywhere.

## Rules

### SBX: how the probe behaves

- **SBX-1 What the probe may change.** Only these. (a) The probe binary the host copies in, and its private scratch
  directory (`mkdtemp`, 0700), both removed at the end, on every box, existing ones included. (b) On a throwaway box,
  PER-5's markers in storage roots. (c) Running `sudo -n -l` for AMP-1, which lists policy and runs no command, and
  which sudo may log to the system's auth log. (d) A listener the probe binds on loopback, on an ephemeral port, for
  TWN-1's client check, closed at the end. (e) One `CONNECT` to the canary through the box's own proxy for EGR-3,
  when that proxy is local (loopback or the box's own address) and the person approved it in the plan (SBX-3). A marker is a regular file named
  `.sandprobe-<run id>` holding only the run id. It is created with `openat(O_CREAT|O_EXCL|O_NOFOLLOW|O_WRONLY)` on a
  directory pinned `O_PATH|O_DIRECTORY|O_NOFOLLOW`, which needs no read permission, and the probe records its device, inode and length. A marker is never
  removed by name: no check before an unlink can stop a same-user process swapping the name in between, and deleting
  someone else's file is no allowed effect. Markers are placed only on throwaway boxes and on volumes Sandprobe created
  for the run, and go when that box, and each such volume, is deleted by its immutable ID with the provider reporting
  the deletion done (PRV-1). Nothing else is ever marked. Never: a shell redirection or append as a write test; a marker in a directory something consumes
  (cron, systemd, profile.d, PATH, package or git config); opening a FIFO, socket or device; connecting to any local
  listener or unix socket the probe didn't create itself in this run, except an approved local proxy under (e); running any command through sudo; signals;
  ptrace. A run whose box or volume isn't confirmed deleted, or that crashes or loses its box mid-reset, lists every
  marker it may have
  left as an unresolved cleanup item: its path, and its device and inode when the probe confirmed them, else marked
  unconfirmed (the host plans each marker path before placing it). It never prints an unconditional removal command.
- **SBX-2 Never a secret's value.** Readability is proven on a pinned inode, so a path swapped mid-check can't make
  the probe open a FIFO or device: `openat(O_PATH|O_NOFOLLOW)`, which opens nothing for I/O; `fstat` on that
  descriptor must show a regular file; only then is that same inode reopened read-only through
  `/proc/self/fd/<n>` (`O_RDONLY|O_NONBLOCK|O_NOCTTY`, with `O_NOATIME` where the probe owns the file) and closed,
  reading nothing. An `EPERM` to an open carrying `O_NOATIME` can be the filesystem refusing the flag, as Docker
  Desktop's file sharing does, not the file refusing the agent: the open is asked once more without the flag, and only
  that answer counts, so a readable file is never recorded as refused (found 19 November 2026). Without `/proc`, the check is unknown. No byte, no hash, no length: the only thing
  derived from `fstat`'s size is, in memory, whether the file is empty, and no size is ever emitted. A path is resolved as the kernel resolves it, one
  component at a time on directory descriptors, never from its text: each name is opened `O_PATH|O_NOFOLLOW` in the
  real directory reached so far; a symlink is read with `readlinkat`, an absolute target resolved from `/`, a relative
  one from the real directory holding the link; `..` is opened by the kernel and must be the directory the walk came
  from, else the path is unknown. One budget of 8 links covers the whole path, a directory's links and the last name's
  alike, each recorded; past it the path is unknown. A path reaches the walk exactly as given, never cleaned
  lexically: a home, a PATH entry or the working directory is joined to a name with a plain `/`, since cleaning would
  collapse `link/..` to nothing where the kernel follows the link first and takes `..` from where it leads; only the
  walk takes `.`, `..` and repeated slashes. Every check of the path acts on the descriptors that walk holds,
  and only a final target whose descriptor `fstat` shows to be a regular file is opened. A chain that can't be resolved, loops, or
  ends anywhere but a regular file is unknown for that path, never absent or a pass. The environment gives names only. Metadata services give role or identity
  names from their listing paths, never a credential document. The probe's own environment holds values because the
  OS put them there; the probe never copies, measures, prints, writes or sends them.
- **SBX-3 Where the network goes.** Only to: the canary (SBX-11); the link-local metadata addresses SEC-4 names; vsock
  CID 2 on AMP-6's ports, on throwaway boxes only; EGR-6's hosts once approved, handshake only; the listener the
  probe itself binds on loopback for TWN-1 (SBX-1 (d)); the proxy the box's proxy variables name, for EGR-3 only,
  with one `CONNECT` to the canary (the plan authorizes it as a class; a local one only if the person opted in up
  front, `-allow-local-proxy` for agents, else EGR-3 is skipped); and `$KUBERNETES_SERVICE_HOST` for AMP-7, handshake
  only, never at a local address. Every fixed destination appears in the plan, every box-named one in the plan as a
  class and in the resolved plan as an exact endpoint before any contact (UX-4), and all of them in `contacted`. Every attempt to
  the canary carries the nonce the host issued for that one check (TLS SNI, DNS name, first payload bytes), so a receipt
  names exactly one check: direct and proxy attempts on 443 never share one. EGR-6 and AMP-6 can't carry one and never
  produce receipts, which is why they are find-only. Once the box exists, the host learns the agent's proxy from a
  survey run of the probe through the agent's path that reports the proxy variables as SBX-5 records them, the
  Kubernetes API the agent's environment names, and whether `/dev/vsock` exists. AMP-7's API, like EGR-3's proxy, is
  named in the manifest, and the probe contacts only that one, never at a local address. With no proxy,
  EGR-3 is skipped (GRD-3). One the agent names but Sandprobe can't parse leaves EGR-3 selected: the manifest says so,
  the probe contacts nothing, and EGR-3 ends unknown. The manifest names the planned proxy and whether a local one is
  approved. The probe
  contacts only that proxy, and one that resolves to a local address (loopback, unspecified, or the box's own) only
  with approval; each EGR-3 attempt names the canary as its destination and the proxy it went through as `via`.
  A provider's rules of engagement can narrow this list for its boxes, and the checks they exclude are skipped (PRV-5).
  No scans, and nothing beyond this list.
- **SBX-4 As the agent, by the agent's path.** The adapter starts the probe the way the platform starts the agent's
  commands (PRV), and records the exact launch command. The probe records who it ran as: uid, gid, groups, `CapEff`,
  `CapInh`, `CapPrm`, `CapBnd`, `CapAmb`, `NoNewPrivs`, `Seccomp`, the inode of each `/proc/self/ns/*`, its cgroup, its parent
  chain (process names), the launch mode (`exec`, `workload`, `self`, `other`), and its scan of the system binary
  directories for setuid-root files, with whether the scan completed. `NoNewPrivs` is reported as 0 or 1 when the
  kernel's `/proc/self/status` has it, and as absent when it doesn't, as on GKE's gVisor. A line that is there but
  isn't 0 or 1 stops the probe. Absent is read as unknown:
  AMP-3 is then unknown, never a pass or a finding, AMP-2 treats it as possibly 0, and a workload contract reads it as
  an unknown row, never a configuration finding. Any other value invalidates the run. Only a missing `CapEff` still stops the probe. A probe run on a path the agent
  doesn't use would under-report: a policy layer can score well while the agent's normal path runs unenforced.
- **SBX-5 A host-shipped probe.** The probe is `sandprobe-probe`, a static Go binary built without cgo (no dynamic
  loader, so `LD_PRELOAD` and `/etc/ld.so.preload` can't reach it), for linux/amd64 and linux/arm64. The host copies it
  in through the provider and runs it by absolute path through the agent's path. The probe reports the digest of its
  own `/proc/self/exe`, and a mismatch invalidates the run; that catches an accidental swap, not a lying substitute,
  so reports call the probe host-shipped, never attested (SBX-10). The probe executes no tool from the box except
  `sudo -n -l` for AMP-1. In wrapper mode (LNC-2) it starts only its own `/proc/self/exe`, the same file. It records the box's `curl` and `sudo` by `lstat` and `readlink` only (path, owner, mode, link target), never
  opening, reading or hashing them, since a PATH entry can point at a secret; it records the
  resolver configuration, `LD_PRELOAD` and `/etc/ld.so.preload`, any agent-writable PATH directory ahead of the
  system's, and the proxy variables sanitised: scheme, host, port, and whether credentials are present, never their
  values.
- **SBX-6 The probe's own client, for every route.** Every network attempt, direct or through the box's proxy, uses the
  probe's own Go client. A proxy URL's credentials are stripped and never used, so a proxy that needs them leaves
  EGR-3 unknown. A positive needs a canary receipt for this run. A negative needs TWN-1's network proof. Comparing the
  agent's own tools (its `curl`, its wrappers) is a separate diagnostic, out of scope for now; if added, it is opt-in,
  named in the plan, and never safety-critical.
- **SBX-7 Time limits.** 3 s per network attempt, 10 s per check, 90 s for the whole probe. A timed-out attempt is
  tried once more. Anything cut off is unknown. Adapters bound their own steps (create 5 min, reset 3 min, delete 3 min).
- **SBX-8 Observed, or unknown.** A two-sided check passes only on its negative proof (TWN); a find-only check never
  passes (KND-2). Any other error, unexpected output or cut-off attempt is unknown. Nothing defaults to pass.
- **SBX-9 One grader.** The probe emits observations, never a grade. The host grades them (GRD), so `run`, `self` and
  `report` grade alike, and the grader is tested apart from any box.
- **SBX-10 What the promise covers.** "No false passes" holds against faults, misconfiguration, wrappers and shims in
  the agent's environment, for the host-shipped probe run as the agent. It does not hold against a box that deceives
  the probe: one that substitutes or tampers with it before or during the run can report the expected digest and
  fabricate every observation, and the host can't tell. The only evidence from outside the box is the canary's
  receipts, which can prove a way out but never a refusal. Also outside the promise: interception in the kernel or
  hypervisor; escapes below the probe; resource exhaustion (AWS documents that one Nitro Sandbox can exhaust the
  parent's conntrack table and DNS resolver budget; we don't test it); and anything a box does only to other
  processes. In `self` and `other` modes the host didn't ship the probe at all. Every report states this boundary
  beside the grade, in these words: "Sandprobe's "no false passes" rule covers faults, misconfiguration, wrappers, and
  shims in the agent's environment when the host-shipped probe actually runs as the agent. It does not cover a box
  that substitutes for or tampers with the probe before or during the run: that box can report the expected digest,
  fabricate every in-box observation, and the host cannot tell. Only the canary's network receipts come from outside
  the box; they can prove a way out, never a refusal." OUT-2's page shows a report saved with exactly the earlier
  wording of the boundary, or of the not-tested list, in the current one; the report's embedded JSON keeps its own
  strings, and no other text is mapped.
- **SBX-11 The canary.** Ours, at `canary.<our domain>`: a TLS echo with a pinned key on 443, plain
  TCP listeners on 22, 80 and 8080, UDP 53, and the authoritative name server for `<nonce>.dns.<our domain>`. It
  records every attempt that carries a nonce: time, port, protocol, source address. It never needs to know the route:
  the nonce says which check sent it. Throughout the probe's network window the host connects to each canary port in
  use once a second, and the canary confirms each of those connects. A confirmation counts only when it proves the
  canary itself answered: on 443 a TLS handshake under the run's pinned key; on a plain port, the canary's signature,
  with that key, over the port and a fresh challenge from the host, checked against the public key the canary's
  status gave over the control channel, whose SHA-256 is the pin. An answer anything else could give, such as a bare
  health line, confirms nothing, so an impostor on the host's path can't stand in for an unreachable canary. The box's wall clock is never compared with the host's:
  the probe reports its run's length and each attempt's destination, start and end as offsets on its own monotonic
  clock, and the host records its own launch and return times, which bracket the probe physically. The health checks
  must cover that whole bracket. An attempt with no negative proof: one whose destination isn't the planned endpoint
  (which invalidates the run), one outside the probe's own run, any attempt in a run longer than the bracket (plus
  250 ms of slack), or any attempt on a port the health checks didn't cover. Before the
  probe runs, the host arms the run with the canary: the run ID, a lifetime, and each check nonce with the protocol
  and port that check uses (the document nonce isn't armed). The canary counts an attempt only when its nonce is armed
  and arrives on that nonce's protocol and port. For each armed nonce it keeps that count, the time and source of the
  first such attempt, and a separate count of the nonce arriving anywhere else. It drops everything else that looks
  like a nonce unrecorded, so nobody on the internet can fill its memory, and no attempt on another port can crowd out
  the one the grader matches. It holds at most 8 armed runs of at most 16 nonces each. It refuses an arm past either
  cap, or with a nonce that is malformed, `health`, or armed by another run, and a refused arm leaves the run not
  live. An armed run ends when the host disarms it after the query, or when its lifetime (at most 1 hour, by the
  canary's own clock) runs out; the canary frees an expired run within 30 s, even when idle. The canary serves at most 512 connections at once, and at most 64 from one source
  address; past either cap it closes the connection unread. It reports a run overloaded when, while the run was armed,
  a connection cap was hit or the kernel's counts of dropped connections (listen overflows and drops) or of dropped
  UDP datagrams rose: a flood can keep the box's attempt from ever reaching the canary while the host's health checks
  still get through. An overloaded run gives no network negative at all: every pass and every `not_found` it would
  have given is unknown, while a receipt is still a finding. After the window the host asks for the run's receipts. A
  network pass, or a find-only `not_found`, needs that query to have completed and to have been sent, by the host's
  clock, at least 2 s after the probe returned. The canary answers with the run's counts as they stand when it
  answers, so the canary's clock is never compared with the host's. With every field at its longest the answer is
  under 8,000 characters, well under the command channel's 24,000 (a test encodes that worst case), and the canary
  refuses to send one over 16,000. A failed or early query makes every such check unknown, while a receipt in hand is
  still a finding. A receipt shows that the check's nonce left the box and reached our canary on that protocol and
  port. It doesn't show that the box's own connection took the check's route: anything that saw the nonce leave (an
  egress proxy, a resolver, a logger) could have carried or replayed it. So a finding says the nonce reached our
  canary, and names the route the probe sent it on, never that the route connected. The report names the source
  address of the first matching attempt: for EGR-1 possibly the resolver that asked our name server, possibly
  whatever replayed the name. The canary answers from memory, over a control
  channel only the host reaches (never one on the box's network: for fixtures, a unix socket inside the canary's
  container; live, a unix socket on the canary's own instance, which the host reaches only through the cloud's command
  channel, never over the network; a reply cut short doesn't parse, and the query didn't complete), with its pin. A
  public canary also answers over HCN-1's path, which the box can reach: there each run is guarded by its secret and
  generation (HCN-2), and each answer counts only under the pinned control key's signature (HCN-1). The
  plan's pin comes from the canary's status answer, and the arm must answer with the same pin. The key is new on every
  start, so a reply under another pin comes from a restarted canary whose armed runs are gone, and the query didn't
  complete; nor did it when the canary no longer holds the run (expired, disarmed, or never armed). Its DNS answers
  are never larger than the query; reflection off spoofed sources stays possible, amplification doesn't. The operator canary is `canary.probe.ac0.dev`, the authoritative server for
  `dns.probe.ac0.dev`, on an EC2 instance that runs nothing else and accepts nothing but the canary's ports
  (`deploy/canary.sh`); fixtures run a local canary (Tests).

### KND: kinds of check and of evidence

- **KND-1 Two-sided checks** end `pass`, `finding`, `absent`, `scoped_out` or `unknown`. A pass needs the check's
  negative proof (TWN-1). `absent` needs a verified absence (TWN-2). `scoped_out` is allowed only where a discovery rule
  can show the check has nothing to apply to: SEC-2 and SEC-5 when no other process is visible (a PID namespace, or
  `hidepid`), and AMP-8's block devices when none is visible. It needs a reason and that rule's discovery count; a
  count above zero makes it unknown. It is listed, never counted as a pass.
- **KND-2 Find-only checks** end `finding`, `not_found` or `unknown` (AMP-1 also `absent`). They exist where no
  trustworthy negative proof does: a proxy's refusal of our canary, DNS and UDP that may leave later or elsewhere, an
  unreachable metadata address, a closed vsock port, a handshake-only host, a sudo policy the agent can't read, a
  marker that something other than the reset may have removed. `not_found` is never a pass, and every report lists
  these checks under "not proven". An indicator finding from a two-sided check (PER-1 to PER-4, AMP-4, AMP-5) still
  counts toward the grade at its severity.
- **KND-3 Evidence is a proof or an indicator.** A proof shows the capability: a file opened, a canary receipt, a
  privileged command run. An indicator shows exposure: a metadata service answering with a role attached, a handshake
  to an upload-capable host, a reachable Kubernetes API. Every finding says which.

### TWN: negative proofs

- **TWN-1 Every two-sided negative has a proof.** It runs through the same mechanism, in the same check, and the
  refusal must be the specific one expected. A sanity check that a client works (loopback) is a precondition, never
  the proof. A failed proof, or any other error, makes the check unknown.
- **TWN-2 Absence is verified.** `lstat` returns `ENOENT` for the exact path, from the probe, and its parent directory
  is searchable by the probe. Otherwise the check is unknown.
- **TWN-3 A reset is proven, not assumed.** It is what makes a surviving marker a PER-5 finding rather than a box that
  was never reset. The run goes: survey, plan and the main probe run on the original box; then the marks; then the
  reset; then a short recheck on the box after it. The survey takes a read-only inventory of the storage roots the
  agent can write (path, device and inode; nothing created), deduplicated by device and inode, and the host resolves
  the plan's marker rule against it (UX-4): a writable mount the adapter doesn't declare part of the box is listed and
  never marked. The main run corroborates
  the inventory. The mark touches only the approved paths, each only if its directory is still the one the survey
  saw; a root that is new or changed since is unknown, never marked.
  Recheck diagnostics distinguish inode mismatch, length mismatch and both, using fixed text without file
  contents or numeric identities. Every mismatch remains unknown and unread; diagnostics neither relax the
  identity guard nor establish that a provider filesystem caused the mismatch (TWN-3).
  Root identity comes from the provider, never the box: mount source, filesystem type, device and mount ID are
  observations only, since another filesystem can share them and mount IDs change on every boot. Two reset models:
  - **Restore in place** (same provider ID, such as Sprites): the host issues the restore of a named checkpoint and the
    provider reports that operation done; the box keeps its provider ID; the boot ID or restore ID changed; and the
    adapter establishes a stable filesystem identity for every root from the provider. A boot ID change alone is a
    reboot, not a restore. A root without a stable provider identity can't show that a marker is gone: its absence
    leaves that root unknown, so PER-5 can't be `not_found`. A marker found after a proven restore is a finding
    whatever its root's identity: the recheck finds the placed marker's state (its inode, at its placed length,
    holding exactly the run id), so run data written after the checkpoint was present at the planned path after the
    restore. That is the claim, and no more: which filesystem held it stays unproven, since an inode number can repeat
    on another filesystem and a clone could have carried the file. A root whose
    provider identity is there and changed contradicts a restore in place, and stays unknown.
    On Sprites (seen 9 Nov): before the probe, the adapter takes a checkpoint, and the provider's checkpoint list must
    gain exactly one new version, which is the checkpoint; none or more than one leaves the reset unproven. The reset
    restores exactly that version through the provider's API. The host gives each restore attempt an ID of its own,
    which is the operation's ID, since Sprites gives none. Done is that call's own response stream ending cleanly on
    the `complete` event for exactly that version, plus the provider's state after it: the same sprite ID, by PRV-1's
    name check, and a changed restore ID, which is the provider's `Current` checkpoint time. The boot ID doesn't
    change, since a restore restarts the sprite's container, not its VM. The declared roots are the sprite's own
    filesystems: `/` (the overlay over the sprite's user data), `/tmp` and `/var/lib/docker` (each its own ext4).
    Anything else the survey finds (tmpfs mounts, `/.sprite/*`) is listed and never marked. Sprites exposes no
    identity per filesystem, so these roots have none: on Sprites, PER-5 finds a surviving marker or stays unknown,
    never `not_found`, until the provider binds an immutable ID to each root.
  - **Recreate** (a new box from the same image, such as AWS, Modal, Baseten and the fixtures): the provider reports
    the new box created, with a new provider ID, which stands in for the boot ID (containers share their host's); only
    persistent volumes Sandprobe created for this run, attached the provider's default way, are roots, each bound to
    its immutable volume ID and its provider-declared mount path and subpath, all three the same before and after. A
    volume can outlive its box, so after the recheck the host deletes each one by ID and records the provider's
    confirmation. A volume Sandprobe didn't create, or can't delete with that confirmation, is never marked; with no
    such volume, PER-5 is skipped.
  The host acts on the mark's report only if it names exactly the planned markers, in order; the recheck's input is
  built from the plan, with only each mark's outcome taken from the report. The recheck pins each marker the way SBX-2 pins a file (`O_PATH|O_NOFOLLOW` under the root pinned
  `O_PATH|O_DIRECTORY|O_NOFOLLOW`, a regular file on its descriptor), and reads it only when its inode, and its length, are
  the placed marker's: then exactly the run id and nothing after. Any other file at that name is unknown, unread.
  Absence is `ENOENT` on the name under the opened root. Any gap makes the affected root unknown, and PER-5's
  `not_found` needs every planned root marked, rechecked and definitively without its marker after a proven reset.
  A root the agent can't write takes no marker and stays a gap, never a negative for that root: a root directory the
  agent can't write doesn't show it can't write elsewhere on that storage (a home or a working directory often lies
  on `/`, which it can't write). The survey lists only roots the agent can write, so a declared root it can't write is
  planned without the survey's identity and never marked; the mark then observes, read-only and creating nothing,
  whether the root's current permissions let the agent write and search it (`faccessat(AT_EACCESS, W_OK|X_OK)` on
  the root pinned with `O_PATH`, so a root it can't read is still diagnosed) and says so. The
  report names each gap's cause: the mark's or the recheck's own reason, each bounded since it comes from the box, and
  for a root whose provider identity can't show it is the same storage, whether the provider gave it no identity (as
  on Sprites) or a different one.

| Mechanism | Refusal that counts | Negative proof |
|-|-|-|
| file read (SEC-2, SEC-3, SEC-5) | `EACCES`, `EPERM` on `open` of a resolved regular target (SBX-2); and TWN-4 holds | the probe's own 0600 file opens through the same call; as non-root, its own 0000 file is refused |
| write permission (PER-1 to PER-4, AMP-4, AMP-8 kernel settings) | `faccessat(AT_EACCESS, W_OK)` gives `EACCES` or `EROFS` for the path and every ancestor directory up to `/`, through symlinks; an ancestor counts as safe only if not writable, or sticky with neither it nor the path owned by the agent; and TWN-4 holds | the same call allows the probe's scratch directory, and refuses its own 0500 directory as non-root, which shows the call answers; TWN-4 decides what a refusal means (the probe owns that directory, so its refusal alone is no negative) |
| read permission (AMP-8 block devices) | `faccessat2(AT_EMPTY_PATH\|AT_EACCESS, R_OK)` gives `EACCES` or `EPERM` on each pinned block-device node (EVD-12), never opened for I/O; and TWN-4 holds | the same call allows the probe's own scratch file, and refuses its own 0000 file as non-root |
| `/proc/<pid>/environ`, `/proc/<pid>/mem` | `EACCES`, `EPERM`; and TWN-4 holds | the same file of a child the probe starts opens |
| TCP or TLS out (EGR-2, EGR-5 TCP) | exactly one of `ENETUNREACH`, `EHOSTUNREACH`, `ECONNREFUSED` (each subject to the evidence rule beside it), or `ETIMEDOUT` on both tries; `EACCES`/`EPERM` are always unknown; any other error, or any failure after the TCP handshake, is unknown | all four: kernel evidence the attempt happened. For a non-blocking `connect` that returns `EINPROGRESS`, `TCP_INFO` must show `SYN_SENT`, or count the SYN in `tcpi_segs_out`, before the final error arrives through `SO_ERROR` (and SYN retransmits for a timeout). The counter survives the socket closing, so an exchange too fast to sample in `SYN_SENT` (a local network) still shows the SYN went out; a connect never issued sends nothing. An immediate error (no `EINPROGRESS`) counts only when kernel state independently implies it: `ENETUNREACH` or `EHOSTUNREACH` only when the kernel's own route lookup for the canary's address (netlink `RTM_GETROUTE`, after policy rules) returns no route, unreachable or prohibit. An immediate `ECONNREFUSED`, `EACCES` or `EPERM` never counts: an active filter elsewhere doesn't show it denied this call. A bound local port alone is not evidence; the same client call reached the loopback listener the probe bound itself in this run (SBX-1 (d)); confirmed canary health on that port covered the attempt's whole span (SBX-11); no receipt for this run on that port. The pass names destination, port and route. |

- **TWN-5 Host process-refusal consistency.** The host also checks the reported original-agent identity before
  accepting a refusal-based SEC-2 or SEC-5 pass. Effective or permitted `CAP_SETUID`, `CAP_SETGID`,
  `CAP_SYS_PTRACE`, `CAP_SYS_ADMIN` or `CAP_SYS_MODULE` makes that refusal inconclusive, as TWN-4 already
  requires of the probe. Missing or malformed permitted-capability evidence cannot establish this negative.
  Bounding capabilities alone are not held powers. This guard can only downgrade a claimed negative to unknown;
  it never makes an unknown, not-found or finding into a pass. Dropping capabilities is a configuration change,
  not a proof: the new run still needs full target coverage, eligible refusals and both applicable twins.
  Verified disappearance of every planned process target is not a refusal and keeps its existing proof rules.
- **TWN-4 A refusal holds only while the agent can't undo it.** A refusal from the table above counts toward a pass
  only if the agent couldn't get the access it was refused whatever the path's mode is now, and nothing is opened, read
  or changed to find out. Capabilities count permitted or effective (a permitted one can be raised at will), read with
  `capget(2)`, never from `/proc`; a failed read counts all of them.
  The kernel answers for the agent as it is (`faccessat`, the open), ACLs and security modules included; TWN-4 adds what
  a change could gain, by a model of the kernel's permission rules over every lookup the kernel makes, on SBX-2's
  walk. Each entry on the way is kept, in the real directory it is looked up in; a symlink entry is kept as well, then
  followed, a directory's as well as the last name's, within SBX-2's one budget of eight links, so every directory
  judged is a real one and every link is an entry the agent might replace. An entry is spared as a mount point, which
  can't be renamed or removed, only when `statx` says so (`STATX_ATTR_MOUNT_ROOT`, in a kernel whose attribute mask
  carries it); a change of device alone never spares one, since a Btrfs subvolume shows one too and stays an entry its
  directory can rename. One identity at a time, the model asks whether any identity the agent can
  assume (any uid with `CAP_SETUID`, any groups with `CAP_SETGID`, its capabilities raised) can search every directory
  a lookup happens in and get the access at the end, or, for a write, create or replace any entry on the way, a
  symlink's included, in its directory (a sticky directory sparing only an entry neither it nor the agent owns), after
  the modes it can change first. Replacing an entry is a write's gain only: it redirects the path, and reads nothing
  that was there. Past a directory the probe can't search it sees nothing, so a path the agent could reach beyond
  one is unknown, never a pass. So is a path whose modes alone would let the agent in though the kernel refused it
  (an ACL or a security module decides), and one with an ACL on the way while the agent holds a power to change
  identity or mode, or owns that inode; an ACL the probe can't rule out (reading its attribute fails other than as
  absent or unsupported) counts as one.
  Only groups owning a resolved inode affect this model; unrelated existing groups
  must not consume its identity-search budget. Group combinations are bounded to
  ten relevant groups. If more exist, a witnessed access still counts, but a search
  without a witness is unknown, never a negative proof from an unexplored identity.
  - **Write** (write permission): the agent can make a path, or a directory on it, writable by identity or by mode.
    Identity works with modes as they are, procfs and sysfs included: `CAP_SETUID` makes it any user, so a path its
    owner may write is writable to it (proc gives uid 0 a sysctl's owner bits), and `CAP_SETGID` any group, so a path a
    group may write is. Mode needs a mode that can change, so never in procfs or sysfs: owning the path, at any mode,
    `CAP_CHOWN`, `CAP_FOWNER`, `CAP_SETUID` again (the owner it becomes can change the mode), and `CAP_DAC_OVERRIDE`,
    which writes past the mode outright. A read-only mount stops all of these; `CAP_SYS_ADMIN`, which could remount
    it, falls under the everywhere rule below. A sticky directory protects only an entry neither it nor the agent
    owns, and never from `CAP_FOWNER`, `CAP_CHOWN` or `CAP_SETUID`. Such a path is found,
    saying how, where the check's findings are indicators (PER-1 to PER-4; AMP-4, as a socket the agent could give
    itself connect permission on); where they are proofs (AMP-8's kernel settings) it leaves the check unknown.
  - **Read** (file read, read permission): a refusal is no negative while the agent owns the file (where its mode can
    change), or owns a directory on the way that refuses it a search, or holds `CAP_DAC_READ_SEARCH`,
    `CAP_DAC_OVERRIDE`, `CAP_CHOWN`, `CAP_FOWNER`, `CAP_SETUID` or `CAP_SETGID`: the check is then unknown, naming them,
    since its findings are proofs and SBX-2 never reads a file to make one. Owning a directory the agent can already
    search gives it no read of another's file in it. Under these, an absence stays a fact (TWN-2).
  - **Process files** (`/proc/<pid>/environ`, `/proc/<pid>/mem`): access follows ptrace's rules, which no mode or
    ownership changes, so a refusal is no negative only while the agent holds `CAP_SYS_PTRACE`, or `CAP_SETUID` or
    `CAP_SETGID`, with which it could take another process's identity.
  - **Everywhere**, `CAP_SYS_ADMIN`, `CAP_SYS_MODULE` and `CAP_SYS_PTRACE` reach past file permissions and the mount
    table altogether, as AMP-2's Critical capabilities do: with any, no negative from these checks stands, before any
    of their early returns. A pass, an allowed absence (AMP-1's and AMP-4's included) and a `scoped_out` (SEC-2, SEC-5,
    AMP-8's block devices) are each unknown, naming it, since a mount can hide a path or stand in for one, and hidepid
    can be remounted. Capabilities AMP-2 grades High that this rule doesn't name, such as `CAP_MKNOD` and
    `CAP_SETFCAP`, are left to AMP-2.
  The twins still prove each call answers both ways; they don't make a refusal hold. An agent whose capabilities pass a
  read call itself (`CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE`) opens the probe's own 0000 file, so the refusing twin
  fails and no non-root pass can stand (GRD-5).

### Checks

Severity is that of a finding. Kind: 2 is two-sided, F is find-only. Evidence: P is proof, I is indicator.

**SEC: readable secrets**

| ID | Checks | How | Kind | Ev | Sev | From |
|-|-|-|-|-|-|-|
| SEC-1 | secret-shaped names in the agent's environment (`KEY`, `TOKEN`, `SECRET`, `PASS`, `CREDENTIAL`, `AUTH`, `PRIVATE`, `DSN`, `_PAT`, `DATABASE_URL`) | names only, so an indicator: a secret-shaped name doesn't prove a secret is there; `SANDPROBE_TWIN`, set by the adapter, shows through the same read | 2 | I | High | internal research; Northflank, 30 Oct |
| SEC-2 | other processes' environment, same UID and other UIDs | `open` of `/proc/<pid>/environ`; never Sandprobe's own idle process, when the host names it (DKR-2), nor Sandprobe's own wrapper, when the kernel shows it is the probe's direct parent running the probe's own file (LNC-3); `scoped_out` when no such process is visible | 2 | P | High | check-box ISO-1 |
| SEC-3 | credential files: `~/.aws/credentials`, `~/.config/gcloud/`, `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`, `~/.git-credentials`, `~/.config/gh/hosts.yml`, `~/.npmrc`, `~/.pypirc`, `~/.ssh/id_*`, `/etc/shadow`, the files AI coding tools document as their credential store on Linux (`~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.codex/.credentials.json`, `~/.gemini/oauth_creds.json`, `~/.aider/oauth-keys.env`, `~/.cline/data/secrets.json`, `~/.config/goose/secrets.yaml`; a file that holds credentials only sometimes, such as a tool's general config, isn't listed (a `.env` such as Gemini CLI's `~/.gemini/.env` isn't listed either, but the `.env` discovery below covers it like any other `.env`), and a tool's own relocation variable, such as `CLAUDE_CONFIG_DIR`, isn't followed), every file under `/run/secrets` (walked four levels down, through symlinked directories, so Kubernetes' and EKS's service account token directories are covered), `/var/run/secrets/kubernetes.io/serviceaccount/token` (a symlink chain in Kubernetes), `.env` in home and the working directory (depth 2, `/` included, procfs and sysfs skipped) | `lstat`; symlinks resolved per SBX-2; `open` read-only of a regular target only. Discovery (`~/.ssh`, `/run/secrets`, `.env`) asks what the agent can reach: a directory it can't search is skipped, since nothing in it is reachable; one it can search but not list makes SEC-3 unknown, except that at the last `.env` level its `.env` is checked by name; any other error is unknown. A proof needs the file to be non-empty (SBX-2's in-memory bit; no size is emitted); a readable empty file is an Info indicator | 2 | P | High | internal research; check-box BOX-3 |
| SEC-4 | metadata credentials: AWS IMDSv1 and v2 role listing; GCP service account listing; ECS (`169.254.170.2`) and EKS Pod Identity (`169.254.170.23`) by their variables and a TCP connect, no request; Azure isn't contacted, since it has no listing that names an identity without an identity call. Never a role's credential document, and never a metadata address that is local to the box. One deadline (SBX-7's 10 s) covers the whole check; each listing is asked on its own, so a service ignoring one request is still asked the others, and only nothing accepting a connection skips the rest. Time running out before every listing was asked is unknown, unless a role was already found. An answer is read whole or not at all (a body cut short by a stall, a close, a cap or its own length is an error); a request line or header holding a control character is never sent, and an IMDSv2 token that isn't token-shaped is never sent back, leaving SEC-4 unknown unless another listing names a role | a role or identity is listed or offered | F | I | High | AWS Nitro launch (isolated mode allows IMDS and Pod Identity); Hugging Face timeline, July |
| SEC-5 | other processes' memory: a same-UID process that isn't the probe's descendant, and another UID's | `open` of `/proc/<pid>/mem`, no read; never Sandprobe's own idle process, when the host names it (DKR-2), nor Sandprobe's own wrapper, under the same conditions (LNC-3); `ptrace_scope` recorded; `scoped_out` when none is visible | 2 | P | High | Daytona advisory, 13 Apr |

**EGR: ways out**

| ID | Checks | How | Kind | Ev | Sev | From |
|-|-|-|-|-|-|-|
| EGR-1 | A looked-up name reaches our name server | a lookup of `<nonce>.dns.<our domain>` through the box's resolver; a logged query is the finding, whatever the answer | F | P | Medium | internal research |
| EGR-2 | A nonce sent by HTTPS straight out reaches our canary | TLS to the canary's IP, SNI `<nonce>.canary.<our domain>`, key matches our pin, reply echoes the nonce | 2 | P | Medium | internal research |
| EGR-3 | HTTPS through the box's proxy variables | as EGR-2, through the proxy `HTTPS_PROXY` and friends name, by the probe's own client (SBX-6); a local proxy only with approval (SBX-3), else skipped | F | P | Medium | VerCellBreak, 12 Oct |
| EGR-4 | TLS interception | the key isn't our pin: interception recorded, and EGR-2 for that route is unknown, never a pass | F | I | Info | internal research |
| EGR-5 | other ports out | TCP 22, 80 and 8080 to the canary's IP, two-sided per port; UDP 53 to the canary's IP, find-only; the nonce in the first bytes | 2 per TCP port, F for UDP | P | Medium | check-box ISO-2 |
| EGR-6 | upload-capable hosts on an allowlist (needs approval, open question 2) | TLS handshake only, no request: `github.com`, `raw.githubusercontent.com`, `registry.npmjs.org`, `pypi.org`, `s3.amazonaws.com`, `storage.googleapis.com`, `api.anthropic.com`, `api.openai.com`, the provider's own API | F | I | Medium | VerCellBreak; Pluto on Claude Managed Agents |

**PER: persistence that survives a reset**

| ID | Checks | How | Kind | Ev | Sev | From |
|-|-|-|-|-|-|-|
| PER-1 | startup files a session may run: `~/.bashrc`, `~/.profile`, `~/.bash_profile`, `~/.zshrc`, `/etc/profile.d/`, `/etc/bash.bashrc`. Whether the agent's path sources them is recorded, not assumed | write or replace, per TWN-1's write-permission row; never opened for writing | 2 | I | Low | internal research |
| PER-2 | PATH directories ahead of the system's, and `/usr/local/bin` | as PER-1. PATH is split as `execvp` splits it in glibc and musl, on every colon, each entry as given (SBX-2): an empty entry, the whole of an empty PATH or one at either end or between two colons, is the working directory. An unset PATH has no one search: glibc's `execvp` searches `confstr(_CS_PATH)` (`/bin:/usr/bin`), musl's its own default, dash and bash their compiled defaults, and Debian's bash ends its default in `.`, the working directory; the probe can't tell which one the agent's launcher uses, so with PATH unset PER-2 is unknown, saying so, unless it finds a writable directory anyway | 2 | I | Low | internal research |
| PER-3 | boot and schedule: `/etc/systemd/system/`, `~/.config/systemd/user/`, `/etc/cron.d/`, the cron spool, `/etc/rc.local`, `/etc/init.d/` | as PER-1 | 2 | I | Low | internal research |
| PER-4 | supply chain and access: `~/.npmrc`, pip config, `~/.gitconfig`, git hook templates, `~/.ssh/authorized_keys` | as PER-1 | 2 | I | Low | internal research |
| PER-5 | storage that survives the provider's reset | throwaway boxes only, after the main run: a marker in each storage root the agent can write: home, the working directory, and each writable mount the adapter declares part of the box (deleted with it), never a persistent volume Sandprobe didn't create; as the plan's rule states them and the survey's read-only inventory resolves them, deduplicated, looked for after the reset (TWN-3). A surviving marker is the finding, proven by TWN-3; with every planned root marked and rechecked after a proven reset and no marker left, `not_found`, since something other than the reset may have removed it, and other data's persistence stays not proven. A root that refused its marker, changed, or couldn't be rechecked is unknown, and so is PER-5 unless a marker survived elsewhere; a refusal is never that root's negative, and the report names each gap's cause (TWN-3). Where the reset recreates the box, only persistent volumes Sandprobe created for the run and deletes after it, by ID with the provider's confirmation; with none, skipped. The host, not the probe, decides High: from the catalog's PER-1 to PER-4 targets that lie in a surviving root and the recheck's `write_perm` observations of them | F | P | High if a replaceable PER-1 to PER-4 path lies in a surviving root, else Medium | internal research |

**AMP: amplifiers**

| ID | Checks | How | Kind | Ev | Sev | From |
|-|-|-|-|-|-|-|
| AMP-1 | sudo without a password | `sudo -n -l` only, which lists policy and runs no command, from a root-owned setuid sudo at a fixed path: a regular file there, or the one a symlink chain from there ends at, which is how Debian's alternatives and sudo-rs install it (`/usr/bin/sudo` to `/etc/alternatives/sudo` to `/usr/lib/cargo/bin/sudo`). The path is followed on SBX-2's walk, one component at a time, every symlink on the way, a directory's as well as the last name's, counted against SBX-2's 8 hops and named in the chain the result reports; past 8 it is unknown. The chain is trusted by an allow-list, never by guessing what the agent can't do: every link on it is owned by root, and so is every directory on the real path to each link and to the file, none of them world-writable (sticky or not) or writable by the agent (`faccessat(AT_EACCESS, W_OK)` refuses); an owner can make its own directory writable at any time, so one the agent owns fails whatever its mode. The file is a regular, root-owned, setuid file the agent can't write, named `sudo` or `sudo.ws` (sudo-rs's file is `sudo`), so a chain can't be pointed at another setuid program. These checks bind only an agent that isn't root and holds no capability: one that is root, or holds any capability in its permitted, effective or inheritable set (read with `capget(2)`, never from `/proc`), could have replaced, exchanged or re-owned a link or directory and left it looking like root's (`CAP_FOWNER` passes a sticky bit and changes any mode, `CAP_CHOWN` re-owns, `CAP_SETUID` becomes the owner, `CAP_SYS_ADMIN` mounts over a path, and a permitted capability can be raised at will), so for it no sudo runs and AMP-1 is unknown, naming the capabilities. The file is pinned with `O_PATH` and `O_NOFOLLOW`, checked on that descriptor to be the inode the walk ended at and the one the kernel reaches from the fixed path, and run from that descriptor with `execveat(fd, "", argv, envp, AT_EMPTY_PATH)` in a child the probe forks itself, never through a path such as `/proc/self/fd/<n>`, which a mount over `/proc` could redirect; the descriptor stays close-on-exec, so a `#!` file can't run. The checked inode is the one that runs, and the result names the chain it ran. A sudo found only elsewhere on PATH, or failing a check, is recorded and never run, and AMP-1 is then unknown, its reason naming what failed for each fixed path; so is a run ended by a signal, since a child that died before its exec looks the same. Found: a listed `NOPASSWD` rule; Critical when it allows all commands, High for named commands. Only that classification leaves, with the number of rules: a rule's commands are never recorded, since an argument can be a secret (SBX-2). The listing is read as it arrives, and sudo's whole run is bounded by SBX-7's 10 s, after which it is killed with everything it started (its own process group) and AMP-1 is unknown. `absent` when no sudo exists at `/usr/bin/sudo`, `/bin/sudo`, `/usr/local/bin/sudo` or on PATH. Each PATH entry is taken as given, never cleaned (SBX-2), split as PER-2 says, an empty or relative one from the working directory as `execvp` searches it; with PATH unset and no sudo at a fixed path, AMP-1 is unknown, never absent, since where the agent's launcher then looks can't be told (PER-2); an entry is skipped as a fixed path's directory only when the kernel reaches that very directory (the same device and inode), never by its spelling. Otherwise `not_found`: a site's `listpw` setting can hide a `NOPASSWD` rule, and the agent can't read the policy to rule it out. sudo may log the listing, and sudo-rs sends a denied call to syslog; the arguments are fixed and hold nothing secret | F | P | Critical or High | check-sprite (exit 87); check-box BOX-2; internal research |
| AMP-2 | root or capabilities | `/proc/self/status`: uid 0, or a held capability among `SYS_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `DAC_OVERRIDE` or `DAC_READ_SEARCH`, is Critical; any other held capability is High. Held means effective, permitted (a process raises a permitted capability into its effective set at will, with `capset(2)`) or ambient (always permitted as well); the evidence names each one, effective or only permitted. An inheritable capability is held only once an `execve` of a file whose file capabilities name it makes it permitted, which `NoNewPrivs` 1 forbids; with `NoNewPrivs` 0, an inheritable capability the agent doesn't otherwise hold leaves AMP-2 unknown, naming it, since the probe doesn't look for such files. The bounding set only caps what an `execve` can grant, and isn't held: AMP-2 is what the agent holds now, and what an `execve` of a setuid-root file or a file with file capabilities could give it is AMP-3's. An identity without `CapPrm`, or without `CapInh` while `NoNewPrivs` is 0, leaves AMP-2 unknown unless the uid or `CapEff` already make it a finding | 2 | P | Critical | check-sprite (exit 82) |
| AMP-3 | new privileges | Whether an `execve` could give the agent a privilege it doesn't hold now: a setuid-root file, or a file whose file capabilities the kernel grants on exec (the file's permitted set ANDed with the bounding set, and its inheritable set ANDed with the agent's), wherever the file is. `NoNewPrivs` 1 forbids both, and is the only pass. With `NoNewPrivs` 0, setuid-root files in the system binary directories are a finding. Otherwise AMP-3 is unknown, saying why: the probe scans only those directories, and only for setuid-root files, so it can't rule out a setuid-root file elsewhere or a file with file capabilities anywhere; setting no-new-privileges settles it. A scan that didn't complete is unknown too | 2 | P | Medium | check-sprite (exit 83); check-box ISO-2 |
| AMP-4 | control sockets | `lstat` and `faccessat(W_OK)` on the socket file and its directories, never connected, a refusal counting only as TWN-4 says (a socket the agent can make writable is found, as one it could give itself connect permission on): `/.sprite/api.sock`, docker, containerd and podman sockets are High; the system bus is Medium. An indicator: the server may be gone (a stale socket) or reject the agent by peer UID, which no permission check, nor even a connect, can rule out. Abstract sockets from `/proc/net/unix` are listed | 2 | I | High | check-sprite (exits 84, 85); check-box ISO-2, ISO-4 |
| AMP-5 | local daemons | LISTEN entries and owner UIDs from `/proc/net/tcp` and `tcp6`, never connected; a known control port (2375, 2376, 10250) in the probe's network namespace is High. An indicator: an owner-match firewall rule can block what the table shows | 2 | I | High | check-box ISO-4; internal research |
| AMP-6 | vsock to the host | `/dev/vsock` and the local CID; on throwaway boxes, connect to CID 2 on a fixed port list (to be set from the AWS docs; unverified), sending nothing. The survey reports whether `/dev/vsock` exists (`lstat` only); without it AMP-6 is skipped, and until the port list is set a present device leaves it unknown | F | P | Medium | AWS Nitro launch ("not absolute isolation") |
| AMP-7 | the Kubernetes API | TCP and TLS handshake to the API `$KUBERNETES_SERVICE_HOST` names, no request; the survey reports it, the plan names it, and the probe contacts only that one, never at a local address | F | I | Medium | AWS Nitro launch (EKS) |
| AMP-8 | kernel and host surfaces, graded as two checks: kernel settings (`faccessat(W_OK)` on named `/proc/sys` entries, never written, a refusal counting only as TWN-4 says) and block devices (`lstat` and `faccessat(R_OK)`, never opened; none visible is `scoped_out`) | 2 | P | High | CDK-style checks, kept non-mutating |

### CHN: chains

- **CHN-1 A readable credential or process surface, with a proven way out.** Critical and confirmed: a proof of a
  readable surface (SEC-2 or SEC-5 found, or SEC-3 found on a non-empty file) and a canary receipt (EGR-1, EGR-2, EGR-3
  or EGR-5 found). The probe never reads a value, so it claims neither that a secret is present nor what the data is,
  only that the agent can open that surface and can send data out. High and potential, titled "a secret may be able to leave": either side rests on an indicator
  (SEC-1, SEC-4, an empty SEC-3 file, EGR-6, AMP-7). The finding names its parts, which stay listed.
- **CHN-2 A proven root-equivalent amplifier caps everything.** AMP-1 at Critical, or AMP-2 at Critical, is a Critical finding no
  other result offsets, and the report's notes say every refusal above held only for an unprivileged agent. Indicators (AMP-4, AMP-5) never trigger
  CHN-2 on their own; the report still shows them as serious exposed surfaces.
- **CHN-3 Credentials and the Kubernetes API.** A readable service account token (SEC-3) with AMP-7 found is High and
  potential.

### GRD: the grade

- **GRD-1 Letters.** F: any Critical. D: any High. C: any Medium. B: only Low. A: nothing above Info, and complete.
  The grader still computes the letter, but no generic output reports it: not OUT-1 (since `sandprobe/6`, AGT-6), the
  page or the terminal (SCR-3, UX-6), `profile` (ANL-2), `assess` (CAL-3) or `-min` (OUT-4). The headline is the
  score (SCR-2), beside the findings and their counts by severity. The letter is still reported in two places,
  until each drops it too: the managed-workload evaluations, as the workload assessment's `legacy_generic_grade` and in
  the legacy standard report kept beside it (WGR-4); and CAL-6's CI calibration summary, as `legacy_grade`.
- **GRD-2 Complete.** Every two-sided check in the manifest ended `pass`, `finding`, `absent` or `scoped_out`. Any
  unknown makes the run incomplete, and wherever its score is shown it says so with the count, such as
  `Incomplete: 3 checks unknown` (SCR-3, UX-6). GRD-1's letter, where it is still computed, is
  then the worse of its findings' letter and C, never A or B.
- **GRD-3 Skipped is not unknown.** A check not selected for this run (EGR-6 unapproved; EGR-3 when the agent's
  environment names no proxy, or names a local one nobody approved; AMP-6 with no vsock device, or on an existing box
  (PRV-1); any write-based check on an existing box; a check a provider's rules of engagement exclude, PRV-5; a check that would contact a
  provider-owned endpoint under PRV-15's default for an unidentified provider, or RCP-4's for a recipe) is `skipped`
  and listed. Only the checks these gates name can be skipped (EGR-3, EGR-6, PER-5 and AMP-6, and SEC-4 and AMP-7 for
  a provider whose rules exclude them or under PRV-15's or RCP-4's default), only by the host, and each with its
  reason; AMP-2 and AMP-3 never are. A provider-endpoint skip (SEC-4, EGR-3, AMP-6, AMP-7) also records its kind in
  the manifest's `SkipKinds` (SCR-2): `provider_terms` from a native adapter's PRV row (PRV-5) or from the PRV row of
  the provider a `run exec` declares (PRV-17), `opt_in` under PRV-15's or RCP-4's default. Skips change no finding, count or completeness.
- **GRD-4 The score says what it covers.** Beside every score: "Host-graded on N checks in this sandbox at <time>,
  using the in-box probe's self-reported observations; not a certification" (reports saved before 0.3.5 keep their own wording: "graded on N
  checks for this box at <time>, from a host-shipped probe's own observations; not a certification"), SBX-10's boundary, the not-proven list (KND-2), and the
  scoped-out and skipped lists.
- **GRD-5 The host trusts nothing from the box.** Before the run, the host fixes the manifest: the mode, the checks
  selected, each check's planned targets and discovery rules (from the catalog), the run nonce, one nonce and one
  planned endpoint per canary check, EGR-3's proxy and whether a local one is approved, the box's immutable provider
  ID, the probe's digest, each provider-endpoint skip's kind (GRD-3), and the provider-endpoint checks the person
  attested (PRV-15). A pass or an absence
  must cover every planned target and report every discovery rule with exactly the targets it found; a gap is unknown,
  and a target nobody planned invalidates the run. The probe reports its identity (SBX-4) once, and the host always
  grades AMP-2 and AMP-3 from it, whether or not the probe reports them: AMP-2 from uid and the capability sets its row names, AMP-3 from
  NoNewPrivs and the setuid scan (with NoNewPrivs 0, AMP-3 is unknown unless a completed scan lists setuid-root files). Any AMP-2 or AMP-3 observation that differs, whatever its result, or a proof's
  root flag that contradicts the identity, invalidates the run, as does a missing identity. So does an unsound
  manifest: a check neither selected nor skipped, both, selected twice, or skipped without a GRD-3 gate or a reason;
  a skip kind on a check that isn't skipped or isn't a provider endpoint, or a kind other than SCR-2's two; an
  attestation on a check that isn't a provider endpoint, is named twice, or still carries a skip kind;
  a selected canary check without its own nonce or a planned endpoint; or EGR-3 without a planned proxy (unless the
  manifest says the agent's can't be parsed, and then never with one) or with an unapproved loopback one. So does an attempt through any proxy but the planned one, through a loopback proxy
  nobody approved, or through a proxy on any route but EGR-3's. The probe's
  observations are keyed to it. A check the manifest expects and the observations lack is unknown. Any of these makes
  the run invalid, with no score and exit 5, and the report says why: a duplicate check ID, an ID not in the manifest,
  two outcomes for one check, a nonce, box ID or digest that doesn't match, malformed evidence, a field over its limit
  (2 KB per evidence field, 1 MB per document), or an unrecognised override field.

### OUT: what it writes

- **OUT-1 JSON.** `schema` (AGT-6): `sandprobe/6` in every report a run writes, but `sandprobe/7` in one that carries
  `run.recipe`. A report from before it declares the
  lowest earlier version whose fields it needs: `sandprobe/1`; `sandprobe/2`
  when the manifest carries SCR-2's `SkipKinds` or PRV-15's `Attested`; `sandprobe/3` for RUN-17's Nitro host-controller contract; `sandprobe/4` for EVD-10's explicit HTTP marker protocol; `sandprobe/5` when the manifest carries PRV-17's `declared_provider`; `probe {version, sha256, host_shipped}`; `run {id, nonce, started_at` (RFC 3339,
  UTC)`, duration_ms, mode, provider, box {provider_id, name, created_by_sandprobe}, recipe {own, sha256}}` (`recipe` only for a run through a
  person's own recipe, RCP-4); `manifest`; `identity` (SBX-4);
  `toolchain [{name, path, owner, mode, link_target}]` (lstat metadata of box tools, never a hash: only `probe.sha256` is a digest); `overrides []`; `checks [{id, category, kind, result, evidence_class,
  severity, scope {destination, port, route}, evidence, proof {mechanism, result}, clients, fix, duration_ms,
  attestation}]` (`attestation` only for a check PRV-15's `-provider-endpoints` selected);
  `findings [{id, severity, class, title, checks, fix}]`; `grade {complete, valid, unknown, counts}`;
  `limits {not_tested, not_proven, scoped_out, skipped}`; `contacted [{host, port, proto, check}]`; `receipts []`;
  `markers [{path, dev, inode, confirmed, cleanup}]` (cleanup: gone with its box or volume, the provider having confirmed the deletion, or an unresolved item); `reset {operation_id, before, after}`; `provider_calls []`. Names map onto
  OpenTelemetry: the grade becomes a `sandprobe.grade` metric, and each finding a log event under `security_rule.id`,
  `security_rule.name` and `security_rule.category`. The exporter itself is later.
  `grade` carries no letter (GRD-1); `sandprobe/1` to `sandprobe/5` had `grade.letter`. A gate reads `findings`,
  `grade.counts`, the score (`sandprobe scorecard -o json`), `sandprobe compare` or `-min` (OUT-4).
- **OUT-2 HTML.** One self-contained file that loads nothing from the network, holding everything the JSON does, passes
  included, with their proofs (re-rendered from an older report, that report as `sandprobe/6`, without its letter: SCR-3). Every string from the box is escaped as text, and the embedded JSON is encoded for a
  script data block. A Content-Security-Policy meta tag sets `default-src 'none'`, inline styles, and `script-src` to a
  random nonce the host makes for that report, so text a box injects can't run. Its layout is UX-11.
- **OUT-3 What talks to what.** Reports are written locally: no upload, no telemetry. The host contacts only the
  provider's own API (through its CLI or SDK) and our canary (liveness and receipts, carrying the run's nonces only). The
  box, through the probe, contacts exactly SBX-3's list, which includes metadata addresses, EGR-6's public hosts once
  approved, and vsock; the plan and `contacted` list each one.
- **OUT-4 Exit codes.** 0 graded; 2 usage error; 3 needs approval; 4 needs login; 5 incomplete or invalid; 6 a valid
  run whose green-category score is below `-min` (`-min <0..6>` requires at least that many green categories; `-min full`
  requires every applicable category green, `Score == Of`); 7 a box or volume Sandprobe created is neither confirmed
  deleted nor explicitly retained under PRV-7. `-min` is an absolute category-count gate only, not a severity or
  proof-coverage regression floor: a higher-severity finding inside an already-red category, or a proven `pass`
  degrading to find-only `not_found` (`Green · not proven`), can leave `Score` unchanged and still exit 0, and `-min full`
  accepts 5/5 when Cloud access is not applicable (`Of == 5`). On providers whose reviewed scope excludes Cloud access (`Of == 5`),
  `run exec` with PRV-17's `-provider` among them, `-min 6` can never pass and is refused before creation (for `run
  exec`, before anything runs in the box) with exit 2 pointing to `-min full`. Regression-sensitive CI
  must gate on `sandprobe compare` or validated OUT-1 JSON (`findings`, `grade.counts`, `checks`). Retired letter values
  (`-min A` to `-min F`) fail with exit 2. After a run, 7 takes precedence over 6, 6 over 5, and 5 over 0. A run that
  ends 5, 6 or 7 still writes its reports. `run modal` alone can also end 8, stopped with no report (PRV-18), and its
  run that ends 5 because it couldn't be cleared writes none.

### UX: the human experience

- **UX-1 Install.** One command (brew, a curl script, or `go install`) gets one binary, which carries the probe builds.
  Not yet: until release builds exist, `make` builds the probes and then the binary; a `go install` alone carries no
  probe, and `run` says so and stops before creating anything.
- **UX-2 Pick.** `sandprobe` with no arguments in a terminal asks where the agent runs (Sprites, AWS Nitro Sandboxes,
  Modal, Baseten, exe.dev, somewhere else) and what to probe: a new throwaway box with default settings, or a box the user
  already has.
- **UX-3 Access.** The CLI checks the provider's own CLI or SDK is present and logged in. If not, it prints the exact
  command (`sprite login`) and stops. It never asks for, reads or stores a credential.
- **UX-4 A plan, then one confirmation.** Before anything is created, the plan lists: what will be created; the launch
  path; where the probe binary and its scratch directory go; where markers go; every fixed host, port and metadata
  address the probe will contact (the canary, SEC-4's addresses, EGR-6's hosts once approved), and each class of
  destination only the box can name. SEC-4's are one list in the catalog (`catalog.Metadata`: 169.254.169.254:80,
  169.254.170.2:80 and 169.254.170.23:80, the last two with the variable that offers each), which the probe dials
  and every plan and report names, each with its port and condition, so the plan and the probe can't disagree. AMP-7
  and EGR-3 have no fixed destination: each is the one the box's environment names; the files it will open read-only; that it will run `sudo -n -l`, which runs no
  command and may be logged; what the reset does; what will be deleted; and whether a local proxy may be contacted if
  the box names one (the default is no, and EGR-3 is then skipped; `-allow-local-proxy` for agents). One confirmation,
  before anything is created; nothing later asks again. What only the new box can tell, the plan authorizes as a
  bounded class: markers are `.sandprobe-<run id>` in the agent's home, its working directory, each writable mount the
  adapter declares part of the box (deleted with it), and each volume Sandprobe creates; the proxy is the one the
  agent's environment names, for EGR-3 only; the Kubernetes API is the one its environment names, for AMP-7 only.
  Once the box exists, the survey supplies the actual values, and the resolved plan names each exact path and endpoint
  before anything is marked or contacted; the manifest pins them (GRD-5), and the report lists them. A value outside
  its approved class (a local proxy without the opt-in, a mount the adapter doesn't declare) is never contacted or
  marked: its check is skipped, or that root listed and left alone. For an existing box, the plan says: the probe binary and scratch
  directory, both removed; no markers, no reset, no deletion; and it asks the user to confirm the box isn't a
  production host by typing its name (PRV-2).
- **UX-5 The live run.** Because the probe returns all observations at the end of an invocation, live terminal output
  shows only real host phases derived from the adapter's plan (such as `network`, `canary`, `box`, `probe`, `reset`
  only when the run resets, and `delete`, `cleanup` or `retain`), never simulated per-check progress. Every runner
  feeds them from its own plan, the canary's steps included: `run docker`, `exec`, `aws-nitro`, a recipe, `sprites`,
  `e2b`, `vercel`, `daytona`, `cloudflare`, `boat`, `exe.dev` and `baseten`. A phase shows `✓` only when it itself
  finished, since AGENTS rule 1 holds for the live view too: a runner starts a later work phase only once the one
  before it finished, and marks its probe (and reset) finished only when the probe returned; the cleanup phase runs
  whatever happened before it, so reaching it finishes nothing, and a confirmed cleanup completes only that phase. A
  phase cut short reads `✗ did not finish`; an unconfirmed cleanup, or a `retain` that didn't retain, `✗ not
  confirmed`; a phase that never started, such as a `delete` when nothing was created, `– not run`. When stderr is a
  TTY (with `TERM` other than `dumb`, `CI` unset, `-o text`, and reduced motion off), the CLI updates a compact phase
  list in place with a header (`sandprobe`, provider) and an elapsed timer, marking each finished phase with its
  escaped detail. When stderr is not a TTY, or under `CI`, `TERM=dumb` or reduced motion, it prints append-only step
  lines with no cursor movement or spinner.
- **UX-6 The score.** At the end of a run, the terminal summary leads with the header (provider, sanitized box name,
  observed uid when known, duration) and the score (`SCORE x/y`, `x of y categories green`), with no letter grade and no
  ASCII box map (the spatial map lives in OUT-2's web report). Beside the score sit any `NotCounted` line (`x/5`), any
  incomplete status (`Incomplete: n check(s) unknown`), measurement coverage (`conclusive/total checks`, how many were
  graded, and `not a certification`, GRD-4), and the six category rows (`✗ RED`, `✓ GREEN`, `◌ GREEN · NOT PROVEN`,
  `– N/A`), whose reasons use only fixed catalog labels, never box strings (SCR-3). A green row's not-proven line says
  only "not proven" and the checks' catalog labels: a find-only check's `not_found` reason is the box's own text, which the
  grader doesn't authenticate, so it never becomes host prose. Below the categories, when a chain or finding fired, the
  summary shows the top finding's exact sentence, severity and evidence class (KND-3): `proof` only for a proven finding
  that isn't a potential chain, and `a sign we saw, not confirmed` for anything else, a class the report doesn't name
  included; then any canary receipt count and route summary from `d.Receipts`, and `Fix first`, whose last line
  is the fixed "Run sandprobe fix <report.json> for every fix, in order." (FIX-1); then `Cleanup` (`✓` when
  confirmed, or a loud `✗` warning when cleanup is unconfirmed, exit 7) and the HTML report path. An invalid run shows
  `SCORE none` and the escaped invalid reason, with no category rows or counts. Every string from the box, command line
  or saved report has all control characters, Unicode format characters (category `Cf`, including bidi
  overrides/isolates, ALM, zero-width characters and BOM) and line/paragraph separators escaped before printing.
- **UX-7 Post-run keys and finding walker.** When both stdin and stdout are foreground terminals (`-o text`, `TERM`
  other than `dumb`, and both `CI` and `SANDPROBE_NO_KEYS` unset), the summary offers single-key actions. Foreground
  fails closed: stdin's terminal must answer `TIOCGPGRP` with this process's own group; an error (such as a terminal
  that isn't this session's controlling one), a group of zero or less, or another group means no keys. The keys work in
  raw mode, restoring cooked terminal state on exit, `EOF`, idle timeout, `SIGTERM`, `SIGHUP`, `SIGINT`, `SIGQUIT` and
  `SIGTSTP` suspension: `o` resolves the written OUT-2 report to a verified regular absolute path before invoking `open`
  or `xdg-open` (so a leading `-` in `-out` can never be parsed as an option), `Enter` walks findings and unknowns one
  by one by severity (showing ID, title, severity, a finding's evidence class as UX-6 words it (an unknown check has
  none), escaped evidence and fix, with `j`/`k` or arrows to move, `c` to copy the fix via stdin to a fixed clipboard
  helper, `e` to explain the check from `catalog.Guide`, `b` or `Esc` back to the summary), `e` explains a check, and
  `q`, `Ctrl-C`, `Ctrl-D`, or `Esc` on the summary, quits with OUT-4's exit code. An untouched key bar exits
  automatically after 15 seconds (`SANDPROBE_KEY_IDLE_MS` overrides in 50–600000 ms) with OUT-4's exit code so
  pseudo-terminal wrappers with an open silent stdin cannot hang indefinitely.
- **UX-8 Three palettes, and the system's scheme.** The web report has three palettes over one layout. `light` is a
  calm off-white page (#f7f7f5) with white panels, and `graphite` a near-black page (#0a0a0a) with panels a step
  lighter. Both are the site's world, set as a compact architectural sheet: sharp hairline edges, quiet regular-weight Geist, Geist
  Mono only for what the tool reports, and red and green only for results. `mission` (amber on black, a light CRT
  feel, a failure in inverse video) is the alternative. Results sit on hairline ledger rows rather than tinted pill
  stickers (the top bar's JSON download action is the page's pill button): a failure is red text (`mission` draws it in
  inverse video); a pass is green; Info, No finding, Not run and N/A are neutral; an unknown carries a dashed underline,
  never green. Every other mark of an unknown is dashed too, as are the map's mark, a category row's line for a test
  that is not proven, and the `none found · unproven` label and dot of a green row with no conclusive check (SCR-2). That holds
  in every palette. The page shows no letter grade (SCR-3). `-theme` takes `auto`, `light`, `graphite` or `mission`.
  `auto`, the default, follows the viewer's system: every page carries all three palettes, and a
  `prefers-color-scheme` rule in it shows `graphite` where the system is dark and `light` anywhere else. The browser
  decides each time the page is viewed. Nothing about the viewer is known when the page is written, so the same file
  is right on either machine. `light`, `graphite` and `mission` show that palette whatever the system says.
  `dark` is another name for `graphite`, on `-theme` and as a remembered value; the page's attribute, its button's
  label and the value it stores stay `graphite`. Any
  other value renders `auto`, as an unknown value always rendered the default, and that includes `modern`, the cyan
  palette `graphite` replaced. The page's own button steps through `auto`, `light`, `graphite` and `mission`, and
  the page remembers that choice locally, `auto` included. A remembered choice wins over `-theme`. The page reads a
  remembered `modern` as `graphite`, the dark palette that viewer chose, and ignores any other value it doesn't
  know. UX-9 sets each palette's contrast and the type's sizes. The page loads no font (OUT-2): it names Geist
  and Geist Mono first, then Inter and JetBrains Mono, then system fonts. The TUI prototype keeps its own `modern` and
  `mission`.
- **UX-9 Accessibility.** Every category and check state shows as a symbol and a word, never color alone. On the web
  report, in every palette (UX-8), text meets WCAG AA contrast, 4.5:1, on every surface it is drawn on, a tinted
  pill and a hovered or selected entry included, and every mark that carries a result or marks a control (a
  pill's outline, a dot, a dashed unknown mark, a link's underline, the focus outline) meets 3:1. Panel hairlines are
  decoration and only have to stay visible (1.2:1); only a border, a stroke or an underline can be one, never text.
  The floors hold for every color the stylesheet's rules use outside `@keyframes`, not for a chosen list of them; a
  color that reaches a rule through a local custom property is measured there, as every token that property is set
  to. A keyframe may set only a color listed for its animation: the flash behind a row a link lands on sets the
  selection wash, and the row's text keeps 4.5:1 on it. On a screen, body text is 14px on a line height of 1.55 and
  no text is under 12px, however its size is written (a relative size is taken at the least its parent can be), the
  map's included at the smallest size it is drawn (it scrolls sideways before it shrinks further); `mission` keeps
  its own type, a 13px body and 10.5px capitals, with nothing else of its under 12px. Print keeps its own palette
  (UX-11) and fits the map to the page. The tests hold these floors from the page's stylesheet alone, and what they
  can't see is stated, not checked: a color set in the page's markup, or on a property the tests don't name (a
  filter, a background image), isn't measured; where an element sits, so which surfaces its color is drawn on, and
  what a relative size is relative to, are written in the tests' tables; and a color the stylesheet writes out
  instead of taking from a palette is listed there with its reason, not measured. `NO_COLOR`
  (when set and non-empty) and `TERM=dumb` suppress ANSI color, and non-UTF-8 locales (`LC_ALL`/`LC_CTYPE`/`LANG` set
  to `C` or `POSIX`) use ASCII symbols. A green row that isn't proven (SCR-2) has its own symbol and words in the
  terminal, never color alone: `◌ GREEN · NOT PROVEN`, or `o GREEN . NOT PROVEN` when the first of `LC_ALL`, `LC_CTYPE`
  and `LANG` that is set is `C` or `POSIX`; when its question would pass 80 columns, the question moves to the next
  line. Reduced motion (`SANDPROBE_REDUCED_MOTION=1`) shows static frames and disables in-place terminal spinners.
  Terminal output wraps cleanly within 80 display columns (accounting for wide East Asian and emoji code points). That
  holds for every terminal surface, the offline `sandprobe scorecard` included: its coverage sentence,
  row details, statement and saved-report note wrap at 80 columns, `NO_COLOR` and `TERM=dumb` drop its color, and
  under a `C` or `POSIX` locale its row symbols are ASCII (`x`, `+`, `-`, `o`). Nothing flashes more than three times
  a second.
- **UX-10 Time.** The probe itself takes at most 90 s. Create to delete takes about 2 minutes on Sprites and Modal
  (estimates, not yet measured). AWS takes longer, about 20 minutes (estimate), because its plan includes creating and
  deleting an EKS cluster; its adapter's step bounds are raised to match (cluster create 25 min, delete 20 min), and
  the plan says so.
- **UX-11 The web report is the final report.** Every run writes OUT-2's page next to its JSON, and the score screen
  offers `o` to open it in an interactive terminal. The page is laid out as SCR-3 says: it leads with the score and shows no letter grade. It
  holds one sentence saying what a hijacked agent can do, the containment map (each mark links to its evidence), every
  finding with its fix, the unknowns, the not-proven tests, every verified pass with its proof, and how the probe ran (identity, every
  host contacted, every marker and its fate, the reset's evidence). It carries every palette and follows the
  system's light or dark scheme (UX-8), honours reduced motion, fits a phone, and prints on white whatever the
  screen shows.

### AGT: the agent contract

- **AGT-1 No terminal, no animation.** Unless both stdin and stdout are foreground terminals (for prompts and UX-7's
  keys) or stderr is a terminal (for UX-5's live phases), and never with `-o json`, `-o ndjson`, `TERM=dumb` or `CI`
  set, the CLI never animates, enters raw mode, prompts or waits for input. A terminal whose foreground can't be
  confirmed as this process's group counts as not foreground (UX-7). `SANDPROBE_NO_KEYS=1` skips UX-7's post-run
  keys even on an interactive terminal, and an untouched post-run key bar auto-exits after 15 seconds with OUT-4's exit
  code so PTY wrappers that leave stdin open cannot block forever.
- **AGT-2 Commands.** Every one takes `-o json`.

| Command | Does | Creates anything |
|-|-|-|
| `sandprobe providers` | which providers are ready, with the login command for each that isn't | no |
| `sandprobe plan <provider>` | UX-4's plan: what would be created, run, contacted, marked and deleted | no |
| `sandprobe run <provider>` | the plan, then the probe, reset and delete | yes, needs `-y` |
| `sandprobe self` | probes the box it's in, as the current user; unattested (SBX-10) | its scratch directory only |
| `sandprobe report <file>` | grades and renders a results file from `other` mode; unattested | no |
| `sandprobe cleanup baseten -baseten-state <journal> [-y]` | verify and delete only a prior run's recorded Baseten incarnation (PRV-7); no canary | none without `-y`; otherwise verified deletion |
| `sandprobe explain <check>` | what a check does, why it matters, its proof, its fix | no |
| `sandprobe fix <report.json> [-platform <name>]` | a saved report's red checks as ranked actions, with a platform's proven snippet or general advice, and the rerun and compare steps (FIX-1 to FIX-8) | no |
| `sandprobe guide` | the agent guide; `-install claude` writes a Claude Code skill, `-install codex` an AGENTS.md block | the skill or block only |
| `sandprobe schema` | the JSON Schema for OUT-1 | no |
| `sandprobe feedback bug\|feature\|idea` | shows a public issue for summationai/sandprobe, then files exactly that one with the person's consent (FBK-1, FBK-5) | an issue, only with `-confirm <code>` or a typed yes |

- **AGT-3 Approval.** Outside a terminal, anything that creates, resets or deletes needs `-y`. Without it, `run`
  exits 3 and prints the plan as JSON with `needs_approval: true`. A local proxy for EGR-3 needs `-allow-local-proxy`, or EGR-3 is skipped. An existing box also needs `-attest <provider id>`,
  naming the box the person confirmed isn't production. The guide tells agents to show the plan to their person and
  get both before running again. The provider `run exec -provider` names (PRV-17) comes only from the person: an agent
  never infers it from the exec command, a hostname, the environment, a report or provider-like text, and never adds
  or changes it to turn a red category into not applicable. The guide, every block it installs and the CLI's own help
  say so, and no remediation text suggests the flag.
- **AGT-4 Streams.** `-o json` prints one OUT-1 document on stdout at the end. `-o ndjson` prints one event per line
  (`step`, `check`, `result`, `error`). Logs go to stderr.
- **AGT-5 Errors say what to do.** `{"error": "<code>", "message": "...", "fix": "<command or action>"}`, with codes
  from a fixed list: `usage`, `cli_missing`, `not_logged_in`, `needs_approval`, `needs_attestation`, `provider_error`,
  `timeout`, `invalid_run`.
- **AGT-6 A stable schema.** A breaking change to OUT-1 bumps `sandprobe/N`. A new field is breaking, since readers
  refuse unknown fields (JON-1). A report declares the lowest version whose fields it needs, so one that needs none of
  a newer version's fields keeps the older identifier, byte for byte, and older readers still read it. A reader takes
  every version it knows and refuses a report whose declared version isn't exactly the one its fields need: a
  `sandprobe/1` report carrying `SkipKinds` or attestations, or a `sandprobe/2` one with neither. A new field appears
  only in the form the writer gives it, which omits an empty one: a present `SkipKinds`, `Attested` or check
  `attestation` that is empty or null is refused in any version, since a JSON decoder reads it like an absent one, so
  a `sandprobe/1` report carries none of them in any form (JON-1). A reader older than a report refuses
  it as unsupported input; its fix names the versions it reads, and the report's own `schema` says which it is. Versions:
  `sandprobe/1`; `sandprobe/2` adds the manifest's `SkipKinds` (SCR-2), and its `Attested` with a check's
  `attestation` (PRV-15), both new in one release; `sandprobe/3` adds RUN-17's Nitro host-controller contract semantics. A schema3 contract requires at least that report version, with or without schema2 fields.
  `sandprobe/4` adds EVD-10's manifest `canary_tcp80_protocol`: present empty/null declarations are refused;
  legacy reports omit it. A nonempty declaration requires exactly version4, or `sandprobe/6`.
  `sandprobe/5` adds PRV-17's manifest `declared_provider`: a report carrying it declares exactly `sandprobe/5` or `sandprobe/6`, a
  `sandprobe/5` report without it is refused, and a present empty or null value is refused in any version. Only `run
  exec` writes it, and `run exec` writes neither RUN-17's contract nor EVD-10's protocol, so no report needs both.
  `sandprobe/6` removes `grade.letter` (GRD-1). Removing a field is breaking too, since a reader may depend on it, and
  every earlier version defines the letter, so a report without one can keep no earlier identifier: every report a
  run writes declares exactly `sandprobe/6`, whatever its manifest carries, unless it carries `run.recipe` (below). `sandprobe/6` takes any field of versions
  2 to 5, in the writer's form as above and under that field's own rules (SCR-2, PRV-15, RUN-17, EVD-10, PRV-17),
  which hold whatever the version: under `sandprobe/6` the version no longer says which of them a report carries.
  That includes RUN-17's contract and EVD-10's protocol: a reader accepts each under `sandprobe/6` by its own
  validators, and never refuses it for the version, though only the workload evaluations write them today.
  A `sandprobe/6` report with a `letter` key in any form, empty or null included, is refused. Reports that declare
  `sandprobe/1` to `sandprobe/5` still read, as before: each is exactly the lowest of those five its fields need and
  carries its letter as a string, so one whose `letter` is absent or null is refused. The letter is then ignored
  (ANL-1). A page re-rendered from one (SCR-3's `-out`) embeds it as `sandprobe/6`: no letter, the version changed and
  nothing else, since the same document without its letter under its old identifier is one this reader refuses. Every
  older report this reader takes, valid or invalid and whichever of versions 1 to 5 it declares, reads back that way.
  The one writer left for those versions is the managed-workload evaluations' legacy standard report
  (WGR-4, RUN-17, EVD-10), until that path drops the letter too.
  `sandprobe/7` adds `run.recipe` (RCP-4), and nothing else. 0.3.3, the first release to read `sandprobe/6`, shipped
  without the record and would refuse it as an unknown field, so the record needs its own version. A report
  carrying `run.recipe` declares exactly `sandprobe/7`, and every other report a run writes stays `sandprobe/6`,
  the lowest version its fields need, so a 0.3.3 reader keeps reading it. `sandprobe/7` takes everything
  `sandprobe/6` does, under the same rules, and has no letter either. The record under `sandprobe/1` to
  `sandprobe/6` is refused, and so is a `sandprobe/7` report without it, or with it present but null. A page
  re-rendered from a `sandprobe/7` report (SCR-3's `-out`) embeds it as `sandprobe/7`, unchanged.

### PRV: providers

- **PRV-1 Only our own throwaway boxes are reset or deleted,** addressed by the immutable ID their create call
  returned in this run (except PRV-7 recovery of an authenticated prior-run journal and PRV-13’s explicit exe.dev name-addressed lifecycle exception). Names and labels are recorded but are never the authority outside PRV-13. An existing box is never reset or
  deleted, and gets non-mutating checks only: no markers, no vsock connects (GRD-3 lists what that skips). The only
  things placed on it are the probe binary and its scratch directory, both removed at the end; a failed removal is
  reported with its cleanup command. Where a provider reaches a box only by name (Sprites: exec, checkpoint, restore
  and delete; Baseten: PRV-6 incarnation guards), the name must answer with the recorded ID immediately before each such call, or the call isn't made,
  and on each side of every read of the box's state by name (the checkpoint list), or the read doesn't count;
  a delete counts only on the provider's "not found" after, and a restore whose box answers with another ID after it
  ends the run's PER-5 there, with no recheck. The race between a check and its call is residual, and the run's
  record states it beside the cleanup outcome. A create that fails without returning an ID
  leaves its name recorded: if the provider then shows a box by that name, it is reported unresolved, never deleted.
- **PRV-2 Never production.** Throwaway boxes are created only in the org or account the operator names.
  sandprobe has no list of production hosts, so for an existing box the boundary is the person's attestation (UX-4,
  AGT-3), which the report records, and the report says that's what the boundary is.
- **PRV-3 Every provider call is recorded.** Create, copy, exec, reset and delete land in `provider_calls`, with the
  IDs they returned. A failed delete is shown loudly, with the command that finishes it.
- **PRV-4 Each adapter states its agent path and its reset,** and the report shows both (SBX-4, TWN-3).
- **PRV-5 A provider's rules of engagement narrow the checks.** Before any probe runs on a provider, its published
  security-research, bug bounty, penetration-testing and acceptable-use terms are read, and the PRV row cites what
  they say. Where they or the project owner exclude a destination or surface for that provider, the host skips
  the checks that would touch it (GRD-3), each with its reason and the kind `provider_terms` (SCR-2), and the report
  lists them. A surface that is only
  detected, such as a control socket's `lstat`, isn't excluded: detecting it is fine, using it isn't. Modal: SEC-4,
  AMP-6, AMP-7 and EGR-3, since each would send a request to an endpoint Modal owns.

- **PRV-6 Baseten lifecycle and bounded scope.** Authenticate at `https://api.baseten.co/v1/token` with a host-only
  personal API key or full-access team key, exchanging it for an access token scoped to the sandbox API across accessible teams (not one sandbox). Never send the API key
  to the guest, or put either credential in a report, journal, command, or error. Read the key from
  `SANDPROBE_BASETEN_KEY_FILE` (a regular owner-only file belonging to the current user), or `BASETEN_API_KEY`; an explicitly selected file that
  cannot be read never falls back to another credential. HTTP redirects are refused. HTTP errors expose only status
  codes, never provider bodies, headers, request payloads, or underlying transport errors.
  - Create once, with a fresh random `sandprobe-` name, unique `external_id`, no secrets, previews or volumes,
    the built-in `baseten/base-image:latest`, the default CPU/memory allocation, and `TTL_MAX_AGE DELETE 15m`.
    Persist the intended name, team and external ID in an exclusive mode-0600 state file in an owned, non-symlink directory with no group/world write access before the POST. Do not
    retry creation or adopt a sandbox found by name after a lost/malformed response. Such a run exits 7 and leaves
    the journal for manual reconciliation; automatic expiry is a backstop, not confirmed cleanup.
  - The API addresses sandboxes by name and permits reuse after termination. Bind each call to the create-returned
    name, execution URL, `created_at` and `external_id`, persist that tuple before upload, wait within the run deadline for `DEPLOYED` with the same tuple, and compare a fresh GET
    before upload, execution and delete. No call proceeds after detecting a replacement. This is a documented name/operation race,
    as for Sprites, not conditional deletion by immutable server ID. Record that residual beside cleanup.
  - Guest execution URLs must be HTTPS, without userinfo, port, query, fragment or non-root path, and match
    `sbx-<created-name>-<team>.<region>.b10.co` or `.b10.run`. Only the sandbox access token is sent there.
    Upload the shipped binary through the filesystem API; execute through `/process` as the image's default user,
    with `SANDPROBE_TWIN=1`, no automatic restart, a bounded timeout and an explicit completed/exit-zero response.
    Stdin is the host-generated manifest encoded in a fixed shell pipeline, never credential material.
  - Suspend/resume is not a reset. With no run-owned persistent volume, PER-5 is skipped with its recorded reason.
    Initial provider-control exclusions are SEC-4, EGR-3, AMP-6 and AMP-7; no metadata, proxy, vsock or Kubernetes
    API requests. Probe traffic goes only to our canary and DNS names we control. Every excluded check stays visible.
  - Delete only the recorded incarnation and confirm a subsequent 404 or `TERMINATED`. A replacement, an unknown
    status, failed identity check, timeout or failed deletion remains unconfirmed and exits 7. Persist state until
    confirmed deletion. Independent cleanup runs after cancellation; no success is inferred from DELETE acceptance.
  - Terms reviewed 11 Nov 2026: [Baseten terms, section 4.3](https://www.baseten.co/terms-and-conditions) restrict
    attempts to "gain unauthorized access" and use to "build a competing product or service". No affirmative research
    permission was found. A live run needs the operator's own authorization, with reasonable spend. Initial scope is the CPU-only, canary-only subset above: one sandbox at a time, at most two live runs for
    this implementation, 15-minute maximum age each; no unrelated workloads or provider-control probes. Normal
    authenticated inventory is separate. Docs: [management](https://docs.baseten.co/sandboxes/manage),
    [authentication](https://docs.baseten.co/sandboxes/authentication), and
    [runtime](https://docs.baseten.co/reference/sandbox-api/overview).

- **PRV-7 Explicit Baseten inspection retention.** An operator may keep the sandbox at the end of a run for
  inspection. `run baseten -keep-sandbox -y` requests this before creation; it is never enabled by an environment
  variable or by default. The plan names the spend and cleanup change. Baseten-only flags on other providers fail
  as usage errors. Ordinary runs keep PRV-6's 15-minute maximum age and verified deletion.
  - Inspection runs request `TTL_MAX_AGE DELETE 1h` at creation, with the same default CPU size and no secrets,
    volumes or previews. This is one hour from creation, not from run completion. The private journal records the
    retention request and absolute expiry derived from the create-returned timestamp before execution.
  - Only a valid, complete graded run with no error/cancellation may retain its original deployed incarnation.
    A finding of any severity or failing `-min` is not an execution error and may still be retained for inspection. A final identity
    check, the server's unchanged `TTL_MAX_AGE DELETE 1h` policy, and a present positive `expires_in` consistent with
    recorded creation time plus one hour (five seconds of clock/rounding tolerance) are required, then the journal is
    marked retained. Retention never updates or extends that deadline. Failure, incomplete/invalid runs, interruption, or failed retention verification use normal
    independent-context deletion; unresolved deletion still exits 7. Retention never overrides the stop-and-report
    rule or authorizes repeating a held probe surface.
  - Reports explicitly say intentionally retained, never deleted, and add optional `cleanup.retention` containing
    `expires_at`, `state_file`, and a structured `cleanup_command` argument list. This additive field needs no version of
    its own (a Baseten report declares `sandprobe/6`; before that, `sandprobe/2` for SCR-2's skip kinds). Normal grading exit codes apply after verified intentional retention; report-write failure after
    retention remains an error and prints the journal path/expiry to stderr. Never lose the operator's recovery path.
  - `cleanup baseten -baseten-state <journal> -y` needs no canary. It reads only a regular current-user-owned mode-0600
    journal without following symlinks, rejects unknown/malformed fields or an unconfirmed create, restores its recorded
    team (rejecting a conflicting explicit selector), and deletes only the recorded incarnation using PRV-6's checks.
    No approval means no provider calls. Expired/terminated resources still require verified terminal/404 before
    journal retirement. Replacement or failed deletion retains the journal and exits 7. This explicitly permits
    cleanup of a prior run's own recorded resource, never adoption of an existing unrelated sandbox.
  - Local fake-provider tests cover retention lifecycle/expiry, interrupted/invalid runs, expiry verification failure,
    state recovery, replacement, cleanup approval and truthful report output. No additional live probe is authorized
    by this feature.

- **PRV-8 E2B bounded baseline.** Use the E2B-managed default `base` CPU template and native management API at
  `https://api.e2b.app`, with the existing probe, canary and grader. Read `SANDPROBE_E2B_KEY_FILE` (a current-user-owned,
  regular owner-only file) or `E2B_API_KEY`; an explicitly selected unreadable file never falls back. Never send the
  management key into the sandbox, command arguments, journals, reports or errors. Refuse redirects; HTTP errors
  include only status. Use the official Python `e2b==2.63.0` SDK for file/command runtime transport, with a configurable
  host Python 3.11+ interpreter and a clean environment; feed only the sandbox-scoped access token via stdin. Check its exact version
  before creating anything. No implicit SDK installation. Pin every runtime dependency and its artifact hashes in
  `internal/host/e2b-requirements.lock`; install with `pip --require-hashes --only-binary=:all:`. Record the interpreter
  dependency in the plan and README.
  - Journal a unique run marker before one POST to `/v2/sandboxes`, requesting `templateID=base`, secure controller access (v2 default),
    `autoPause=false`, a 900-second timeout, `allow_internet_access=true` (the provider default), empty injected environment
    and no volumes or previews. The egress checks measure that default rather than asserting it must block traffic. Never retry create.
    Record the returned immutable sandbox ID immediately, even if other response fields are invalid. An ambiguous
    create retains an unresolved journal and exits 7; never discover or delete a box by its name or marker.
  - Check returned-ID metadata before runtime calls and deletion. Verify the server expiry is positive and within
    901 seconds of server runtime and at most 16 minutes from the create request (one minute provisioning tolerance).
    Runtime URLs use only E2B-managed `e2b.app` domains, with the recorded ID/port routing headers and scoped token.
    Run as the template's normal `user`, not root. Upload into a private random scratch directory and verify SHA-256
    before execution. Input is a private file removed by the command wrapper; output and time are bounded.
  - Normal runs always delete using a fresh cleanup context and confirm GET returns 404. Cancellation and failures
    do the same. Keep unresolved journals, never claim deletion on 401/403 or failed transport. No retention, pause,
    connect/resume, reset, custom templates, model calls or persistent storage in this initial adapter. PER-5 is skipped.
    SEC-4, EGR-3, AMP-6 and AMP-7 are excluded with reasons; EGR-6 remains unapproved. All test traffic goes only to
    our canary or names under its DNS domain. This is `exec` mode, not an agentic workload benchmark.
  - Terms reviewed 12 Nov 2026: [E2B terms](https://e2b.dev/terms), Prohibited Conduct 7 prohibits testing
    "the vulnerability of any part of the Services"; the adjacent clauses restrict interference and circumvention.
    [Security](https://e2b.dev/security) supplies no affirmative research authorization. A live run needs the operator's own recorded authorization for this
    bounded scope, never represented as provider permission. Offline builds and tests are always permitted.

- **PRV-9 Vercel bounded baseline.** Use the managed Vercel Sandbox API over the official SDK's exact fixed base `https://vercel.com/api`,
  as documented by the official `@vercel/sandbox` 3.9.1 source (12 Nov). Native Go HTTP implements this wire contract;
  no SDK runtime dependency. Do not substitute a different API origin or remove the `/api` prefix; local HTTP contract tests assert the literal origin/prefix for all lifecycle/runtime requests. Project creation remains on the documented public REST origin in its separate setup helper. Read `SANDPROBE_VERCEL_KEY_FILE` (regular, current-user-owned, owner-only, no symlink/FIFO)
  or `VERCEL_TOKEN`, and require explicit `VERCEL_TEAM_ID` and `VERCEL_PROJECT_ID`. A selected bad file never falls back.
  Confirm the project belongs to the selected team before creation. The API token never enters guest commands,
  environment, files, journals or reports. Refuse redirects and expose only fixed operation/status and allowlisted diagnostic category/field labels on provider errors; never raw response bodies, URLs, server messages/codes or credentials. Read at most64KiB for diagnostic classification; malformed/oversized bodies yield no hints. Diagnostic labels describe provider wording, not an established cause.
  - Validate every reusable sandbox name against the exact generated-name grammar before any named GET or DELETE; invalid names never reach the provider and cleanup preserves the unresolved journal.
  - Journal random requested name/run tag and selected team/project before one POST `/v3/sandboxes`: built-in
    `vercel/sandbox/universal` image, `persistent=false`, timeout900000ms, two CPU cores, empty env/ports/mounts,
    explicit allow-all baseline networking with no credential injection or proxy configuration. Native command calls
    target the immutable create-returned session ID, invoke the image's fixed absolute `/bin/bash -c` without a fallback or retry, use sudo=false and SANDPROBE_TWIN=1, a 95000ms command timeout,
    the template's ordinary user and immutable create-returned working directory. Accept only `/vercel` (current universal image) or `/vercel/sandbox` (legacy image); persist it before runtime and require it unchanged on each runtime identity check. Derive the private scratch path from that recorded directory and reject a response/upload path under the other directory. Never assume a directory exists or create an alternative base directory. No agent/model workload or privilege escalation is executed.
  - Persist the returned session ID before parsing optional fields; preserve unresolved journals and never retry
    create or adopt by name. All sandbox-name reads set resume=false. Check random name, createdAt, run tag,
    currentSessionId, non-persistence/no snapshot/no mounts and runtime lifetime before each operation. Require
    session timeout in (0,900000]ms, start/creation not more than60s in the future, and create-request to server
    start/creation within120s; now must precede server start plus its timeout. No timeout extension is allowed. Runtime
    requests use only the immutable returned session ID. Upload a gzip/tar containing only the named file into a
    private random directory; verify SHA256 before execution. Bound command stream wire bytes and combined
    stdout/stderr, require initial/final command identity and explicit zero exit status; never treat truncated streams
    or a missing terminal event as success. No command POST is retried.
  - Cleanup runs under a fresh three-minute context: stop only the immutable returned session ID, verify terminal
    status or definitive404, then delete the original non-persistent sandbox record only after identity checks and
    verify named GET404. No snapshots, drives, resume or timeout extension. Name deletion has a residual check/call
    race, recorded beside cleanup; the dedicated project and random names reduce competing writers but do not prove
    the race impossible. A replacement name is never adopted. Unconfirmed VM/record cleanup keeps the journal and
    exits7. A timeout stops compute but is not proof the named record was deleted.
  - As with E2B, exclude SEC-4, EGR-3, AMP-6 and AMP-7 with reasons; EGR-6 stays unapproved and PER-5 is skipped without
    resettable run-owned storage. All network test traffic goes only to our canary or DNS names under its domain.
  - Terms: Vercel's published testing
    policy permits Pro/Enterprise customers to test their own applications, and says they "must not target the
    underlying hosting infrastructure and platform". A run needs a Pro or Enterprise team (checked by read-only API inventory). Scope
    stays within our own disposable guest, with no provider-control requests, exploits, escapes, load or other tenants.
    Terms source: https://vercel.com/kb/guide/penetration-testing-on-vercel; security guidance:
    https://vercel.com/docs/sandbox/concepts/security. Record any unavailable guidance rather than inventing consent.
  - Vercel's AUP (https://vercel.com/legal/acceptable-use-policy, last updated 21 Apr 2026, reviewed 13 Nov) says "You
    may conduct benchmark tests of a service", with an AI Services exception. Public disclosure must provide enough
    information to reproduce tests. The policy also forbids security undermining and unauthorized access. A run is CPU
    guest compute with no AI/model calls. This AUP allowance does not override the penetration-testing platform
    exclusion or establish provider approval.
    Live-evidence builds must come from a recorded source commit with the actual binary digest retained.
    One CPU sandbox combines upload/survey checks and one benchmark; no separate live smoke, retry or continuous job.
    Attempts are a finite budget the operator sets, with no automatic retry.
    One dedicated empty project may be created for this test: validate the token file before the exclusive intent journal, journal intent before a single POST, never retry or
    adopt after ambiguous creation, and persist the create-returned project ID immediately. The empty project is
    intentionally retained as an explicit residual with its recorded ID; no project deletion or deployments are
    performed. Sandbox/session/drive/snapshot compute resources must still be confirmed gone. Existing projects
    are never modified by setup.

| Provider | Default box | Agent path | Reset, and what TWN-3 can prove | Deleted | Verified |
|-|-|-|-|-|-|
| Sprites (Fly) | `sprite create sandprobe-<12 hex>`, default settings, in the operator's Sprites org | `sprite exec`, as the sprite's default user. The CLI reads `-s` and `-o` from any argument, even after `--`, so the probe's command goes as one `sh -c` string | a checkpoint before the probe (exactly one new version), a restore of exactly that version after, done by its own stream's `complete` event; same sprite ID, the provider's `Current` checkpoint time changes; roots `/`, `/tmp` and `/var/lib/docker`, with no provider identity each, so PER-5 finds or stays unknown, never `not_found` (TWN-3) | `sprite destroy` by name: Sprites has no delete by ID (`DELETE /v1/sprites/{name}`; a GET by ID is a 404, checked 9 Nov). The name must answer with the recorded ID just before, and a 404 after (PRV-1); the race between is residual, and the report states it | lifecycle verified live: create, exec, upload and destroy; the default user is `sprite`. Terms read 20 Nov (PRV-5): Fly's [AUP](https://fly.io/legal/acceptable-use-policy/) lists "Security testing (network or application scanning, phishing, or penetration testing)" among prohibited uses. Sandprobe isn't security testing of Fly; it checks that a customer can safely do the plumbing to use their own sprite as an agent sandbox, from inside that sprite. So SEC-4, EGR-3, AMP-6 and AMP-7, which would contact a Fly-owned endpoint, are excluded: no check traffic from the sprite reaches Fly; the host itself still uses Fly's API to create, checkpoint, restore and delete the sprite |
| AWS Nitro Sandboxes | an EKS Auto Mode cluster only Sandprobe uses (Kubernetes 1.37, the operator's AWS profile (`PROFILE`), made and deleted by `deploy/eks.sh`, which needs no add-ons: Auto Mode brings the runtime classes and sandbox-capable nodes). Pod A is the docs' own example: `public.ecr.aws/amazonlinux/amazonlinux:2023`, `runtimeClassName: isolated-sandbox`, its image's default user. Pod B adds `sandbox.amazonaws.com/network-isolated: "true"`, which boots the sandbox with no network device (the EKS user guide, read 23 Nov 2026, says the guest's vsock channel "can still reach guest-bound ports" (its sandboxing page) and that the vsock device "is accessible to all processes inside the guest, including container workloads" (its network isolation page); on 23 Nov 2026 pod B's container had no `/dev/vsock`, so AMP-6, which looks only for that file, was skipped with "no vsock device" and didn't test that channel) | `kubectl exec -i` into the pod's container, as its default user, with a kubeconfig of Sandprobe's own (never the user's): isolated mode permits `exec` and stdin. Confidential mode denies both, so it waits for a workload adapter | none in v1: the default pod has no persistent volume, so PER-5 is skipped (a recreate around an EBS volume Sandprobe creates can follow) | each pod by name once its UID is checked, in Sandprobe's own cluster; then the cluster, its IAM roles and whatever else `deploy/eks.sh` recorded, each by its recorded ID and confirmed not found | docs read 10 Nov 2026 (EKS user guide, Nitro Sandboxes); lifecycle verified live for pods A and B, each deleted and the cluster torn down. Terms read 23 Nov 2026 (PRV-5): AWS's [penetration testing policy](https://aws.amazon.com/security/penetration-testing/) says "AWS customers are welcome to carry out security assessments or penetration tests of their AWS infrastructure without prior approval for the services listed in the next section under “Permitted Services.”" Amazon EKS isn't on that list; its EC2 and ECS lines read "Amazon EC2 instances, WAF, NAT Gateways, and Elastic Load Balancers" and "Amazon Elastic Container Service". "Customers seeking to test non approved services will need to work directly with AWS Support or your account representative." "Customers are not permitted to conduct any security assessments of AWS infrastructure or the AWS services themselves." The policy's "security assessment" includes activity "performed remotely against your AWS assets, amongst/between your AWS assets, or locally within the virtualized assets themselves". AWS's [Acceptable Use Policy](https://aws.amazon.com/aup/) (last updated 1 Jul 2021) forbids using the services "to violate the security, integrity, or availability of any user, network, computer or communications system, software application, or network or computing device". A run creates one pod in the operator's own cluster and probes it from inside: SEC-4 asks the metadata addresses the plan lists, the operator's own node's instance metadata service among them, which role or identity the pod can reach, never a role's credential document; AMP-7 makes only a TCP and TLS handshake, with no request, with the cluster's own Kubernetes API; AMP-6 connects to nothing; the other checks' test traffic goes to the canary, its names looked up through the pod's own resolver, and EGR-3's through a proxy only when the pod's environment names one. No check is excluded. A run doesn't carry AWS's permission, and Sandprobe claims no AWS approval: each operator reads the policy and decides, including whether to work with AWS Support or an account representative first |
| Modal | a sandbox in the operator's own Modal workspace, App `sandprobe`, through `github.com/modal-labs/modal-client/go` v0.11.1 (the older `libmodal/modal-go` is deprecated and has no sidecars). Image `python:3.12-slim-bookworm`, close to Modal's own `debian_slim` default, built once in that App; runtime and size left to Modal's defaults; a 15-minute timeout as a spend backstop; tagged `sandprobe-run=<run id>`. `sandprobe run modal` (PRV-18) makes this sandbox, POC-2's `default`; `sandprobe poc modal run -variant <setup>` (POC-1) makes that one or another of POC-2's setups: `domain-empty`, `domain-one`, `block`, `block-vm`, `sidecar` | `Sandbox.Exec` with stdin, as the image's default user (root) | none: PER-5 is skipped. A terminate and recreate would test only a Volume, and the probe's sandbox mounts none | terminate by ID; confirmed when the sandbox polls finished and a list by its tag shows nothing running. The App and the built images stay, named as residual | docs and SDK read 10 Nov; lifecycle verified live for all six setups: each sandbox created, probed, terminated and confirmed gone by ID and tag. Terms, [modal.com/legal/terms](https://modal.com/legal/terms) and the [security page](https://modal.com/docs/guide/security), read 25 Nov 2026: nothing found on customers testing their own sandboxes, on benchmarks or on penetration tests by customers. Customers agree not to "reverse engineer, decompile, disassemble, or otherwise attempt to discover the underlying structure, ideas, or algorithms of the Service or any software used to provide or make the Service available"; a run reads what its own sandbox exposes to its own agent, and the four checks that would contact a Modal-owned endpoint are excluded (PRV-5). The security page says "When performing security research, you must use a Modal Workspace whose name ends in `-H1-<username>`", under its bug bounty; a run is a check of the operator's own configuration, not bounty research, and claims no permission from Modal. Its shared responsibility table asks customers to run untrusted code "with guardrails such as egress restrictions, resource limits, and timeouts" |
| Vercel Sandbox | built-in universal image, two CPU cores, persistent=false, timeout900000ms; no env/ports/mounts (PRV-9) | native HTTPS command stream, ordinary image user, immutable create-returned session ID, sudo=false | no reset; PER-5 skipped | stop session by ID and verify terminal, identity-guarded named record deletion and GET404; retained empty project recorded | lifecycle verified live: private upload and digest, survey, checks and cleanup; the empty project is retained as a recorded residual |
| E2B Sandbox | default base CPU template; no injected secrets or persistent storage; 900-second runtime timeout (PRV-8) | official pinned Python SDK file/command transport, explicit user; native management by returned ID | no reset or PER-5; no pause/resume | delete only create-returned immutable ID after matching run marker, then verify GET 404 | lifecycle verified live: boxes and canary cleanup verified |
| Cloudflare native Sandbox | built-in Debian image; lite instance, durable_object scheduling; image default root; Internet explicitly enabled, no app credentials (PRV-10) | authenticated dedicated Worker; native exec/stdin, inherited PATH plus twin marker; uploaded digest checked | no reset or persistent storage; PER-5 skipped | container fenced/stopped; recorded Worker/application/namespace IDs removed and independently verified | lifecycle verified live; all resources and receiver DNS removed. Declared native configuration, not a universal SDK/default or escape claim |
| Baseten Sandbox | built-in base image, CPU/default memory, no volumes or injected secrets; random name and 15-minute delete expiry (PRV-6) | filesystem upload and `/process` through its returned URL, as the image default user | no reset: suspend/resume preserves state; PER-5 skipped without a run-owned volume | by create-returned name with incarnation checks, then terminal state/404; name-operation race recorded | API inventory and lifecycle verified live (create, upload, digest, survey, delete), with deletion confirmed |
| exe.dev | one standalone 2-vCPU Ubuntu 24.04 VM, egress=all, no supplied integrations/credentials (PRV-13) | native HTTPS /exec and bounded asynchronous probe wrapper as image user | none; PER-5 skipped | original create-returned name with pinned birth/region/run tags; explicit name-addressed exception and residual race | adapter under implementation; scoped read-only access verified 17 Nov; no live baseline yet |
| self | the current box | the current user | none; unattested | nothing | |
| other | none; prints the one-liner that downloads the probe and runs it as the agent | the user's | none; unattested | nothing | |

## Cloudflare Sandboxes (PRV-10)

- Scope: an account-scoped token for an explicitly named account; only newly created Sandprobe resources, never existing Workers/apps. No provider approval is claimed. A live run is one lifecycle smoke and one graded CPU baseline, stopping on failure or a suspected provider flaw; no automatic retry. No paid-plan purchase or account-wide subdomain mutation.
- Terms reviewed 13 Nov: [Self-Serve Agreement](https://www.cloudflare.com/terms/) section 2.2.2: “You are permitted to perform benchmark tests of our Services.” Disclosure must enable reproduction. Section 2.7 prohibits abusive/malicious use. [Testing policy](https://developers.cloudflare.com/fundamentals/reference/scans-penetration/) limits testing to customer assets, forbids exploiting findings, and excludes provider destinations except its bounty scope. This run is guest permission observations and canary markers only, no network scans/exploits/host/provider-control requests; no zone penetration test. SEC-4, EGR-3, EGR-6, AMP-6, AMP-7 and PER-5 remain skipped. No secret values read.
- Deploy a fresh randomly named authenticated controller Worker with one Durable Object/container class. Use documented native Durable Object Container API and built-in `cloudflare/debian-trixie` image, `durable_object` scheduling, smallest `lite` instance, default image identity, Internet enabled for scoped canary probes. This is a declared test configuration, not a claim about every Cloudflare sandbox setup. No R2/KV/volumes/snapshots/custom DNS/images or service credentials in guest.
- Deployment script validates owner-only token and explicit account, writes mode-0600 exclusive intent before the first mutation, refuses existing name, uses pinned Wrangler only for offline bundling, then makes single native API mutations without printing provider output/credentials, records provider-created deployment/version ID, namespace IDs and container application IDs; the script name is reusable, so guarded deletion retains a check/delete race. Failed writes are never retried automatically. Cleanup refuses mismatching script identity and deletes only recorded resources; unresolved intent remains manual reconciliation, not adoption. Never delete unknown resources or broad account inventories.
- Worker exposes POST-only create/status/exec/upload/destroy routes after verifying a separate random bearer capability against its SHA-256 stored in Worker vars. Management token never enters Worker/guest or command lines. Requests are bound to one random run nonce and immutable DO ID; nonce and bearer travel over TLS. No unauthenticated exec or previews. Limits: 16MiB body, 8MiB stdout, fixed error codes only, no provider error bodies or guest stderr in diagnostics.
- Durable Object records create intent and absolute expiry before start, rejects repeated create, does not auto-start stopped boxes. Hard lifetime 15 minutes: persisted alarm destroys container and fences future use; two-minute inactivity limit is additional. Container boot ID is pinned before guest operations; changed/unavailable identity stops the run. VM/container lifecycle identity and self-observed boot ID remain distinct, explicitly recorded residuals.
- Guest exec uses direct argument arrays and stdin streams, no injected provider credential. Probe upload writes only a mktemp-created mode-0700 `/tmp/.sandprobe-...` directory, checks SHA-256 before execution. Both upload and execution require exact boot identity. Direct stdin carries probe requests; upload is constrained to the private directory. Command timeout destroys/fences the whole container instead of leaving descendants. No pause/resume/reset; PER-5 skipped.
- Every CLI run writes private intent before create; create response DO ID/boot ID pinned and journaled. Cleanup has independent context, sends destroy without starting the box, checks stopped/fenced state and retains journal on ambiguity. Controller cleanup additionally removes Worker/application/namespace resources via recorded IDs; backstop expiry is not cleanup proof. Read-only account preflight and offline plan never create resources.
- Preflight must find an existing workers.dev subdomain and usable Containers access; missing setup stops before mutations. Never purchase a plan or register/change account-wide subdomains. Native exec inherits only PATH, not the full image/start environment; reports describe this exec-mode configuration. Startup requires bounded readiness verification without repeating start/create. Controller origin is pinned HTTPS workers.dev and all redirects are refused.
- Tests: controller auth/body/identity/expiry/no-recreate/timeout and cleanup regressions, Go transport/upload/identity and approval-gate tests; deployment helper intent/identity/error-sanitization unit tests. Independent code and security reviews before live mutations. Credential scan before storing evidence.

## Sprites setup and the agent's launch path, 20 November 2026

So a person can grade their own sprite configuration, not only a default one,
and can see a fix land.

- **SPR-1 Setup.** `sandprobe run sprites -setup <file> -y` runs the person's setup script once in the new sprite, as
  the sprite's default user, through `sh -s` on its standard input, after the probe's upload and before the checkpoint,
  so the reset (TWN-3) restores the configured box. Nothing the script prints is kept or shown: a nonzero exit stops
  the run with its exit code only, and the sprite is destroyed as on any failure. The script is read before the plan
  is shown: opened without blocking, then checked on the descriptor it opened (a regular file, never a pipe or
  device, never empty) and read through a 256 KiB bound, and its SHA-256 names
  it in the plan, beside how it runs and the launcher it may leave, and in the report's box name. It runs the person's own code on a sprite Sandprobe created for the run, so it
  needs nothing beyond the run's own approval (AGT-3).
- **SPR-2 The agent's launch path.** When the setup leaves an executable `/usr/local/bin/agent-exec`, every probe call
  (survey, probe and recheck) runs through it, as `agent-exec <probe> <flags>`, the way the person's agent's commands
  run; the plan and the report say so. Only a launcher the setup made counts: one already in the new sprite before
  the setup runs stops the run there, with nothing routed through it, and a check whose call failed counts for nothing.
  Each of the setup's calls (the check, the script, the launcher check) addresses the sprite by name, so each is
  preceded by its own PRV-1 check that the name still answers with the create-returned ID. Without it, the probe runs as the sprite's
  default user, as before. The probe
  is uploaded under `/var/tmp`, so a launcher that gives the agent a private `/tmp` still finds it. Tests:
  `internal/host/sprites_test.go` (setup on standard input, the launcher found and used, the upload outside `/tmp`);
  `TestSpriteSetupRefusesAPreexistingLauncher`, `TestSpriteSetupFailureCases` (a name that changes hands before the script or the launcher check, a failed pre-check); `cmd/sandprobe/sprites_test.go` (`TestSpritesPlanNamesTheSetup`, `TestReadSetupBounds`: a file over the bound, empty,
  a FIFO, a directory or missing is refused).

## Local Docker (PRV-14)

So a demo or a CI job runs as plain `sandprobe` commands against a container on the operator's own machine. No
provider is involved, so no provider terms apply.

- **PRV-14 Local Docker.** `sandprobe run docker <image> [-as <user>] -y [-- <docker run options>]` grades a
  throwaway container. Its canary is always the local one below: `-canary`, `-canary-url` and `-canary-pin` given as
  flags are refused before anything runs, and their environment values are never read (HCN-5); to probe a container
  against another canary, `run exec` through `docker exec` takes them. Before anything is created, Docker must answer and the image must exist locally (nothing is
  pulled). The run creates, and deletes by the ID Docker returned: a bridge network on a free 172.30.N.0/24, a canary
  container on it (the canary binary carried inside sandprobe, in the debian image pinned by digest in
  test/probe.sh), and the container under test, started from the image with supported options passed through
  unchanged, and Sandprobe's own idle process as its entrypoint unless the options name one (DKR-1). Reject `--rm`/enabled `--rm=...` before creation: automatic deletion can
  bypass ownership checks on inherited anonymous volumes; Sandprobe manages teardown.
  Explicit `--rm=false` remains allowed. The probe is bind-mounted read-only at /opt/sandprobe/sandprobe-probe and runs through `docker exec -u`
  as `-as`, else the created container's own user (read from the container, so a `--user` option that overrides the
  image's is the user graded, either way round), else root. Sandprobe adds its network and points the box's resolver at the
  canary only when the options name no network; otherwise the box keeps the network it was given. The box declares
  TWN-3's recreate model, as in the fixtures, with no volume, so PER-5 is skipped and the container is never reset
  (DKR-5). A container that stops before or while the probe runs stops the run, with nothing graded, and says why
  (DKR-3). Every Docker call runs under the
  run's deadline (five minutes) and Ctrl-C, so a hung daemon or start-up still reaches the cleanup, which has its own.
  Before each tested-container create/reset, record the existing volume inventory.
  Capture the created container's mounts and mount-origin metadata; track only fresh,
  implicit local anonymous volumes (image VOLUME or source-less volume mounts), bound
  to their returned names and creation timestamps. An anonymous label alone is never
  ownership. Preserve every pre-existing, explicit-source and inherited volume.
  Remove tested containers without `rm -v`; remove only the tracked run-created volumes
  after checking their creation identity. Ambiguous inheritance, inventory/capture
  failure, replacement or unconfirmed deletion stays unknown cleanup (exit7), never
  an empty inventory or a successful teardown. Named/user-supplied volumes are never
  removed by this anonymous-volume cleanup. A create failure without a returned ID is
  explicitly unconfirmed, never evidence nothing was created. Choose the bridge
  subnet from a read-only projected network inventory and make one network-create
  attempt. A lost/failed response retains the attempted name/subnet, exits7 and
  stops without retry or name-based deletion. Cleanup checks request only IDs,
  names and creation identity, never full credential-bearing inspect JSON.
  Teardown confirms the container, those volumes, the canary and the
  network absent by ID; anything left is exit 7, named with its ID. Residual, stated
  in every report: egress is measured to a canary on a network Sandprobe created, with the box's resolver pointed at
  it, so a receipt proves the box can send data out to an address it was given, not that it reaches the internet.
  EGR-6 stays skipped (open question 2). Tests: `cmd/sandprobe/docker_test.go` (option pass-through and network
  detection; with `SANDPROBE_FIXTURES=1`, a locked-down and an open container end to end with every resource gone).
  PR40 review regressions cover pre-existing anonymous volumes mounted explicitly
  and through volumes-from, source-less fresh volumes, reset tracking, reused names,
  partial inventory failure and cleanup after a startup failure. Docker's name-addressed
  volume removal retains a check-to-delete replacement race; no host-attestation claim.

## exe.dev integration and bounded validation (PRV-13)

- Scope: an expiring tag-scoped key at a private local path. One short CPU sandbox baseline, stopping on the first completed result; no automatic create retry, no repeat probing, no production VM, exploit, escape, guest requests to provider metadata/control endpoints, secret values or LLM workload. Terms checked 17 Nov: https://exe.dev/docs/terms-of-service section 2.2 bars use "for benchmarking or competitive analysis of the Service"; a live run needs the operator's own clearance for this bounded run, never represented as provider-written permission. Read-only account/help/empty scoped-list checks run before creation.
- Transport: native Go HTTPS POST to fixed origin https://exe.dev/exec, redirects disabled, no credential in argv, guest, report, error or journal. Host credential is an owner-only regular non-symlink file, maximum 8 KiB, expiring and preferably restricted to tag sandprobe and commands help,whoami,new,ls,stat,ssh,rm. No command/body/provider error text is logged. Creation refusals may expose only fixed allowlisted hint labels (command_contract, standalone_access, billing_or_plan, name_contract, permission, image_contract, unclassified_response) inferred from bounded error/message/reason strings, never raw text or arbitrary keys. Preserve the sanitized HTTP/refusal cause before generic unconfirmed-name errors; journal only the fixed hint. CLI distinguishes requested intent from confirmed create-returned identity. JSON management replies and base64 NDJSON execution frames are bounded and must be complete; exec requires exactly one explicit zero exit_code terminal frame, no error, duplicate fields or terminal frames, trailing events or nonempty stderr. Multiple stdout/stderr chunks are valid, including equal chunks; nonempty stderr still fails. HTTP200 alone is never success. No retries on mutations or guest commands.
- Creation: exclusive private lifecycle journal written and synced BEFORE the single create POST. Standalone CPU VM, 2 vCPU/4GB, explicit ubuntu:24.04 image and egress=all, no prompt, setup script, integrations or service/model credentials supplied. Only SANDPROBE_TWIN=1 is passed. This is the Ubuntu/no-integration configuration, not a claim about default exeuntu/Shelley. Random requested name plus generic sandprobe and unique per-run tags; record the create-returned name immediately, before parsing optional metadata; persist canonical create timestamp and list region/tags atomically and sync the journal before guest execution. Never adopt a VM from a list after an ambiguous create. Existing unresolved journals block a new create. There is no provider-enforced expiry in the documented create API; a bounded local context and independent cleanup are not a crash-proof TTL. Costs can continue after a host crash until journal-based cleanup completes.
- Name-addressed identity exception: exe.dev's documented create/list/delete API exposes a VM name and created_at rather than an immutable resource ID or conditional delete. ID() returns the original create-returned name, explicitly a name, under this limited exception to PRV-1. Pin a fresh created_at, region and the two run tags from list. Account whoami.region may be empty and is not VM identity; bind the first matching created VM’s actual region only after original create-name, birth and run-tag verification, durably before execution. Cleanup may finish this binding after interruption using the confirmed create identity, never by adopting an unconfirmed name. Check this provider metadata immediately before every command/delete and both before and after read-like execution; never resume/restart or follow changed identity. A changed guest boot ID stops execution. Guard boot validation and the intended command in the SAME guest shell. These checks reduce name-reuse risk but cannot make name-based exec/delete atomic; same-account concurrent replacement and tag-visibility loss remain residual. Never represent a guest boot ID or synthesized fingerprint as an immutable provider ID. Cleanup absence is scoped API visibility, not provider-internal erasure proof.
- Runtime: detect amd64/arm64, private mktemp directory, chunked base64 upload below the 64KiB request limit with fixed generated paths and SHA-256 verification after decompression. No command text comes from API response fields. Command quoting survives both lobby and guest shells. Each /exec call is bounded below its documented 30-second limit. The probe is launched exactly once through a detached run-owned wrapper with private output/stderr/completion files and a 95-second timeout; short read-only polls retrieve only complete output after an atomic exit-status marker. Launch requires an explicit acknowledgment and is never retried after ambiguity. Polls enforce boot identity and output limits, require zero stored exit status and empty stderr, and stop on cancellation/deadline. Timeout/missing completion never becomes successful probe evidence. Stdin is a generated private file, hash-verified and removed on command exit. The only supported probe modes are survey and scoped full exec; use the common host.Execute, grading, canary health and receipt verification. SEC-4/EGR-3/AMP-6/AMP-7 are excluded; EGR-6 needs approved upload targets and PER-5 needs resettable storage, so stay skipped. No restart/pause is presented as reset evidence.
- Cleanup: run-independent bounded context even after cancellation. Validate original name/birth/region/run tags, persist a delete-attempt marker before issuing rm once (never repeat an ambiguous mutation after restart), require a successful response listing the original name as deleted, then require an authenticated scoped list to be empty for that exact name. HTTP404, forbidden responses, malformed lists, a hidden replacement, retained or unexpected delete results are not deletion proof. Retain journal and return cleanup exit7 when unresolved; successful deletion/absence retires it. A separate cleanup command can load only a valid, owner-only same-user journal and recheck original identity; it cannot adopt by guessed name. If create was ambiguous or name was never confirmed, retain intent for owner reconciliation rather than deleting by name.
- Proof before merge: independent code and security reviews of spec and code; local HTTP fixtures for real documented command shapes, strict streamed exit evidence, response caps, quoting, uploads, identity changes, crash journals and deletion; CLI plan/approval before credentials, cleanup independent of cancellation. Live validation waits for reviewed code and a healthy separately controlled receiver. Saved evidence must distinguish API success, guest observations, receiver receipts and scoped cleanup, and record failed preparations without claiming a completed baseline.

## Boat bounded baseline (PRV-11)

- Scope: the operator's own API key and one bounded guest baseline, with lifecycle/upload/survey/grade; no separate smoke, automatic create retry or repeat after failure. A live run needs the operator's informed authorization, never a claimed provider-written approval. Own fresh sandbox only, read-only account identity required; creation explicitly pins the documented personal wallet with org=personal and X-Boat-Org:personal, never the mutable active wallet.
- Terms reviewed 13 Nov: https://boat.dev/terms. TOS-10 says “You may not probe, bypass, disable, reverse engineer” its security/access controls. TOS-6 also bars “unauthorized vulnerability scanning, intrusion, exploitation, or network abuse”. TOS-3 supports testing workloads. This creates a scope/terms condition: a live run needs the operator's informed authorization, never a claimed provider waiver. No exploits, bypasses, privileged actions or provider-control requests. The scope is guest permission metadata and unique markers to our own canary only. SEC-4, EGR-3, EGR-6, AMP-6 and AMP-7 stay excluded; PER-5 skipped without run-owned resettable storage. No secret values, external scanning, provider endpoints or LLM workload. Stop and restrict evidence on a suspected provider-specific flaw (AGENTS rule 7).
- Lifecycle/transport: native fixed-origin API https://boat.dev/api/v1; small CPU VM, base environment, explicit noEnv=true / snapshots=false / monitoring=false, ttlSeconds=900 auto-archive backstop (not deletion); no model prompt, previews, snapshots, volumes, injected service credentials or resume. One create POST, return ID journaled before polling. Pin create ID and run label before any follow-up. Create and lookup timestamps can differ slightly: validate both against the request window and require a maximum one-second difference, journal the first lookup timestamp as canonical, then require it unchanged. Cleanup uses exact create-returned ID plus run label, owner access, personal wallet and fresh canonical birth even if runtime policy validation failed. Never adopt by name. The noEnv request must be accompanied by explicit holdsCreatorLogins=false and wipePendingUntilRestart=false in lookup; a retained base environment display label is not evidence of attached secrets, and is not used as no-env proof. Reject unknown or unexpected environment labels; keep provider assertions distinct from secret-value evidence. Command timeout 95 seconds, synchronous, no detached/streaming; require explicit zero exit, success, not timed out/truncated. Gzip probe for the 5MiB file API limit, upload only generated safe filenames in a random private /tmp directory. File-write size has no documented unit: require explicit success and a nonnegative declared size; record response-path equality as metadata rather than a gate because the API canonicalizes paths, but prove exact uploaded bytes with remote SHA-256 for every probe/input write rather than assuming that size equals decoded bytes. Decompress as guest and verify original probe SHA-256. Upload refusals log only fixed presence/match flags and integer sizes, never response bodies. Preserve run-owned sandbox/deletion-operation IDs in failure cleanup messages before retiring journals. Permanent delete includes X-Ascii-Confirm-Delete equal to exact sandbox ID; journal returned deletion-operation ID before polling it to completed (kind=sandbox and targetId=original ID) and verify sandbox404. Auto-stop retains snapshots and is not cleanup proof; do not create saved snapshots. Provider audit/backup retention is outside run-owned compute deletion.
- Before mutation: validate owner-only no-symlink key, explicit target scope, create-private journal directory and shipped probe. Exclusive/fsynced intent precedes single create; atomic state updates preserve previous cleanup identity. Uncertain creates remain unresolved (no name/tag adoption). All error bodies/URLs/provider messages/credentials suppressed; host requests refuse redirects, helper errors never emit raw SDK stderr. Requests/results bounded, shell paths generated and validated, no keys on arguments or guest environment.
- Cleanup runs with a separate bounded context after success/failure/interruption; preserve identity journal and exit 7 if uncertain. No other account resources may be touched. Guest boot ID is self-observed, not host/cross-tenant attestation; provider identity checks and name races remain explicit. Full report complete means selected checks accounted for; skipped checks are not passes. Credential scan and independent code/security review before live; exact-ID cleanup inventory afterwards.
- Offline tests cover key/target safety, single create and immediate-ID journaling, altered identity/boot/policy refusal, upload digest, bounded sanitized command response, interrupted cleanup, deletion proof and approval-before-credentials; SDK/wire fixtures checked against pinned primary code/docs.

## Daytona bounded baseline (PRV-12)

- Scope: the operator's own API key and one bounded guest baseline, with lifecycle/upload/survey/grade; no separate smoke, automatic create retry or repeat after failure. A live run needs the operator's informed authorization, never a claimed provider-written approval. Own fresh sandbox only. Read-only API access is checked before mutation; the API key is organization-scoped, but preflight does not return the organization identity. The create-returned organization is pinned immediately after the immutable sandbox ID; no JWT or mutable active-organization selector is used. This pre-create identity visibility limitation remains explicit.
- Terms reviewed 13 Nov: https://www.daytona.io/terms-of-service. Section 8 bars vulnerability testing without written permission. Current https://www.daytona.io/docs/en/acceptable-use/ permits targeted owned/authorized-system testing without notice but expressly defers to ToS/agreement on conflicts and distinguishes testing Daytona itself. A live run needs the operator's informed authorization, never a claimed provider waiver. The scope is guest permission metadata and unique markers to our own canary only. SEC-4, EGR-3, EGR-6, AMP-6 and AMP-7 stay excluded; PER-5 skipped without run-owned resettable storage. No secret values, external scanning, provider endpoints or LLM workload. Stop and restrict evidence on a suspected provider-specific flaw (AGENTS rule 7).
- Lifecycle/transport: official daytona==0.198.0 Python SDK in preinstalled pinned host venv; fixed API origin https://app.daytona.io/api. Generated management create call returns ID before SDK startup waits, allowing immediate host journal. Default prebuilt CPU snapshot, no GPU/custom build; user default; ephemeral autoDeleteInterval=0 / autoStopInterval=15 / autoPauseInterval=0 / public=false, empty env/secrets/volumes, no pause/resume, snapshots, volumes or public previews. Runtime is pinned to the approved US HTTPS proxy https://proxy.app.daytona.io/toolbox with exact sandbox-ID path; both generated SDK and upload HTTP clients reject all redirects and mutations are not retried. Runtime uses SDK get by exact ID after run-label/creation/policy/state checks, explicit twin env and 95-second command timeout, private random probe upload and SHA-256 check. Host pins boot identity across guest operations. Delete only original create-returned ID, verify original lookup404 or identity-bound DESTROYED/desiredState=destroyed, as the pinned SDK documents; distinguish retained terminal metadata from absent records and never treat stop as deletion. Idle stop is a cost backstop, not absolute expiry or deletion proof. SDK logging/stdout/stderr are isolated; only fixed operation/status error labels escape.
- Before mutation: validate owner-only no-symlink key, explicit target scope, create-private journal directory and shipped probe. Exclusive/fsynced intent precedes single create; atomic state updates preserve previous cleanup identity. Uncertain creates remain unresolved (no name/tag adoption). All error bodies/URLs/provider messages/credentials suppressed; host requests refuse redirects, helper errors never emit raw SDK stderr. Requests/results bounded, shell paths generated and validated, no keys on arguments or guest environment.
- Cleanup runs with a separate bounded context after success/failure/interruption; preserve identity journal and exit 7 if uncertain. No other account resources may be touched. Guest boot ID is self-observed, not host/cross-tenant attestation; provider identity checks and name races remain explicit. Full report complete means selected checks accounted for; skipped checks are not passes. Credential scan and independent code/security review before live; exact-ID cleanup inventory afterwards.
- Offline tests cover key/target safety, single create and immediate-ID journaling, altered identity/boot/policy refusal, upload digest, bounded sanitized command response, interrupted cleanup, deletion proof and approval-before-credentials; SDK/wire fixtures checked against pinned primary code/docs.

## Modal proof of concept (outside v1)

The proof of concept runs a small probe on Modal Sandboxes in the operator's own account: a default sandbox, a few
locked-down network setups, and a sidecar watching the main container's traffic, all talking only to our own test
server. It compares runs and runs something beside the box, both
outside v1 ("Not in v1"), so it lives behind a build tag and never ships.

- **POC-1 Scope.** `sandprobe poc modal ...` exists only in a binary built with `-tags poc` (`make poc`); a release
  build has no `poc` command. It runs in the operator's own workspace, named in `SANDPROBE_MODAL_WORKSPACE` (nothing
  runs without it), with the token `~/.modal.toml` already holds,
  which is never printed or logged. CPU sandboxes only, within the operator's spend cap. Every sandbox has
  POC-2's timeout as a server-side backstop. The token stays on the host: the SDK reads it from `~/.modal.toml`, and it
  never enters a sandbox's files, environment or image. SDK errors reach the terminal and every artifact only as a
  fixed category and gRPC status code, never their text, and the SDK's own logger is discarded. Output goes to a
  private local directory: each setup's OUT-1 and OUT-2
  reports, the sidecar's log and visibility matrix, and the summary (POC-8). Nothing is uploaded or shared; any summary
  goes to Modal privately, and only once the project owner approves it. One setup runs per invocation. The
  operator reads its raw record against POC-5 and clears it before rendering its reports or starting the next setup.

- **POC-2 The setups.** Each is the Modal row's sandbox with one change. The probe runs as in any other run.

  | Setup | Created with | Modal's docs say |
  |-|-|-|
  | `default` | nothing more | egress is open to any public IP |
  | `domain-empty` | `OutboundDomainAllowlist` set, with no entries (the SDK: non-nil means allowlist mode) | TLS on 443 only to listed names, matched on SNI; other traffic only to a CIDR allowlist; DNS still answers |
  | `domain-one` | `OutboundDomainAllowlist` holding one name: `<t>.canary.<our domain>`, `t` a fresh nonce | as above, so the twin (POC-3) reaches the canary while EGR-2's own name, at the same IP and port, is refused |
  | `block` | `BlockNetwork` | all outbound traffic dropped, DNS included |
  | `block-vm` | `BlockNetwork`, `Runtime: vm` | as `block`, in a VM with its own kernel; skipped and listed if the workspace can't create one |
  | `sidecar` | `proxy_traffic_via_sidecar: watch` and an empty `OutboundCIDRAllowlist` on the main container; a sidecar `watch` (POC-6) | TCP 443 from the main container is relayed through the sidecar as raw TLS; other traffic follows the main container's CIDR allowlist, so is refused; DNS still answers |

  `domain-one`'s name and EGR-2's both resolve to the canary through a wildcard `*.canary.<our domain>` record,
  created and deleted by `deploy/canary.sh` beside its other records. Modal resolves an allowlisted SNI itself, and
  the sidecar's relay has only the SNI to go on.

- **POC-3 An allowed twin for the allowlist.** In `domain-one`, after the probe and only once POC-5's gate has
  passed, the host runs the same probe again with a manifest that selects only EGR-2, with nonce `t` and the same
  endpoint, pin and route. The probe's own client then makes the identical attempt, varying only the SNI's nonce:
  `<t>.canary.<our domain>`, the one name the allowlist holds. The canary is armed for `t` on its own run (SBX-11).
  A twin receipt, beside EGR-2's refusal in the main run, shows the allowlist admitted its one name and refused
  EGR-2's at the same IP, port and route. That refusal needs TWN-1's full proof and no receipt for EGR-2's nonce.
  EGR-2's pass still needs TWN-1 as in any run; a policy error or a missing receipt alone stays unknown. Without
  the twin's receipt, the refusal stands on TWN-1 alone, and the summary says the allowlist wasn't shown to admit
  anything. The twin run is evidence only: it's never graded.

- **POC-4 What isn't tested on Modal, and why.** Every item below is listed in the summary's last section.
  - SEC-4, AMP-6, AMP-7 and EGR-3 are skipped (PRV-5): they would send requests to Modal-owned endpoints.
  - EGR-6 is skipped, as everywhere.
  - PER-5 is skipped: see the Modal row.
  - AMP-4 still runs. It does `lstat` and access checks and never connects. A Modal socket it finds is reported,
    never used.
  - Fronting through a shared CDN isn't tested: it needs a third party's server. `domain-one` covers only how the
    allowlist matches.
  - Inbound through unencrypted tunnels isn't tested: it would open ports to the internet.
  - GPU sandboxes, the Datadog integration and the Outbound Policy aren't tested.
  - The PoC sends nothing that tries to escape the box or reach other tenants, and puts no load on anything.

- **POC-5 Stop and report.** This rule applies when a result suggests a real flaw on Modal's side, not a documented
  trade-off. The cases are:
  - The box sees or reaches another sandbox's or customer's data, processes or network.
  - A documented control doesn't hold beyond the DNS and fronting cases Modal documents.
  - Modal's own credentials are readable in the box.
  - There are signs of host access: writable host paths, or the host's processes or devices.
  - The main container sees the sidecar's processes, or the sidecar sees the main container's processes or files.

  A gate runs after every step that could reveal one, and the next step runs only once it passes: after the probe
  returns, after the twin, and after each `look` row. It checks the canary's counts for this setup's own nonces, the
  run's check nonces and the twin's. The canary keeps no others, and host health is never a receipt. Its rules:
  - `block` and `block-vm`: any count, for any nonce, on any protocol or port.
  - `domain-empty`: any TCP count, on the nonce's own port or elsewhere.
  - `domain-one`: any TCP count for a nonce other than the twin's, or the twin's nonce counted anywhere but TCP 443.
  - `sidecar`: a TCP count on 22, 80 or 8080, or any nonce counted elsewhere on TCP. Then, once the relay's log is
    read in full (POC-6), a TCP 443 count for a nonce the complete log shows no relay of. A log that's missing,
    unreadable or truncated isn't a bypass. It leaves the sidecar's attribution unknown, and the setup ends there,
    before `look`.

  DNS counts under an allowlist are Modal's documented behaviour and pass the gate. That means EGR-1, and EGR-5 on
  UDP 53, each on its own port. `look` stops itself at its first unexpected sighting (POC-6). A secret-shaped name
  whose source POC-7 can't establish holds the setup for the operator.

  When the gate trips:
  - The next step doesn't run.
  - The sandbox is deleted as usual, with its cleanup receipt.
  - No OUT-1, OUT-2, matrix or summary input is generated for that setup.
  - What's kept is a private incident note: the setup, the gate's rule, timestamps, and the counts per nonce of our
    own. Nothing else is kept.
  - The PoC exits 8, and the operator tells the project owner.
  - Nothing is re-run, repeated or widened to confirm it.

  The project owner decides on reporting it privately to Modal. A setup that passes every gate keeps only our own raw
  record, in `raw/<setup>/`: the probe's document, the canary's counts, the relay's log, `look`'s rows, and
  timestamps. The operator reads that against the cases above. OUT-1, OUT-2 and the matrix are rendered from it only
  after that clearance (`sandprobe poc modal render`). On a case, no report is ever rendered, and the raw record is
  kept only as the incident's own logs. The create request each setup sends is unit-tested against its table row,
  so a misconfigured setup can't pass for a failing control.

- **POC-6 The sidecar observer.** The sidecar is a Sandprobe image: `alpine:3.21`, built in our App before the
  sandbox (sidecar images must be prebuilt). After the sidecar starts, the SDK's filesystem API copies in
  `sandprobe-aux`, a PoC-only binary. It's written under a temporary name and then renamed, and the sidecar's
  entrypoint waits for the final name before running `relay`. The sidecar's own CIDR allowlist holds only the
  canary's /32. DNS through Modal's resolver stays open to it, as Modal documents, so its only non-DNS egress is to
  the canary.

  `relay` works like this:
  - It listens on TCP 443, and writes `ready` once it does. The host waits for that, through the sidecar's exec,
    before the probe runs; with no `ready`, the setup ends unknown.
  - It reads a ClientHello, up to 16 KiB and 5 s, and accepts only an SNI whose first label is nonce-shaped under
    `canary.<our domain>`.
  - It connects only to the canary's pinned IP on 443, never resolving a name. It replays the ClientHello and
    splices both ways, never terminating TLS, so the canary's pin still holds.
  - Every other connection is closed. Its log line says only that one was refused, and the ClientHello's length,
    never its SNI.
  - It writes a line when it accepts a connection (time, nonce) and one when it ends (bytes each way, outcome).
    Each line is synced to the sidecar's own disk before the next. No payload is ever recorded.

  After the probe's receipt wait, the host reads the whole log through the sidecar's exec. A TCP 443 receipt is
  attributed to the sidecar only when the log holds that nonce's accept and end lines, with bytes both ways and the
  outcome `relayed`. A log that's missing, unreadable or lacks the end line leaves attribution unknown. A 443
  receipt with no relay of its nonce, in a complete log, is a bypass and trips POC-5's gate. DNS receipts are reported
  apart, since the sidecar never handles DNS.

  Then `sandprobe-aux look` runs in each direction, by exec. The main container's command keeps a fresh marker in its
  own arguments, writes it to `/tmp`, `/root` and a shared ephemeral Volume, and answers it on TCP 7070. The sidecar's
  command keeps a second marker in its arguments. `look` checks its rows in order, and stops at the first unexpected
  sighting, so nothing after it runs.

  | From the sidecar | How | Expected, from Modal's docs |
  |-|-|-|
  | main's processes | its own `/proc/*/cmdline`, for main's marker | not seen: separate gVisor or VM boundary |
  | main's files | `lstat` of the exact paths main wrote | not seen: mounts are per container |
  | a shared Volume | read the marker file, before and after `ReloadVolumes` | seen, perhaps only after a reload |
  | main's network | TCP connect to `main:7070`, one line read | seen: every port on main is reachable |
  | main's HTTPS | the relay log against the canary's TCP 443 receipts | each relayed attempt, by SNI only |
  | main's DNS | EGR-1's receipt; the relay never sees it | not seen |

  | From the main container | How | Expected |
  |-|-|-|
  | the sidecar's processes | its own `/proc/*/cmdline`, for the sidecar's marker | not seen |
  | the sidecar's relay | the probe's EGR-2, which Modal routes there | reached; that's the design |

  Main's stdout and stderr aren't looked for on their own. Modal gives a sidecar no streams, and the only path to
  them would run through main's processes, which the first row tests and which must not be seen. Each side reads
  only its own `/proc` and filesystem, the shared Volume, and the one port main opened.

- **POC-7 Buckets.** Each finding on Modal falls in one bucket, A to D, or is listed as by design, by a table reviewed
  here, never by judgment when the summary is built. By design is never counted as a gap.
  - **A, documented, with a Modal control:** Modal's docs name the exposure, and a Modal setting closes it.
  - **B, a default you can change:** the exposure comes from a default the customer brings or leaves, such as the
    image's user or files, and is fixed in the customer's own image or code.
  - **C, a gap with no control today:** no Modal setting closes it short of blocking all network.
  - **D, only Modal can tell:** it can't be judged from inside one sandbox.

  | Finding | Setups | Bucket | What closes it | Modal's words |
  |-|-|-|-|-|
  | EGR-1, EGR-2, EGR-5 | `default` | A | `block_network`; the domain and CIDR allowlists for all but DNS | "By default, Sandboxes can make outbound connections to any public IP address." |
  | EGR-1; EGR-5 on UDP 53 | any allowlist, `sidecar` | C | only `block_network` | "DNS traffic is allowed without restriction except when all outbound traffic is blocked." |
  | EGR-2 through the sidecar | `sidecar` | A | the sidecar's own allowlists, which Modal documents | "Each Sidecar has its own outbound network policy, independent of the main container's and open by default." |
  | AMP-2: uid 0, or root's capabilities | all | B | a non-root `USER` in the image | none: the image's default |
  | AMP-3: `NoNewPrivs` 0 with setuid-root files | all | B | an image with no setuid-root files | none |
  | PER-1 to PER-4: startup, PATH, schedule and access files the agent can replace | all | B | a non-root user that owns neither its home nor the PATH, schedule and startup directories, in the image | none |
  | SEC-2, SEC-5: other processes' environment and memory, when every PID the finding opened has a name in the raw record (`/proc/<pid>/comm`, names only, listed after the probe): PID 1 Modal's init `dumb-init`, every other one the setup's own command (`sleep`, `sh`, `python3`). A PID with no recorded name, or any other name, isn't placed | all on gVisor | B | the agent under a UID of its own, apart from every other process in the box | none |
  | SEC-3: the image's own `/etc/shadow`, readable as root; any other credential file holds the setup under POC-5 | all | B | a non-root `USER` in the image | none: the image's default |
  | SEC-1: a secret-shaped name the image declares, or the host set | all | B | the customer's own image and environment | none |
  | SEC-2, SEC-5 in the VM: no row; a finding there stops the summary until a reviewed change adds one | `block-vm` | none | none | none |
  | AMP-8 in the VM, only for these surfaces: `/proc/sys/kernel/core_pattern`, `/proc/sys/kernel/sysrq`, `/proc/sys/net/ipv4/ip_forward`, and the guest's `vda`, `loop`, `ram`, `zram` and `nullb` devices. Any other path isn't placed | `block-vm` | by design: listed, never counted as a gap | nothing needed: it's the sandbox's own kernel | "the Sandbox runs in its own virtual machine with its own Linux kernel." |
  | AMP-8 on gVisor: a setting of gVisor's own kernel writable as root | every setup but `block-vm` | D | Modal's to say: what that setting reaches | none |
  | AMP-4: a Modal control socket found, never connected | all | D | Modal's to say: who may use it | none |

  SEC-1 reports names only, so a name's source comes from two lists made before the run: the names the host sets
  (none), and the names the image's config declares (`docker image inspect`, names only). Any other secret-shaped
  name holds the setup for the operator (POC-5). The summary won't build until a reviewed change here classifies it.

  Bucket D also holds these, untested: separation between tenants on a shared host, the host's kernel and runtime
  patching, and GPU memory reuse. A finding this table doesn't cover stops the summary until a reviewed change here
  covers it.

- **POC-8 The one-page summary.** `sandprobe poc modal summary` builds `summary.html` and `summary.md` from the
  setups' reports, the twin's receipt and the sidecar's matrix. The HTML follows OUT-2's rules: self-contained, under
  its CSP. Its sections, in order:
  1. One row per setup tested, with its bucket counts.
  2. The findings by bucket, one line each: what we saw, which setups it applies to, and the Modal control that
     closes it, linked to the doc that says so.
  3. The gaps that apply: bucket C, plus any B a careful customer would still hit.
  4. What the sidecar saw and what it couldn't.
  5. What wasn't tested, and why (POC-4).

  Each setup's score stays in its own report. The wording is plain and factual, and it credits Modal's docs
  wherever they already describe what we saw.

- **POC-9 Cleanup receipt.** Each setup's report carries the receipt:
  - every sandbox, by ID, terminated, polled finished, and absent from a running list by its tag;
  - the sidecar, terminated with it;
  - the ephemeral Volume, closed;
  - the twin's and the run's canary nonces, disarmed.

  The App and the two built images stay between setups and are listed as residual. `sandprobe poc modal cleanup`
  deletes the images by ID at the end, and leaves the empty App, which `modal app stop sandprobe` removes. Spend is
  estimated, not measured. Every setup keeps Modal's default size, a 0.125-core and 128 MiB request that may burst.
  The estimate is each sandbox's lifetime, from its create call to the end of its teardown (to its 15-minute timeout
  if it wasn't confirmed deleted), at that request and Modal's published non-preemptible sandbox rates
  (modal.com/pricing, read 10 Nov: $0.00003942 per core-second and $0.00000667 per GiB-second). It claims no
  direction: the lifetime counts create and teardown time Modal may not bill, and bursting bills more. The summary
  says so, and points to the workspace's usage page for the real figure. Image builds aren't included.

## Releases, 21 November 2026

- **REL-1 A reproducible build.** `make release` builds the four `sandprobe` binaries a release ships (macOS and
  Linux, arm64 and amd64) from one commit: cgo off, `-trimpath`, `-buildvcs=false` and `-ldflags "-s -w"`. They embed
  the Linux probes and canary as `make probes` builds them: cgo off, `-trimpath` and `-buildvcs=false` (deterministic,
  not stripped), with the probe's `BuildVersion` set to the CLI's `Version`. Each binary is compressed with `gzip -9 -n`. `SHA256SUMS` lists the `.gz` files, which
  the installer checks, and `SHA256SUMS-binaries` lists the uncompressed binaries, so anyone with the same Go version
  can rebuild and compare without depending on their gzip.
- **REL-2 Two builds, one release.** The release workflow runs REL-1 twice, on separate runners from separate clean
  checkouts of the same commit, and publishes only if every file matches byte for byte and both checksum files
  match the files they list (the binaries' after decompressing every archive). It does the same on every pull
  request, publishing nothing. A release publishes the CLI's own `Version` as the tag `v<Version>`, from `main`, and
  stops if the version asked for, the CLI's `version` output and the probe's `BuildVersion` don't all agree. A
  version is `x.y.z`, or `x.y.z-rc.N` for a release candidate, each part digits; the release stops on anything else,
  before anything is published. An `x.y.z-rc.N` version publishes as a GitHub pre-release, never marked Latest. An
  `x.y.z` version publishes as a full release, which GitHub marks Latest by its own rule (newest by date and version).
- **REL-3 Provenance.** Each published `.gz`, and both checksum files, carry a GitHub build attestation for the
  workflow run that built them. Verifying one binds it to this repository's release workflow, on `main`, at the
  release's commit:
  `gh attestation verify <file> --repo summationai/sandprobe --signer-workflow
  summationai/sandprobe/.github/workflows/release.yml --source-ref refs/heads/main --source-digest <release commit>
  --deny-self-hosted-runners`. The repository alone (`--repo`) is only the minimum identity check, and a
  `SHA256SUMS` fetched beside a file proves transport integrity, not authenticity, unless the checksum file's own
  attestation is verified the same way. The release notes give the exact command with the commit filled in. The
  release workflow creates the tag `v<Version>`. The repository refuses any other new tag; a version-shaped tag can
  be made by anyone with write access, so a release is authentic only when its files verify as above, never because
  its tag exists. CI parses every workflow, `.yml` and `.yaml`, and fails unless the release workflow's publish job
  is the only place that grants `contents: write` or `write-all`; the repository's default workflow permission stays
  read.

## AWS Nitro setup recovery, 23 November 2026

So an expired AWS session can't leave `deploy/eks.sh` stuck behind a state file that records nothing.

- **CLN-2 No record before AWS answers.** `deploy/eks.sh up` asks AWS who the profile is (`aws sts get-caller-identity`,
  with the profile and region) before it writes its state file. If that fails, such as on an expired SSO session, up
  stops with a fixed message that names the profile, says nothing was recorded or created, and gives the commands that
  show AWS's error and sign an SSO profile in again. It prints none of the AWS CLI's own output, and it exits 3, a code
  eks.sh uses for this refusal alone: identity not proven, nothing written, nothing created. `down` makes no such
  check, so a recorded deployment can be retired while the session is expired. up writes `crole`, `nrole` and
  `cluster` each before its create, so a state file with none of them records no create: an earlier up stopped before
  its first one, on a failed read or before this rule. For such a file, `status` and up's refusal say so before any AWS
  call, and print the command that retires it, then say to run up again. The command names the profile, the region,
  and the state file when it isn't the default, so it reaches the same file as pasted. `down` on such a file makes no
  AWS call, keeps the record as `<state>.down-<time>`, as every down does, and says nothing was created. A state file
  with any of those keys is handled as before: down deletes what it records by ID and confirms each is gone, and a
  cluster asked for but never seen stays unresolved (PRV-1). The managed runner (RUN-1) journals the cluster's intent
  before it calls up. It records that cluster as `not_created`, durably, only when up exits 3 and no state file exists,
  not even a link; its cleanup then makes no call for the cluster and counts it confirmed. Any other failed up with no
  state file stays `cluster_cleanup_unconfirmed`. `Commands.call` keeps the last command's exit code for this check.

## Local Docker entrypoint and scratch, 24 November 2026

So `run docker` grades an agent image as it is. Most agent images' own entrypoint exits without a task or a terminal,
which left `run docker` nothing to probe, and the keep-alive a person added instead became the very process SEC-2 and
SEC-5 found.

- **DKR-1 Sandprobe's own idle process.** Unless the person's options name `--entrypoint` (`--entrypoint X` or
  `--entrypoint=X`), `run docker` creates the container with `--entrypoint /opt/sandprobe/sandprobe-probe`, the probe
  PRV-14 already bind-mounts read-only there, and the one argument `-idle` after the image, so the image's own
  ENTRYPOINT and CMD never run. Unless the options name a health option (`--no-healthcheck`, or any `--health-*`),
  Sandprobe also passes `--no-healthcheck`, so the image's HEALTHCHECK never runs either: it is the one other process
  Docker starts from an image's configuration at run time (ONBUILD acts only at build, and STOPSIGNAL starts nothing).
  In `-idle` the probe reads no input, touches no image or workload data, writes nothing and starts no process (the
  Go runtime's own start-up reads, such as the cgroup's CPU limit, aside); as the container's init it reaps any orphan
  the kernel hands it, and it never exits on its own. Unless the options name `--init`, Sandprobe also passes
  `--init=false`, so Docker starts no init of its own ahead of it, whatever the daemon's default. The plan's Runs line
  says the idle process runs and the image's entrypoint, command and health check don't. The report says the image's
  processes never ran only when Docker's record of the container shows no health check (none, or `NONE`); otherwise
  it says the health check may have run, and SEC-2 and SEC-5 count it if it ran during the probe. With `--entrypoint`
  in the options, Sandprobe adds neither its entrypoint, `-idle`, `--init=false` nor `--no-healthcheck`: the person's
  process starts with no arguments, as Docker starts an `--entrypoint` given without a command, and the plan and the
  report's residual say it runs, with any health check the image has, and that SEC-2 and SEC-5 count them like any
  other process. A health option the person names is theirs to keep, and the plan and the report say so.
- **DKR-2 The idle process isn't another process.** SEC-2 and SEC-5 skip one PID beyond the probe and its twins: PID 1,
  and only when the host's input says PID 1 is Sandprobe's idle process. The host says so only from Docker's own
  record of the created container, read with a narrow format, never from the box: `.Path` is
  `/opt/sandprobe/sandprobe-probe`, `.Args` is exactly `["-idle"]`, `.HostConfig.PidMode` is empty (the container's
  own PID namespace), `.HostConfig.Init` is false, and the options name no `--entrypoint`. Then PID 1 in the box's PID
  namespace, the one the probe joins through `docker exec`, is the process Docker started with that entrypoint: no
  other process can take PID 1 in its namespace, and the idle process never execs. Anything else (the person's
  `--entrypoint`, `--init`, `--pid`, a record that doesn't match or doesn't come) names nothing, and the idle process
  is counted: noise, never a false pass. A spoof can't hide a process: nothing about a process (its name, command
  line, executable or environment) is read to choose it, since any process in the box can run the bind-mounted probe
  with `-idle` itself; such a copy is at another PID, and is counted. Skipping the idle process hides no secret: its
  environment is the container's, which `docker exec` gives the probe as well, so SEC-1 reads the same names, and its
  memory is the static probe's. The host's fact travels in the probe's input only, so the manifest and OUT-1's schema
  are unchanged. With nothing else visible, SEC-2 and SEC-5 are `scoped_out` (TWN-4's capabilities still make them
  unknown first), with a reason naming the idle process, and the report's residual says the image's own processes
  didn't run, so these checks saw none of them.
- **DKR-3 An early exit says why.** One second after the create, and again when the survey or the probe fails, the host
  reads `.State.Running`, `.State.ExitCode` and `.State.OOMKilled`, a narrow format, never the whole inspect document
  or the container's logs, before the teardown. A container that isn't running stops the run, with nothing graded and
  exit 5 (7 if its cleanup isn't confirmed), and the error names what stopped (the person's `--entrypoint`, by its
  value, or Sandprobe's idle process), when (before the probe ran, or while it ran) and how: its exit code as Docker
  recorded it, or, when Docker's record says so, that Docker killed it for memory. An exit code alone never names a
  signal, since a process can exit with 137 itself. A known cause is never left as "see the message" or a bare invalid
  run. The fix runs as pasted, each word shell-quoted where it needs it: for the person's entrypoint, the same
  `run docker` command without `--entrypoint`, so Sandprobe keeps the container running itself; for the idle process,
  the same command without the person's docker options, to show whether one of them stops it, or the same command
  again when there are none. A record Docker doesn't give leaves the run's own error as it was.
- **DKR-4 Scratch on a read-only root.** When the options make the root read-only (`--read-only`, or `--read-only=`
  with a true value), Sandprobe adds `--tmpfs /opt/sandprobe/scratch:rw,noexec,nosuid,nodev,size=16m,mode=1777` and
  tells the probe, in its input, to make its private scratch directory (mode 0700, removed when it exits) there rather
  than in its temporary directory. The path is Sandprobe's own, beside the probe: never `/tmp`, and never a path the
  image uses. The plan names it as Sandprobe's own addition, and so does the report's residual. No check counts it:
  it is on no check's target list, the host drops it from the survey's storage roots before it plans, so PER-5 can
  never mark it, and PER-5 is skipped on `run docker` anyway (DKR-5). Without a read-only root nothing is added.
- **DKR-5 PER-5 on `run docker`.** The box declares TWN-3's recreate model with no volume: Sandprobe creates no
  persistent volume for the run, a named volume in the options is the person's and never marked (PRV-14), and an
  image's `VOLUME` gets a fresh anonymous volume at every create, so nothing can carry a marker across a recreate.
  So PER-5 is always skipped, "no root this run may mark", no marker is placed, and the container is never reset. The
  plan's Marks and Reset lines say none, and `docs/providers/docker.md` says the same.

## run exec's own launcher, 24 November 2026

`run exec` turned Secrets red on every box. The person's command starts a `sh` that runs PRV-15's script, and the
script started the probe as that shell's child. The shell runs as the agent's uid, so SEC-2 and SEC-5 opened its
environment and memory and reported a finding on it. This was reproduced on `debian:bookworm-slim` through
`docker exec -i -u agent <ctr> sh`, and on Modal through a bridge. No agent can fix it: the shell is Sandprobe's own
transport. Skipping the shell isn't safe. Its `/proc/<pid>/environ` is the environment it was started with, not the
one it passes on: dash, Debian's and Ubuntu's `sh`, doesn't pass a name that isn't a shell identifier (`MY-KEY`,
`a.b`), and a shell can change a value before it starts a child (tested 24 November 2026). So these rules remove the
shell instead: it replaces itself with the shipped probe before any check runs, and only that verified process is
skipped.

- **LNC-1 The shell replaces itself with Sandprobe's wrapper.** For the main run only, after the shell has made and
  marked the owned scratch, decoded the probe and its input, and made the probe executable (PRV-15), the script's
  last command is `exec <scratch>/p -wrap <scratch> -expect-uid <uid> < <scratch>/in`, every value a literal the host
  fixed. The token and the owner never go on that command line, since another uid in the box can read any process's
  command line. The host writes them as the input file's first line instead, `<token> <owner>` and a newline, 50 bytes,
  before the probe's input, so the shell does nothing new. The script sets, exports and unsets no variable before it. From then on the shell's process
  image is gone: its memory, its start-up state and the environment it was started with, a name it didn't pass on
  and a value it changed included. The process that remains is the shipped probe in wrapper mode, with the
  environment the shell passed on. The other invocations (the architecture, the identity preflight, the survey) are
  unchanged. If the `exec` fails, a shell that carries on prints the refusal `SP-START-<token> 96` and exits, and a
  shell that exits on a failed `exec` frames nothing. Either way the run stops and nothing is graded, and the
  separate confirm-gone invocation removes the scratch.
- **LNC-2 The wrapper does only this, and fails closed.** Wrapper mode takes exactly three arguments, in order: the
  scratch path, in PRV-15's form, and `-expect-uid <uid>`. Anything else is refused. The wrapper runs no check, reads
  only its stdin's first line, its own environment and the scratch's owner mark, and starts no program but its own
  executable. In order, it:
  - reads exactly 50 bytes from its stdin, unbuffered, so the rest stays for the run: the token and the owner, 24
    lowercase hex each, a space between them and a newline after. A short or malformed line makes it exit nonzero
    with nothing printed and nothing removed: the host finds no frame, and the confirm-gone invocation removes the
    scratch;
  - prints the start marker;
  - reads its own environment from `/proc/self/environ`, exactly as `exec` gave it;
  - starts the run from `/proc/self/exe` with `-expect-uid <uid>`. The run gets the wrapper's stdin (the probe's
    input, after the first line), stdout and stderr, and that environment entry for entry, in order, with duplicates, entries without `=` and empty entries
    kept. The wrapper adds only `SANDPROBE_TWIN=1`, and only when no entry has that name. It never sets, unsets,
    reorders or rewrites another entry;
  - passes TERM, INT and HUP on to the run, and waits for it;
  - takes the run's status: its exit code, or 128 plus the signal that ended it;
  - removes the scratch only when PRV-15's ownership test holds: a real directory, not a link, whose `.sp-owner`
    holds the owner token. Anything else at the path is left alone;
  - prints the end marker with that status, and exits 0.

  If it can't read its environment or start the run, it starts nothing, removes the scratch the same way, and prints
  the end marker with status 96. The host then reports that the wrapper couldn't start the run, and grades nothing.
  An untrappable kill (SIGKILL) leaves no end marker: the host reports the run as not framed, and the separate
  confirm-gone invocation (PRV-15) stays the fallback that removes the scratch. The host classifies an invocation by
  its frame first, and only then by how the person's command ended:
  - a start marker that carries a refusal (97, 98 or 96) is that refusal;
  - a start marker with no end marker after it is an unframed run, nothing graded, whatever the command's own exit.
    Only a fixed label says how the command ended: cut off at its limit, cancelled, or failed; never the command's
    own text;
  - a failed command is "the command failed", whether it framed nothing or framed a whole run, since a command that
    failed counts for nothing (PRV-15);
  - a command that succeeded but framed nothing never framed a probe run;
  - a whole frame from a command that succeeded carries the probe's status.

  The confirm-gone invocation runs after every one of these, except when the scratch path was already there (97). The run it starts is bound with
  `-expect-uid`, as before, and refuses at startup as anyone else.
- **LNC-3 The run skips only its direct parent, verified by the kernel.** SEC-2 and SEC-5 skip one more process: the
  probe's direct parent, and only when it is the wrapper by the kernel's account. No argument, variable or name
  chooses it. Before `/proc` is listed, the probe takes `getppid()`, opens `/proc/<ppid>` (`O_PATH|O_DIRECTORY`) to
  pin that process, and stats `exe` through that descriptor and `/proc/self/exe`. The parent is the wrapper only when
  both are the same file, by device and inode. After the check's sweep, the probe checks again: `getppid()` is
  unchanged, and `exe` through the pinned descriptor still gives the same device and inode. A parent that died, that
  `exec`ed another file, or whose PID now belongs to another process fails this. If the first check fails in any
  way, the parent is counted as before: an error, another file, a copy of the probe at another path, or no parent in
  the box (`getppid()` 0). If the second check fails, the check ends `unknown`. Every other process stays counted,
  ancestors included: whatever started the shell (ssh's user-owned `sshd` session process, `su`, `sudo -u`, a
  bridge, or any other wrapper in the person's command) and its own ancestors. The host's script doesn't bound what
  those processes hold. They hold what their own program, configuration and session hold, and an agent started the
  same way could open them. So they are measured like any other process. That can be noise, but never a false pass.
- **LNC-4 Why the skip hides nothing.** The skipped process is the shipped probe, the file whose digest the run
  reports (SBX-5). Its environment is exactly what `exec` gave it. The run's environment is that, entry for entry,
  plus at most `SANDPROBE_TWIN`, so the wrapper holds no name or value the run doesn't, and SEC-1 reads every name
  either holds. Its memory holds the static probe, its arguments (the scratch path and the uid), the run's token and
  the scratch's owner token, and that environment. The two tokens are Sandprobe's own, made for this run, and hold
  nothing of the box's; they stay off every command line, so another uid can't read them there. The shell is no longer a process: its start-up state and
  the environment it was started with ended when `exec` replaced it, before any check ran. Nothing reads another
  process's environment or memory: SEC-2 and SEC-5 still only open. When the wrapper is skipped, each check records it,
  as DKR-2 records PID 1: a pass or a finding carries a reason that names the wrapper's PID and LNC-3, and a
  `scoped_out` (no other process visible) says that Sandprobe's own wrapper was the only one. That reason is the box's
  text. It stays in the report's JSON and is never shown as host text (UX-6). OUT-1's schema doesn't change.
- **LNC-5 Other runners.** `run docker` starts the probe with `docker exec` directly. Its parent is outside the
  box's PID namespace (`getppid()` is 0 there), so nothing is skipped. `run kubernetes`, and every recipe, reach the
  box through `sp_shell` with PRV-15's script (for Kubernetes, `kubectl exec -i` into the pod, starting `sh`), so the
  main run goes through the wrapper. The native adapters (PRV) don't use wrapper mode. Their probe's parent isn't the
  probe's own file, so it is counted as before. Sprites `exec`s the probe, or SPR-2's launcher, from `sh -c`, and AWS
  Nitro starts it through `env`, so neither leaves Sandprobe's shell behind. Boat's `sh -c` keeps a trap, so its
  shell stays the probe's parent, and exe.dev's worker runs the probe under `timeout` inside `sh -c`. Whether those,
  or the adapters not checked here, count a process of their own is for each adapter to check, outside this rule.

## Feedback, 24 November 2026

So an agent, or a person, can file a bug, a feature request or an idea as a public issue without sending anything a
box or a machine holds.

- **FBK-1 One command, one place.** `sandprobe feedback bug|feature|idea -title <one line> -body-file <file, or - for
  standard input> [-report <report.json>] [-provider <name>] [-o json] [-confirm <code>]` files a public issue on
  `github.com/summationai/sandprobe` and nowhere else: no other host, repository or service, and no telemetry. It
  takes no `-y`: FBK-5's code replaces it, and `-y` is a usage error that says so. The
  title is the kind's prefix (`Bug: `, `Feature: `, `Idea: `), then `-title`. The label is the one the issue forms
  already use: `bug` for a bug, `enhancement` for a feature or an idea. `-provider` names the provider or run mode the
  feedback is about, from a fixed list: the native providers, `aws-nitro`, `docker`, `exec` and the shipped recipes.
  Any other value is a usage error.
- **FBK-2 What it sends.** The issue body is the `-body-file` text as given, with CRLF read as LF and a leading byte
  order mark dropped. Then comes FBK-3's summary when `-report` names a report. Then a fixed environment block under
  the bug-report form's own headings: `### Sandprobe version` (this binary's `Version` and the Go version it was built
  with) and `### Where you ran it` (`GOOS/GOARCH`, then `-provider`, or else the summary's provider when it isn't
  `other`). Last is one line saying it was filed with `sandprobe feedback`. Nothing else is sent: no file, path, host
  name, user name or environment variable. The title is one line of at most 200 characters. The body is valid UTF-8,
  not blank, and at most 48 KiB. Neither may hold a control character, other than the body's tab and newline, or a
  Unicode format character, so the preview can't hide or reorder what is sent.
- **FBK-3 A summary, never the report.** `-report` reads a saved report as ANL-1 does. When that fails, the command
  is refused with ANL-1's fixed error, and nothing from the file is shown. The summary holds only values from fixed
  vocabularies: the provider, when FBK-1's list names it, else `other`; whether the run is valid and complete; SCR-2's
  score and what it is out of, for a valid run; and each check's catalog ID with its result, where a result outside
  OUT-1's own reads `other`. It never holds a path, a file name, an environment variable's name, a box's name or ID,
  a run ID or nonce, evidence, a reason, a receipt, a marker, or any other string from the report. A report's names
  and paths can identify a person's box, and the issue is public. The summary says, as ANL-1 requires, that the saved
  report was checked for structure only and not re-verified.
- **FBK-4 Refuse, never redact.** Before anything is shown or contacted, the whole outgoing text is scanned: the
  title and the body, with the summary and the environment block. When in doubt it refuses, since a refusal costs a
  rewrite and a leak can't be taken back. It refuses, at any length:
  - a private key (PEM or PuTTY), a JSON Web Token, a Slack webhook, and these keys and tokens, each known by every
    prefix its issuer uses: AWS key IDs (`AKIA`, `ASIA` and AWS's other `A???` ID prefixes), GitHub (`ghp_`, `gho_`,
    `ghu_`, `ghs_`, `ghr_`, `github_pat_`), Anthropic (`sk-ant-`), OpenAI (`sk-`), and Slack (`xox` and any letter,
    such as `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`, `xoxe-`, and `xapp-`, `xwfp-`, and the rotating
    `xoxe.xoxp-` and `xoxe.xapp-` forms);
  - an `Authorization` or `Proxy-Authorization` header with any value, and a `Bearer` value or a `Basic` credential
    anywhere;
  - a URL whose user information holds a password, even with an empty user name (`https://:x@host`);
  - a credential field: a key whose name says it holds a credential (one holding `token`, `secret`, `password`,
    `passwd`, `passphrase`, `api-key`, `access-key`, `private-key`, `client-key`, `key-data`, `certificate-data`,
    `credential` or `cookie`, the key `auth`, or `pass` or `pwd` as one word of a longer name such as `DB_PASS` or
    `MYSQL_PWD`, written with `-`, `_` or nothing between the words, in any case),
    with any value. That covers YAML, INI, JSON, environment-variable and header forms (`access-token: x`,
    `aws_secret_access_key = x`, `"refresh_token": "x"`, `AWS_SESSION_TOKEN=x`, `X-Auth-Token: x`), and a command-line
    flag with such a name (`--token x`).
  - the whole value: a value is read the way a shell joins one. Quoted parts (`"..."` and `'...'`) and unquoted parts
    next to each other are one word, so a placeholder part never excuses the rest (`TOKEN="<redacted>"x` is refused).
    Inside `"..."`, a backslash goes only before `$`, a backtick, `"` or `\`, as a shell's does, and stays before
    anything else; a word an escape changed must be a placeholder both as read and raw, every backslash kept, so
    `"tr\ue"` and `"\$TOKEN"` are refused. A field's or a header's value is every word up to a `#` after a space or
    the line's end, so `password: <redacted> x` is refused. A backtick is always data: it neither quotes nor ends a
    value, escaped or not, so text after inline code on the same line is part of the value, and `` `token: <redacted>`
    in the config `` is refused by design. Each word is checked exactly as read, nothing stripped, so `'true)'` isn't
    `true`; a placeholder must match whole, and when it's unclear where a value ends, the scan keeps reading and
    refuses. An unquoted `,` or `;` only separates words and never ends the value, so `TOKEN=<redacted>,x` and
    `TOKEN=<redacted>;x` are refused, and a list after a credential key on its line must be all placeholders; the same
    holds on a continuation line. A flag's and a `Bearer`'s value is one word, commas and backticks included.
  - an escaped name: each line is also scanned as its reader decodes it, with `\u`, `\U` and `\x` escapes and HTML
    numeric references decoded, so `"pass\u0077ord": x` and `&#112;assword: x` are fields like any other.
  - a value on another line: a credential field, flag or `Authorization` header, or a `Bearer`, whose line ends at
    the key, its separator, its scheme or a comment, takes the next line that isn't blank or a comment as its value.
    That covers a YAML value on the next line, JSON's next token, a YAML explicit key (`? token`), and a header's
    folded continuation. A line that ends with a credential key and no separator, followed by a line that starts
    with `:` or `=`, takes what follows that, or the next line, as the value. After any line naming a credential,
    with or without a value, each later line indented deeper
    than it continues the value, as YAML and folded headers allow, and must be a placeholder too. A YAML block scalar
    (`token: |` or `>`) is refused outright, whatever follows.
  - a credential in a document: the person's own body, and each fenced code block in it, is also parsed as YAML
    (with `go.yaml.in/yaml/v3`, the YAML organization's maintained module and this command's one dependency) and,
    separately, as JSON, since YAML reads most JSON but not a key whose colon is on the next line. YAML is read
    document by document to the end. JSON is read as a token stream, never into a map, so a repeated key can't hide
    an earlier value. In each one that parses, every mapping key named as above, or `Authorization`, written or
    through a YAML alias, is refused unless its value is empty or a placeholder; an alias, a merge, a tag or a
    non-empty mapping or list as the value is refused. A key's escapes are decoded first, so `"pass\u0077ord"` is
    `password`. Fences follow CommonMark: a block, after any blockquote or list markers, closes only at a fence of the
    same character at least as long as its opener, so a longer fence holds shorter ones, and each block's own content
    is walked again, fences and all. A parse that fails adds nothing, and its error is never shown. This walk only
    adds refusals to the line rules.
  - a walk it can't finish: fenced blocks nested more than 16 deep; JSON nested more than 10,000 containers deep, the
    root counted, whether the deepest is empty or not, including the decoder's own depth error; a JSON walk stopped by
    anything but a plain syntax error or the document's end; a YAML document past the parser's own depth or alias
    limits; or a parser that panics. The refusal names the limit; it
    never passes what it didn't read.

  The only values these let through are obvious placeholders: `<...>`, `[...]`, `$NAME` or `${NAME}`, a mask such as
  `***` or `xxx`, and `redacted`, `none`, `null`, `nil`, `empty`, `unset`, `hidden`, `masked`, `true`, `false`, `~`
  or `n/a`. A `Bearer` value may also be an ordinary word, such as `token` or `authentication`, and a `Basic` value
  is a credential only when it has a digit, `+`, `/`, `=`, or an upper-case letter after its first. Exactly two of
  Sandprobe's own lines print its Secrets area or category as a key, and they aren't credential fields: `profile`'s
  `secrets: map[...]; finding IDs [...]` and `compare`'s `  ● Secrets: <a Secrets check's question>`, as 0.3.0's
  `compare` printed it (CMP-2 now writes `Secrets › <question>`, which is no key), each matched
  whole, with only counts, check IDs and the catalog's own questions inside. `secrets: x` or any other line is refused
  like the rest. Two patterns need
  a length, since nothing else marks them: a hex string of 32 or more digits, and a base64 string of 32 or more
  characters with a digit, an upper-case and a lower-case letter. It also refuses home-directory paths:
  `/Users/<name>`, `/home/<name>`, `C:\Users\<name>`, and this machine's own home directory unless that is `/` or
  `/root`. Any match refuses the whole issue and exits 2. The refusal names each match's place
  (the title, or the body's line and column) and its pattern, and shows `[REDACTED]` for the matched text, which it
  never prints. Sandprobe never rewrites the text: the person or the agent edits it and runs the command again.
- **FBK-5 Consent to exactly this issue.** A person's explicit consent is bound to exactly what is posted, and it
  replaces AGT-3's `-y` for this command. FBK-4's scan always comes first: a credential refuses the issue whatever
  `-confirm` holds.
  - **Preview.** Without `-confirm`, the command sends nothing and makes no link. It prints the preview: that the
    issue is PUBLIC, the repository, the gh account it would be filed as (or that it would be a link), the title, the
    labels and the body. Then it prints a confirmation code, and exits 3. The code is the first 12 hex digits of
    SHA-256 over a fixed encoding of exactly what would be posted: the repository, the way it goes (`gh` or `link`),
    the gh login, the labels, the title and the body, as they would reach gh's arguments and standard input. `-o json`
    doesn't change it.
  - **Confirm.** `-confirm <code>` files, or prints the link, only when the code equals the code of what it would post
    now. Otherwise it files nothing and makes no link, and exits 3 with AGT-5's error `feedback.changed`. The error
    says whether the way it goes changed (the code matches the same issue as a link, but gh is now signed in) or the
    issue did, and that it must be previewed and approved again. It never prints the new code. An edit, another
    account, another label, another way, or another Sandprobe version all change the code.
  - **Terminal.** Only when UX-7's own gate for its keys allows (AGT-1): standard input and output both terminals,
    standard output the process's own, the process in the terminal's foreground process group, and none of `CI`,
    `SANDPROBE_NO_KEYS` or `TERM=dumb` set. Then, without `-o json` or `-confirm`, it may ask the person instead,
    after the preview: "File this public issue as @<login>? Type yes:", or, for a link, "Print the
    link to file this public issue yourself? Type yes:". It reads the answer from `/dev/tty` and accepts only `yes`.
    Anything else, or no `/dev/tty`, sends nothing and exits 3. A background job, a terminal that isn't this session's
    own, or CI is never asked, so a read can never stop it.
  - **Agents.** An agent never answers that prompt and never files on its own judgement. It shows its person the
    exact title and body, says the issue is public, names the account, and asks ("May I file this public issue as
    @<login>?"). It runs again with `-confirm <code>` only after a clear yes in the conversation, and changes nothing
    in between.
- **FBK-6 Through gh, or a link.** Sandprobe files through `gh` when gh is on PATH and one read-only query,
  `gh api graphql --hostname github.com -f query=<a fixed query>`, returns the signed-in account's login and its
  permission on
  summationai/sandprobe, with the login in GitHub's own form (letters, digits and single hyphens, at most 39). It runs
  `gh issue create --repo github.com/summationai/sandprobe --title=<title> --body-file -`, with the body on standard
  input. It adds `--label=<label>` only when that account may triage the repository; an issue from any other account
  arrives without a label, its kind in its title's prefix. Each value is one argument, never a shell string, and it
  never adds `--attach`. The repository names
  its host, so `GH_HOST` and `GH_REPO` can't move it. gh uses its own sign-in: Sandprobe never reads a token, from the
  environment or from gh, and never prints gh's error output, only its exit status. An issue counts as filed only when
  gh exits 0 and prints a URL under `https://github.com/summationai/sandprobe/issues/`. Without gh, Sandprobe files
  nothing. On a confirmed run only (FBK-5) it prints a link that a person opens to file the issue; a preview never
  prints it, since opening it sends the draft to GitHub. The link is
  `https://github.com/summationai/sandprobe/issues/new`
  with `template` and `title`, and the form's own fields. `template` is `bug-report.yml` for a bug, or
  `feature-request.yml` for a feature or an idea; the form adds its label, where a `labels` parameter would fail for
  anyone who can't triage. The body and summary go in the form's main field (`actual` or `details`), and the
  environment goes in `version` and `platform`. Every value is percent-encoded. The link is at most 8,000 characters.
  A longer one leaves the main field out, and the body and summary are written to a new file only the person can
  read, whose path is printed, for the person to paste. When gh fails, or exits 0 with no such URL, the command prints
  the link, says nothing is confirmed filed and to check the repository's issues before opening it, and exits 5.
- **FBK-7 Output.** In text, the command prints the preview, then the code and what to do with it, or, once
  confirmed, the issue's URL or the link. `-o json` prints one document: `repo`, `public` (always `true`), `kind`,
  `title`, `labels`, `body`, `via` (`gh` or `link`) and `filed`. It adds `account`, the gh login, when it goes
  through gh. A preview adds `needs_approval: true` and `confirm`, the code. A confirmed run adds `url` (the issue's,
  or the link), `body_file` when one was written, and `note` when gh failed. A refusal under `-o json` is AGT-5's
  error with code `feedback.refused` and `matches`, each with `where`, `line`, `column`, `pattern` and `text`, which
  is always `[REDACTED]`. Exit codes: 0 when filed or when the link is printed; 2 for usage (`-y` included) or a
  refusal; 3 for a preview, a no, or a code that doesn't match; 5 when gh failed.

## Declared provider for run exec, 24 November 2026

On `run exec` the four provider-endpoint checks are off by default as `opt_in` (PRV-15), so Cloud access reads "Not
tested: opt in with -provider-endpoints SEC-4,AMP-7 if your provider's terms allow" and the score is out of six. On a
provider whose PRV row excludes those checks, that red can never be acted on, and an agent running a fix loop chases
it forever. PRV-17 lets the operator name the provider, so this binary's own PRV row for it decides those checks, as it
already does for that provider's native adapter. It amends PRV-15, SCR-2, GRD-3, ANL-1, AGT-3, AGT-6, OUT-1 and OUT-4
in place, each pointing here.

- **PRV-18 Modal lifecycle.** `sandprobe run modal -y` makes the Modal row's `default` sandbox, and only that: no
  `-variant` (one is a usage error), sidecar, allowlist, volume, GPU, tunnel or injected secret. Everything else on Modal stays in the proof of
  concept (POC-1 to POC-9), or goes through `run exec`.
  - **Workspace.** Nothing runs without `SANDPROBE_MODAL_WORKSPACE`, a name of lowercase letters, digits and hyphens.
    Modal's SDK, built into the binary, reads the token from its own environment variables or
    `~/.modal.toml`; no other code does, and it's never printed, logged or sent into the sandbox. Every call but the auth
    exchange waits for the server's own answer that the token belongs to that workspace (POC-1's gate), so a token
    for another one creates nothing. `plan`, `providers` and an unapproved `run` make no SDK call and read no token.
  - **Order.** After approval: the canary is proven and its slot reserved (HCN-5), then the gate, the App and the image,
    then a private journal, `~/.config/sandprobe/modal-<run tag>.state` (mode 600), then the create. The journal holds
    the workspace, the App, the image ID, the random run tag the create request carries, and the time; the ID is added
    once the create returns it. If the journal can't be written nothing is created; if the ID can't be added, nothing
    runs in the sandbox and it's terminated by that ID.
  - **Scope.** PRV-5's four are skipped as `provider_terms`, so Cloud access is not applicable and the score is out of
    five (SCR-2). PER-5 is skipped: there is no reset. Traffic goes only to the canary. The sandbox keeps Modal's default
    size, CPU only, and has a 15-minute timeout as a spend backstop; the run's own deadline is ten minutes.
  - **Deletion.** Terminate by the create-returned ID only, then confirm: the sandbox polls finished, and a list of the
    App's running sandboxes by the run tag is empty. It has three minutes of its own, whatever ended the run. The
    journal is removed only then. A create that returned no ID, or anything short of that confirmation, keeps the
    journal, names it, and exits 7; nothing is ever terminated by tag.
  - **What stays.** The App `sandprobe` and the built image stay in the operator's workspace. The plan, the residual and
    the page say so, with `modal app stop sandprobe` for the App.
  - **Errors.** Only a fixed category and a gRPC code (POC-1).
  - **Stop (AGENTS rule 7, POC-5).** POC-5's network counts have no rule for an open sandbox, but its other checks of
    the probe's document apply, after the deletion and before any report. SEC-1 naming anything the image's own config
    doesn't declare (`PATH`, `LANG`, `GPG_KEY`, `PYTHON_VERSION`, `PYTHON_SHA256`) and the host didn't set, SEC-3 naming
    any file but the image's own `/etc/shadow`, or an evidence line that isn't exactly the probe's own sentence, stops the run. No
    report is written. What's kept is a private note (mode 600, beside the journals): the rule with its names or paths,
    never a value, the times and the cleanup. Neither the terminal nor `-o json` repeats the names or paths,
    nor the reason a document is invalid, which can quote them. The run
    exits 8, or 7 when the sandbox isn't confirmed gone. Evidence that can't clear the gate (the canary not armed, not
    read or overloaded, or a document that is invalid or doesn't parse) writes no report and exits 5, or 7. POC-5's other cases, cross-tenant
    and host access among them, have no check here that proves one; rule 7 still binds whoever reads the report.
- **PRV-17 A declared provider.** `sandprobe run exec -provider <name> ...` and `sandprobe plan exec -provider <name>
  ...` name the provider the box runs on.
  - **The name comes from the person, never from an agent.** The operator names it. An agent running Sandprobe never
    infers it from the exec command, a hostname, the environment, a report or any provider-like text, and never adds
    or changes it to turn a red category into not applicable. The CLI's own help (`sandprobe help`) says so today,
    beside the flag; AGT-2's `sandprobe guide` isn't built yet, and when it is, its output and every block it
    installs say so too (AGT-3). No remediation text suggests the flag: not Cloud access's "Not tested" reason, not a
    check's fix or `explain`, and not the fix of an error the flag didn't cause. The rest of this rule, and security's
    acceptance of `-min full` below, rest on this.
  - **The binary's table decides what the name excludes, never the report.** `<name>` must be a key of this binary's
    own table of PRV-row exclusions (`host.TermsExclusions`, the table SCR-2 already scores native adapters by:
    today `baseten`, `boat`, `cloudflare`, `daytona`, `e2b`, `exe.dev`, `modal`, `sprites` and `vercel`), spelled
    exactly as the table spells it. Nothing a report, the box or the environment says adds a name or changes an entry.
    There is no alias, no case folding and no environment default, so the declaration is typed for each run, like PRV-15's attestation.
  - **Reviewed scope, not the provider's terms.** An entry is Sandprobe's reviewed scope for that provider: for some
    providers it follows their published terms, and for others, Modal's among them, it is the project owner's own
    rules of engagement (PRV-5). So nothing PRV-17 prints claims the provider's terms exclude an endpoint. It says
    "Sandprobe's reviewed scope for <name> excludes these provider-owned endpoints", with the entry's own reasons.
  - **Usage errors, before the plan exists (exit 2):** a name the table lacks, `exec`, `docker`, `aws-nitro`,
    `kubernetes` and a differently cased key among them, where the error lists the valid names, sorted, and never
    echoes the value given, since it may be pasted text or a credential; an empty value; the flag anywhere but `run
    exec` and `plan exec` (a native adapter is already its own provider, a shipped recipe keeps RCP-4's exclusions,
    `run docker` runs these checks, and an offline command reads only what a report records); and
    `-provider-endpoints` naming a check the declared provider's entry excludes, since that scope keeps it off. That
    error's fix is "leave out -provider-endpoints for the checks that scope excludes", never a change of provider.
    Every entry today excludes all four, so with `-provider`, any `-provider-endpoints` value is refused. The rule is
    per check so that an entry excluding fewer leaves the rest `opt_in`, and attestable.
  - **What it changes in the run.** Each check the entry excludes is skipped with the entry's own reason and kind
    `provider_terms` (PRV-5, GRD-3), in place of PRV-15's `opt_in` skip. Any other check of PRV-15's four keeps its
    `opt_in` skip, which `-provider-endpoints` may lift as before. Nothing else changes: the same checks run, nothing
    more is contacted, no finding or completeness changes (GRD-3's skips touch neither GRD-1 nor GRD-2), and the box is still an
    existing box under PRV-15: non-mutating checks only, no reset, its residual kept.
  - **Recording.** The report still records the run as provider `exec` (`run.provider`). The host writes the name to
    the manifest's `declared_provider`, beside `SkipKinds` and `Attested`: like them it is a policy input the host
    fixed before the probe ran, so it belongs in the host's record (GRD-5), and it never reaches the probe's input.
    Only `run exec` writes it, only when `-provider` was given, and a report carrying it declares `sandprobe/6`
    (`sandprobe/5` before the letter left OUT-1, AGT-6). `Execute` refuses, before anything runs, a name the table lacks, a run that isn't `run exec`'s (kind
    `opt_in`, no workload contract, no EVD-10 protocol), and exclusions that don't carry each of the entry's checks
    with the entry's own reason, unattested; so this binary never writes a report its own reader refuses.
  - **Policy.** For a report whose `run.provider` is `exec` and whose manifest has `declared_provider`, SCR-2's policy
    kinds come from that name's entry in this binary's table: each check it excludes is `provider_terms`, and the
    rest of PRV-15's four are `opt_in`. Without `declared_provider`, or with a name the table lacks, an `exec` report's
    policy is PRV-15's `opt_in` for all four, unchanged.
  - **Every human-readable plan and result says it's the operator's word.** Wherever a declared provider makes Cloud
    access not applicable, the text says "The operator declared the provider as <name>; Sandprobe did not verify
    it". The not-applicable row reads SCR-2's fixed reason, then that sentence: "Not applicable: this box holds no
    cloud identity of yours that Sandprobe checks here; Sandprobe's reviewed scope for <name> excludes these
    provider-owned endpoints. The operator declared the provider as <name>; Sandprobe did not verify it". The line
    beside the score reads "Cloud access isn't counted: Sandprobe's reviewed scope for <name> excludes these
    provider-owned endpoints (<reasons>). The operator declared the provider as <name>; Sandprobe did not verify it.",
    with the entry's reasons from this binary's table, never the report's text. Both reach every rendering that shows
    the row and the line: the run's own summary, `scorecard`'s text and its `-out` page, and the run's page. In the
    card's JSON the row carries `scope` and `declared_provider`, both the name, so a reader of the rows can tell it
    from a native adapter's not-applicable row, which carries `scope` alone. A workload exposure card (SCR-4) never
    carries `declared_provider`, since the managed workload runners never declare one, and its validator refuses a
    card that does, so the workload page never shows a declared provider at all; its native rows read the same
    reviewed-scope line. A workload card is unauthenticated input: SCR-7 rebuilds every row it shows, so no string
    the card stores, `scope` and `declared_provider` included, reaches output on its own word. The line beside the
    score names only a table key, else "the provider", and adds the unverified sentence only when the row's
    `declared_provider` equals that key.
  - **Plan.** Before approval (AGT-3), the plan has a "Provider, as the operator declared it (-provider, PRV-17)"
    section, which reads "Cloud access: not applicable — Sandprobe's reviewed scope for <name> excludes these
    provider-owned endpoints. The operator declared the provider as <name>; Sandprobe did not verify it.", then each
    excluded check as "<ID> (<what it reaches>) stays off: <the entry's reason>". Its box-named destinations read
    "none: <IDs> stay off: Sandprobe's reviewed scope for <name> excludes these provider-owned endpoints (PRV-17)", and
    its residual ends "The operator declared the provider as <name> with -provider; Sandprobe did not verify it, and
    Cloud access isn't counted on that word alone (PRV-17)." Its JSON carries `declared_provider` and those lines as
    `declared`. `plan`, and a run that isn't approved, contact nothing, as before.
  - **`-min 6`** with `-provider` is refused before anything runs in the box (OUT-4), with "-min 6 can never pass on
    exec: Cloud access is not applicable, since Sandprobe's reviewed scope for <name> excludes these provider-owned
    endpoints, so the score is out of 5. The operator declared the provider as <name>; Sandprobe did not verify it".
  - **ANL-1.** A saved report is refused (exit 2, as for any refused input) when: `declared_provider` is present but
    empty or null, or present under `sandprobe/1` to `sandprobe/4` (AGT-6); it is on a report whose `run.provider`
    isn't `exec`, or beside any workload contract (WGR-1, RUN-17's included) or EVD-10's protocol; it names a provider
    this binary's table lacks, a report from a newer binary with a newer entry included, since its kinds can't be
    checked; any check the entry excludes isn't skipped with kind `provider_terms`, or is attested; or any other check
    carries `provider_terms`. As today, `provider_terms` on a `run exec` report without `declared_provider` is
    refused, so editing `SkipKinds` alone still changes nothing.
  - **Compare.** A report with a declared provider against one without it, or one declaring another provider, is a
    changed setup (CMP-1's `declared_configuration`, exit 5), never like-for-like and never an improvement, even when
    their `provider_terms` skip sets are the same.
  - **What this changes, and why it's acceptable.** Until now only a native adapter could make Cloud access not
    applicable, and there the binary itself created the box through that provider's API, so the run established the
    provider. With PRV-17 the operator's word at run time does it for an existing box. That word can't be checked from
    the box: GRD-5 never lets anything the box returns shrink the score, and asking the provider's own endpoints what
    it is would contact exactly what its reviewed scope excludes. A host-side hint such as the command's first word
    (`modal`, `sprite`) is the operator's own text too, and proves nothing about where the shell lands. So the
    declared provider is the operator's word, recorded like the rest of the manifest. It is acceptable because:
    - It is never a pass (rule 1). A not-applicable row is never green; it leaves only the denominator; SCR-5's
      coverage still counts SEC-4 and AMP-7 as skipped; and no finding changes. Under `opt_in` and under a
      declared provider alike those checks never ran, so a false declaration turns a red "Not tested" into "Not
      applicable", never an untested check into a proven one.
    - It has the same standing as the two declarations `run exec` already rests on: PRV-2's that the box is the
      agent's and not production, and PRV-15's per-check attestation that the provider's terms allow a check. Each is
      typed for each run, shown in the plan before approval, and recorded in the report.
    - It comes from the person, never from the agent the score is about (above), and every human-readable plan and
      result says Sandprobe didn't verify it.
    - `compare` never reads adding or changing it as an improvement (above), so a fix loop or CI gate that compares
      runs sees a changed setup.
    - Saved reports gain no new forgery. Today an edited `run exec` report whose `run.provider` is changed to a native
      adapter's name, with its four kinds changed to `provider_terms`, already reads out of five, and ANL-1 already
      says such an edit can't be told apart; what SCR-2's tests pin is narrower, that editing the kinds alone changes
      nothing. That still holds for every report without `declared_provider`, and for one with it, whose kinds must
      equal the named entry's. Adding `declared_provider` means editing it, the kinds and the schema together: an
      edit of the same kind as changing `run.provider`, which ANL-1 already can't detect.

    The cost, stated: a gate on `-min full` alone accepts 5/5 once Cloud access is not applicable (OUT-4), so an
    operator who names a provider falsely turns that gate's exit 6 into 0 for Cloud access. The security review
    accepted this under the trust boundary above: it holds only while the name comes from the person and every result
    says it is unverified. Regression-sensitive gates use `compare` or OUT-1's JSON, as OUT-4 already says. Nothing
    stronger is available without trusting the box or contacting the provider.

## Fix loop, 24 November 2026

So a run ends with changes a person, or their agent, can make to the sandbox's own config or code, and with the way to
see whether each one worked: run, fix, rerun, compare. The catalog's fix sentences stay as they are: some can't be done
on the provider at hand ("mount /proc/sys read-only" means nothing on Modal, which runs gVisor), so `fix` gives a
platform's own setting only where a rerun proved it there, and labels everything else general advice.

- **FIX-1 One saved report in, actions out.** `sandprobe fix <report.json> [-platform <name>] [-o json]` reads one
  saved report under ANL-1's input rules. It makes no network call, writes no file and starts no process, so it never
  creates, changes or contacts a box. It has its own flags. Like `scorecard`, `profile` and `compare`, every rendering
  says the report was structurally checked only and not re-verified: ANL-1's saved-report note in text, and
  `verification: "structural_only_unauthenticated"` with that note in JSON. An invalid run (GRD-5) has nothing to fix:
  no actions, a fixed note, exit 5. An incomplete run keeps its plan, and says so: the JSON's `complete` is false and
  `unknown` lists the grade's unknown check IDs, the text opens with "This report is incomplete: n checks unknown; a
  rerun may change the plan.", and it exits 5, as `scorecard` does. A complete run exits 0, with or without actions;
  2 is usage or a refused report.
- **FIX-2 What fix acts on.** A check is red for `fix` when its result is a finding above Info (SCR-2's bar), or when
  it is unknown while the agent holds a capability that TWN-4 says keeps that check's refusals from standing. `fix`
  decides that only from structured data: the report's AMP-2 is a finding, and its identity's capability sets
  (`cap_eff`, `cap_prm` and `cap_amb`, each a hex set) hold one of the powers TWN-4 names for the check's catalog
  mechanism: `CAP_SYS_ADMIN`, `CAP_SYS_MODULE` or `CAP_SYS_PTRACE` for any of them; for a file or block-device read,
  also `CAP_CHOWN`, `CAP_FOWNER`, `CAP_SETUID`, `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH` or `CAP_SETGID`; for another
  process's files, also `CAP_SETUID` or `CAP_SETGID`; for write permission, also `CAP_CHOWN`, `CAP_FOWNER`,
  `CAP_SETUID`, `CAP_SETGID` or `CAP_DAC_OVERRIDE`. A set that doesn't parse, or an identity that is missing, decides
  nothing, and the check stays undecided. `fix` never reads a check's reason or evidence, so text a report holds
  can't change what is offered, its order, what could turn green or what is undecided. Such a check can only join the
  `run-as-user` action, which AMP-2's finding already offers; it never adds or drops an action. Every other unknown,
  and every category red because nothing in it was tested, is listed apart by check ID or category name with fixed
  text: as not decided by a setting, or, for Cloud access left untested, as not an action for an agent (FIX-5).
- **FIX-3 Actions.** `internal/fix` holds one table. Each action has an ID, a plain title, its trigger checks, and,
  per platform, the snippet a rerun proved there (FIX-4). Every catalog check that can be red is the trigger of exactly
  one action, and a test keeps it so. An action is offered only when one of its triggers is red, so a side effect
  never offers one: running as non-root is offered only when AMP-2 is found, never for a readable `.env` on a box whose
  agent isn't root. An offered action addresses its red triggers, and `run-as-user` also FIX-2's capability unknowns.
  A rerun on one baseline can't show the same change clears the same check on another box (`/etc/shadow` may close
  while a credential in the agent's home stays open), so a red check that a snippet's rerun also cleared, beyond its
  triggers, is only a side effect: the action lists it under `may_also_clear`, and the text says "this may also clear it; a
  rerun proves it" and that each keeps its own action; it never removes, merges, demotes or shortens the check's own action, never counts toward the
  action's rank or the categories it could turn green, and never takes the place of that action's general advice.
  The report holds no structured data that would show a side effect covers every target, so no exception exists.
  Each action in the output has its ID, title, the check IDs it addresses (findings and unknowns apart), those it may
  also clear, the categories that could turn green, whether a rerun tested its snippet on this platform
  (`platform_tested`), and either that snippet with its known costs and where it was proven, or the catalog's fix
  sentence for each of its checks (`catalog.Guide`), labelled "General advice, not proven on this platform". A proven
  action whose triggers include a check its snippet wasn't proven to clear gives that check's general advice too.
- **FIX-4 Proven snippets only.** The platform is the report's run provider when it is in FBK-1's fixed list
  (`docker`, the shipped recipes such as `kubernetes`, and the native providers); for a `run exec` report, `-platform`
  names it from the same list, and without it the platform is unknown. `-platform` on any other report is a usage
  error, as is a name outside the list. It is the person's own declaration: an agent passes it only when its person
  names the platform, never by inference. A `run exec` report's declared provider (PRV-17's `declared_provider`)
  never picks the platform either: it decides only what SCR-2 counts, so a `-provider modal` report whose Cloud
  access is not applicable lists Cloud access nowhere, and still gets Modal's snippets only with `-platform modal`. Snippets exist for two platforms, each from a rerun:
  - **Modal**, from three `run exec` rounds on one throwaway sandbox per round (python:3.12-slim-bookworm, commands
    through the SDK's `Sandbox.exec`), 24 November 2026. Round 0, Modal's defaults (root, network open): 0/6. Round 1,
    `run-as-user` and `block-network`: 3/6. Round 2, plus `clean-env` and `protect-home`: 4/6. `run-as-user`: in the
    image `useradd -m -u 1000 -s /bin/bash agent`, and the agent's commands through `setpriv --reuid=1000
    --regid=1000 --init-groups --inh-caps=-all --ambient-caps=-all --no-new-privs <cmd>`; it cleared AMP-2, SEC-3,
    SEC-5, PER-2 and AMP-8.sys, and the TWN-4 unknowns AMP-1, AMP-4 and AMP-8.blk. `block-network`:
    `modal.Sandbox.create(..., block_network=True)`; it cleared EGR-1, EGR-2, EGR-5.22, EGR-5.80, EGR-5.8080 and
    EGR-5.53u. `clean-env`: `setpriv ... --reset-env <cmd>`; it cleared SEC-1. `protect-home`: in the image `chown -R
    root:root /home/agent; chmod 0755 /home/agent; mkdir -p /work; chown agent:agent /work`, and `workdir="/work"` on
    exec; it cleared PER-1, PER-3 and PER-4. The last two were proven with `run-as-user` in place, so when both are
    offered they come after it. A round changed two things at once; each check is credited to the change whose
    mechanism reaches it (users and files, or the network, or the environment). SEC-2 stayed found in every round (it
    counted `run exec`'s own launcher shell, which LNC-1 now leaves out) and AMP-3 was never found, so no Modal snippet
    claims either.
  - **Docker**, from FIX-9's fixture test, each action alone from a baseline where its triggers are red:
    `run-as-user` `--user 1000:1000 --cap-drop ALL` (AMP-2, SEC-3, PER-2, and the TWN-4 unknowns of a root agent
    holding `CAP_SYS_PTRACE`); `no-new-privileges` `--security-opt no-new-privileges` (AMP-3); `block-network`
    `--network none` (EGR-1, EGR-2, each EGR-5 port); `protect-home` `--read-only --tmpfs /tmp` (PER-1 to PER-4, even
    as root); `isolate-processes` `--user` set to a user other than the agent's for the container's own processes, with
    the agent through `docker exec -u` (`-as` in `run docker`) (SEC-2, SEC-5); and `clean-env`, the image without the
    `ENV` line that held the key (SEC-1). Unsetting a variable with `-e NAME` is never offered: on a host that exports
    NAME, it passes the host's own value into the box.
  Every other action and platform gets general advice.
- **FIX-5 Costs and limits.** Each snippet carries its known costs as fixed text. `block-network` cuts the agent off
  from its model API too, on Modal and on Docker. DNS (EGR-1) and UDP 53 (EGR-5.53u) then have no receipt, which isn't
  proof (KND-2), so Exfiltration's row turns green with a "not proven: DNS, UDP 53" line. On Modal it is the only
  egress setting proven; `fix` makes no claim about Modal's domain or CIDR allowlists, which this loop didn't test.
  `protect-home` on Docker makes the whole root read-only: the agent writes only to `/tmp` and to what is mounted for
  it. Cloud access red because SEC-4 and AMP-7 were skipped (PRV-15's and RCP-4's defaults) is never an action and
  names no flag: `fix` lists it under "Not an action for an agent", saying it wasn't tested because its checks contact
  the provider's own endpoints, outside Sandprobe's reviewed scope for this run, and that only the person decides
  whether they are tested. `fix` never suggests `-provider`, `-provider-endpoints`, `-platform` or a provider name, anywhere: an
  agent never infers, adds or changes the provider to clear a red; only the person declares it. A category red because
  the run had no canary (HCN-5) says to rerun with one.
- **FIX-6 Ranking.** An action could turn a category green when that category is red on the report's scorecard
  (SCR-2) and every check that holds it red, each finding above Info and each unknown, is among the action's
  addressed checks (FIX-3: its red triggers and capability unknowns, never its side effects), together with those of
  an action it comes after (FIX-4) when that one is offered too. A category
  red because nothing in it was tested never turns green from an action. Actions that could turn at least one
  category green come first; then more checks addressed, side effects not counted; then more categories; then table order. An action proven
  only with another in place is moved to just after it.
- **FIX-7 The loop.** The output ends with the next steps for the report's run mode, as templates: apply the top
  action, with the person's OK; rerun into a new folder; compare; run `fix` again. For `run docker`: `sandprobe run
  docker <image> -as <user> -y -out <next-folder> -- <your docker run options, with the fix>`. For `run exec`:
  `sandprobe run exec -as <user> -y -out <next-folder> -- <your command>`. For a recipe:
  `sandprobe run <recipe> -as <user> -y -out <next-folder>`; for a native provider: `sandprobe run <provider> -y -out
  <next-folder>`, each name from the fixed list; for any other report: `sandprobe run <the way you ran it> -y -out
  <next-folder>`. Then `sandprobe compare
  <report.json> <next-folder>/*.json`, whose score line and "Got better" show what changed (CMP-2), with "No longer
  found, but not proven" never read as fixed, and `sandprobe fix <next-folder>/*.json` with the same flags as before. The image, user, command and docker
  options stay placeholders: the report doesn't keep the person's command, and what it does keep is untrusted
  (FIX-8).
- **FIX-8 Predictions, built from fixed text only.** Each action says its checks "should clear; a rerun proves it".
  `fix` never marks a check fixed, never edits a report, and its JSON has no pass or fixed field: only a rerun and
  `compare` show what changed. Its text and JSON (`schema: "sandprobe.fix/1"`) are built only from catalog check IDs,
  the catalog's and SCR-1's fixed text, the action table and fixed sentences:
  never from a string the report holds (a box name, evidence, a reason, a finding's text or fix, a provider ID, a
  path), as SCR-3 requires of the scorecard. The report's provider becomes a platform only by matching the fixed list;
  anything else is "unknown". Text output wraps at 80 columns (UX-9).
- **FIX-9 The Docker proof.** With `SANDPROBE_FIXTURES=1` and local Docker only, a test builds a weak image like the
  demo's (debian, an `agent` user with a writable home, a secret-shaped `ENV`, run as root on the default network) and
  three variants: without the `ENV` (clean-env's image change), with a long-running process of its own started by
  `--entrypoint`, and both. It runs `run docker` and `fix -o json` from four baselines, and reruns with one action's
  options added: from the root box, every offered Docker action alone; from the agent's own user, `protect-home`;
  from a root agent holding `CAP_SYS_PTRACE`, `run-as-user`, which must take TWN-4 unknowns; and from the image's own
  process running as the agent's uid, `isolate-processes`. Each time it asserts that every check the action addressed
  was red and is no longer, and that every category it said could turn green is green; and, over all of them, that
  every check the table claims for Docker was shown red, then cleared. It then runs the loop, top action first, until
  `fix` offers nothing, from the bare box and from the one whose own process runs, and asserts each ends at a full
  score that never fell on the way. Each run's own teardown removes its container, canary and network by ID; the test
  removes only the image tags it built.

- **FIX-10 The Modal bridge example.** `examples/modal/bridge.py` reaches one throwaway sandbox of the person's own
  for `run exec`. Its app name and tag key are fixed in code, never read from its state. `create` first reserves the
  state path as a new private file (`O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600, then checked to be a regular file owned by
  the person with one link), so a path in the way fails before anything is created. It then creates the sandbox with
  a random tag in the create request itself (`tags=`, modal 1.5.5 or later; an SDK without it fails before creating
  anything), CPU only, with a 15-minute timeout as the backstop, and at once writes the ID create returned with the
  tag, then fsyncs the file and its directory. If anything after create fails, a Ctrl-C or SIGTERM included, it
  terminates the sandbox through the object create returned, never through a lookup, confirms it finished, removes
  the state it wrote, and exits 1 naming only the failure's type; a termination it can't confirm keeps the state,
  names the sandbox's ID and its timeout, and exits 7. A create that fails without returning removes the reservation
  and says a sandbox may still exist until its timeout. `sh` and `rm` read the state only as such a private file (no
  symlink, regular, the person's own, one link, no group or other bits, at most 4 KiB, exactly its four fields with no
  duplicate, each in its form) and, before any exec or terminate, list the live sandboxes of the fixed app carrying
  the recorded tag: exactly one, whose ID is the recorded one, or they refuse, exit 2 and touch nothing. They act on
  that listed sandbox, never on an ID looked up alone. When none is listed, the sandbox may simply have ended at its
  timeout: `rm` says so, and that the person removes the state file once Modal shows it finished. `rm` then confirms
  the sandbox finished and nothing with the tag still runs before it removes the state, and exits 7 otherwise. The
  token stays with Modal's SDK; nothing reads or prints it. No SDK text reaches the terminal, on any path: one
  boundary around each verb's whole lifecycle (the exec, the stdin pump and both output pumps, the wait, every list,
  terminate and poll) turns any exception into a fixed line with the exception's type alone and the verb's documented
  exit (`sh` 1, `rm` 7 once its guard passed, a refusal 2); each pump thread catches its own exception and records only
  its type for the main thread to report; and `sys.excepthook`, `threading.excepthook`, `sys.unraisablehook` and
  `warnings.showwarning` print a fixed line and a type only, while the SDK's logging is off. A traceback, `str(e)` or
  `repr(e)` is never printed, under `python -X dev` too. `sh` owns every pump's lifetime, so none outlives its exit
  path, in one ordered sequence: (1) the remote process ends, or waiting for it fails; (2) a stop event goes to every
  pump, and the stdin pump (2 s) and both output pumps (5 s each) are joined within those bounds; (3) only then is the
  shared failure slot read, once, and nothing writes it after; (4) stdout and stderr are flushed, and the bridge
  exits. The stdin pump reads descriptor 0 with `select` (0.1 s) and `os.read`, never a buffered stream, and the
  output pumps write descriptors 1 and 2 with `os.write`, so no pump holds a stream lock at exit; a closed or invalid
  descriptor 0 reads as end of input, and `/dev/null` and a regular file end at their end. The remote's own exit code
  passes through only when waiting succeeded, no pump failed and every pump finished in time; a pump's failure, a
  failed wait or a join that runs out is exit 1 with a fixed line and the type, and a pump still running then makes
  the bridge leave with `os._exit` after the flush, so the interpreter never finalizes around it. Input the remote
  no longer wants is told apart by order, never by an error's text. Every stdin call (each write, drain and
  end-of-input, not only each loop) first passes one gate: under the lock the main thread holds to mark the remote's
  end, it checks that mark, and the call counts as begun only once it passed the gate. So, by construction, no stdin
  call begins after the remote's end is marked: the pump stops quietly at the gate, input that comes later is never
  sent, and nothing it would have done can fail. Only a call already past the gate, in flight when the remote ended,
  may still fail, and it counts, even when the remote's end caused it, since the bridge can't tell that from a broken
  session (the safe side: exit 1, never a false success). Marking the end never waits for a call in flight.

  Its offline delayed-stdin fixture cancels and joins its writer before closing that writer's pipe descriptor;
  a callback already in progress may observe BrokenPipeError when the fake remote has ended. No delayed write
  may target a descriptor reused by another subprocess. This changes test ownership only, never bridge behavior.

## Tests

Every test here runs on public data. Tests that need a saved report use `demo/reports` and `test/reports`, which
are runs of local Docker boxes against the local canary (`test/reports/README.md` rebuilds them). Replays of recorded
provider runs stay with the operators' records (AGENTS rule 9), not in this repository.

| Extension rule | Tests |
| --- | --- |
| FIX-1 to FIX-8 | `internal/fix/fix_test.go`: every red-capable catalog check is the trigger of exactly one action and every Docker and Modal claim is a catalog check; the Modal rounds, built in memory, rank from direct checks only, `block-network` then `run-as-user` (its side effects under `may_also_clear`) on round 0 and `protect-home` first on round 1, with no Modal action claiming SEC-2 or AMP-3; `run-as-user` is never offered without AMP-2's finding (`demo/reports/vibe.json`, `regressed.json`); a capability unknown joins only `run-as-user`, decided from the identity's capability sets, and a report whose reasons lie about TWN-4 ranks exactly as one whose reasons don't; a root box whose SEC-3 is red keeps `remove-credential-files` beside `run-as-user`, and on Modal so do SEC-5's, PER-2's and AMP-8.sys's own actions, each side effect only under `may_also_clear` and outside rank and could-turn-green; general advice is the catalog's sentence, never the report's; Cloud access skipped by default is "not an action for an agent", never an action, and no output names `-provider`, `-provider-endpoints` or "terms"; a report whose every string carries ESC, bidi, newline and shell payloads gives text and JSON with none of them. `cmd/sandprobe/fix_test.go`: flags, `-platform` only on `run exec` reports and only from the list, exit codes (5 for an invalid run as an invalid run writes it, and for `test/reports/canary-down.json`, incomplete, with its plan, `complete: false` and its unknown IDs), the saved-report note, 80 columns, a hostile `run.provider` |
| FIX-9 | `cmd/sandprobe/fix_docker_test.go` `TestFixLoopDocker`, with `SANDPROBE_FIXTURES=1` |
| FIX-4 with PRV-17 | `cmd/sandprobe/fix_test.go` `TestFixDeclaredProvider` (a `sandprobe/5` report declaring `modal`, through `host.Plan` and the grader) and, with `SANDPROBE_FIXTURES=1`, `fix_docker_test.go` `TestFixDeclaredProviderDocker` (`run exec -provider modal -no-canary` into a local container): the report loads, reads out of five, lists Cloud access nowhere, takes its platform only from `-platform` (none, `docker` or `modal`), and never says `-provider`, `-platform` or "declared" |
| PRV-18 | `internal/host/modal_gate_test.go` `TestModalStop` (the 10 Nov documents' own findings clear; any other SEC-1 name or SEC-3 path, an evidence line that isn't exactly the probe's own sentence, and a document that doesn't parse trip); `cmd/sandprobe/modal_test.go` `TestModalStopped` (a trip keeps only the private note, writes no report, prints none of the names or paths, and exits 8, or 7 when the deletion isn't confirmed; unsound evidence exits 5 with no report); `internal/host/modal_test.go` against a fake of the SDK: `TestModalJournal` (the tag on disk before the create and the ID after it, mode 600; no journal, no create; an ID that can't be recorded; a create with no ID, a failed terminate and a sandbox still running by tag each keep the journal and terminate nothing by tag; a confirmed deletion removes it), `TestModalWorkspaceName`, `TestModalBox`, `TestModalTokenNeverLeaks`, `TestModalExclusions`; `cmd/sandprobe/modal_test.go`: `TestModalPlanAndApproval` (the plan and an unapproved run make no SDK call; an approved run with no workspace or a bad one stops before the canary; any `-variant`, aws-nitro's default included, and `-min 6` are usage errors), `TestModalReadiness`, `TestModalCleanupBudget` |
| FIX-10 | `examples/modal/bridge_test.py` against a fake `modal` module; `Sanitized.test_delayed_stdin_writer_finishes_before_pipe_close` verifies cancellation/join before descriptor release and normal broken-pipe handling; run by `cmd/sandprobe/fix_test.go` `TestModalBridge`: ID substitution, tag mismatch, another app's sandbox, ambiguous and missing matches each refuse before any exec or terminate; a symlinked, non-regular, group-readable, duplicate-keyed or malformed state refuses; a state path in the way stops create before it creates; a failure after create, at the state write or by an interrupt, terminates the created sandbox through the object create returned, and an unconfirmed one exits 7 keeping the state; under `python -X dev`, a sentinel raised by the fake SDK at a stdout or stderr read, a stdin write, drain or write_eof, a wait, a list in `sh` or `rm`, a terminate, a poll, a thread of its own, a warning, a log line or an unraisable `__del__` never reaches stdout or stderr, and each exits with its documented code; and, each run 50 times as `python -X dev` subprocesses with no "Fatal Python error", traceback or sentinel: the remote ending while stdin stays open (its code passes through, 0 and 3), stdin closed at start, stdin `/dev/null`, a large file still being pumped when the remote ends, a stdin write failing mid-pump (1), wait returning at once while a later `write_eof` fails (1), a late drain failure (1), a late write failure while the remote runs (1), the remote ending before more input arrives (its code, 3, the input never sent), stdout failing after the wait (1), a pump that never ends (1, after its bound), and the barrier: a write, or an end-of-input, in flight when the remote ends with 3, which then returns: no drain may begin after it, and 3 passes through (200 runs) |
| FBK-1 to FBK-7 | `cmd/sandprobe/feedback_test.go`, with `PATH` pinned in every test to a directory holding a fake `gh` that records the full arguments, standard input and `GH_HOST`/`GH_REPO` of every call, or holding none, so no test can reach GitHub: `TestFeedbackKinds` (each kind's prefix, label, form and main field, through gh and through the link, once confirmed), `TestFeedbackRefusesCredentials` (one refusal per FBK-4 pattern, home paths included, each naming the place and the pattern and never printing the matched text, in text and in `-o json`, with nothing sent and gh never run; ordinary text and placeholders pass, one key a line; a list after a key on its line is refused by design), `TestFeedbackPassesOwnOutput` (every check's `explain`, and `scorecard`, `profile` and `assess` of every saved report in text and JSON, and `compare`, pass the scan; `secrets: x`, `SECRETS=`, longer names and an altered own line don't), `TestFeedbackRefusesShortCredentials` (the security reviews of #65: short values in every header, Bearer, Basic, URL, YAML, INI, JSON, environment, flag and prefixed-token form; every Slack prefix; a URL with an empty user; `DB_PASS` and `MYSQL_PWD`; a YAML or JSON value on the next line, a second continuation line, a continuation after a placeholder, a block scalar, an explicit key, a folded `Authorization` header, and credentials found only by the YAML and JSON walks of a fenced block or the whole body, an escaped key among them; round 3's shell-joined values (`"<redacted>"x` in field, header, flag, Bearer and continuation form, and a placeholder followed by more words), round 5's double-quote backslashes (`"tr\ue"` in Bearer, header, field and flag form, and `"\$TOKEN"`, whose raw form isn't a placeholder), each leaking without the fix; round 5's backticks after an escaped one (`` note \` token: <redacted>`x ``, its Bearer form, a double-escaped `\\`, and a quoted value before the backtick), each leaking without the fix, and a backtick inside quotes; round 4's unmatched backticks and closing punctuation (`Bearer <redacted>` then a stray backtick, and `'true)'` in Bearer, flag, header and field form), and its comma and semicolon lists (`TOKEN=<redacted>,x`, `export TOKEN=<redacted>,x`, `TOKEN=<redacted>;x`, `Authorization: Token <redacted>,x`, `--token=<redacted>,x`, a YAML scalar or flow sequence with a comma, and a continuation line), each but the flow sequence leaking without the fix, escaped and HTML-referenced names in prose, a YAML alias key inside a fence nested in a longer one, the same in a seventeenth YAML document, and a repeated, escaped JSON key with its colon on another line; through gh and through the link, in text and in `-o json`, with and without a `-confirm` code: each is refused, the value appears in no output, gh is never run, and no link or file is made), `TestFeedbackWalkLimits` (JSON nested past 10,000 behind a split colon that YAML can't read, and fences nested past 16, refuse and name the limit; `walkJSON` alone reads exactly 10,000 containers, with or without a value inside, and refuses one more, an unclosed run, and Codex's round 4 body, but not prose or a short cut-off document; a repeated JSON key can't hide the first one's value), `TestFeedbackPromptGatePTY` (over a real PTY: a foreground terminal asks and takes only `yes`; a background process group, a PTY that isn't the session's controlling terminal, `CI`, `TERM=dumb` and `SANDPROBE_NO_KEYS` never ask and never block), `TestFeedbackReportSummary` (a saved report made hostile in the test, with credentials, home paths, variable names and a box name in every free-text field and as its provider, still passes ANL-1; none of them reaches the preview, gh's arguments, its standard input or the link; an edited report gets ANL-1's fixed error), `TestFeedbackTransport` (the exact arguments of the graphql query and of `issue create`, unchanged with `GH_HOST` and `GH_REPO` set; the body on standard input; the label only for an account that can triage; gh absent or not signed in gives the link once confirmed; gh failing or printing no issue URL exits 5 with the link), `TestFeedbackLink` (percent-encoding, the 8,000-character limit, and the body written to a private file when it is longer), `TestFeedbackJSON` (one document with FBK-7's fields; `public` and, through gh, `account`; a login not in GitHub's form means no gh), `TestFeedbackConsent` (a preview prints the code, exits 3, makes no link and never runs `issue create`; the matching code files exactly the previewed title, labels and body; an edited body, another account, gh signed in after a link preview, or a wrong code is refused with `feedback.changed` and nothing filed or linked; `-o json` doesn't change the code; `-y` is a usage error; the terminal prompt accepts only `yes`, and no `/dev/tty` means no filing), `TestFeedbackUsage` (a bad kind, title, body, `-provider` or `-confirm`) |
| REL-1 to REL-3 | `.github/workflows/release.yml` on every pull request: REL-1 twice on separate runners, compared file by file, publishing nothing, and `.github/release-version_test.sh` (REL-2's version grammar: `x.y.z` publishes as a full release, `x.y.z-rc.N` as a pre-release never marked Latest, and everything else is refused, a leading `v`, another suffix, a missing part, a second line and an empty version among them); on a release, the version check before anything is published, then the attestation |
| QCK-1/QCK-2 | Linux quick metadata/no-follow FIFO/symlink tests, status/error/name bounds tests, static amd64/arm64 packaging checksums |
| ANL-2 terminal escaping | `cmd/sandprobe/scorecard_test.go` `TestPrintableEscapesUnicodeFormatControls` (bidi/isolate/zero-width/BOM and existing control escaping; ordinary Unicode preserved) |
| SCR-6 | `internal/report/fix_test.go` `TestHTMLExecutedCountsExcludeScopeOnlyResults` (unknown/not-found counted; missing/skipped/scoped-out excluded, every palette) |
| SCR-5 | synthetic six-category coverage partition and malformed/missing/unknown/scoped-out cases, unchanged RC scores, invalid/historical coverage absence, terminal/HTML/workload coverage visibility and count validation |
| SCR-1/SCR-2/SCR-3 | `internal/report/scorecard_test.go`: every catalog check in exactly one category, green only with a tested check and no unknown or finding above Info, invalid has no score, the page leads with the score and puts the rest under Appendix, reasons never carry box strings; `cmd/sandprobe` scorecard regression; `internal/report/fix_test.go` (SCR-3's page): `TestPageOrder` (the header with the box, its provider, each chain's sentence and the run's facts, never `run.mode`; then the score, its strip and the six rows, each with "x/y tests run" and a link to each of its tests; then What to fix with the chain first in its severity, unknowns in their own unfolded group and the rest folded; then the technical appendix), `TestEveryTestOnce` (on every saved report's page, fresh and re-rendered, in every palette, each catalog check's row appears exactly once and every link to a test lands on a row), `TestEveryTestOnceUnrated` (a failure with no known severity, which only an edited report has, still shows once and is counted), `TestCountsComeFromRows` (the strip, each group heading, the fold and the rail count the rows shown, and equal the grade's counts), `TestUnknownIsNeverAPass` (an unknown row is dashed, outside the fold and never green; an incomplete run says so beside the score, dashed; a not-proven test sits in the fold, never as a pass), `TestNoLetterGrade` (no letter grade anywhere on the page or in its title, for a valid, an incomplete and an invalid run; the title carries the score; an invalid run says plainly that it is invalid and has no score; the JSON the page embeds carries no letter and declares `sandprobe/6`, from a run or re-rendered from an older report that has one), `TestHeaderFacts` (the probe's version escaped as text, the attestation line fixed, the lead sentence without a chain), `TestInvalidHasNoCounts` (an invalid page has no strip, no group and no count) |
| AGT-6 (field presence) | `internal/analysis/presence_test.go`: `TestNewFieldsPresentAreCanonical` (the security re-review of #8: a committed `sandprobe/1` report reads as before with the new fields absent, and is refused with `SkipKinds` as `{}` (the reviewer's reproduction) or null, `Attested` as `[]` or null, or a check's `attestation` as `""` or null; a canonical `sandprobe/2` report reads, and is refused with `Attested` as `[]` or null, an `attestation` null, `SkipKinds` as `{}` or null with nothing else new, or no new field at all) |
| AGT-6 (no letter), GRD-1, OUT-1, ANL-1, ANL-2, CAL-3, CMP-1 | `internal/report/scorecard_na_test.go` `TestReportSchemaVersions` (every report `Build` writes declares `sandprobe/6` and marshals no `letter`, with skip kinds, attestations, a declared provider or none, valid or invalid; `BuildLegacy`, the workload evaluations' writer, declares the lowest of `sandprobe/1` to `sandprobe/5` its manifest needs and writes the grader's letter, empty on an invalid run; the two differ in nothing else); `internal/analysis/letter_test.go`: `TestLetterMatchesSchema` (a `sandprobe/1` report reads with its letter, and is refused with it absent, null, empty, lower case, two letters, not a string or not one of the five; a `sandprobe/6` report reads with no letter, and is refused with one kept, empty or null; an unknown version is refused either way; under `sandprobe/6` each earlier field keeps its own rule: skip kinds read, and are refused empty, null, of a kind this binary's policy doesn't derive or on a tested check; RUN-17's contract reads on `aws-nitro` only; EVD-10's protocol reads, and is refused unknown or empty; a declared provider reads, and is refused empty, null, unknown, on a native adapter's report, with its kinds turned `opt_in`, removed with its kinds kept, or beside EVD-10's protocol; an invalid run reads as `sandprobe/6` with no letter and as an earlier version with an empty one, never the other way round), `TestSavedLetterIsIgnored` (an older report, the same report as `sandprobe/6` and the same report with another letter give the same profile and assessment and compare as unchanged; no profile, assessment or comparison carries the letter; they declare `sandprobe.profile/2` and `sandprobe.assessment/2`), `TestReRenderedPageReadsBack` (an older report of each version, `sandprobe/1` plain, `sandprobe/2` with skip kinds and with attestations, `sandprobe/3` with RUN-17's contract, `sandprobe/4` with EVD-10's protocol, `sandprobe/5` with a declared provider, and an invalid `sandprobe/2` run with its empty letter, is re-rendered by `SavedHTML`; the page's `report-data` parses through `Parse`, declares `sandprobe/6`, carries no letter, and equals the saved report in everything else, an invalid run still invalid with its reason; a report already `sandprobe/6` embeds unchanged); `internal/analysis/assessment_test.go` `TestAssessmentCalibration` (the highest-severity finding IDs); `cmd/sandprobe/letter_test.go` `TestNoLetterInOfflineOutput` (on every saved report, each of `scorecard`, `profile`, `assess`, `compare`, `fix` and `feedback`'s preview, in text and JSON, shows no letter and gives byte for byte the same output for the older report and for its `sandprobe/6` form; one against the other compares as unchanged; the page `-out` re-renders embeds, from either, a `sandprobe/6` report with no letter that `scorecard` reads back to the same card; `profile` and `assess` declare their new versions and `highest_severity_finding_ids_unverified`), `TestOnlyWorkloadEvaluationsWriteALetter` (`BuildLegacy` is called only by the two managed-workload evaluations, and every runner writes its report with `Build`); `cmd/sandprobe/fix_test.go` `TestFixInvalidRun` (an invalid `sandprobe/6` report) |
| SCR-2 (not applicable) | `internal/report/scorecard_na_test.go`, on a Docker fixture run replanned through `host.Plan`, the grader and `Build`: `TestScoreNotApplicable` (each native adapter's PRV-row exclusions make Cloud access not applicable with SCR-2's fixed reason, never green, out of five, named on one line with this binary's own PRV reasons, in JSON and on the page, which carries no saved-report note; the findings, their counts and completeness equal the same run's without a kind), `TestNativesAreThePolicy` (the providers treated as provider terms are exactly `host.TermsExclusions`; exec and the shipped recipe derive opt-in; docker and aws-nitro nothing), `TestScoreOptInStaysNotTested` (run exec's and a recipe's defaults: red, out of six, "Not tested: opt in with -provider-endpoints SEC-4,AMP-7 if your provider's terms allow"), `TestScoreNoCanaryIsNeverNotApplicable` (Exfiltration "not tested: run without a canary", red, incomplete), `TestNotApplicableNeedsTheHostsKind` (no kind, a row the manifest never skipped, an empty reason, one check tested, unknown or missing, or a provider-terms kind on run exec, whose policy is opt-in: never not applicable; the box answering "skipped", or answering a check the host skipped, invalidates the run), `TestWorkloadExposureNotApplicable` (a forged out-of-six, green, extra, unknown or dropped not-applicable row, or provider-terms reasons on a counted row, is refused), `TestCleanBoxReadsFiveOfFive` (a clean box reads 5/5 in the card, its JSON and the page, never 6/6, Cloud access never green); `TestSixOfSixIsClean` (every saved Docker report stays out of six with nothing left out, and a full score has no finding above Info and is complete); `internal/host`: `TestPlanRecordsSkipKinds` (a kind only for the host's own exclusions, never a survey-driven skip, never in the probe's input; the grader refuses a kind on a check that isn't skipped or isn't an endpoint, or that isn't a kind; Execute refuses an unknown kind); `cmd/sandprobe/scorecard_na_test.go`: `TestExclusionKinds` (every adapter's exclusions record a kind: opt-in for run exec and recipes, provider terms for the rest), `TestScorecardNotApplicable` (Sprites and E2B read "Score 2/5" with the line; exec and kubernetes "Score 2/6" with the opt-in hint; the same in `-o json`), `TestReportSchemaVersions` (AGT-6: a saved `sandprobe/1` report and a `sandprobe/2` one with skip kinds still read, and so does each as `sandprobe/6` with no letter; a `sandprobe/1` report carrying skip kinds, a `sandprobe/2` one without them, a `sandprobe/6` report with a letter, a `sandprobe/1` or `sandprobe/2` report without one, and an unknown version are refused, and the refusal names the versions this build reads), `TestScorecardNoCanaryStaysRed` (exit 5, red), `TestCompareNotApplicable` (tested to not applicable is coverage loss and a changed setup; opt-in to not applicable is a changed setup, exit 5; a matched pair, and a report with no kind against an opt-in one, read unchanged), `TestScorecardRefusesForgedKinds` (ANL-1, as saved and as `sandprobe/6`), `TestScorecardRefusesForgedProvenance` (the security review's forgery: a valid run exec report with SEC-4 and AMP-7 edited from opt_in to provider_terms is refused, as saved and as `sandprobe/6`, and scored directly stays out of six), `TestOfflineRenderingsSayNotReVerified` (ANL-1: scorecard text, JSON and the `-out` page, profile, assess and compare each say the saved report wasn't re-verified) |
| SCR-2 (green · not proven) | `internal/report/scorecard_test.go`: `TestGreenNotProven` (the demo vibe report's Cloud access, SEC-4 and AMP-7 both `not_found`, 0/2 conclusive: green, counted in the score, flagged in the card and its JSON, and a dashed `GREEN · NOT PROVEN` badge and dot on the page; a row of only `scoped_out` checks is flagged; a green row with a `pass` beside a `not_found` ("not proven: DNS") or with an Info finding beside `not_found` stays plain GREEN; no red row is flagged; a supplied flag on a proven or red row, or on a card without coverage, is refused, and a dropped flag on a 0-conclusive row stays valid), `TestGreenNotProvenNeverStrengthens` (a 0-conclusive category with one unknown stays red and unflagged; each native adapter's not-applicable Cloud access, run exec's and a recipe's opt-in "Not tested", a plain "Not tested" row and an invalid run, which has no rows, never carry the flag or the label); `internal/report/scorecard_coverage_test.go` `TestHistoricalDisplayFlagIsDerivedWithoutMutatingInput` (a `sandprobe.workload-exposure/1` card without the flag renders "Green · not proven" from its validated coverage without changing the caller's card; a contradicting supplied flag is refused); `cmd/sandprobe/scorecard_test.go` `TestScorecardGreenNotProven` (`scorecard` on saved `sandprobe/1` reports, the demo vibe report and `test/reports`, and on a saved `sandprobe/2` run exec report that opts in SEC-4 only: `◌ GREEN · NOT PROVEN` on Cloud access, proven green rows still `● GREEN`, `green_not_proven: true` in `-o json` on that row only; `o GREEN . NOT PROVEN` and no `◌` under `LC_ALL=C`; every category row within 80 columns, a long question moved to the next line) |
| HCN-1 | `internal/canarycontrol`: the whole public path over HTTPS, every answer verified under the pinned control key and naming the canary's receipt address and domain (`TestPublicAnswersNameTheReceiptAddress`); an answer replayed for another challenge, altered, re-signed or under an unpinned key is refused; the control name never gets the receipt key and a box name never reaches the control server; method, path, unknown field, op mismatch, trailing data and oversize refusals; a long run label never makes an answer over the bound (`TestPublicAnswerBoundedForLongRun`, `TestControlAnswerBounded`); a control key file that's a symlink, not regular, open to others, not this user's, oversize or carrying trailing bytes is refused (`TestLoadKeyFileSafety`); a browser's cross-site POST (simple content type, Origin or Sec-Fetch-Site) is refused (`TestControlRefusesBrowserPosts`); `TestPublicNeedsAChallenge`; host: `TestHTTPSCanaryImpostor` (an impostor behind a trusted interception root and a redirected name is never believed, and Execute stops before the probe), `TestHTTPSCanaryRefusesRedirectAndOversize`, `TestNewHTTPSCanaryChecks`, `TestHTTPSCanaryAddressFromSignedStatus` (the receipt address comes from the signed status, never from where the control connection went, and a changed one is refused), `TestHTTPSCanaryErrorsRedact` |
| HCN-2 | `TestPublicSecretGuardsTheRun`: without the secret a box can't query, disarm, re-arm its run or arm its nonce elsewhere, and the host's receipt survives; `TestPublicCantTouchOperatorRuns`; `TestPublicGenerationChangesOnRearm`; host: `TestHTTPSCanaryRearmedRun` (a re-armed run is never read: the old secret is refused, and the thief's secret shows another generation) |
| HCN-3 | `TestPublicReservation` (no arm without a reservation; one slot per secret; release; expiry), `TestPublicBounds` (per-source runs at once and per hour, by reservation), `TestPublicGlobalBound`, `TestSourceOf` (IPv6 /64), `TestPublicOverloadAtACap`; host: `TestHTTPSCanaryRun` (no arm without a reservation; reserve, arm, receipt, disarm) ; `TestHTTPSCanaryLostAnswersRelease` (a reserve, arm or disarm lost before or after the canary acted never leaves a slot held past Close), `TestHTTPSCanaryCloseRetries` (a Close that couldn't release keeps the slots for the next one) |
| HCN-5 (no canary) | `internal/host`: `TestPlanNoCanary` (the canary checks stay selected for the grader, but the probe's input names none of them and carries no canary address, nonce or domain), `TestExecuteNoCanaryAsksNothing` (no canary is asked anything and no receipt is awaited), `TestExecuteThroughExecBoxNoCanary` (the shipped probe through `docker exec`: valid, incomplete, every canary check unknown with the host's reason, EGR-3 still skipped as a provider endpoint); `internal/grade`: `TestNoCanaryIsUnknownNeverAnswered` (each canary check unknown with the host's reason, and a box that answers one anyway makes the run invalid); `internal/report`: `TestScoreNoCanary` (the category reads "not tested: run without a canary" and stays red); `cmd/sandprobe`: `TestNoCanaryFlag` (the plan says none, and `-no-canary` with any canary flag, or outside exec, is refused); `cmd/sandprobe`: `TestNoCanaryPlanWording` (for `run exec` and `run kubernetes` under `-no-canary`, with each set of attested checks, the plan's destinations are exactly those the probe's input from `host.Plan` lets it contact: every catalog SEC-4 address when SEC-4 is selected, AMP-7's handshake when the survey names an API, a proxy only when EGR-3 reaches the probe, which it never does, and nothing for AMP-6, whose probe code dials nothing; the line itself says no test traffic goes to any canary and the run ends incomplete; the help names only SEC-4's and AMP-7's connections) |
| DKR-1 | `cmd/sandprobe-probe/main_test.go` on Linux: `TestProbeArguments` (`-idle` alone, never with more), `TestIdleStaysUp` (it writes nothing and doesn't return); `cmd/sandprobe/docker_test.go`: `TestDockerBoxArgs`, `TestDockerEntrypointArgs` (Sandprobe's entrypoint, `--init=false`, `--no-healthcheck` and `-idle` unless the person names `--entrypoint`, either spelling, `--init` or a health option), `TestDockerPlanSaysWhatRuns`, `TestDockerHealthOff` (Docker's record read as off only for none or `NONE`); with `SANDPROBE_FIXTURES=1`, `TestDockerEntrypointRuns` (an image whose own entrypoint exits at once runs to a valid report), `TestDockerHealthcheckNeverRuns` (an image whose one-second HEALTHCHECK writes a file through a bind mount: no file after a default run, and the report says no health check ran; with the person's `--health-interval`, the file is written and the report says it may have run) |
| DKR-2 | `internal/probe/idle_test.go` in `test/probe.sh`, as nobody and as root: `TestOtherPIDs` (PID 1 skipped only when named; the probe and its twins never counted), `TestIdleSpoofCounted` (a copy of the idle process, same binary, `-idle` and a secret in its environment, at another PID, is still a finding); `internal/host` `TestPlanOwnInitAndScratch` (the fact reaches the probe's input, never the manifest); with `SANDPROBE_FIXTURES=1`, `TestDockerEntrypointRuns` (the idle process, as the agent's uid, isn't counted; the person's `--entrypoint` set to the probe's own path and kept alive on stdin, and any run with `--init`, are) |
| DKR-3 | `cmd/sandprobe/docker_test.go`: `TestDockerStopNamesTheCause` (a fake docker: the person's entrypoint exiting at once, exit 137 while the probe runs reported as that exit code and never as a signal, and Docker's out-of-memory kill named as such, each with its fix, the cleanup still run), `TestDockerStopFixRunsAsPasted` (the fix read back through `sh`, then parsed by the CLI into a plan); with `SANDPROBE_FIXTURES=1`, `TestDockerEntrypointRuns` (an entrypoint that exits at once, one that exits on purpose with 137, and one that exits when the probe's main run starts) |
| DKR-4 | `internal/probe/idle_test.go` `TestTwinsInScratch`; `internal/host` `TestPlanOwnInitAndScratch` (never marked, whatever the survey says; `/`, `/tmp` and relative paths refused); `TestDockerEntrypointArgs`, `TestDockerPlanSaysWhatRuns`; with `SANDPROBE_FIXTURES=1`, `TestDockerEntrypointRuns` (`--read-only` with no writable `/tmp` runs to a valid report) |
| DKR-5 | `TestDockerPlanSaysWhatRuns` (Marks and Reset say none); with `SANDPROBE_FIXTURES=1`, `TestDockerEntrypointRuns` (PER-5 skipped, "no root this run may mark") |
| LNC-1, LNC-2 | `internal/host/exec_test.go`: `TestExecMainRunExecsWrapper` (the main run's script ends with `exec` of the probe in wrapper mode, with the literal scratch and `-expect-uid`, and its input on stdin; the input file decodes to the token and owner line, then the probe's input; neither token is on any command line; it sets, exports and unsets no variable; every other invocation's script is unchanged, with `SANDPROBE_TWIN=1` on its probe's command line), `TestExecWrapperFallback` (through a real local `sh` and a fake wrapper: a run the wrapper framed reads back, with the scratch gone; a wrapper that frames nothing, a status 96, a failed run, and a wrapper that prints its start marker and is then killed by SIGKILL, cut off at its limit or cancelled are each classified as LNC-2 orders them, the killed, cut-off and cancelled ones as unframed runs with a fixed label and no output to grade, and the confirm-gone invocation leaves no scratch); `internal/probe/wrap_test.go` in `test/probe.sh`, as nobody and as root: `TestWrapFraming` (success: the start marker, the run's output, the end marker with status 0 and the scratch gone; a run that exits 3: status 3, scratch gone; TERM, INT and HUP sent to the wrapper reach the run: status 128 plus the signal, scratch gone; a scratch without the owner's mark, or a link, never removed; a run that can't start: status 96, nothing run, scratch gone; a short or malformed first line: nothing printed, nothing removed, a nonzero exit), `TestWrapKilled` (SIGKILL to the wrapper: no end marker, and the scratch is left for confirm-gone); `cmd/sandprobe-probe/main_test.go` `TestProbeArguments` (`-wrap` takes exactly the scratch path and `-expect-uid N`, in their forms; anything else is refused) |
| LNC-3 | `internal/probe/wrap_test.go` in `test/probe.sh`, as nobody and as root: `TestParentPin` (a parent running the probe's own file is pinned; a parent running another file, a copy of the probe at another path, PID 0 and a PID that isn't there are not, so they are counted; a pin fails after its process exits, after it `exec`s another file, and when `getppid()` differs), `TestWrappedRunSkipsOnlyItsWrapper` (the test binary as wrapper, under a `sh` that stays alive: SEC-2 and SEC-5 skip the wrapper's PID only, with the reason naming it, and never list it; SEC-2 finds the `sh` grandparent, and so does SEC-5 where Yama's `ptrace_scope` is absent or 0, while under 1 the kernel refuses SEC-5 a non-descendant, so it lists the `sh` refused, never found; a run started straight from `sh` skips nothing; a wrapper killed between the pin and SEC-2's second check leaves SEC-2 unknown, and SEC-5 after it unknown or counting every process, with no skip claimed); `internal/probe/idle_test.go` `TestOtherPIDs` (PID 1 with `OwnInit` as before, with and without a pinned wrapper) |
| LNC-4 | `internal/probe/wrap_test.go` `TestWrapperHoldsOnlyTheRunsEnvironment` in `test/probe.sh`, as nobody and as root (the test, not the probe, reads both environments, whose values are fake): a dash `sh` given `MY-KEY=sandprobe-fake` and `a.b=sandprobe-fake` `exec`s the wrapper, and neither the wrapper's `/proc/<pid>/environ` nor the run's holds them; a `sh` that changes `FOO_TOKEN` from `sandprobe-fake-a` to `sandprobe-fake-b` and exports it before `exec`: the wrapper's environment holds only `-b`, as the run's does; each time, the wrapper's entries equal the run's minus `SANDPROBE_TWIN`, in order, duplicates and entries without `=` kept; with `SANDPROBE_FIXTURES=1`, `internal/host/exec_docker_test.go` `TestExecWrapper` on `debian:bookworm-slim` with `useradd -m -u 1000 agent`, through `ExecBox` as `agent` and `docker exec -i -u agent <ctr> sh`: the box alone (SEC-2 and SEC-5 pass with twin proof, each reason naming the wrapper's PID); a same-uid decoy from `docker exec -d -u agent <ctr> sleep 300` (SEC-2 a finding on the decoy's PID, and SEC-5 too where Yama allows it, never the wrapper's); the person's `docker exec` given `-e MY-KEY=sandprobe-fake` (dash drops the name before `exec`, so a pass with the wrapper skipped); no scratch left |
| LNC-5 | `internal/host` `TestOnlyExecMainRunWraps` (`DockerBox.Probe`'s command runs the probe directly, with no wrapper; a recipe's `sp_shell` main run goes through `ExecBox`'s wrapper) |
| HCN-5 (which canary) | `cmd/sandprobe/canary_test.go`, all offline or on a local stand-in: `TestCanaryPrecedence` (`-canary`, by flag or `SANDPROBE_CANARY`, over `-canary-url` with its pin, over the hosted canary; a stray `canary-*.state` file is chosen only when named; a pin without its URL is refused), `TestStrayCanaryStateIsIgnored` (with one stray state file and nothing named, the plans of `run exec` and of every native adapter, and `providers`, name the hosted canary, who runs it and HCN-4's retention, never the stray file, its address or SSM; named, the same file is the operator canary; a named file that doesn't load isn't ready), `TestNativeRunOnTheHostedCanary` (the seam every native adapter shares: the hosted canary, here a real canary on a local port with its own pin, gives its signed status and holds the run's slot before any box; `Execute` through it is live with its receipts read; `closeCanary` leaves no slot held; a named operator canary that doesn't load stops the run), `TestCanaryFlagsBeatTheEnvironment` (a stale `SANDPROBE_CANARY` beside an explicit `-canary-url` and `-canary-pin`: `plan e2b` names the URL; any canary flag sets every `SANDPROBE_CANARY*` value aside, so an explicit URL never takes the environment's pin and `-no-canary` isn't refused for the environment's canary; with no flag, the environment stands in), `TestDockerRefusesCanaryFlags` (PRV-14: `plan` and `run docker` refuse each canary flag before any Docker call, and never read the environment's canary), `TestExecReleasesTheSlotAfterACancelledCleanup` (run exec's teardown gives the hosted canary's slot back under its own budget after a scratch cleanup that used all of its own), `TestPublicCanaryPlansDiscloseRetention` (on the hosted canary and on one `-canary-url` names, the plans of run exec, the Kubernetes recipe and all nine native adapters end their residual with the one shared HCN-4 sentence, which names both addresses, the box's for at most 30 minutes and the host's in a rate counter for at most an hour, in memory only; on an operator canary every residual is its own alone, and run docker's plan is unchanged); `internal/host`: `TestPublicCanaryThroughAReset` (PER-5's restore model on a real public canary: status, arm, probe, query and disarm, in that order, all before the mark, the reset and the recheck, which ask the canary nothing; one reserved slot covers the run, and Close leaves none held) |
| RCP-1/RCP-2 | `internal/host/recipe_test.go`: `TestParseRecipe` (the header's keys, the functions, exclusions only from the provider endpoints, `env:` only its own `SANDPROBE_` names, the 64 KiB bound, a header value that isn't printable ASCII or is over 400 characters, a defined reset noted (RCP-3), and the shipped recipe), `TestRecipeCallsRecorded` (`provider_calls` list `sp_create`, `sp_delete` and the last `sp_gone` in the fixed form with the recipe's SHA-256, the exit code and the create-returned ID, and nothing the recipe printed; a create with no ID is listed without one), `TestRecipeLifecycle` (each call gets the host's box, name and target and never the process's own, stdin from `/dev/null`, `sp_shell` carries PRV-15's script), `TestRecipeCreateWithoutID` (empty, two lines, bad characters, too long or failed: the name is reported and nothing deleted; an ID with a failed create is still deleted by it), `TestRecipeGone` (only 0 is gone; 1, 2 or anything else names the ID), `TestRecipeWhoisGuards` (no invocation and no delete once the name holds another box; the residual reports the race), `TestRecipeErrorsWithhold` (an error carries what the recipe wrote to fd 3, and never its stderr, even a line posing as the recipe's), `TestRecipeMessagesCantBeReopened` (a tool with fd 3 closed finds no message file to reopen by name, and none is left), `TestRecipeSaysIsBounded` (fd 3 is a pipe, never a file; a recipe that writes 32 MiB to it returns at once with an error that carries only the start of the flood, and the capture never holds more than 4 KiB however `io.Copy` feeds it; an 8 MiB flood of stdout keeps 64 KiB; a child left holding fd 3 delays the call by about a second, not until it exits), `TestRecipeSaysIsASCII` (U+009B, U+202E, an invalid UTF-8 sequence, ESC and a carriage return written to fd 3 never reach an error: only printable ASCII does; the same three in `sp_ready`'s line or in a header value refuse the recipe without echoing them); `internal/host/exec_docker_test.go`: `TestRecipeThroughDocker` (`SANDPROBE_FIXTURES=1`: an ID-addressed recipe runs the shipped probe through its `sp_shell` and deletes its container by ID, confirmed gone) |
| RCP-4 (own recipe) | `internal/host/recipe_test.go`: `TestOwnRecipe` (named `own-<12 hex>` from its SHA-256; all four exclusions whether the header lists four, one or none; any other check still refused; `provider: modal` stays the recipe's word; the residual names the SHA-256 and says nobody reviewed it; no shipped recipe is named `recipe` or `own-`); `internal/report/scorecard_na_test.go`: `TestOwnRecipePolicy` (the policy for `recipe` is the four as `opt_in`, never `provider_terms`, with or without a declared provider); `internal/report/scorecard_na_test.go`: `TestOwnRecipeRecordWritten` (`Build` writes `run.recipe` as exactly `{"own":true,"sha256":"<64 hex>"}` and declares `sandprobe/7` for an own recipe's run, and writes no `recipe` key and `sandprobe/6` for any other; `SavedHTML` embeds a `sandprobe/7` report as `sandprobe/7` and an older one as `sandprobe/6`); `internal/analysis/analysis_test.go`: `TestOwnRecipeReport` (a `recipe` report with its record and `opt_in` kinds loads; one with a `provider_terms` kind, a declared provider, or under a provider name the policy lacks, is refused), `TestOwnRecipeRecordForged` (refused: a `recipe` report without the record; the record on an `exec`, `kubernetes` or `docker` report; `own` false or absent; a digest that is empty, absent, short, long, upper case or not hex; a box not created by Sandprobe; the record under each of `sandprobe/1` to `sandprobe/6`, and a `recipe` report under them without it; a `sandprobe/7` report without the record, on any provider, or with a letter; the record null, empty, a string, or carrying a path or any other key), `TestCompareOwnRecipe` (two otherwise identical own-recipe reports with different SHA-256s, and one with the record against the same run without it, are a `declared_configuration` change and never no observed change; the same record on both sides compares as unchanged); `cmd/sandprobe/recipe_own_test.go`: `TestOwnRecipeUsage` (`-recipe` beside a provider, on another command or empty; `-provider`, `--`, `-block-device-path`, `-setup`, `-keep-sandbox`, a bad `-as`, a bad `-min`, `-no-canary` with a canary flag and a bad `-provider-endpoints` are refused; `-as`, `-scratch`, `-no-canary`, `-provider-endpoints` and `-allow-local-proxy` plan), `TestOwnRecipeFile` (missing, over 64 KiB, a directory, a FIFO, a symlink, empty, no header, a missing function or provider, an unprintable header value, an exclusion that isn't a provider endpoint, `addressed-by: name` without `sp_whois`: each a usage error, in text and JSON, that echoes no header value, `env:` name or exclusion from the file, and none of its code runs; exactly 64 KiB still plans), `TestOwnRecipePlan` (the path as given, the full SHA-256 of the bytes on disk, own recipe, not reviewed, the provider as the recipe's word, terms not reviewed, trusted host code, `sp_ready` already ran, the target, the four exclusions, in text and JSON; a path that isn't plain is shown quoted; a defined reset is said never to be called (RCP-3); an unapproved run exits 3 with `needs_approval`, creates nothing and leaves no record; a name-addressed own recipe plans with the `sp_whois` guard and the reported race; a failing `sp_ready` exits 4 with only what the recipe wrote to fd 3), `TestOwnRecipeExclusions` (a header that lists one exclusion, three or none still plans all four off, each skip's reason quotes nothing from the header, and `-provider-endpoints` lifts any of them only by name), `TestOwnRecipeCleanupExits` (a create that returns two lines, bad characters or nothing, or fails, exits 7 naming the box, deletes nothing and keeps a mode-600 record named `recipe-own-<12 hex>-sandprobe-<12 hex>.state`, with no part of the path in its name, that holds the SHA-256, the file's absolute path and the target; a box whose `sp_gone` answers 1 or 2 exits 7 naming its ID with the record kept; one it confirms gone exits 5 with the record removed), `TestOwnRecipeAnnounced` (`plan -recipe` and an unapproved `run -recipe`, in text and with `-o json`, write one stderr line with the path as given and the full SHA-256 before the file's first execution: a recipe whose top-level code records that it ran hasn't run when the line is written, and has after; a usage error or a refused file writes no such line), `TestOwnRecipeReportConsumers` (a saved `recipe` report with its record loads in `scorecard`, `profile`, `assess`, `compare`, `fix` and `feedback`'s preview, in text and JSON; the page `scorecard -out` re-renders embeds the record unchanged, as `sandprobe/7`, and reads back; the same report without the record, with the record forged, or declaring `sandprobe/6`, is refused by each; `compare` of two such reports with different SHA-256s, or of one against a `run exec` report of the same run, exits 5 with `declared_configuration`, and of one against itself exits 0), `TestOwnRecipeHostileMessages` (U+009B, U+202E and an invalid UTF-8 sequence written to fd 3 by a failing `sp_ready` and a failing `sp_create` reach neither stderr nor the `-o json` error, and neither the cleanup outcome a report records nor the line stderr gets when `sp_gone` can't tell), `TestExampleRecipe` (`examples/recipes/docker-template.sh` parses as an own recipe and isn't shipped), `TestOwnRecipeDocker` (`SANDPROBE_FIXTURES=1`: the example recipe end to end on local Docker without a canary, as `nobody`: exit 5 incomplete, the saved report loads under ANL-1 as `sandprobe/7`, `run.provider` `recipe`, created by Sandprobe, `run.recipe` holding `own` true and the SHA-256 of the file's bytes, the same SHA-256 in the create's `provider_calls` entry with the box's ID and in the residual, four `opt_in` skips, Cloud access "Not tested" and counted, no path of the recipe in the report, and the container and the record gone; a copy whose header lists one exclusion still has all four skipped as `opt_in` in its manifest; `-as root` on that box stops before any check and the container is still deleted; a template that isn't a local image stops at `sp_ready`) |
| PRV-16 | `internal/host/recipe_kube_test.go` with a stub `kubectl`: `TestKubernetesRecipeCalls` (every call names the context, and the namespace where it reaches the cluster; no apply; the overrides are read from their file and never appear on a command line; `get pods` is checked; the delete is the raw API call with the UID precondition and its grace), `TestKubernetesRecipeRefuses` (no context, a bad or capitalised namespace, an unreadable overrides file, a refused permission, an API server URL with a user, query or fragment part (refused without printing it) or that isn't a URL, a proxy's path (shown only as the origin), a changed API server, path or cluster settings, a stub kubectl that writes a message as the recipe on stderr and on fd 3 (never shown), and overrides that make anything but the pod or move it to another namespace), `TestKubernetesRecipeGone` (absent or another UID 0, ours 1, kubectl failing or no target 2), `TestKubernetesRecipeChildrenCantSpeak` (every kubectl in the recipe runs with fd 3 closed), `TestKubernetesRecipeWait` (no exec during the create; a node that refuses exec at first is retried; one that always refuses stops after 12 tries; any other exec failure, a name that holds another UID or none, and a lookup that prints the right UID but fails, stop without a retry, the last three with no exec; kubectl's message is never shown; an own recipe's `sp_wait` is never called, `TestOwnRecipeNeverWaits`; a kubectl that stalls on the lookup or the exec is stopped at the wait's limit and on a cancel, and is dead when `Wait` returns, `TestKubernetesRecipeWaitStalls`); `cmd/sandprobe/recipe_test.go`: `TestRecipePlan` (the plan names the target, the ID-only delete, the whois guard, the exclusions and the skipped PER-5; an unapproved run creates nothing; no context is a login error; passthrough, a canary flag with `-no-canary`, and a bad `-as` are refused), `TestRecipeRunCleanupExits` (a create with no ID exits 7 naming the box, deletes nothing and keeps its record; an ID whose box never became ready exits 7 naming it, after a delete asked though the run had used more than the delete's whole budget, and the record keeps the ID), `TestRecipeRunStopsWithoutRecord` (an ID that can't be written to the record stops the run before anything runs in the box, which is deleted), `TestKubernetesRecipeLive` (with `SANDPROBE_KIND_KUBECONFIG` and a `kind-` context only: a real run without a canary, incomplete, its pod confirmed gone and no pod or record left; `-as nobody` on the default root pod stops before any check, and the pod is deleted) |
| HCN-8 | `internal/canary/maintenance_test.go`: private drain/status/resume, reservation/arm ordering, receipt preservation, expiry, legacy omission and public refusal; `internal/canarycontrol/maintenance_test.go`: maintenance routes unavailable on public HTTP |
| HCN-7 | `deploy/canary_test.sh`: the operator canary's service unchanged (the non-public user data was checked byte for byte against main's), the hosted canary's signed control for its own address, its control key made once in its own state directory, its wait for its address, staging only on request, its own domain, state file and namespace, `publicstart` taking only an address before any AWS call, and `publiccheck` running under `set -u` on macOS's bash 3.2 with and without staging (an empty argument array once stopped a production deploy's final check); `TestCanaryCheckRefusals` (a URL without its pin, a pin without its URL, by flag or environment, a URL that isn't `https://control.<domain>`, `-tls-insecure` outside `canary check`); `TestCanaryCheckDefaultsToTheHostedCanary` (with nothing named, beside a stray operator state file, `canary check` asks the hosted canary, here a stand-in on a local port under its own pin, names it in text and JSON, and leaves every slot free; `-canary`, by flag or `SANDPROBE_CANARY`, is refused before anything is asked; `-tls-insecure` without `-canary-url` is refused; under a pin the stand-in doesn't sign with, its status is unproven, exit 4); `TestOperatorCanaryFixRunsAsPasted` (the refusal of an operator canary prints a fix that is a command alone: it passes `sh -n`; run through `sh` where `deploy/canary.sh` is a stub, it hands the stub `AWS_PROFILE`'s value exactly, or an empty `PROFILE` when that is unset, and `status`; with `AWS_PROFILE` unset, the real `canary.sh` refuses before its stubbed `aws` is called) |
| ANL-1/ANL-2/CMP-1 | `internal/analysis` saved-report corpus, contradictions, descriptor refusal and comparison tests; `cmd/sandprobe` offline CLI regressions |
| CMP-2 | `internal/analysis/analysis_test.go` `TestCompareBetter` (finding to `pass` or `absent`, and `unknown` to `pass`, better; finding or `unknown` to `scoped_out` no longer applies, never better; finding to `not_found` or `unknown` not proven, never better, and to `unknown` still coverage loss and incomplete; `unknown` to `not_found`, a dropped severity and clean to clean in neither list; a pair with one check better and another worse keeps both; each score is SCR-2's; an invalid run has a `null` score and empty lists); `cmd/sandprobe/analysis_test.go` `TestCompareGolden`, text and `-o json` against `cmd/sandprobe/testdata/compare/`: `egress-open` to `egress-refused` (finding to `pass` better, finding to `not_found` not proven, 2/6 to 3/6, exit 0), `canary-down` to `egress-refused` (`unknown` to `pass` and finding to `pass` better, the identity lines, exit 5), `vibe` to `hardened` (the fix loop: 1/6 to 6/6, identity changed, exit 5), and `hardened` with a PER-1 finding to `regressed` (PER-1 better, SEC-3 worse, `Verdict: worse.`, exit 6); `TestCompareNoScoreAndNoLongerApplies` (no score line when a run is invalid, and the words say which; a `scoped_out` check listed under "No longer applies", never under Got better); `TestCompareASCIIAndWidth` (every golden pair, and a scoped-out pair, under `LC_ALL=C` and `LC_ALL=POSIX`: ASCII only, `*`, `>` and `->`; in every locale, each line within 80 display columns); `cmd/sandprobe/feedback_test.go` `TestFeedbackPassesOwnOutput` (compare's wrapped output passes FBK-4 with no exemption) |
| JON-1/JON-2 | `internal/strictjson` framing/bounds/fuzz; `cmd/sandprobe-probe` input and argument regressions; offline Linux CI |


Boat PRV-11: `internal/host/boat_test.go` checks single create, explicit no-env/snapshot/monitoring/personal-wallet policy, immediate ID journaling including malformed optional fields, identity and command truncation rejection, and target-bound permanent deletion. `cmd/sandprobe/boat_test.go` checks approval before credentials.

Daytona PRV-12: `internal/host/daytona_test.go` checks single create, immediate ID journaling, ambiguous create refusal and original-ID terminal cleanup. `cmd/sandprobe/daytona_test.go` checks approval before credentials. `make test-daytona-sdk` checks pinned generated models, creation policies, fixed URL scope, redirect/retry rejection and offline SDK version checks; install the lock with --require-hashes --only-binary=:all:.

Cloudflare PRV-10: `internal/host/cloudflare_test.go` covers capability-file/origin safety, intent-before-create, no retry, prior-run refusal, explicit response evidence, upload/survey lifecycle and cleanup. `cmd/sandprobe/cloudflare_test.go` checks approval before credentials and honest no-intent cleanup. `node --test deploy/cloudflare/controller.test.mjs` checks authentication, single create, identity/expiry fencing, body bounds and timeout/bootstrap failure. `python3 -m unittest discover -s deploy/cloudflare -p manage_test.py` checks preflight, safe key files, exclusive/atomic journals, identity-change refusal and staged cleanup recovery.

PRV-9 project setup: `python3 -m unittest discover -s deploy -p vercel_project_test.py` checks token validation before intent, exclusive intent before POST, immediate ID journal before GET, ambiguous-create retention and refusal to issue a second create.

Vercel PRV-9: `internal/host/vercel_test.go` verifies token-file safety, team/project binding, create-returned directory persistence/pinning and cross-base upload refusal, exact SDK origin/prefix, fixed-label bounded diagnostics, create ambiguity and
identity journaling before optional parsing, replacement/persistence/timeout checks, gzip/tar upload integrity,
stream output limits and terminal-event validation, redirect/error sanitation, immutable-session cleanup and
GET404 record deletion. `cmd/sandprobe/vercel_test.go` covers offline planning, approval-before-credentials and
cleanup using an independent bounded context. Provider wire fixtures follow official SDK3.9.1 contract shapes.

E2B PRV-8: `internal/host/e2b_test.go` covers credential-file ownership, FIFO and symlink rejection, create-ID
journaling before optional-field parsing, expiry, identity checks, redirect/error sanitization, upload integrity,
SDK isolation, bounded output and deletion confirmation. `cmd/sandprobe/e2b_test.go` covers offline planning,
approval-before-credentials and independent bounded cleanup. `internal/host/e2b_runtime_test.py` covers the pinned
SDK constructor, ID/port/token binding, explicit user and twin marker, and streaming stdout/stderr limits.
Validate the dependency lock by installing into a fresh venv with `--require-hashes --only-binary=:all:` and running
`make test-e2b-sdk`. The opt-in live lifecycle test and baseline need the operator's authorization (PRV-8).

Baseten PRV-6/PRV-7: `internal/host/baseten_test.go` covers credential handling, token exchange, URL/redirect validation,
create ambiguity and expiry, incarnation replacement, terminal execution, upload, persistent lifecycle state and
verified cleanup. `cmd/sandprobe/baseten_test.go` covers bounded scope, CLI planning and approval, and cleanup exit precedence. PRV-7 cases also cover retained/failed/interrupted lifecycle, server expiry policy,
private journal recovery, cleanup approval and grade/report semantics.

Every rule has a test. Fixture boxes run in local Docker (Docker Desktop is on this Mac), each built from a Dockerfile
under `test/fixtures/`, beside a local canary container that plays SBX-11. A fixture's "reset" is defined per case.
`test/fixtures.sh` builds the images and runs each fixture through the whole host path: the survey, the plan, health
on the canary's published ports, the probe through `docker exec` as the fixture's agent user (the probe bind-mounted
read-only), the receipt query through `docker exec` into the canary, and the grade. A stub (`test/fixtures/stub`)
plants instance metadata at 169.254.169.254, on its own link-local network, with one role whose credential document
must never be asked for, and a TLS endpoint standing in for the Kubernetes API; its request log is checked. The
fixtures' Docker box is reset by recreation (TWN-3's recreate model): removed, then created again from the same
arguments with the volumes Sandprobe created for it, each identified by its name and creation time, so a volume made
again under the same name is another volume. Teardown deletes the box by its container ID and a volume only while its
name still names the volume created for the run, and reports either gone only on Docker's definitive "no such"
answer. Docker deletes volumes by name alone, so a volume made again under the name between that check and the
deletion could still be removed: a limit of this local fixture adapter only, since real providers' adapters delete
by immutable ID.
Fake secrets hold only `sandprobe-fake` and nothing secret is ever planted.

| Fixture | Planted | Must report |
|-|-|-|
| `clean` | non-root user, no capabilities, `NoNewPrivs`, read-only root, no network | A only once every two-sided check is exercised or `scoped_out` with a reason, with its find-only checks listed as not proven; never because a path, tool or service is missing |
| `holes` | sudo `NOPASSWD`; fake credential files (one empty), one behind a relative symlink and one behind a Kubernetes-style token symlink chain; `FAKE_API_TOKEN`; a root stub socket at `/var/run/docker.sock`, mode 0666; a metadata stub with a role; open egress to the canary; writable `/etc/profile.d`; a root-owned 0444 `~/.bashrc` in an agent-writable home; a persistent volume | F; each hole found by its check (PER-1 by replacement; the empty file an Info indicator); CHN-1 confirmed from the non-empty file, potential from `FAKE_API_TOKEN` |
| `deceptive` | a box `curl` shim that opens a fake secret, and a curl config that adds an unplanned destination; a box `curl` that is a symlink to a short fake secret; a sudo shim in an agent-writable PATH directory that writes a sentinel; a sentinel-writing shim at `/usr/local/bin/sudo` with `/usr/local/bin` agent-writable; `/usr/bin/sudo` replaced by a symlink to a shim; a root-owned mode 4777 sudo in a safe directory; a root-owned sudo shim earlier in PATH that prints the password prompt while the real sudo is `NOPASSWD`; `LD_PRELOAD` and `/etc/ld.so.preload` libraries that fail `connect`; a proxy that answers 403 while direct egress is open; a proxy URL holding credentials; a TLS interceptor with its own key; a resolver that lies about the canary | no affected check passes; the box's `curl` never runs (process accounting shows it); the fake secret behind the `curl` symlink is never opened or hashed (an access watch shows it); no sudo shim's sentinel is ever written, and AMP-1 is unknown where no sudo qualifies; the proxy credentials appear in no argument, canary traffic, log or report; EGR-2 never passes through the interceptor; never A or B |
| `network` | the canary refusing connections while egress is open; the canary failing only during one attempt; a wrong SNI on an open network; a name server that logs the query and returns NXDOMAIN; a resolver that answers our name locally while other queries leave; egress open on one port only; a fault-injection build of the probe that skips `connect` and reports a refusal; another that prebinds a local port, skips `connect` and returns a refusal-shaped error; others that return an immediate `ECONNREFUSED`, `EHOSTUNREACH` or `EPERM` without calling `connect`, the last beside an unrelated active seccomp filter | any refusal without TWN-1's full proof is unknown, never a pass; the logged query is a finding by receipt; the local answer is `not_found`, never a pass; each port is scoped to itself |
| `policy` | sudo `NOPASSWD` for one command other than `true`, with `listpw=always`; the same with listing behind a password; a policy allowing `true` with a box-controlled `true` early in sudo's path that writes a sentinel | AMP-1 a finding or `not_found`, never a pass; the sentinel is never written, because sudo never runs a command |
| `sudors` | sudo-rs on Ubuntu 26.04 as shipped, `/usr/bin/sudo` a link to `/etc/alternatives/sudo`, a link to the root-owned setuid `/usr/lib/cargo/bin/sudo`; an agent with `NOPASSWD` for every command, and one with no rule; the agent with no rule, no capabilities and `NoNewPrivs`, under which sudo-rs stops at once; the same as root; the middle link in a world-writable directory; `/etc/alternatives` itself a link to a directory whose real parent is world-writable; the chain ending nowhere; nine root-owned directory links on the way; root's link to `su` in a directory the agent owns at mode 0555; root's links in a sticky directory, where the agent, holding only `CAP_FOWNER`, moved the link to `su` over the link to sudo, then probed with that capability | AMP-1 walks the chain and runs the pinned file: a `nopasswd_all` finding, and `not_found` with no rule or under `NoNewPrivs`, each naming the chain; the rest unknown, never absent, never run (the `NOPASSWD` agent shows no finding), each naming what failed: root or the capabilities held, the directory not root's or writable, the link not root's, more than 8 links, or a chain that can't be followed; for the `CAP_FOWNER` agent, PER-1 to PER-4 findings and SEC-3 unknown, each naming the capability, never passes (TWN-4) |
| `reset` | a name reused by a replacement with a different volume; a reboot without restore; a restore that fails; a persistent volume remounted at another path or subpath; a cleaner that deletes only the marker while another file survives; a root that refuses its marker beside one that takes it; the same directory reached as home and as a mount; the marker replaced after the reset by an unrelated regular file holding the run id; a marker name swapped while the run ends; a recreate whose box is deleted while its volume, and the marker on it, stay | PER-5 never a finding without TWN-3, never a pass; the cleaner case `not_found`, with other data listed as not proven; a refusing or changed root unknown, never `not_found`, the refusing root's gap naming its cause (the agent can't write it, so the survey didn't list it); one marker per directory; the substitute never read and unknown; no file ever removed by name, every marker listed as a cleanup item when its box or volume isn't confirmed deleted; the surviving volume's marker never reported cleaned up |
| `effects` | a symlink at a marker path; a missing storage root; a FIFO at a credential path; a credential file swapped for a FIFO between the probe's checks (a race harness); a dangling symlink at a credential path; an inotify watcher on home and `/etc`; a cleanup that fails; a socket-activated listener; pre-existing loopback services that log every connection; `HTTPS_PROXY` pointing at one of them, run once without approval and once with | the box's files and inodes change only by the probe binary and its scratch directory, both removed, and listed markers, each gone with its confirmed-deleted box or volume or listed as an unresolved cleanup item, nothing removed by name; no FIFO opened; the dangling link unknown, never absent; the socket-activated listener never activated; no pre-existing local service logs a connection, except the approved proxy, which logs exactly one `CONNECT` to the canary; without approval EGR-3 is skipped and listed; every connection on the fixture network is to a fixed destination the plan named or a box-named one the resolved plan pinned within its approved class |
| `evidence` | a same-UID peer process; a metadata stub with no identity permission; a host that allows a TLS handshake but refuses an upload; `hidepid=2`; a writable stale control socket; a world-writable control socket whose server rejects the agent by peer UID; a control port blocked by an owner-match rule; an agent path that execs commands directly and never sources a writable `~/.bashrc`; the agent's own home at mode 0555 above root's read-only startup files and its own credential file at mode 0000; the same home reached through root's directory link; the agent holding only `CAP_SETGID` over `/root` searchable and its startup files writable only by one group; the agent holding `CAP_DAC_READ_SEARCH` permitted, not effective, over a home root's at mode 0000 and a startup file anyone may write; the home reached through the agent's own link in root's sticky directory, to root's 0555 directory and read-only startup files; the home as root's link to root's 0555 directory whose startup file is a link to `../target`, one anyone may write in the real parent, while `/home/target` beside the link is read-only, and whose credential files are links to `../` names, one closed in the real parent and readable beside the link, the other the reverse; the home as a chain of eight root-owned directory links whose startup and credential files are a ninth link each; `HOME` and the first PATH entry set to `/spcase/base/link/..`, whose link leads to `/review/real/dir`, where the kernel's `/review/real` holds a startup file anyone may write, a readable credential file and a file named `sudo`, while `/spcase/base`, the lexical reading, holds a read-only startup file, a closed credential file and no sudo; the agent as uid 65534 holding no capability, with `NoNewPrivs` 0, Docker's default bounding set, no setuid-root file in the system binary directories and, outside them, a copy of `cat` with `cap_dac_override+ep`, and the same box under Docker's `no-new-privileges` | SEC-5 tests the peer; SEC-4 an indicator, not a proof; EGR-6 an indicator and CHN-1 potential; SEC-2 `scoped_out`, never `absent`; the sockets and the port are indicators, never proofs, never CHN-2; PER-1 an indicator that records the path isn't sourced; the 0555 home's PER-1 a finding that says the agent owns the directory, and SEC-3 unknown for the agent's own 0000 credential file; the linked home's PER-1 a finding naming the real directory; PER-1 unknown under `CAP_SETGID` and under `CAP_DAC_READ_SEARCH`, each naming it, since the probe can't see past the closed directory; the sticky-linked home's PER-1 a finding, since the agent can replace its link; the `../` home's PER-1 a finding and SEC-3 a finding naming only the credential file the kernel lets the agent read; the nine-link home's PER-1 and SEC-3 unknown, more than 8 links; the `link/..` home's PER-1 and SEC-3 findings, and AMP-1 unknown, a sudo only off the fixed paths, never absent; never a pass; for the uid 65534 agent, the test first runs the copy from the agent's shell, and the kernel gives it `CAP_DAC_OVERRIDE` with `NoNewPrivs` 0 and nothing with 1; AMP-2 passes in both, and AMP-3 is unknown with `NoNewPrivs` 0, naming file capabilities and no-new-privileges, and a pass with 1 |
| `substitute` | the probe replaced inside the box by one that reports the expected digest and every check passing | the report calls the probe host-shipped, never attested, with SBX-10's boundary beside the grade; the test records that this substitution is not detected, as SBX-10 says |
| `broken` | a `noexec` scratch filesystem; a box of the wrong architecture | invalid, no letter, exit 5 |

- **Fault builds never ship.** The `network` fixture's fault-injection probes are built with the `sandprobe_faults`
  tag, which replaces `connect` for any address but loopback; the evidence the probe gathers stays honest, so the
  grader must refuse each one. A shipped probe carries none of it, and `SANDPROBE_FAULT` means nothing to it.
- **Release gate.** A probe build ships only if its exact digest produced receipts on every canary port in the
  `network` fixture's open case, so the shipped binary is known to make the attempts it reports.
- **Test overrides are visible.** Endpoints are redirected only through `SANDPROBE_TEST_*` variables. Each one lands in
  `overrides`, and a run with any override stamps TEST ENDPOINTS on its grade, so a real run can't be redirected
  silently.
- **Grader.** Go unit tests feed synthetic observations through every GRD, CHN, KND and TWN rule, including: a check
  omitted; duplicate IDs; an ID not in the manifest; a forged pass; two outcomes for one check; a mismatched nonce, box
  ID or digest; oversized fields; HTML and script payloads in every string field (the HTML report must render them as
  text under its CSP).
- **Agent contract.** A non-terminal `run` without `-y` exits 3 with the plan; an existing box without `-attest` exits
  3; every error carries `fix`; NDJSON parses line by line; every fixture report validates against `sandprobe schema`, whose `toolchain` entries forbid any hash field.
- **TUI.** Golden frames at 80 columns, reduced motion, both palettes; `NO_COLOR` output holds no escape codes.
- **Adapters.** Fake provider CLIs and APIs, in the style of CST-20's fake `sprite`: an adapter refuses to reset or
  delete any ID it didn't create this run, records every call, and reports a failed delete.

| Rules | Test |
|-|-|
| SBX-1, SBX-2 | `effects`, and every fixture: files before and after differ only by listed markers; no evidence field holds `sandprobe-fake` |
| SBX-3 | every fixture: a capture on the fixture network holds only connections to targets the plan named, and `contacted` matches it |
| SBX-4, SBX-5, SBX-6 | `deceptive`; `substitute`; identity fields present in every fixture; an accidentally swapped binary invalidates the run |
| SBX-7, SBX-8, SBX-11 | `network`; a canary that hangs; the release gate; the canary's unit tests (an unarmed nonce, or an armed one on another port, leaves no receipt and can't crowd the matching one out; each cap holds; a refused arm; an expired, disarmed or unknown run, or another pin, fails the query; a hit connection cap, or a rise in the kernel's drop counts, marks the armed run overloaded; the worst-case answer encodes under 8,000 characters, and one over 16,000 is refused; peak healthy concurrency from one address, 8 runs' attempts plus health, stays under the per-source cap); the grader's (an overloaded run passes nothing and finds nothing `not_found`, while a receipt still finds); `deploy/canary_test.sh` (teardown against fake CLIs) |
| SBX-9, GRD, CHN, KND, TWN-1, TWN-2 | grader unit tests; `clean`, `holes`, `evidence` |
| TWN-5 | `TestProcessRefusalCapabilities`: effective/permitted process-access powers, missing evidence and forged passes rejected; bounding-only capabilities, genuine proof after dropping powers, absent targets and preserved findings |
| TWN-4 | `internal/probe/probe_test.go`, as nobody and as root: `TestWriteOwnerPower` (a file under the agent's own 0555 directory found as its owner; `CAP_FOWNER`, `CAP_CHOWN` or `CAP_SETUID` found, `CAP_FSETID` not; a kernel setting never), `TestStickySpares`, `TestJudgeWrite` (nothing found with `CAP_SYS_ADMIN` is unknown; a proof-class check is never found from a mode the agent would first change), `TestSocketCheck` (the agent's own socket at mode 0 found), `TestRefusalsHold` (its own 0000 file, or a refusal under a read power, unknown; an absence still judged as before; a process file's refusal unknown under `CAP_SYS_PTRACE` or `CAP_SETUID`); `TestModelAgainstKernel` (the model against a brute-force search of every setuid, setgroups, chmod, chown and lchown sequence, on curated cases and 12,000 seeded paths: two or three components below `/`, a directory holding an absolute or relative link with its own owner, or a link to a directory followed by `..`; a disagreement either way fails), `TestWalkPathNodes` (a directory link kept as an entry of its own directory, then followed to the real directories; refused past eight links; nothing seen past a directory the probe can't search), `TestWalkAgreesWithKernel` (a last link to `../target` after a directory link lands where the kernel's `stat` does, in the real directory, for the walk and the read pin alike; eight directory links and a last link leave the walk, the read and the write unknown), `TestDeviceChangeIsNoMountPoint` (an entry on another device, unmarked by `STATX_ATTR_MOUNT_ROOT`, still replaceable in the model), `TestRawPaths` (a home, a relative path and a path with repeated slashes and `.`, each naming `link/..`, kept as given and resolved where the kernel's `stat` lands, never at the decoy beside the link; a PATH entry of `link/..`, absolute or relative, finds the sudo the kernel reaches; `..` past a missing name unknown), `TestPathDirs` (PER-2's PATH entries as given), `TestStickyLinkReplaceable` (the agent's own link in root's sticky `/tmp`: a write through it found, and the kernel then allows the rename it rests on), `TestPinSudoStickyLink` (AMP-1 refuses the same link on sudo's chain), `TestReachPastEarlyReturns` (every early negative of a file check, a pass, an allowed absence, a `scoped_out` and AMP-1's absence, unknown under `CAP_SYS_ADMIN`, and its negative without it); `test/probe.sh` runs `TestSetuidProcfs` as nobody with `/proc/sys` writable (a kernel setting root may write leaves AMP-8.sys unknown under `CAP_SETUID`), and `TestTwinReadPower` as nobody holding `CAP_DAC_READ_SEARCH` and `CAP_DAC_OVERRIDE`, where the probe's own 0000 file must open; the grader's case for a file-read twin without its refusing side; `clean` (a read-only root over the agent's own home stays a pass); `evidence` (an owned 0555 home above root's startup files, and an owned 0000 credential file; the same home through root's directory link; `CAP_SETGID` over a group-search `/root` and group-write files, and permitted `CAP_DAC_READ_SEARCH` over a closed home and a file anyone may write, both unknown; the home reached through the agent's own link in root's sticky directory, a finding; a last `../` link after the home's directory link, a finding for the write and for the one read the kernel allows, each decided in the real directory; eight directory links and a last link, unknown; `HOME` and the first PATH entry naming `link/..`, a finding for the write and the read and AMP-1 unknown, never a pass or absent), `sudors` (the `CAP_FOWNER` agent) |
| TWN-3, PER-5 | `reset`; `internal/probe/per5_test.go` `TestRecheckIdentityDiagnostics` (inode, length and combined mismatch remain unknown and unread), `TestMarkUnlisted` (an unlisted root takes no marker and says why, a mode 0111 root included, as nobody and as root), `TestMarkUnreadableRoot` (a mode 0300 root marked and rechecked); `internal/grade/per5_test.go` `TestPER5GapReasons` (each gap's cause named, no identity told from a different one, the box's reasons bounded) |
| SBX-4 (NoNewPrivs absent) | `internal/probe/identity_test.go` `TestParseStatusWithoutNoNewPrivs` (GKE's gVisor status: absent, not fatal; a present line that isn't 0 or 1, and no CapEff, still fatal); `internal/grade/workload_test.go` `TestWorkloadNoNewPrivsAbsent`; `internal/grade/grade_test.go` `TestNoNewPrivsAbsent`, and the absent rows of `TestAMP2CapabilitySets` and `TestAMP3NewPrivs` (AMP-3 unknown with or without setuid files; AMP-2 as for 0) |
| AMP-2 | `internal/grade/grade_test.go` `TestAMP2CapabilitySets` (a capability only permitted, or ambient, counted at its severity and named so; an inheritable one unknown with `NoNewPrivs` 0, ignored with 1; a missing `CapPrm` or `CapInh` unknown unless uid or `CapEff` already find); the `evidence-drs` fixture (`CAP_DAC_READ_SEARCH` permitted, not effective: Critical, never a pass) |
| AMP-3 | `internal/grade/grade_test.go` `TestAMP3NewPrivs` (with `NoNewPrivs` 0 never a pass: setuid-root files a finding; otherwise unknown, naming file capabilities and no-new-privileges, whatever the capability sets hold, empty bounding and inheritable sets and root included; an incomplete scan unknown; `NoNewPrivs` 1 a pass, setuid-root files or not); the `evidence-filecaps` fixture (uid 65534 holding nothing, `NoNewPrivs` 0, Docker's bounding set, no setuid-root file, and a `cap_dac_override+ep` file the kernel lets the agent gain `CAP_DAC_OVERRIDE` through: AMP-2 a pass and AMP-3 unknown, never both passing) and `evidence-filecaps-nnp` (the same box with `NoNewPrivs` 1: the kernel grants nothing, and both pass) |
| AMP-1, PER-2 | `policy`, `sudors`, `deceptive`, `evidence` (a PATH entry of `link/..` whose sudo the kernel reaches: unknown, never absent); `internal/probe/reach_test.go` `TestRawPaths` (the same entry, absolute or relative); `internal/probe/amp_test.go` `TestPATHWorkingDirectory`, as nobody and as root (a writable working directory holding a file named `sudo`, with PATH empty, `::`, ending in a colon, or unset: PER-2 a finding or unknown, and AMP-1 unknown, never a pass or absent); `internal/probe/amp_test.go`, as nobody and as root: `TestPinSudo` (each allow-list refusal saying what failed, a setuid file not named sudo included), `TestWalk` (every link counted and named, a directory's included, `..` taken as the kernel takes it, refused past 8), `TestPrivileged` (root or any capability named, read with `capget`), `TestSudoList` (a stand-in run from its descriptor; a `#!` file never run; a run ended by a signal unknown); `test/probe.sh` also runs `TestSudoList` as root with a fake tree mounted over `/proc`, whose `/proc/self/fd/3` plays a sudo granting everything, and every listing must still come from the pinned stand-in |
| SEC, EGR, PER, AMP | `holes` (found), `clean` (verified or scoped out), `deceptive` and `network` (never pass), `policy` and `sudors` (AMP-1), `evidence` (class right) |
| OUT, AGT | contract tests; schema validation; the grader's injection cases |
| UX, OUT-4, AGT-1 | `cmd/sandprobe/tui_test.go` and `cmd/sandprobe/tui_pty_unix_test.go`: `TestResultGoldenNonTTY` (non-TTY output byte-identical to golden, zero ANSI escapes, zero key bar, no letter grade), `TestResultStatesAndWidth` (valid 1/6 with chain and receipts, clean 6/6, `x/5` not-applicable, `Green · not proven`, incomplete, no-canary, invalid with no counts, unconfirmed cleanup exit 7, and wide CJK/emoji box strings, every line <= 80 display columns), `TestTerminalInjectionEscaped` (control characters, ESC sequences, Unicode line/paragraph separators and category `Cf` format/bidi/zero-width/BOM characters in box name, live phase, invalid reason, evidence, cleanup and walker paths escaped; category rows carry no box strings), `TestModeTable` (TTY vs non-TTY stdout/stdin, `NO_COLOR`, `TERM=dumb`, ASCII `LC_ALL=C`, reduced motion), `TestLivePhasesFromPlan` (plan-derived phases per provider, with no `reset` on Nitro, `exec` or `run docker`, which never resets under DKR-5), `TestWalkerKeysNeverHangNonTTY` (interactive walker steps through findings, explains checks, resolves a leading-`-` `-out` report path to an absolute path before opening, and never waits when stdin or stdout isn't a TTY), `TestPTYKeyLoopIdleEOFSignalsAndOptOut` (real PTY subprocesses, each a session leader with the PTY as its controlling terminal and itself made the foreground group with `tcsetpgrp`, refusing to run otherwise; a child moved to a background group skips the key loop at once: silent open stdin auto-exits on idle timeout, `q`, `Ctrl-D`, master `EOF`, `SIGTERM` and `SIGHUP` each restore cooked `termios`, and `CI=1` / `SANDPROBE_NO_KEYS=1` skip the key loop immediately), `TestMinScoreGate` and `TestMinScoreGateLimitations` (`-min 0..6` and `-min full`, exit precedence 7 > 6 > 5 > 0, refusal of retired letter values and of `-min 6` on 5/5 provider-terms adapters, and explicit demonstration that same-category severity or proof-to-`not_found` regressions keep the score exit unchanged); `cmd/sandprobe/tui_live_test.go`: `TestEveryRunnerFeedsTheLiveTracker` (UX-5: each of the twelve runners builds its tracker from its own `livePhasesFor`, routes the canary through it, starts every phase its plan lists, finishes the probe only on success and hands the cleanup outcome to `close`; no step line bypasses it), `TestLivePhaseNeverTicksSkippedOrFailed` (each adapter's failure paths, in the in-place view: a cut-short phase reads `did not finish`, a never-started one `not run`, an unconfirmed cleanup or unretained `retain` `not confirmed`, and none of them is ticked), `TestRunnersLiveOutcomeOnFailure` (a hung fake Docker run and a failing `run exec` end with no tick on any phase that didn't finish); `cmd/sandprobe/tui_findings_test.go`: `TestEvidenceClassInSummaryAndWalker` (UX-6, UX-7: an indicator-only top finding, a potential chain and an unnamed class read `a sign we saw, not confirmed`, a proven chain `proof`, every walker finding has its class and an unknown none), `TestEscGoesBackFromAFinding` (Enter, then `Esc` or `b`, returns to the summary; only `Esc` on the summary or `q` quits), `TestScorecardFitsEightyColumns` (UX-9: every line of `scorecard` on every saved report within 80 columns, and ASCII only under `LC_ALL=C`), `TestNotFoundReasonNeverBecomesHostText` (UX-6, SBX-10: a fixture bundle built through `host.Plan`, `grade.GradeBytes` and `report.Build` with box-chosen SEC-4 and AMP-7 `not_found` reasons, the probe's usual words, a host-sounding claim or injected text, stays valid and keeps them in its JSON, while the summary and `scorecard` show only "not proven" and catalog labels); `cmd/sandprobe/tui_pty_unix_test.go`: `TestForegroundFailsClosed` (UX-7, AGT-1: a pipe and a PTY that isn't this process's controlling terminal both read as not foreground) |
| SCR-3 | `internal/report/fix_test.go`: `TestPageOrder` (specification sheet, score split, result ledger, 3×2 category matrix, `What to fix` groups, `Other checks` fold, and numbered `Run details` chapters in order), `TestEveryTestOnce`, `TestEveryTestOnceUnrated`, `TestCountsComeFromRows`, `TestUnknownIsNeverAPass`, `TestNoLetterGrade`, `TestHeaderFacts`, `TestInvalidHasNoCounts`, `TestHTMLExecutedCountsExcludeScopeOnlyResults`, `TestPlainEnglishRowsAndIdentity` (service callout, decoded Linux capabilities/`no_new_privs`/`seccomp`, catalog pass/absence explanations, and indicator sign notes), `TestPlainEnglishNeverOverclaims` (a missing, malformed or oversized capability mask, an invalid `no_new_privs` and an unknown seccomp mode read "unknown", seccomp 0 and a report with no seccomp field both read "no filter reported (0)" and never "disabled", and an unnamed high bit is named by its number; every built-in provider has its own label and an unrecognized one is never shown as the page's label; every check's not_found line keeps "doesn't prove" and claims no block or observation, and its scoped-out line "neither a pass nor a failure"; SBX-10's boundary keeps its facts; the hardened demo's page never says a TLS session was seen, its unproven row reads `none found · unproven`, and the clean lead keeps its caveats; a saved report with the earlier boundary shows the current one with every fact, keeps its own strings in the embedded JSON and keeps ANL-1's note; a CHN-1 or CHN-3 finding leads OUT-1's `lead`, and only CHN-2 is left out); `internal/report/scorecard_test.go`: `TestScorePage`, `TestGreenNotProven`; `internal/report/report_test.go`: `TestNoFindingIsNotAllRefusals`, `TestIndicatorsStayIndicators`, `TestPlannedIsNotContacted` |
| UX-8, UX-9, OUT-2 (palettes, contrast, nothing loaded) | `internal/report/report_test.go`: `TestThemes` (no theme, `auto`, `modern` and any unknown value render `auto`; `light`, `graphite` and `mission` render themselves, and `dark` renders `graphite`, the name on the page and its button; every page carries the three palettes and the `prefers-color-scheme` rule that gives `auto` its dark one; the button steps through exactly the four and remembers the choice, a remembered `modern` or `dark` reads as `graphite` and an unknown one is ignored; the fonts named are Geist and Geist Mono first; the contents rail goes away under 900px), `TestSystemScheme` (a dark system gives `auto` exactly `graphite`'s tokens, and no rule names a light system, so `light` shows anywhere else; every palette sets the same tokens; print's palette comes after them all and sets every color token it uses, so a page prints on white whatever the screen shows), `TestHTMLLoadsNothing` (every saved report in `demo/reports` and `test/reports`, in every palette and as a saved re-render: no `<link`, `@import` or `@font-face`, every `src`, `href`, `srcset`, `xlink:href`, `action` or `poster` attribute and every CSS `url(` is a fragment, and the CSP is unchanged); `internal/report/style_test.go`: `TestContrast` (the test parses the page's stylesheet and requires an entry in its `audit` table for every declaration that uses a palette token, on any property, in the stylesheet's rules outside `@keyframes`: the entry says what the color is for there (text, a mark, a hairline or a surface) and which surfaces it is drawn on, and the token is read from the stylesheet, never from the table. A declaration that takes its color from a local custom property needs its entry too, and is measured as every token a rule sets that property to. It fails on a use the table doesn't name, an entry the stylesheet no longer has, a color written out that `fixed` doesn't list with its reason, a role the property can't hold (a `color`, or the `fill` of the map's `<text>`, is always text and never a hairline), a surface no rule's background makes, and any text under 4.5:1, mark under 3:1 or hairline under 1.2:1 on any listed surface in `light`, `graphite` or `mission`; an unknown mark never has a pass's color), `TestTypeSizes` (every `font` and `font-size` a screen rule sets is worked out to the least it can come to: `px`, `rem`, `em` and `%` against the least its parent can be, as `sizeParents` states and the test requires for every relative size, viewport units as nothing, `clamp()`, `min()`, `max()` and `calc()`; none is under 12px, `mission`'s rules included, but for its one capitals rule, named by its selector and held to 10.5px; the map's is taken at the smallest size a screen draws it; body text is 14px on 1.55, and `mission`'s 13px), `TestKeyframeColors` (every color a keyframe sets is the token `keyframeColors` lists for that animation and property, the flash's selection wash and nothing else, and a row's text is at least 4.5:1 on that wash in every palette), `TestLength` (the length arithmetic and the `font` shorthand against known values); `internal/report/theme_test.go`: `TestContrastMath` (the ratio and the blend against known values); `cmd/sandprobe/theme_test.go`: `TestThemeFlag` (`scorecard -out` with no `-theme` writes an `auto` page, each palette's name writes that palette, `dark` writes `graphite`, and `modern` writes `auto`) |
| UX-4 (SEC-4's addresses) | `cmd/sandprobe/sec4_plan_test.go`: `TestPlansNameEverySEC4Address` (docker, aws-nitro, and run exec and run kubernetes with `-provider-endpoints SEC-4` each name 169.254.169.254:80, 169.254.170.2:80 and 169.254.170.23:80 word for word, with each one's condition and what is sent; sprites, e2b, daytona and run exec without SEC-4 name none), `TestProbeDialsTheCatalogMetadata` (the probe's address constants are `catalog.Metadata`'s, and no other metadata address is written in the probe, so a probe address the plans don't name fails) |
| PRV | fake provider tests; then one live run per provider |
| RUN-12 | manager readiness/admin separation and pinned host-model shape/account/retry tests |
| RUN-13 | managed exact collector options reach survey while EGR-6 stays skipped; fresh repair staging and pinned-SDK nonroot read-only filesystem regression |
| RUN-14 | existing managed lifecycle, request-budget and original-ID cleanup regressions; retained continuation provenance and assessment |
| EVD-5 | shared configuration evidence schema, exact image-identity fixtures, Nitro guard and Daytona unavailable-evidence artifact |
| EVD-11 | pinned-SDK exact organization path and binding/error fixtures; host response sanitization and artifact shape validation tests |
| EVD-19 | `test_organization_network_policy_uses_only_bound_sandbox` and `test_organization_policy_pinned_sdk_uses_explicit_sandbox_path`: fresh identity binding, exact sandbox GET, no account API/fallback, strict response identity/boolean and bounded failures |
| EVD-23 | `TestGapDispositions`: policy precedence, missing features, absence/silence, host failures, held-vs-bounding capabilities, complete partition and unchanged scores/results |
| EVD-22 | `TestMeasurementPrerequisites`, `TestGapPlan`, `TestGapPrerequisiteInput`, and `TestGapsCommand`: masked prerequisites, independent scope/implementation gates, unchanged outcomes, private exclusive writes, strict binding/schema/enum rejection and bounded offline output |
| EVD-21 | `TestCollectionFailureStageIsBounded` and `TestCollectionFailureSidecarIsBounded`: survey-stage cause retention, fixed stage extraction, nested SDK status/guard classification, no raw-error serialization and no emitted assessment |
| EVD-20 | `TestManagedEvidenceVersion`, `TestWorkloadSummaryEvidenceVersion`, `test_managed_evidence_versions`: explicit v2 writers, legacy replay, unknown/null version rejection and no unversioned reset-stage downgrade |
| EVD-14 | `test_organization_policy_failure_categories_are_bounded`, `TestOrganizationPolicyFailureReasons`, and `TestDaytonaOrganizationPolicyFailureReasons`: pinned SDK exception categories, raw-data rejection and unchanged unknown/configuration-only semantics |
| EVD-16 | `TestManagedDaytonaPreservesNativeExclusionKind`: native kinds frozen before probe execution, identical selected/skipped sets, Cloud access not applicable but never green, and zero measured/conclusive credit for exclusions |
| EVD-17 | `TestWorkloadExposurePreservesValidatedProvider`: public bundle recomputation retains valid provider scope, matches canonical report scoring and coverage, and invalid contracts never yield a valid score |
| EVD-18 | Empty-marker Linux positive/negative/type/rename calibration; unchanged content-marker guards; zero-length placement validation; host planning, no-marker reset suppression and explicit managed selector forwarding |
| EVD-15 | `TestLinkMarkerSurvivesRenumberingWithoutFollowingTarget`, `TestLinkMarkerRejectsWrongTypeAndMetadata`, `TestLinkMarkerRejectsConcurrentReplacementAndUnsupportedRead`, `TestLinkMarkerCreationIsExclusiveAndRootBound`, existing `TestRecheckIdentityDiagnostics`, `TestPlanMetadataPersistenceMarker`, `TestMetadataMarkerStillRequiresResetAndVolumeProof`, and `TestMetadataMarkerChangesComparisonContext` |
| EVD-12 | Linux synthetic block/character node metadata fixtures, regular/FIFO/missing type rejection, pinned-call replacement/retargeting guards, unsupported-call refusal and existing permission twins |
| EVD-13 | `TestBlockDevicePaths`, `TestPlanBlockDevicePaths`, `TestExecuteRejectsInvalidBlockDevicePaths`, `TestExecBlockDevicePaths`, `TestDeclaredBlockDevices`, and `TestGrades` scoped-out declared-target rejection |
| EVD-10 | explicit protocol planning/rejection and same-pin capability tests; signed control compatibility; probe HTTP/legacy selection; report schema/reader and changed-configuration tests; existing kernel/receipt grading invariance; managed HTTP capability failure stops before paid receiver/provider creation |
| EVD-9 | `internal/canary/http_marker_test.go`: canonical HTTP/80 + independently collected receipts, unarmed completion without proof, legacy compatibility, malformed/oversized/body/host/port rejection, bounded acknowledgement parsing and no raw response leakage |
| EVD-8 | `cmd/sandprobe-daytona-workload/main_test.go` `TestWorkloadPreparationFailuresAreBounded` (read/upload/exec/parse failures remain failed, zero model calls, no raw error disclosure) |
| EVD-7 | `internal/host/daytona_test.go` `TestDaytonaLocalSDKUnavailable` (missing/non-executable interpreter, fixed private-safe error), `TestDaytonaCommandRecordsOneCall` (one event, success/local/provider failure classification) |
| EVD-6 | bounded HTTP/error label fixtures, Linux guest protocol tests and diagnostic/grading invariance |
| SCR-4 | shared managed-completion notice/unchanged exit and JSON tests; shared score recomputation, primary workload rendering, unknown/not-proven retention, managed output and historical rendering compatibility |
| RUN-15 | protected HOME/project/cache parity, original-home metadata guards, unchanged functional workload and managed original-ID cleanup |
| RUN-16 | unique receiver namespace, durable phase/terminal outcome fault cases, lost responses and narrowly bound legacy no-create reconciliation |
| EVD-1 | six-category catalog accounting, grouped missing evidence, invalid input, provider parity and retained Nitro/Daytona grades unchanged |
| EVD-2 | local TLS/raw exchange fault cases and bounded diagnostic values; connected/no receipt remains unknown |
| EVD-3 | Linux O_NOATIME rejection then readable file, and genuine EPERM refusal |
| EVD-4 | existing managed original-ID cleanup and request-budget tests; retained accuracy-validation provenance |
| MEAS-1/MEAS-2 | shared frozen binding, receiver lifecycle ordering, replay/identity/control/receipt/stop failures and positive-delivery grading |
| MEAS-3 | bounded expected-ack/wrong-reply/EOF cases; host receipt requirements unchanged |
| MEAS-7 | approved binding rejection/public-address/duplicate tests; frozen host-plan and pre-survey refusal tests; no-DNS bound TLS probe tests; native adapter and same-policy Python request tests |
| MEAS-6 | upload-host catalog, host plan and pre-survey refusal tests; Linux root/nobody `TestUploadHostsRejectUnapprovedAndNonpublic`, `TestUploadHostsBoundedAndPartialEvidence`, `TestUploadHandshakeVerifiesCertificateWithoutHTTP`; shared Python policy and pre-provision refusal tests |
| MEAS-5 | `TestManagedHostedCanaryLifecycle`, `TestManagedHostedCanaryFailureIsClosedAndSanitized`: local signed-control fixture, shipped trust anchors, reserved slot, release after cancellation, reservation failure, sanitization and unconfirmed-release recovery; CLI and managed collector regressions |
| MEAS-4 | generic SSM/Docker transport fixtures, Daytona original-ID pre-finalization shutdown and cleanup recovery; fresh managed validation |
| PRV-15 (identity) | `internal/probe/whoami_test.go` in `test/probe.sh`, as nobody and as root: the four uids from the kernel's Uid line, `-whoami` resolving names and numbers with no check run, and the shipped probe bound to another uid writing nothing and running no survey while bound to its own it runs; `cmd/sandprobe-probe` argument tests (`-expect-uid` binds a run only, never `-whoami` or `-quick`) |
| PRV-15 (transport) | `internal/host/exec_test.go`: through a real `sh`, nothing runs before the preflight, a refused preflight stops everything, every run is bound with `-expect-uid`, banners outside the markers are ignored, SEC-1's twin is set, a pre-existing scratch path is left alone even when its "already exists" answer is lost, and a path the box swaps in during a run survives the wrapper's own trap (only a path carrying this box's owner token is ever removed, by the trap, the removal invocation or the suggested command), an invocation killed past its limit is cleared by the separate removal invocation, an unreachable box leaves the path and its removal command reported and blocks further runs, a command that fails after running the script counts for nothing, a removal through a failing command or under an unsearchable parent isn't "gone", arguments with shell syntax are refused; `TestExecBoxDocker` (SANDPROBE_FIXTURES=1): the shipped probe through `docker exec -i` as nobody, a switch to root refused with nothing written, no scratch left |
| PRV-15 (provider endpoints) | `cmd/sandprobe/endpoints_test.go`: `TestProviderEndpointsParse` (the four IDs, each once, trimmed; empty, an empty item, `all`, `*`, lowercase, any other ID, a duplicate, another separator, or a check the run doesn't exclude are refused, and an unknown value is never echoed; the rest stay excluded), `TestProviderEndpointsOnlyWhereTheyApply` (refused on run docker, native adapters, aws-nitro and offline commands, and empty or `all` on exec), `TestProviderEndpointsPlan` (each attested check with its attestation, the metadata address and the API handshake it adds, the checks still off, the residual; AMP-6 still won't run on an existing box; `-allow-local-proxy` only with EGR-3; an unapproved run exits 3 with the attestation in its JSON plan), `TestProviderEndpointsWithExplicitCanary` (endpoint selection survives an explicit no-canary or public-canary choice beside stale environment defaults, with no network calls), `TestProviderEndpointsRecipePlan` (a shipped recipe, through a stub kubectl: the same plan lines under RCP-4, nothing past sp_ready), `TestProviderEndpointsAttestationRecord` (ANL-1: the fixed sentence beside exactly the attested checks; another sentence, a missing one, a non-endpoint, a still-skipped check, an attestation on a native adapter's run, or one in a report that declares `sandprobe/1` is refused; each but the last is refused as `sandprobe/6` too), `TestRunExecProviderEndpointsDocker` (`SANDPROBE_FIXTURES=1`: run exec through `docker exec` into a container with no network, so no metadata is reachable: the report declares `sandprobe/6`; SEC-4 and AMP-7 run and end `not_found` or unknown, never a pass or an absence, each with its attestation; EGR-3 and AMP-6 keep `opt_in`; Cloud access is never "not tested" or not applicable, and a green row names its not-proven checks); `internal/host`: `TestPlanAttested` (attested checks selected and recorded sorted in the manifest, never in the probe's input; the rest keep `opt_in`; AMP-6 skipped on an existing box whatever was attested, selected on a throwaway one; EGR-3 attested without a canary is sound, graded but never sent to the probe, and a loopback proxy without `-allow-local-proxy` is skipped with no kind; the grader refuses a non-endpoint, a duplicate or a still-kinded attestation; Execute refuses one that isn't an endpoint, is named twice, or is still excluded); `internal/report`: `TestReportRecordsAttestation` (the sentence beside exactly the attested checks, in the JSON and on the page); `internal/analysis/attested_test.go`, on a Docker fixture run planned with `-provider-endpoints SEC-4,AMP-7`: `TestInvalidRunKeepsAttestedRows` (an invalid run keeps both rows, unknown with "not graded" and the attestation, grades nothing else and lists no unknowns, loads under ANL-1, and its page shows each attestation and the report's real schema; a valid run's page shows each attestation beside its test and in the appendix), `TestAttestedRowsAreRequired` (the code review's reproduction: a report with the attested SEC-4 row deleted is refused, invalid or valid; an invalid report with an unknown row nobody attested, or with unknowns in its grade, is refused), `TestInvalidAttestedRowsStayNotGraded` (the code review of #12: an invalid report whose attested SEC-4 row is turned `not_found` with a reason of its own is refused, as are an attested row turned a finding, given another reason, evidence or a scope, and a graded row nobody attested; the unchanged report still reads) |
| PRV-15 (command) | `cmd/sandprobe/exec_test.go`: run exec refuses a missing command, a passthrough to another provider, a relative or unsafe `-scratch`, a malformed `-as`, a command not on PATH, and `-canary-url` without a pin; with no canary named, even beside a stray `canary-*.state` file, the plan uses the hosted canary and states its retention, and the shipped URL and pin pass `CheckCanaryURL` (`TestRunExecDefaultsToTheHostedCanary`, HCN-5); a pin without its URL, by flag or environment, is refused rather than set aside (`TestRunExecPinWithoutURLIsRefused`); a URL or pin pasted with a credential (userinfo, query, fragment, path, a bad pin) is refused before the plan exists and never appears in its text or JSON, while a valid one is shown canonical; the plan names the box, the scratch path, the user check, the public canary and HCN-4's retention, the four checks off and PER-5 skipped, and no metadata address; without `-y` nothing runs; `TestExecuteThroughExecBox` (SANDPROBE_FIXTURES=1): Execute drives the shipped probe through `docker exec` as nobody, the base64 upload keeps SBX-5's digest, the run is valid, SEC-4, EGR-3, AMP-6, AMP-7 and PER-5 are skipped with their reasons, and no scratch is left |
| PRV-17 (and its SCR-2, GRD-3, ANL-1, AGT-3, AGT-6, OUT-1 and OUT-4 amendments) | `cmd/sandprobe/exec_provider_test.go`: `TestExecProviderParse` (`host.DeclarableProviders` is exactly the table's keys, each accepted; a name the table lacks, `exec`, `docker`, `aws-nitro` and `kubernetes` among them, a differently cased or padded key, a list, a credential-shaped value and an empty value are refused with exit 2 before the plan exists, the error listing the valid names sorted and never echoing the value; the flag is refused on run and plan of a native adapter, `plan kubernetes`, `plan docker`, `scorecard`, `compare` and `providers`), `TestExecProviderConflictsWithOptIn` (`-provider modal` with `-provider-endpoints` naming any of the four is refused, its fix never a change of provider), `TestExecProviderPlan` (the text plan's section, Cloud access line, each excluded check with Modal's own reason, box-named line and residual, byte for byte as PRV-17 quotes them, and never "terms exclude" or "their terms"; an unapproved run exits 3 with `declared_provider`, the five `declared` lines and the residual in its JSON; a plan without `-provider` names no declaration and no reviewed scope), `TestExecProviderMinSix` (`run exec -provider modal -min 6 -y` exits 2 with the unverified sentence before the box's command runs; without `-provider`, and with `-min full`, it isn't refused), `TestScorecardDeclaredProvider` (a saved run exec report declaring modal: "Score 2/5", the row's reason and the line beside the score as PRV-17 quotes them, in `scorecard`'s text; `scope` and `declared_provider` on the row in `-o json`; and the unverified sentence and reviewed scope on the `-out` page, the run's own page and the run's summary), `TestScorecardRefusesForgedDeclaredProvider` (refused with exit 2 and never read out of five, as saved and, but for the version case, as `sandprobe/6`: `provider_terms` with the declaration removed; a kind turned `opt_in` or removed; an excluded check attested or run; a provider the binary doesn't know, `aws-nitro`, `exec` and `Modal` among them; the declaration on a Sprites report, under `sandprobe/2`, or beside EVD-10's protocol; `declared_provider` present but empty or null; and, scored directly with `report.Score`, each report whose kinds differ from the entry stays out of six), `TestCompareDeclaredProvider` (undeclared against modal either way, and modal against sprites with the same skips, each exit 5 with `declared_configuration`; the same declaration on both sides a matched pair), `TestHelpSaysTheProviderComesFromThePerson` (`sandprobe help` says the name comes only from the person, is never inferred, added or changed to clear a red, is the operator's word and never verified, and lists exactly the table's keys), `TestNothingSuggestsProvider` (with `-provider-endpoints` set aside, no `-provider` in any catalog advice or fix, `explain` for the four checks, any rendering of an undeclared run exec report (scorecard text and JSON, profile, compare, the page and the run's summary), or the message and fix of an error the flag didn't cause; undeclared Cloud access still reads PRV-15's opt-in reason); `cmd/sandprobe/scorecard_na_test.go`: `TestScorecardNotApplicable` (Sprites and E2B read the reviewed-scope row and line) and `TestReportSchemaVersions` (the refusal names `sandprobe/1` to `sandprobe/6`); `internal/report/declared_test.go`: `TestScoreDeclaredProvider` (for every key of `host.TermsExclusions`, a run exec report declaring it declares `sandprobe/6` and reads out of five, Cloud access not applicable and never green with its `terms` from that entry, `scope` and `declared_provider` set, and the unverified sentence on the row, the line, the card's JSON and the page; its findings, their counts and completeness are the undeclared run's), `TestWorkloadPageReviewedScope` (a native not-applicable row on the workload page reads the reviewed-scope line and never "their terms"; a card carrying `declared_provider` is refused, so the workload page never renders a declared provider; the line beside the score names only a table key, else "the provider"); `internal/report/scorecard_na_test.go`: `TestScoreNotApplicable` (each native adapter's row and line name Sandprobe's reviewed scope for it, `scope` set and no declaration, never "their terms" or "terms exclude"), `TestNativesAreThePolicy` extended (`PolicyFor`: an exec report declaring modal takes `provider_terms`; no declaration, `aws-nitro`, `Modal` or `exec` take `opt_in`; a declaration beside another provider changes nothing); `internal/host/declared_test.go`: `TestPlanDeclaredProvider` (the manifest records `declared_provider` and each excluded check with Modal's own reason and kind `provider_terms`, the probe's input carries none of it, and the grader accepts the manifest; `checkDeclared` and `Execute` refuse a name the table lacks, a differently cased key, a native adapter's kind or none, run exec's own or another provider's reasons, an excluded check lifted, EVD-10's protocol and a workload contract); `internal/analysis/declared_test.go`: `TestDeclaredProviderPresentIsCanonical` (AGT-6: a canonical `sandprobe/5` report reads; `declared_provider` empty, null or absent under `sandprobe/5`, or carried under `sandprobe/2` or `sandprobe/4`, is refused; a declaration the table lacks or on a native adapter's report is refused; the same report with no declaration and `opt_in` kinds reads as `sandprobe/2`) |
| SCR-7 | `internal/report/row.go`'s `buildRow` is the one row builder for `Score` and the card validator, so every saved-report test above also runs it; the six committed reports in `demo/reports` and `test/reports` read the same `scorecard -o json` and exit status as before it. `internal/report/cardrow_test.go`: `TestCardNotApplicableOnlyWhereTheTableExcludesEveryCheck` (for every provider in `host.TermsExclusions` and every category, a card claiming the category not applicable, in today's form and 0.3.0's, with coverage recording every check skipped, is accepted and rendered exactly where that provider's entry excludes every check of the category, and in 0.2.1's coverage-less form never; the loop fails if no pair is accepted), `TestCardRowInvariants` (sandprobe-codex's two reproductions of 279502a, a not-applicable row with an unproven check with and without coverage, and a green row whose coverage records a finding it doesn't list; found sharing a check with unknown or unproven; a not-applicable row with a found or unknown check, or whose coverage records a finding; a green row with a found or unknown check; unproven or coverage unproven holding a two-sided check; found holding a check that is only ever Info; a 0.2.1-form card with a scope, terms or a green-not-proven flag; a declared provider; an edited score or `of`; a green-not-proven flag on a proven row; a red row turned green and a green one turned red, with counters recounted: each refused and never rendered; and a legitimate Info finding, EGR-4, left off a green row's found list is accepted); `internal/report/declared_test.go`: `TestWorkloadPageReviewedScope` (an arbitrary scope, another real provider's name, that name with its reason, a differently cased key, the row's own name with edited `terms` or reason, and a scope on a counted row, each refused and never rendered; `NotCounted` on an unvalidated card names nothing outside the table and no declaration but the row's scope; a 0.3.0 not-applicable row reads and renders today's wording), `TestWorkloadCardStringsAreDerived` (the security re-review of 7c922f7: 28 single-field mutations of reason, terms, scope, not-proven line, declared provider, check lists, name, question and verification on not-applicable, red and green rows, each refused and never rendered, and on a card without coverage a check of another category, listed twice or unknown to the catalog; each key's reasons pin exactly one key); `internal/report/scorecard_coverage_test.go`: `TestSavedExposureCoverageWithoutNewDisplayFields` and `TestHistoricalDisplayFlagIsDerivedWithoutMutatingInput` on a report the grader could write (two-sided checks pass, find-only ones not found), since a two-sided check is never not found; `internal/report/cardrow_test.go`: `TestCardSEC3SeverityFailsClosed` (sandprobe-codex's final finding on #67: a genuine High SEC-3 card recast as green by clearing found and why, setting green and raising the score with coverage unchanged is refused and never rendered, in process and read from a file; an honest Info SEC-3 card reads green and renders in process, and is refused read from a file, which carries no severity evidence; an Info-only EGR-4 finding read from a file still reads green), `TestCardCoordinatedMutations` (on seven honest cards, a High and an Info SEC-3 card in process and from a file, native Daytona, run exec opt-in and without a canary, and a 0.3.0 legacy card: every combination of found as is, cleared or with one check added or removed, reason, green flipped, not-proven line, one check moved between proven and findings, and totals recounted or stale, over 10,000 cards; every card accepted satisfies an oracle written apart from the validator, which requires each unlisted finding to be Info by evidence, a green row to have a tested check and no finding or unknown, a not-applicable row's provider to exclude and the card to skip every check of the category, and totals to equal the rows); `TestCardWorkIsBounded` (security-agent's review of 0ceb1d3: a Modal card whose Cloud access coverage repeats SEC-4 10, 20 or 10,000 times, any coverage group grown past its category, or a row list grown past it with coverage, is refused with no row built, counted by `cardBuilds`, never timed; without coverage, an oversized row list, or an opt-in reason naming 10,000 checks, is refused within the 36-build ceiling, and the reason's bounded parse reads nothing; `cardOutcomes` never returns more than three maps), and `TestCardCoordinatedMutations` also asserts every one of its cards costs at most 36 builds |
| RUN-22 | fixed diagnostic/refusal/consistency tests; Linux known-fixture success, dependency, syntax and wrong-output cases; both controller artifact and no-text-leak tests |
| RUN-21 | native loopback pinned TLS success/wrong-pin/no-application-data/timeout/invalid-metadata tests and shell fixed-result refusal matrix |
| RUN-20 | offline receiver TLS/port failure-stage, success, no-output-leak and read-only-status tests |
| RUN-19 | controller failure-step sanitization and unchanged model budget; contract mismatch metadata and refusal; setgid-workspace Linux smoke with unsafe-existing-cache refusal and nine cases; EGR-6 stage-count sanitization tests |
| RUN-18 | actual environment-clearing subprocess and original-command/probe binding tests; legacy contract cannot select cleared observations; shared-policy Python workload checks; network-disabled/read-only Linux container with inherited synthetic authority and nine functional cases |
| RUN-17 | host-controller protocol/remote execution/two-attempt/ambiguous-count and identity-absence tests; schema3 contract refusal matrix and report-version selection; original guest-mode regressions |
| RUN-24 | `internal/host/daytona_runtime_test.py`: exact audit/request/organization/time/absence binding and refusal cases; `daytona_volume_test.go`, `daytona_persistent_test.go`: durable rejected consumer, exact-ID storage cleanup and unresolved/contradictory guards |
| RUN-23 | `internal/host/agent_persistent_test.go`: durable deletion/create ordering, UID preconditions, lost-create uncertainty and replacement guards; `experiments/eks-agent/test_persistent_assessment.py`: profile intent, native artifact proof, recovery import, failed-child paths and independent cleanup; `internal/host/agent_workspace_test.go`: creator identity, both static storage profiles and actual pod volume/mount drift; `agent_reset_job_test.go`: original-manifest tampering and cross-language hashes from the real Python renderer; `experiments/eks-agent/test_profile.py`: static owned-volume intent preserves network/identity controls and artifact storage leaves coding/cache paths local; `test_persistent_storage.py`: EBS ownership, metadata/attachment guards and exact operation-scoped absence classification; `internal/host/daytona_runtime_test.py`, `daytona_volume_test.go`, `daytona_persistent_test.go`: original/consumer IDs, same-volume recreation, context guards, unknown-create recovery and terminal tombstone identity; `daytona_artifact_test.go`: exact bounded agent readback and failure metadata; managed Daytona runner tests cover profile forwarding and cleanup outcomes; `cmd/sandprobe-daytona-workload/persistent_test.go`: assessment/recovery exclusion and private lock guards |
| RUN-11 | nullable native-network policy, fixed-stage/no-create status and failed-preparation retention regressions |
| WGR-8 / RUN-10 | portable snapshot contract/grade calibration; managed Daytona lifecycle, principal, workload isolation and failure/cleanup tests |
| WGR-7 | `TestPortableWorkloadDeclaration`, `TestPortableWorkloadCalibration`; version1 retained Nitro report compatibility test |
| WGR-6 | run where the operators keep their recorded collections, not in this repository |
| WGR-1..5 | `internal/grade/workload_test.go` (allowed vs forbidden, mixed proof faults, immutable context, independent positive evidence); `internal/obs/workload_test.go`; `internal/host/workload_test.go`; `internal/probe/workload_test.go` (Linux root/nobody); `internal/report/workload_test.go`; `cmd/sandprobe-agent-grade/workload_test.go`; `experiments/eks-agent/test_workload_contract.py` |
| RUN-8 | `TestAgentPodBindingGuardsEveryInvocation`, `TestAgentPodRejectsNonRunBindingBeforeKubectl`, `test_standard_grade.py`; same-pod standard grading, failed-task preservation, binding changes and independent canary cleanup |
| PRV-5 | a Modal plan selects none of SEC-4, AMP-6, AMP-7 or EGR-3, lists each as skipped with its reason, and its manifest names no metadata address, vsock port, Kubernetes API or proxy |
| PRV-5 (Sprites) | `TestSpritesExclusions`: Sprites excludes exactly SEC-4, EGR-3, AMP-6 and AMP-7, each one Execute accepts; `TestSpritesPlanContactsOnlyTheCanary`: the plan names no metadata address or box-named destination |
| POC-1, POC-2, POC-5 | each setup's create request against its table row (an empty allowlist stays allowlist mode, never open); the gate against synthetic counts for every setup, including the twin's nonce on another port, a nonce counted elsewhere, a 443 count missing from a complete relay log (trips), and a truncated log (unknown, stops before `look`); a tripped gate renders no report and runs no later step; a token-shaped sentinel planted in an SDK error appears in no terminal line, call record or artifact |
| POC-6 | the relay against a local TLS server at a stand-in pinned IP: an owned nonce relayed with bytes counted and the pin intact through it; a non-owned SNI, a missing SNI and a name that would resolve elsewhere each refused, with no SNI and no payload in the log; `ready` only once listening; attribution unknown with a missing or truncated log; `look` against a planted marker, its absence, and a stop at the first sighting with no later row run |
| POC-7, POC-8 | the summary from fixture reports: every finding bucketed by the table, an unbucketed one refused, no letter grade, the HTML under OUT-2's CSP with hostile strings rendered as text |
| POC-9 | a fake Modal API: a sandbox terminated and confirmed by ID and tag, a failed terminate reported with its fix |
| CLN-2 | `deploy/eks_test.sh` with a fake `aws`, run with and without `DURABLE_STATE=1`: up with a failing `sts get-caller-identity` writes no state file, makes no other AWS call and prints none of the fake's error; a failed read after it leaves a state file with no `crole`, `nrole` or `cluster`, and then `status` and up refuse with no AWS call, printing the retire command; that command, run as printed with `PROFILE` and `STATE` unset, retires the record with no AWS call and says nothing was created; and up then gets past its refusal to the identity check, and exits 3 only there; `experiments/eks-agent/test_runner.py`: `test_cln2_identity_refusal_records_cluster_not_created` (exit 3 with no `eks.state`: the cluster is journaled `not_created`, and cleanup confirms with no `eks.sh down` call) and `test_cln2_other_missing_state_stays_unconfirmed` (exit 1, no exit code, or exit 3 beside an `eks.state` link: the cluster stays `creating`, and cleanup records `cluster_cleanup_unconfirmed` with no `eks.sh down` call); `experiments/eks-agent/test_lifecycle.py`: `test_commands_keep_the_last_exit_code` |

## Open questions

| # | Question | Blocks |
|-|-|-|
| 2 | May EGR-6 handshake with the listed public hosts? | enabling EGR-6 only; it stays skipped and listed until then |
| 3 | ControlPlane's sandbox-probe (Apache-2.0, 14 checks). Default: our own IDs, mappable to theirs | nothing yet |

exe.dev PRV-13: `internal/host/exedev_test.go` covers bounded native API transport, streamed completion, generated-path quoting and chunked digest-verified upload, exact create-returned name/birth/run-tag identity, no ambiguous-create adoption, private crash journals and acknowledged deletion plus scoped absence. `cmd/sandprobe/exedev_test.go` covers plans and approval before credentials and run-independent cleanup.
