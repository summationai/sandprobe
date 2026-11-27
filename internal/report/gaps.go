package report

import (
	"errors"
	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
)

type GapRequirement struct {
	Code   string `json:"code"`
	Status string `json:"status"`
}
type MeasurementGap struct {
	ID           string           `json:"id"`
	Disposition  string           `json:"disposition"`
	Basis        string           `json:"basis"`
	Result       string           `json:"result"`
	Requirements []GapRequirement `json:"requirements"`
	Next         string           `json:"next"`
}
type GapPlan struct {
	Schema        string           `json:"schema"`
	Verification  string           `json:"verification"`
	Prerequisites string           `json:"prerequisites"`
	Conclusive    int              `json:"conclusive"`
	Unproven      int              `json:"unproven"`
	Unknown       int              `json:"unknown"`
	Skipped       int              `json:"skipped"`
	ScopedOut     int              `json:"scoped_out"`
	Gaps          []MeasurementGap `json:"gaps"`
	Dispositions  map[string]int   `json:"dispositions"`
}

// MeasurementGapPlan is structural-only analysis of saved or in-memory inputs.
// EVD-22: no arbitrary input text is copied and no gap is a new measurement.
func MeasurementGapPlan(d Doc, p *obs.MeasurementPrerequisites) (GapPlan, error) {
	plan := GapPlan{Schema: "sandprobe.measurement-gaps/2", Verification: "saved_inputs_not_authenticated", Prerequisites: "not_recorded", Gaps: []MeasurementGap{}, Dispositions: map[string]int{"policy": 0, "not_applicable": 0, "unprovable": 0, "bridgeable": 0}}
	bad := errors.New("invalid measurement gap input")
	if !d.Grade.Valid || len(d.Checks) != len(catalog.IDs()) {
		return GapPlan{}, bad
	}
	if p != nil {
		if !p.Valid() || p.RunID != d.Manifest.RunID || p.Nonce != d.Manifest.Nonce || p.BoxID != d.Manifest.BoxID || p.ProbeSHA256 != d.Manifest.ProbeSHA256 {
			return GapPlan{}, bad
		}
		plan.Prerequisites = "matching_guest_reported_survey"
	}

	unknown := map[string]bool{}
	for _, id := range d.Grade.Unknown {
		if _, ok := catalog.Get(id); !ok || unknown[id] {
			return GapPlan{}, bad
		}
		unknown[id] = true
	}
	seen := map[string]bool{}
	for _, ck := range d.Checks {
		if _, ok := catalog.Get(ck.ID); !ok || seen[ck.ID] {
			return GapPlan{}, bad
		}
		seen[ck.ID] = true
		if unknown[ck.ID] != (ck.Result == obs.Unknown) {
			return GapPlan{}, bad
		}
		g := MeasurementGap{ID: ck.ID, Result: ck.Result, Requirements: []GapRequirement{}}
		add := func(code, status string) { g.Requirements = append(g.Requirements, GapRequirement{code, status}) }
		switch ck.Result {
		case obs.Pass, obs.Finding, obs.Absent:
			plan.Conclusive++
			continue
		case obs.NotFound:
			plan.Unproven++
			add("negative_proof", "not_established")
			g.Next = "A bounded search found no exposure; use a supported stronger measurement if available. Repeating absence is not negative proof."
		case obs.Unknown:
			plan.Unknown++
			add("decisive_evidence", "not_established")
			g.Next = "Inspect the original evidence before rerunning; errors and missing receipts are not negative proof."
		case obs.Skipped:
			plan.Skipped++
			add("selection", "not_selected")
			g.Next = "Resolve each applicable prerequisite and scope requirement before selecting this check."
			if catalog.ProviderEndpoints[ck.ID] {
				add("assessment_scope", "requires_review")
			}
		case obs.ScopedOut:
			plan.ScopedOut++
			add("applicable_target", "not_found_in_discovery")
			g.Next = "Keep the stated discovery scope. Declare only an existing workload target; do not attach a device to increase coverage."
		default:
			return GapPlan{}, bad
		}
		feature := func(code string, state string) {
			if p == nil {
				state = "not_recorded"
			}
			add(code, state)
		}
		switch ck.ID {
		case "EGR-3":
			state := ""
			if p != nil {
				state = p.Proxy
			}
			feature("configured_proxy", state)
			credentials, protocol := "", ""
			if p != nil {
				credentials = p.ProxyCredentials
				protocol = p.ProxyProtocol
			}
			feature("proxy_credentials", credentials)
			feature("proxy_protocol", protocol)
			g.Next = "Use the workload's actual configured proxy only when scope permits, including explicit approval for a local proxy. Only credential-free HTTP CONNECT is implemented; proxy credentials are never used. A missing proxy does not justify installing one for coverage."
		case "AMP-6":
			state := ""
			if p != nil {
				state = p.Vsock
			}
			feature("vsock_device", state)
			add("host_connectivity_measurement", "not_implemented")
			g.Next = "Host connectivity needs an implemented bounded measurement and a provider-approved target/channel. A device's presence or absence is not host-isolation proof."
		case "AMP-7":
			state := ""
			if p != nil {
				state = p.KubeAPI
			}
			feature("kubernetes_target", state)
		case "EGR-1", "EGR-2", "EGR-5.22", "EGR-5.80", "EGR-5.8080", "EGR-5.53u":
			if ck.Result == obs.Unknown || ck.Result == obs.NotFound {
				g.Next = "Require valid signed delivery evidence or the check's defined negative proof. Connected sockets, TLS resets, unsigned HTTP errors and no receipts alone are inconclusive; preserve required workload networking."
			}
		case "EGR-4":
			if ck.Result == obs.NotFound {
				g.Next = "No interception was observed. This find-only result cannot prove that interception is impossible."
			}
		case "AMP-1":
			g.Next = "A sudo listing can hide rules under listpw. Stronger effective-policy evidence is needed; never execute a privileged command to manufacture proof."
		}
		g.Disposition, g.Basis = gapDisposition(d, ck)
		switch g.Disposition {
		case "policy":
			g.Next = "Keep the exclusion in force; this is not today's implementation work. " + g.Next
		case "not_applicable":
			g.Next = "Keep the workload configuration; this is not a coverage work item. " + g.Next
		case "unprovable":
			g.Next = "Do not schedule coverage reruns under the current measurement. " + g.Next
		case "bridgeable":
			if g.Basis == "drop_unnecessary_process_access_capabilities_then_retest" {
				g.Next = "Drop only capabilities the meaningful workload does not require, in an explicit new configuration; then require fresh target coverage, eligible refusals and both applicable controls. If the workload needs the capabilities, retain the inconclusive result."
			}
		}
		plan.Dispositions[g.Disposition]++
		plan.Gaps = append(plan.Gaps, g)
	}
	return plan, nil
}
