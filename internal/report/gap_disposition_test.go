package report

import (
	"encoding/json"
	"reflect"
	"sandprobe/internal/obs"
	"strings"
	"testing"
)

func TestGapDispositions(t *testing.T) {
	d := doc(obs.Pass, map[string]Check{"SEC-4": {Result: obs.Skipped}, "EGR-3": {Result: obs.Skipped}, "AMP-6": {Result: obs.Skipped}, "AMP-7": {Result: obs.Skipped}, "AMP-8.blk": {Result: obs.ScopedOut}, "EGR-1": {Result: obs.NotFound}, "EGR-4": {Result: obs.NotFound}, "EGR-5.53u": {Result: obs.NotFound}, "SEC-5": {Result: obs.Unknown}})
	d.Grade.Unknown = []string{"SEC-5"}
	d.Identity = &obs.Identity{CapEff: "00000000000000c0", CapPrm: "0000000000000000"}
	d.Manifest.SkipKinds = map[string]string{"AMP-6": obs.SkipProviderTerms}
	original, _ := json.Marshal(d)
	before := Score(d)
	plan, err := MeasurementGapPlan(d, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Schema != "sandprobe.measurement-gaps/2" || plan.Dispositions["policy"] != 4 || plan.Dispositions["not_applicable"] != 1 || plan.Dispositions["unprovable"] != 3 || plan.Dispositions["bridgeable"] != 1 {
		t.Fatal("wrong partition", plan.Dispositions)
	}
	count := 0
	for _, n := range plan.Dispositions {
		count += n
	}
	if count != len(plan.Gaps) {
		t.Fatal("partition lost or duplicated rows")
	}
	for _, g := range plan.Gaps {
		if g.ID == "SEC-5" && (g.Disposition != "bridgeable" || !strings.Contains(g.Basis, "capabilities_then_retest")) {
			t.Fatal("held capabilities not actionable")
		}
		if g.ID == "AMP-6" && g.Disposition != "policy" {
			t.Fatal("implementation work bypassed policy")
		}
	}
	after, _ := json.Marshal(d)
	if string(original) != string(after) || !reflect.DeepEqual(before, Score(d)) {
		t.Fatal("classification changed security results")
	}
	cases := []struct {
		check    Check
		manifest obs.Manifest
		want     string
	}{
		{Check{ID: "EGR-6", Result: obs.Skipped}, obs.Manifest{}, "policy"},
		{Check{ID: "EGR-3", Result: obs.Skipped}, obs.Manifest{Skipped: map[string]string{"EGR-3": "the agent's environment names no proxy"}}, "not_applicable"},
		{Check{ID: "AMP-6", Result: obs.Skipped}, obs.Manifest{Skipped: map[string]string{"AMP-6": "no vsock device"}}, "not_applicable"},
		{Check{ID: "AMP-6", Result: obs.Skipped}, obs.Manifest{Skipped: map[string]string{"AMP-6": "no vsock device"}, SkipKinds: map[string]string{"AMP-6": obs.SkipProviderTerms}}, "policy"},
		{Check{ID: "PER-5", Result: obs.Skipped}, obs.Manifest{}, "not_applicable"},
		{Check{ID: "AMP-7", Result: obs.NotFound, Reason: "the agent's environment names no Kubernetes API"}, obs.Manifest{}, "not_applicable"},
		{Check{ID: "AMP-7", Result: obs.NotFound, Reason: "NEVER_EXPORT"}, obs.Manifest{}, "unprovable"},
		{Check{ID: "EGR-2", Result: obs.Unknown, Reason: "a connected outcome isn't a refusal"}, obs.Manifest{}, "unprovable"},
		{Check{ID: "EGR-5.80", Result: obs.Unknown, Reason: "NEVER_EXPORT"}, obs.Manifest{}, "unprovable"},
		{Check{ID: "EGR-2", Result: obs.Unknown, Reason: "the canary isn't live, so no network result counts (SBX-11)"}, obs.Manifest{}, "bridgeable"},
		{Check{ID: "EGR-2", Result: obs.Unknown}, obs.Manifest{NoCanary: true}, "policy"},
	}
	for _, c := range cases {
		d.Manifest = c.manifest
		got, basis := gapDisposition(d, c.check)
		if got != c.want || strings.Contains(basis, "NEVER_EXPORT") {
			t.Fatalf("%s/%s: wrong bounded disposition %s", c.check.ID, c.check.Result, got)
		}
	}
	d.Identity = &obs.Identity{CapEff: "0000000000000000", CapPrm: "0000000000000000", CapBnd: "00000000000000c0"}
	_, basis := gapDisposition(d, Check{ID: "SEC-5", Result: obs.Unknown})
	if strings.Contains(basis, "drop_unnecessary") {
		t.Fatal("bounding capability treated as held")
	}
	d.Identity.CapPrm = "00000000000000c0"
	_, basis = gapDisposition(d, Check{ID: "SEC-5", Result: obs.Unknown})
	if !strings.Contains(basis, "drop_unnecessary") {
		t.Fatal("permitted capability ignored")
	}
}
