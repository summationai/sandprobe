package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sandprobe/internal/analysis"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
	"strings"
	"testing"
)

func TestGapsCommand(t *testing.T) {
	path := "../../demo/reports/hardened.json"
	d, err := analysis.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(path)
	invoke := func(args []string) (int, string) {
		t.Helper()
		var out, stderr bytes.Buffer
		code := run(args, &out, &stderr)
		if strings.Contains(out.String()+stderr.String(), "NEVER_EXPORT") {
			t.Fatal("raw input leaked")
		}
		return code, out.String()
	}
	code, out := invoke([]string{"gaps", path, "-o", "json"})
	want := exitGraded
	if !d.Grade.Complete {
		want = exitPartial
	}
	if code != want {
		t.Fatal("command failed", code, out)
	}
	var p report.GapPlan
	if json.Unmarshal([]byte(out), &p) != nil || p.Schema != "sandprobe.measurement-gaps/2" || p.Prerequisites != "not_recorded" {
		t.Fatal("not a gap plan")
	}
	if p.Conclusive+p.Unproven+p.Unknown+p.Skipped+p.ScopedOut != 28 {
		t.Fatal("lost checks")
	}
	ctx := obs.MeasurementPrerequisites{Schema: obs.MeasurementPrerequisitesSchema, RunID: d.Manifest.RunID, Nonce: d.Manifest.Nonce, BoxID: d.Manifest.BoxID, ProbeSHA256: d.Manifest.ProbeSHA256, Proxy: "not_configured", ProxyCredentials: "not_applicable", ProxyProtocol: "not_applicable", KubeAPI: "absent", Vsock: "absent"}
	raw, _ := json.Marshal(ctx)
	sidecar := filepath.Join(t.TempDir(), "p.json")
	os.WriteFile(sidecar, raw, 0600)
	if code, out = invoke([]string{"gaps", path, sidecar, "-o", "json"}); code != want || !strings.Contains(out, "matching_guest_reported_survey") {
		t.Fatal("matching context refused", code, out)
	}
	ctx.BoxID = "NEVER_EXPORT_OTHER_BOX"
	raw, _ = json.Marshal(ctx)
	os.WriteFile(sidecar, raw, 0600)
	if code, _ = invoke([]string{"gaps", path, sidecar, "-o", "json"}); code != exitUsage {
		t.Fatal("cross-run sidecar accepted")
	}
	if code, _ = invoke([]string{"gaps", "-o", "json"}); code != exitUsage {
		t.Fatal("missing report accepted")
	}
	if code, out = invoke([]string{"gaps", path}); code != want || !strings.Contains(out, "not authenticated") {
		t.Fatal("text omitted provenance")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(original, after) {
		t.Fatal("changed source report")
	}
}
