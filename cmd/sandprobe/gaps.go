package main

import (
	"fmt"
	"sandprobe/internal/analysis"
	"sandprobe/internal/obs"
	"sandprobe/internal/report"
)

// EVD-22: an offline plan explains blockers, never alters or re-verifies a report.
func gaps(o opts, args []string) (int, error) {
	if len(args) < 1 || len(args) > 2 {
		return 0, fail("usage", "name a saved report and optionally its prerequisite sidecar", "sandprobe gaps <report.json> [<prerequisites.json>] [-o json]", exitUsage)
	}
	d, err := analysis.Load(args[0])
	if err != nil {
		return 0, fail("report.input", "unsupported, inconsistent or unsafe report input", reportInputFix, exitUsage)
	}
	var p *obs.MeasurementPrerequisites
	if len(args) == 2 {
		p, err = analysis.LoadPrerequisites(args[1])
		if err != nil {
			return 0, fail("gaps.input", "invalid prerequisite sidecar", "use the matching, unedited measurement-prerequisites.json from this run", exitUsage)
		}
	}
	plan, err := report.MeasurementGapPlan(*d, p)
	if err != nil {
		return 0, fail("gaps.input", "invalid assessment or mismatched prerequisites", "use a valid report and its matching prerequisite sidecar", exitUsage)
	}
	if o.json() {
		o.emit(plan)
	} else {
		fmt.Fprintf(o.stdout, "Saved-input gap analysis (not authenticated)\n%d conclusive; %d unproven; %d unknown; %d skipped; %d scoped out\nPrerequisites: %s\n", plan.Conclusive, plan.Unproven, plan.Unknown, plan.Skipped, plan.ScopedOut, plan.Prerequisites)
		fmt.Fprintf(o.stdout, "Dispositions: %d policy; %d not applicable; %d unprovable; %d bridgeable\n", plan.Dispositions["policy"], plan.Dispositions["not_applicable"], plan.Dispositions["unprovable"], plan.Dispositions["bridgeable"])
		for _, g := range plan.Gaps {
			fmt.Fprintf(o.stdout, "\n%s (%s; %s)\n", g.ID, g.Result, g.Disposition)
			for _, r := range g.Requirements {
				fmt.Fprintf(o.stdout, "  %s: %s\n", r.Code, r.Status)
			}
			printWrapped(o.stdout, "  ", g.Next, "", "")
		}
	}
	if !d.Grade.Complete {
		return exitPartial, nil
	}
	return exitGraded, nil
}
