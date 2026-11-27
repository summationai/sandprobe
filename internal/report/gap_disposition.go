package report

import (
	"sandprobe/internal/catalog"
	"sandprobe/internal/obs"
	"strconv"
)

// EVD-23: dispositions decide what to investigate, never what passes. Scope
// restrictions remain in force even when another prerequisite is also missing.
func gapDisposition(d Doc, c Check) (string, string) {
	ck, _ := catalog.Get(c.ID)
	if d.Manifest.NoCanary && catalog.NeedsCanary(ck) {
		return "policy", "canary_opted_out"
	}
	if c.Result == obs.Skipped {
		if kind := d.Manifest.SkipKinds[c.ID]; kind == obs.SkipProviderTerms || kind == obs.SkipOptIn {
			return "policy", "explicit_endpoint_exclusion"
		}
		// Only these exact host-authored explanations establish a feature gate.
		// Never interpret arbitrary SDK/guest error text or a redacted target as absence.
		switch {
		case c.ID == "EGR-3" && d.Manifest.Skipped[c.ID] == "the agent's environment names no proxy":
			return "not_applicable", "no_configured_proxy"
		case c.ID == "AMP-6" && d.Manifest.Skipped[c.ID] == "no vsock device":
			return "not_applicable", "no_vsock_device"
		case c.ID == "PER-5":
			return "not_applicable", "no_selected_reset_storage_measurement"
		case c.ID == "EGR-6":
			return "policy", "upload_hosts_not_approved"
		default:
			return "policy", "host_did_not_select_check"
		}
	}
	if c.Result == obs.ScopedOut {
		return "not_applicable", "no_target_in_defined_discovery"
	}
	if c.ID == "AMP-7" && d.Manifest.KubeAPI == "" && c.Reason == "the agent's environment names no Kubernetes API" {
		return "not_applicable", "no_kubernetes_target_named"
	}
	if c.Result == obs.NotFound {
		return "unprovable", "find_only_silence_is_not_absence"
	}
	if (c.ID == "SEC-2" || c.ID == "SEC-5") && heldProcessCapability(d.Identity) {
		return "bridgeable", "drop_unnecessary_process_access_capabilities_then_retest"
	}
	if catalog.NeedsCanary(ck) {
		switch c.Reason {
		case "the canary isn't live, so no network result counts (SBX-11)":
			return "bridgeable", "repair_canary_prerequisite_then_retest"
		case "the canary was overloaded while the run was armed, so the box's attempt may never have reached it (SBX-11)":
			return "bridgeable", "repair_canary_capacity_then_retest"
		case "the probe's run is longer than the host's launch-to-return bracket", "an attempt's timing falls outside the probe's own run":
			return "bridgeable", "investigate_collection_timing"
		case "canary health didn't cover the host's launch-to-return bracket on this port":
			return "bridgeable", "repair_health_bracketing_then_retest"
		case "the host's receipt query didn't complete, or was sent less than 2 s after the probe returned, so no receipt can be ruled out":
			return "bridgeable", "repair_receipt_collection_then_retest"
		default:
			return "unprovable", "route_has_no_decisive_delivery_or_denial_proof"
		}
	}
	if c.ID == "SEC-4" {
		return "unprovable", "metadata_silence_is_not_absence"
	}
	return "bridgeable", "bounded_investigation_needed_not_a_promised_fix"
}

func heldProcessCapability(id *obs.Identity) bool {
	if id == nil {
		return false
	}
	const mask = uint64(1<<6 | 1<<7 | 1<<16 | 1<<19 | 1<<21)
	for _, set := range []string{id.CapEff, id.CapPrm} {
		bits, err := strconv.ParseUint(set, 16, 64)
		if err == nil && bits&mask != 0 {
			return true
		}
	}
	return false
}
