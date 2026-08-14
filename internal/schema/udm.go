// Package schema embeds a mock dictionary of valid Google SecOps UDM field
// paths, used by the udm-schema lint rule to catch typos and unknown fields.
// In a production deployment this would be generated from the published UDM
// field list; the set below covers the commonly used families.
package schema

import "strings"

// exact holds fully qualified UDM paths (relative to an event variable).
var exact = map[string]bool{}

// prefixes are path families where arbitrary suffixes are allowed
// (e.g. labels / additional key-value structures).
var prefixes = []string{
	"additional.fields",
	"about.labels",
	"metadata.tags",
}

var fieldList = []string{
	// metadata
	"metadata.event_type", "metadata.event_timestamp", "metadata.collected_timestamp",
	"metadata.product_name", "metadata.vendor_name", "metadata.product_event_type",
	"metadata.product_log_id", "metadata.description", "metadata.id", "metadata.log_type",

	// principal
	"principal.hostname", "principal.asset_id", "principal.ip", "principal.port", "principal.mac",
	"principal.user.userid", "principal.user.user_display_name", "principal.user.windows_sid",
	"principal.user.email_addresses", "principal.user.employee_id",
	"principal.process.pid", "principal.process.command_line",
	"principal.process.file.full_path", "principal.process.file.sha256", "principal.process.file.md5",
	"principal.process.parent_process.pid", "principal.process.parent_process.command_line",
	"principal.asset.asset_id", "principal.asset.hostname",
	"principal.location.country_or_region", "principal.location.city",

	// target
	"target.hostname", "target.asset_id", "target.ip", "target.port", "target.mac",
	"target.user.userid", "target.user.user_display_name", "target.user.email_addresses",
	"target.user.windows_sid",
	"target.process.pid", "target.process.command_line",
	"target.process.file.full_path", "target.process.file.sha256", "target.process.file.md5",
	"target.file.full_path", "target.file.sha256", "target.file.md5", "target.file.size",
	"target.domain.name", "target.url", "target.application",
	"target.resource.name", "target.resource.resource_type", "target.resource.resource_subtype",

	// src / intermediary / observer (subset)
	"src.hostname", "src.ip", "src.port",
	"intermediary.hostname", "intermediary.ip",
	"observer.hostname", "observer.ip",

	// network
	"network.application_protocol", "network.direction", "network.ip_protocol",
	"network.session_id", "network.sent_bytes", "network.received_bytes",
	"network.http.method", "network.http.user_agent", "network.http.response_code",
	"network.http.referral_url",
	"network.dns.questions.name", "network.dns.answers.data",
	"network.email.from", "network.email.to", "network.email.subject",

	// security_result
	"security_result.action", "security_result.severity", "security_result.rule_name",
	"security_result.summary", "security_result.description", "security_result.category",
	"security_result.category_details", "security_result.detection_fields.value",

	// about (entity annotations)
	"about.hostname", "about.ip", "about.file.sha256", "about.user.userid",
}

func init() {
	for _, f := range fieldList {
		exact[f] = true
	}
}

// Valid reports whether path is a known UDM field path.
func Valid(path string) bool {
	if exact[path] {
		return true
	}
	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, p+".") {
			return true
		}
	}
	return false
}

// Nearest returns the closest known field path (edit distance ≤ 3) as a
// "did you mean" suggestion, or "" when nothing is close.
func Nearest(path string) string {
	best, bestDist := "", 4
	for _, f := range fieldList {
		if d := levenshtein(path, f); d < bestDist {
			best, bestDist = f, d
		}
	}
	return best
}

func levenshtein(a, b string) int {
	if a == b {
		return 0
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(min(cur[j-1]+1, prev[j]+1), prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}