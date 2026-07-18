package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// TerminalOptions configures the terminal renderer.
type TerminalOptions struct {
	NoColor bool
	// Verbose lists individual CVEs under each instruction.
	Verbose bool
	// Top limits the number of instructions shown (0 = all with findings).
	Top int
}

type palette struct{ reset, bold, dim, red, yellow, blue, magenta, green string }

func newPalette(noColor bool) palette {
	if noColor {
		return palette{}
	}
	return palette{
		reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
		red: "\x1b[31m", yellow: "\x1b[33m", blue: "\x1b[34m",
		magenta: "\x1b[35m", green: "\x1b[32m",
	}
}

func (p palette) severity(s Severity) string {
	switch s {
	case SeverityCritical:
		return p.bold + p.red
	case SeverityHigh:
		return p.red
	case SeverityMedium:
		return p.yellow
	case SeverityLow:
		return p.blue
	default:
		return p.dim
	}
}

// WriteTerminal renders the report for humans.
func WriteTerminal(w io.Writer, r *Report, opts TerminalOptions) {
	p := newPalette(opts.NoColor)

	if r.Image != "" {
		fmt.Fprintf(w, "%sImage:%s      %s\n", p.bold, p.reset, r.Image)
	}
	fmt.Fprintf(w, "%sDockerfile:%s %s\n", p.bold, p.reset, r.Dockerfile)
	if r.Scanner != "" {
		fmt.Fprintf(w, "%sScanner:%s    %s\n", p.bold, p.reset, r.Scanner)
	}
	fmt.Fprintln(w)

	if r.Scanner != "" {
		writeVulnSection(w, r, p, opts)
	}
	if len(r.Lint) > 0 {
		writeLintSection(w, r, p)
	}
	writeSummary(w, r, p)
}

func writeVulnSection(w io.Writer, r *Report, p palette, opts TerminalOptions) {
	withFindings := make([]Instruction, 0, len(r.Instructions))
	for _, in := range r.Instructions {
		if in.Total > 0 {
			withFindings = append(withFindings, in)
		}
	}
	if len(withFindings) == 0 && r.Unattributed == nil {
		fmt.Fprintf(w, "%sNo vulnerabilities found.%s\n\n", p.green, p.reset)
		return
	}

	fmt.Fprintf(w, "%sInstructions ranked by remediation impact%s\n\n", p.bold, p.reset)
	shown := withFindings
	if opts.Top > 0 && len(shown) > opts.Top {
		shown = shown[:opts.Top]
	}
	for rank, in := range shown {
		src := oneLine(in.Source, 78)
		loc := fmt.Sprintf("%s:%d", r.Dockerfile, in.StartLine)
		fmt.Fprintf(w, "%s%2d.%s %s%s%s\n", p.bold, rank+1, p.reset, p.bold, src, p.reset)
		fmt.Fprintf(w, "    %s%s%s", p.dim, loc, p.reset)
		if in.BaseImage {
			fmt.Fprintf(w, "  %s[base image]%s", p.magenta, p.reset)
		}
		if in.LayerSize > 0 {
			fmt.Fprintf(w, "  %s%s in %d layer(s)%s", p.dim, HumanSize(in.LayerSize), len(in.Layers), p.reset)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "    %s  fixable: %d/%d  impact score: %.1f\n",
			severityLine(in.Counts, p), in.Fixable, in.Total, in.Score)
		if in.BaseImage {
			fmt.Fprintf(w, "    %s→ a base image update is the single change that removes these%s\n", p.dim, p.reset)
		}
		if opts.Verbose {
			writeVulns(w, in.Vulns, p)
		}
		fmt.Fprintln(w)
	}
	if r.Unattributed != nil {
		fmt.Fprintf(w, "%s !  %d finding(s) could not be attributed to an instruction%s\n\n",
			p.yellow, r.Unattributed.Total, p.reset)
	}
}

func writeVulns(w io.Writer, vulns []Vuln, p palette) {
	sorted := make([]Vuln, len(vulns))
	copy(sorted, vulns)
	sort.SliceStable(sorted, func(a, b int) bool { return sorted[a].Severity > sorted[b].Severity })
	for _, v := range sorted {
		fix := ""
		if v.Fixable {
			fix = fmt.Sprintf(" (fixed in %s)", v.FixedIn)
		}
		fmt.Fprintf(w, "      %s%-10s%s %-20s %s %s%s\n",
			p.severity(v.Severity), v.Severity, p.reset, v.ID, v.Package, v.Version, fix)
	}
}

func writeLintSection(w io.Writer, r *Report, p palette) {
	fmt.Fprintf(w, "%sDockerfile findings%s\n\n", p.bold, p.reset)
	for _, l := range r.Lint {
		fmt.Fprintf(w, "  %s%-8s%s %s %s:%d%s  %s\n",
			p.severity(l.Severity), l.Severity, p.reset, l.Rule, r.Dockerfile, l.StartLine, p.reset, l.Message)
		if l.Suggestion != "" {
			fmt.Fprintf(w, "           %s→ %s%s\n", p.dim, l.Suggestion, p.reset)
		}
	}
	fmt.Fprintln(w)
}

func writeSummary(w io.Writer, r *Report, p palette) {
	s := r.Summary
	fmt.Fprintf(w, "%sSummary%s\n", p.bold, p.reset)
	if r.Scanner != "" {
		fmt.Fprintf(w, "  vulnerabilities: %d total, %d fixable — %s\n",
			s.TotalVulns, s.Fixable, severityLine(s.Counts, p))
		fmt.Fprintf(w, "  origin: %d from base image, %d from your instructions, %d unattributed\n",
			s.BaseImage, s.OwnLayers, s.Unattributed)
	}
	if s.LintFindings > 0 {
		fmt.Fprintf(w, "  dockerfile findings: %d\n", s.LintFindings)
	}
}

func severityLine(counts map[string]int, p palette) string {
	order := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNegligible, SeverityUnknown}
	parts := make([]string, 0, len(order))
	for _, sev := range order {
		if n := counts[sev.String()]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s%d %s%s", p.severity(sev), n, sev, p.reset))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func oneLine(s string, maxLen int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxLen {
		s = s[:maxLen-1] + "…"
	}
	return s
}
