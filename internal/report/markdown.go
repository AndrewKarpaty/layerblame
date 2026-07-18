package report

import (
	"fmt"
	"io"
)

// WriteMarkdown renders the report as GitHub-flavored Markdown, suitable for
// PR comments.
func WriteMarkdown(w io.Writer, r *Report) error {
	fmt.Fprintf(w, "## layerblame report\n\n")
	if r.Image != "" {
		fmt.Fprintf(w, "**Image:** `%s`  \n", r.Image)
	}
	fmt.Fprintf(w, "**Dockerfile:** `%s`  \n", r.Dockerfile)
	if r.Scanner != "" {
		fmt.Fprintf(w, "**Scanner:** %s  \n", r.Scanner)
	}
	fmt.Fprintln(w)

	if r.Scanner != "" {
		fmt.Fprintf(w, "### Instructions ranked by remediation impact\n\n")
		fmt.Fprintf(w, "| # | Line | Instruction | Crit | High | Med | Low | Fixable | Score |\n")
		fmt.Fprintf(w, "|--:|-----:|-------------|-----:|-----:|----:|----:|--------:|------:|\n")
		rank := 0
		for i := range r.Instructions {
			in := &r.Instructions[i]
			if in.Total == 0 {
				continue
			}
			rank++
			src := oneLine(in.Source, 60)
			if in.BaseImage {
				src += " *(base image)*"
			}
			fmt.Fprintf(w, "| %d | %d | `%s` | %d | %d | %d | %d | %d/%d | %.1f |\n",
				rank, in.StartLine, src,
				in.Count(SeverityCritical), in.Count(SeverityHigh),
				in.Count(SeverityMedium), in.Count(SeverityLow),
				in.Fixable, in.Total, in.Score)
		}
		if rank == 0 {
			fmt.Fprintf(w, "\nNo vulnerabilities found. 🎉\n")
		}
		fmt.Fprintln(w)
		if r.Unattributed != nil {
			fmt.Fprintf(w, "> ⚠️ %d finding(s) could not be attributed to an instruction.\n\n", r.Unattributed.Total)
		}
	}

	if len(r.Lint) > 0 {
		fmt.Fprintf(w, "### Dockerfile findings\n\n")
		fmt.Fprintf(w, "| Rule | Severity | Line | Finding |\n")
		fmt.Fprintf(w, "|------|----------|-----:|---------|\n")
		for _, l := range r.Lint {
			fmt.Fprintf(w, "| %s | %s | %d | %s |\n", l.Rule, l.Severity, l.StartLine, l.Message)
		}
		fmt.Fprintln(w)
	}

	s := r.Summary
	fmt.Fprintf(w, "### Summary\n\n")
	if r.Scanner != "" {
		fmt.Fprintf(w, "- **%d** vulnerabilities (**%d** fixable): %d critical, %d high, %d medium, %d low\n",
			s.TotalVulns, s.Fixable,
			s.Counts[SeverityCritical.String()], s.Counts[SeverityHigh.String()],
			s.Counts[SeverityMedium.String()], s.Counts[SeverityLow.String()])
		fmt.Fprintf(w, "- Origin: **%d** base image · **%d** your instructions · **%d** unattributed\n",
			s.BaseImage, s.OwnLayers, s.Unattributed)
	}
	if s.LintFindings > 0 {
		fmt.Fprintf(w, "- **%d** Dockerfile findings\n", s.LintFindings)
	}
	return nil
}
