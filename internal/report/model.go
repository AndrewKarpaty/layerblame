// Package report defines the layerblame report model and its renderers.
package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Severity orders vulnerability and lint severities from least to most severe.
type Severity int

// Severity levels, least to most severe.
const (
	SeverityUnknown Severity = iota
	SeverityNegligible
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityUnknown:    "unknown",
	SeverityNegligible: "negligible",
	SeverityLow:        "low",
	SeverityMedium:     "medium",
	SeverityHigh:       "high",
	SeverityCritical:   "critical",
}

func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return "unknown"
}

// ParseSeverity maps a scanner severity string to a Severity. Unrecognized
// values map to SeverityUnknown.
func ParseSeverity(s string) Severity {
	for sev, name := range severityNames {
		if strings.EqualFold(s, name) {
			return sev
		}
	}
	return SeverityUnknown
}

// MarshalJSON renders the severity as its lowercase name.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON parses a severity name.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	*s = ParseSeverity(name)
	return nil
}

// Weight is the remediation-impact weight used to rank instructions.
func (s Severity) Weight() float64 {
	switch s {
	case SeverityCritical:
		return 10
	case SeverityHigh:
		return 5
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 0.5
	case SeverityNegligible:
		return 0.1
	default:
		return 1
	}
}

// Vuln is a single vulnerability finding attributed to a layer.
type Vuln struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Package     string   `json:"package"`
	Version     string   `json:"version"`
	FixedIn     string   `json:"fixedIn,omitempty"`
	Fixable     bool     `json:"fixable"`
	LayerDiffID string   `json:"layerDiffID,omitempty"`
	URL         string   `json:"url,omitempty"`
}

// Instruction aggregates the findings introduced by one Dockerfile instruction.
type Instruction struct {
	StartLine int    `json:"startLine"`
	EndLine   int    `json:"endLine"`
	Cmd       string `json:"cmd"`
	Source    string `json:"source"`
	Stage     string `json:"stage,omitempty"`
	// BaseImage is true when this is a FROM instruction carrying findings
	// inherited from the base image rather than introduced by the Dockerfile.
	BaseImage bool     `json:"baseImage,omitempty"`
	Layers    []string `json:"layers,omitempty"`
	LayerSize int64    `json:"layerSize,omitempty"`
	Vulns     []Vuln   `json:"vulns,omitempty"`

	Counts  map[string]int `json:"counts"`
	Total   int            `json:"total"`
	Fixable int            `json:"fixable"`
	// Score is the remediation impact: the severity-weighted number of
	// findings a single change to this instruction would remove.
	Score float64 `json:"score"`
}

// AddVuln records a finding against the instruction and updates aggregates.
func (i *Instruction) AddVuln(v Vuln) {
	if i.Counts == nil {
		i.Counts = map[string]int{}
	}
	i.Vulns = append(i.Vulns, v)
	i.Counts[v.Severity.String()]++
	i.Total++
	if v.Fixable {
		i.Fixable++
	}
	i.Score += v.Severity.Weight()
}

// Count returns the number of findings at the given severity.
func (i *Instruction) Count(s Severity) int {
	return i.Counts[s.String()]
}

// LintFinding is a static-analysis finding on the Dockerfile itself.
type LintFinding struct {
	Rule      string   `json:"rule"`
	Severity  Severity `json:"severity"`
	StartLine int      `json:"startLine"`
	EndLine   int      `json:"endLine"`
	Message   string   `json:"message"`
	// Suggestion describes the concrete change that resolves the finding.
	Suggestion string `json:"suggestion,omitempty"`
}

// Summary holds report-wide aggregates.
type Summary struct {
	TotalVulns   int            `json:"totalVulns"`
	Fixable      int            `json:"fixable"`
	Counts       map[string]int `json:"counts"`
	BaseImage    int            `json:"baseImageVulns"`
	OwnLayers    int            `json:"ownLayerVulns"`
	Unattributed int            `json:"unattributedVulns"`
	LintFindings int            `json:"lintFindings"`
}

// Report is the full layerblame result for one image + Dockerfile pair.
type Report struct {
	Image        string        `json:"image,omitempty"`
	ImageDigest  string        `json:"imageDigest,omitempty"`
	Dockerfile   string        `json:"dockerfile"`
	Scanner      string        `json:"scanner,omitempty"`
	Instructions []Instruction `json:"instructions,omitempty"`
	// Unattributed collects findings whose layer could not be mapped to a
	// Dockerfile instruction.
	Unattributed *Instruction  `json:"unattributed,omitempty"`
	Lint         []LintFinding `json:"lint,omitempty"`
	Summary      Summary       `json:"summary"`
}

// Finalize sorts instructions by remediation impact and computes the summary.
func (r *Report) Finalize() {
	sort.SliceStable(r.Instructions, func(a, b int) bool {
		return r.Instructions[a].Score > r.Instructions[b].Score
	})
	s := Summary{Counts: map[string]int{}}
	add := func(in *Instruction, base bool) {
		for _, v := range in.Vulns {
			s.TotalVulns++
			s.Counts[v.Severity.String()]++
			if v.Fixable {
				s.Fixable++
			}
			if base {
				s.BaseImage++
			} else {
				s.OwnLayers++
			}
		}
	}
	for i := range r.Instructions {
		add(&r.Instructions[i], r.Instructions[i].BaseImage)
	}
	if r.Unattributed != nil {
		for _, v := range r.Unattributed.Vulns {
			s.TotalVulns++
			s.Counts[v.Severity.String()]++
			if v.Fixable {
				s.Fixable++
			}
			s.Unattributed++
		}
	}
	s.LintFindings = len(r.Lint)
	r.Summary = s
}

// MaxSeverity returns the most severe finding in the report, considering both
// vulnerabilities and lint findings.
func (r *Report) MaxSeverity() Severity {
	maxSev := SeverityUnknown
	consider := func(s Severity) {
		if s > maxSev {
			maxSev = s
		}
	}
	for i := range r.Instructions {
		for _, v := range r.Instructions[i].Vulns {
			consider(v.Severity)
		}
	}
	if r.Unattributed != nil {
		for _, v := range r.Unattributed.Vulns {
			consider(v.Severity)
		}
	}
	for _, l := range r.Lint {
		consider(l.Severity)
	}
	return maxSev
}

// HumanSize renders a byte count as a short human-readable string.
func HumanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
