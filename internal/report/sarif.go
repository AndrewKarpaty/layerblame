package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// SARIF rendering targets GitHub code scanning: every result points at the
// Dockerfile line whose instruction introduced the finding, so CVEs show up
// as annotations on the Dockerfile itself.

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
	HelpURI          string       `json:"helpUri,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

func sarifLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// WriteSARIF renders the report as SARIF 2.1.0.
func WriteSARIF(w io.Writer, r *Report) error {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "layerblame",
			InformationURI: "https://github.com/AndrewKarpaty/layerblame",
		}},
		Results: []sarifResult{},
	}
	seenRules := map[string]bool{}
	addRule := func(id, desc, uri string) {
		if seenRules[id] {
			return
		}
		seenRules[id] = true
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID:               id,
			ShortDescription: sarifMessage{Text: desc},
			HelpURI:          uri,
		})
	}
	loc := func(start, end int) []sarifLocation {
		return []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: r.Dockerfile},
			Region:           sarifRegion{StartLine: start, EndLine: end},
		}}}
	}

	for i := range r.Instructions {
		in := &r.Instructions[i]
		for _, v := range in.Vulns {
			addRule(v.ID, fmt.Sprintf("%s in %s", v.ID, v.Package), v.URL)
			msg := fmt.Sprintf("%s (%s) in %s %s, introduced by this instruction", v.ID, v.Severity, v.Package, v.Version)
			if in.BaseImage {
				msg = fmt.Sprintf("%s (%s) in %s %s, inherited from the base image — update the base image to remove it", v.ID, v.Severity, v.Package, v.Version)
			} else if v.Fixable {
				msg += fmt.Sprintf(" — fixed in %s", v.FixedIn)
			}
			run.Results = append(run.Results, sarifResult{
				RuleID:    v.ID,
				Level:     sarifLevel(v.Severity),
				Message:   sarifMessage{Text: msg},
				Locations: loc(in.StartLine, in.EndLine),
			})
		}
	}
	for _, l := range r.Lint {
		addRule(l.Rule, l.Message, "")
		msg := l.Message
		if l.Suggestion != "" {
			msg += ". " + l.Suggestion
		}
		run.Results = append(run.Results, sarifResult{
			RuleID:    l.Rule,
			Level:     sarifLevel(l.Severity),
			Message:   sarifMessage{Text: msg},
			Locations: loc(l.StartLine, l.EndLine),
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []sarifRun{run},
	})
}
