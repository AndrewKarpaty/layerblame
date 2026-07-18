package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func sampleReport() *Report {
	r := &Report{
		Image:      "example.com/app:1",
		Dockerfile: "Dockerfile",
		Scanner:    "grype",
	}
	from := Instruction{StartLine: 1, EndLine: 1, Cmd: "FROM", Source: "FROM alpine:3.20", BaseImage: true}
	from.AddVuln(Vuln{ID: "CVE-2024-0001", Severity: SeverityCritical, Package: "musl", Version: "1.2.4"})
	run := Instruction{StartLine: 2, EndLine: 2, Cmd: "RUN", Source: "RUN apk add curl"}
	run.AddVuln(Vuln{ID: "CVE-2024-0002", Severity: SeverityHigh, Package: "curl", Version: "8.8.0", FixedIn: "8.9.0", Fixable: true})
	r.Instructions = []Instruction{run, from}
	r.Lint = []LintFinding{{Rule: "LB006", Severity: SeverityHigh, StartLine: 1, EndLine: 1, Message: "final stage runs as root"}}
	r.Finalize()
	return r
}

func TestFinalizeRanksAndSummarizes(t *testing.T) {
	r := sampleReport()
	if r.Instructions[0].Cmd != "FROM" {
		t.Errorf("expected FROM (critical, score 10) ranked first, got %s", r.Instructions[0].Cmd)
	}
	s := r.Summary
	if s.TotalVulns != 2 || s.Fixable != 1 || s.BaseImage != 1 || s.OwnLayers != 1 || s.LintFindings != 1 {
		t.Errorf("summary = %+v", s)
	}
	if r.MaxSeverity() != SeverityCritical {
		t.Errorf("max severity = %v", r.MaxSeverity())
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	b, err := json.Marshal(SeverityHigh)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"high"` {
		t.Errorf("marshal = %s", b)
	}
	var s Severity
	if err := json.Unmarshal([]byte(`"critical"`), &s); err != nil || s != SeverityCritical {
		t.Errorf("unmarshal = %v, %v", s, err)
	}
}

func TestWriteSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
		t.Fatalf("sarif doc = %+v", doc)
	}
	results := doc.Runs[0].Results
	if len(results) != 3 { // 2 vulns + 1 lint
		t.Fatalf("results = %d, want 3", len(results))
	}
	for _, res := range results {
		loc := res.Locations[0].PhysicalLocation
		if loc.ArtifactLocation.URI != "Dockerfile" || loc.Region.StartLine == 0 {
			t.Errorf("result %s has bad location %+v", res.RuleID, loc)
		}
	}
}

func TestWriteTerminalNoColor(t *testing.T) {
	var buf bytes.Buffer
	WriteTerminal(&buf, sampleReport(), TerminalOptions{NoColor: true, Verbose: true})
	out := buf.String()
	for _, want := range []string{"FROM alpine:3.20", "base image", "CVE-2024-0002", "fixable: 1/1", "LB006"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("NoColor output contains ANSI escapes")
	}
}

func TestWriteMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"| 1 | 1 |", "base image", "LB006"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing %q:\n%s", want, out)
		}
	}
}
