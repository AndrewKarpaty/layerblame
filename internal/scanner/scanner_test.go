package scanner

import (
	"path/filepath"
	"testing"

	"github.com/AndrewKarpaty/layerblame/internal/report"
)

func TestParseGrypeFile(t *testing.T) {
	res, err := ParseFile(filepath.Join("testdata", "grype.json"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanner != "grype" {
		t.Errorf("scanner = %q, want grype", res.Scanner)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(res.Findings))
	}
	f := res.Findings[0]
	if f.ID != "CVE-2024-1234" || f.Severity != report.SeverityHigh ||
		f.Package != "curl" || !f.Fixable || f.FixedIn != "8.9.0-r0" ||
		f.LayerDiffID != "sha256:aaa111" {
		t.Errorf("finding = %+v", f)
	}
	if res.Findings[1].Fixable {
		t.Errorf("not-fixed finding marked fixable")
	}
}

func TestParseTrivyFile(t *testing.T) {
	res, err := ParseFile(filepath.Join("testdata", "trivy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanner != "trivy" {
		t.Errorf("scanner = %q, want trivy", res.Scanner)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(res.Findings))
	}
	f := res.Findings[0]
	if f.ID != "CVE-2024-1234" || f.Severity != report.SeverityHigh ||
		!f.Fixable || f.LayerDiffID != "sha256:aaa111" || f.LayerDigest != "sha256:ddd444" {
		t.Errorf("finding = %+v", f)
	}
	if res.Findings[1].Severity != report.SeverityUnknown || res.Findings[1].Fixable {
		t.Errorf("unknown-severity finding = %+v", res.Findings[1])
	}
}

func TestParseUnrecognized(t *testing.T) {
	if _, err := Parse([]byte(`{"hello": "world"}`)); err == nil {
		t.Fatal("expected error for unrecognized format")
	}
	if _, err := Parse([]byte(`not json`)); err == nil {
		t.Fatal("expected error for non-JSON input")
	}
}
