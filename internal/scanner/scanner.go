// Package scanner runs Grype or Trivy against an image and normalizes their
// JSON output into layer-tagged findings.
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/AndrewKarpaty/layerblame/internal/report"
)

// Finding is one vulnerability, tagged with the layer that introduced it.
type Finding struct {
	ID       string
	Severity report.Severity
	Package  string
	Version  string
	FixedIn  string
	Fixable  bool
	// LayerDiffID is the uncompressed digest of the introducing layer;
	// empty when the scanner could not attribute the finding to a layer.
	LayerDiffID string
	// LayerDigest is the compressed digest, when reported (Trivy).
	LayerDigest string
	URL         string
}

// Result is a normalized scan.
type Result struct {
	Scanner  string
	Findings []Finding
}

// Detect returns the first available scanner binary, preferring grype.
func Detect() (string, error) {
	for _, name := range []string{"grype", "trivy"} {
		if _, err := exec.LookPath(name); err == nil {
			return name, nil
		}
	}
	return "", fmt.Errorf("no scanner found: install grype (https://github.com/anchore/grype) or trivy (https://github.com/aquasecurity/trivy), or pass --scan-file with an existing JSON report")
}

// Run executes the named scanner against image and parses its JSON output.
// tar, when set, is a docker-save tarball path scanned instead of the image
// reference. platform may be empty.
func Run(ctx context.Context, name, image, tar, platform string) (*Result, error) {
	var cmd *exec.Cmd
	switch name {
	case "grype":
		target := "registry:" + image
		if tar != "" {
			target = "docker-archive:" + tar
		}
		args := []string{target, "-o", "json"}
		if platform != "" {
			args = append(args, "--platform", platform)
		}
		cmd = exec.CommandContext(ctx, "grype", args...)
	case "trivy":
		args := []string{"image", "--format", "json", "--scanners", "vuln", "--quiet"}
		if tar != "" {
			args = append(args, "--input", tar)
		} else {
			args = append(args, "--image-src", "remote")
			if platform != "" {
				args = append(args, "--platform", platform)
			}
			args = append(args, image)
		}
		cmd = exec.CommandContext(ctx, "trivy", args...)
	default:
		return nil, fmt.Errorf("unknown scanner %q (use grype or trivy)", name)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s failed: %w\n%s", name, err, lastLines(stderr.Bytes(), 10))
	}
	return Parse(stdout.Bytes())
}

// ParseFile reads a grype or trivy JSON report from disk, detecting which
// scanner produced it.
func ParseFile(path string) (*Result, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("parse scan report %s: %w", path, err)
	}
	return r, nil
}

// Parse detects the report format (grype or trivy JSON) and normalizes it.
func Parse(b []byte) (*Result, error) {
	var probe struct {
		Matches       json.RawMessage `json:"matches"`
		SchemaVersion json.RawMessage `json:"SchemaVersion"`
		Results       json.RawMessage `json:"Results"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("not a JSON report: %w", err)
	}
	switch {
	case probe.Matches != nil:
		return parseGrype(b)
	case probe.SchemaVersion != nil || probe.Results != nil:
		return parseTrivy(b)
	default:
		return nil, fmt.Errorf("unrecognized report format: expected grype JSON (top-level \"matches\") or trivy JSON (top-level \"Results\")")
	}
}

type grypeReport struct {
	Matches []struct {
		Vulnerability struct {
			ID         string `json:"id"`
			Severity   string `json:"severity"`
			DataSource string `json:"dataSource"`
			Fix        struct {
				Versions []string `json:"versions"`
				State    string   `json:"state"`
			} `json:"fix"`
		} `json:"vulnerability"`
		Artifact struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Locations []struct {
				Path    string `json:"path"`
				LayerID string `json:"layerID"`
			} `json:"locations"`
		} `json:"artifact"`
	} `json:"matches"`
}

func parseGrype(b []byte) (*Result, error) {
	var rep grypeReport
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("parse grype report: %w", err)
	}
	res := &Result{Scanner: "grype"}
	for _, m := range rep.Matches {
		f := Finding{
			ID:       m.Vulnerability.ID,
			Severity: report.ParseSeverity(m.Vulnerability.Severity),
			Package:  m.Artifact.Name,
			Version:  m.Artifact.Version,
			Fixable:  m.Vulnerability.Fix.State == "fixed",
			URL:      m.Vulnerability.DataSource,
		}
		if len(m.Vulnerability.Fix.Versions) > 0 {
			f.FixedIn = m.Vulnerability.Fix.Versions[0]
		}
		if len(m.Artifact.Locations) > 0 {
			f.LayerDiffID = m.Artifact.Locations[0].LayerID
		}
		res.Findings = append(res.Findings, f)
	}
	return res, nil
}

type trivyReport struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			PrimaryURL       string `json:"PrimaryURL"`
			Layer            struct {
				Digest string `json:"Digest"`
				DiffID string `json:"DiffID"`
			} `json:"Layer"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func parseTrivy(b []byte) (*Result, error) {
	var rep trivyReport
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("parse trivy report: %w", err)
	}
	res := &Result{Scanner: "trivy"}
	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			res.Findings = append(res.Findings, Finding{
				ID:          v.VulnerabilityID,
				Severity:    report.ParseSeverity(v.Severity),
				Package:     v.PkgName,
				Version:     v.InstalledVersion,
				FixedIn:     v.FixedVersion,
				Fixable:     v.FixedVersion != "",
				LayerDiffID: v.Layer.DiffID,
				LayerDigest: v.Layer.Digest,
				URL:         v.PrimaryURL,
			})
		}
	}
	return res, nil
}

func lastLines(b []byte, n int) []byte {
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return bytes.Join(lines, []byte("\n"))
}
