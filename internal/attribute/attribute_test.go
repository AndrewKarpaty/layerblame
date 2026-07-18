package attribute

import (
	"strings"
	"testing"

	"github.com/AndrewKarpaty/layerblame/internal/dockerfile"
	"github.com/AndrewKarpaty/layerblame/internal/registry"
	"github.com/AndrewKarpaty/layerblame/internal/report"
	"github.com/AndrewKarpaty/layerblame/internal/scanner"
)

// A typical buildkit-built image: alpine base (2 history entries) plus a
// Dockerfile with RUN, COPY, USER, ENTRYPOINT.
const simpleDockerfile = `FROM alpine:3.20
RUN apk add --no-cache curl
COPY app /usr/local/bin/app
USER 65532
ENTRYPOINT ["app"]
`

func simpleHistory() []registry.HistoryEntry {
	return []registry.HistoryEntry{
		{Index: 0, CreatedBy: "ADD alpine-minirootfs.tar.gz / # buildkit", DiffID: "sha256:base"},
		{Index: 1, CreatedBy: "CMD [\"/bin/sh\"]", EmptyLayer: true},
		{Index: 2, CreatedBy: "RUN /bin/sh -c apk add --no-cache curl # buildkit", DiffID: "sha256:run1", Size: 4096},
		{Index: 3, CreatedBy: "COPY app /usr/local/bin/app # buildkit", DiffID: "sha256:copy1", Size: 1024},
		{Index: 4, CreatedBy: "USER 65532", EmptyLayer: true},
		{Index: 5, CreatedBy: "ENTRYPOINT [\"app\"]", EmptyLayer: true},
	}
}

func parseDF(t *testing.T, src string) *dockerfile.File {
	t.Helper()
	df, err := dockerfile.ParseReader(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	return df
}

func TestAlignBuildKit(t *testing.T) {
	df := parseDF(t, simpleDockerfile)
	a := Align(simpleHistory(), df)

	if a.BaseEntries != 2 {
		t.Errorf("BaseEntries = %d, want 2", a.BaseEntries)
	}
	wantLines := map[int]int{2: 2, 3: 3, 4: 4, 5: 5} // history index → Dockerfile line
	for hi, line := range wantLines {
		d, ok := a.ByHistoryIndex[hi]
		if !ok {
			t.Errorf("history %d not attributed", hi)
			continue
		}
		if d.StartLine != line {
			t.Errorf("history %d attributed to line %d, want %d", hi, d.StartLine, line)
		}
	}
}

func TestAlignClassicBuilder(t *testing.T) {
	df := parseDF(t, simpleDockerfile)
	history := []registry.HistoryEntry{
		{Index: 0, CreatedBy: "/bin/sh -c #(nop) ADD file:abc in / ", DiffID: "sha256:base"},
		{Index: 1, CreatedBy: "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]", EmptyLayer: true},
		{Index: 2, CreatedBy: "/bin/sh -c apk add --no-cache curl", DiffID: "sha256:run1"},
		{Index: 3, CreatedBy: "/bin/sh -c #(nop) COPY file:xyz in /usr/local/bin/app ", DiffID: "sha256:copy1"},
		{Index: 4, CreatedBy: "/bin/sh -c #(nop)  USER 65532", EmptyLayer: true},
		{Index: 5, CreatedBy: "/bin/sh -c #(nop)  ENTRYPOINT [\"app\"]", EmptyLayer: true},
	}
	a := Align(history, df)
	if a.BaseEntries != 2 {
		t.Errorf("BaseEntries = %d, want 2", a.BaseEntries)
	}
	if d := a.ByHistoryIndex[2]; d == nil || d.StartLine != 2 {
		t.Errorf("RUN history not attributed to line 2: %+v", d)
	}
}

func TestAlignSkipsARG(t *testing.T) {
	df := parseDF(t, `FROM alpine:3.20
ARG VERSION=1
RUN apk add --no-cache curl
`)
	// BuildKit did not record the ARG instruction.
	history := []registry.HistoryEntry{
		{Index: 0, CreatedBy: "ADD alpine-minirootfs.tar.gz / # buildkit", DiffID: "sha256:base"},
		{Index: 1, CreatedBy: "RUN /bin/sh -c apk add --no-cache curl # buildkit", DiffID: "sha256:run1"},
	}
	a := Align(history, df)
	if a.BaseEntries != 1 {
		t.Errorf("BaseEntries = %d, want 1", a.BaseEntries)
	}
	if d := a.ByHistoryIndex[1]; d == nil || d.StartLine != 3 {
		t.Errorf("RUN not attributed to line 3: %+v", d)
	}
}

func TestRunAttributesFindings(t *testing.T) {
	df := parseDF(t, simpleDockerfile)
	img := &registry.Image{Ref: "example.com/app:1", History: simpleHistory()}
	scan := &scanner.Result{
		Scanner: "grype",
		Findings: []scanner.Finding{
			{ID: "CVE-2024-0001", Severity: report.SeverityCritical, Package: "musl", LayerDiffID: "sha256:base"},
			{ID: "CVE-2024-0002", Severity: report.SeverityHigh, Package: "curl", Fixable: true, FixedIn: "8.9.0", LayerDiffID: "sha256:run1"},
			{ID: "CVE-2024-0003", Severity: report.SeverityLow, Package: "curl", LayerDiffID: "sha256:run1"},
			{ID: "CVE-2024-0004", Severity: report.SeverityMedium, Package: "ghost", LayerDiffID: "sha256:nope"},
		},
	}

	rep := Run(img, df, scan)

	if rep.Summary.TotalVulns != 4 || rep.Summary.BaseImage != 1 || rep.Summary.OwnLayers != 2 || rep.Summary.Unattributed != 1 {
		t.Fatalf("summary = %+v", rep.Summary)
	}
	if rep.Summary.Fixable != 1 {
		t.Errorf("fixable = %d, want 1", rep.Summary.Fixable)
	}

	// The FROM line must carry the base finding and be flagged as base image.
	var fromInstr, runInstr *report.Instruction
	for i := range rep.Instructions {
		in := &rep.Instructions[i]
		switch in.Cmd {
		case "FROM":
			fromInstr = in
		case "RUN":
			runInstr = in
		}
	}
	if fromInstr == nil || !fromInstr.BaseImage || fromInstr.StartLine != 1 || fromInstr.Total != 1 {
		t.Errorf("FROM instruction wrong: %+v", fromInstr)
	}
	if runInstr == nil || runInstr.Total != 2 || runInstr.StartLine != 2 {
		t.Errorf("RUN instruction wrong: %+v", runInstr)
	}

	// The RUN line has 1 high + 1 low (score 5.5), base has 1 critical (10):
	// base ranks first.
	if rep.Instructions[0].Cmd != "FROM" {
		t.Errorf("ranking wrong, first = %+v", rep.Instructions[0])
	}
	if rep.Unattributed == nil || rep.Unattributed.Total != 1 {
		t.Errorf("unattributed = %+v", rep.Unattributed)
	}
}

func TestRunMultiStageChain(t *testing.T) {
	df := parseDF(t, `FROM golang:1.26 AS builder
RUN go build -o /app ./...

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /app /app
`)
	history := []registry.HistoryEntry{
		{Index: 0, CreatedBy: "ADD alpine-minirootfs.tar.gz / # buildkit", DiffID: "sha256:base"},
		{Index: 1, CreatedBy: "CMD [\"/bin/sh\"]", EmptyLayer: true},
		{Index: 2, CreatedBy: "RUN /bin/sh -c apk add --no-cache ca-certificates # buildkit", DiffID: "sha256:run"},
		{Index: 3, CreatedBy: "COPY /app /app # buildkit", DiffID: "sha256:copy"},
	}
	img := &registry.Image{Ref: "img", History: history}
	scan := &scanner.Result{Scanner: "trivy", Findings: []scanner.Finding{
		{ID: "CVE-1", Severity: report.SeverityHigh, LayerDiffID: "sha256:copy"},
	}}
	rep := Run(img, df, scan)

	// The COPY --from finding must land on the final stage's COPY line (6),
	// not anywhere in the builder stage.
	found := false
	for _, in := range rep.Instructions {
		if in.Cmd == "COPY" && in.StartLine == 6 && in.Total == 1 {
			found = true
		}
	}
	if !found {
		t.Errorf("COPY --from finding not attributed to line 6: %+v", rep.Instructions)
	}
}
