package dockerfile

import (
	"strings"
	"testing"
)

const multiStage = `# build stage
FROM golang:1.26 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /app /usr/local/bin/app
USER 65532
ENTRYPOINT ["app"]
`

func TestParseMultiStage(t *testing.T) {
	df, err := ParseReader(strings.NewReader(multiStage))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(df.Stages); got != 2 {
		t.Fatalf("stages = %d, want 2", got)
	}
	if df.Stages[0].Name != "builder" || df.Stages[0].BaseName != "golang:1.26" {
		t.Errorf("stage 0 = %q from %q", df.Stages[0].Name, df.Stages[0].BaseName)
	}
	final := df.FinalStage()
	if final.BaseName != "alpine:3.20" {
		t.Errorf("final base = %q, want alpine:3.20", final.BaseName)
	}
	if got := len(final.Instructions); got != 4 {
		t.Fatalf("final stage instructions = %d, want 4", got)
	}

	// Line numbers must point at physical source lines.
	run := final.Instructions[0]
	if run.Cmd != "RUN" || run.StartLine != 10 {
		t.Errorf("final RUN at line %d (cmd %s), want line 10", run.StartLine, run.Cmd)
	}
	cp := final.Instructions[1]
	if cp.Cmd != "COPY" {
		t.Fatalf("expected COPY, got %s", cp.Cmd)
	}
	if from, ok := cp.FromFlag("from"); !ok || from != "builder" {
		t.Errorf("COPY --from = %q, %v", from, ok)
	}
}

func TestParseContinuationLines(t *testing.T) {
	src := "FROM debian:12\nRUN apt-get update && \\\n    apt-get install -y curl && \\\n    rm -rf /var/lib/apt/lists/*\n"
	df, err := ParseReader(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	run := df.Stages[0].Instructions[0]
	if run.StartLine != 2 || run.EndLine != 4 {
		t.Errorf("RUN lines = %d-%d, want 2-4", run.StartLine, run.EndLine)
	}
}

func TestBuildChain(t *testing.T) {
	src := `FROM alpine:3.20 AS base
RUN apk add --no-cache tzdata

FROM golang:1.26 AS builder
RUN go version

FROM base
COPY --from=builder /etc/passwd /tmp/p
`
	df, err := ParseReader(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	stages, root := df.BuildChain()
	if root != "alpine:3.20" {
		t.Errorf("root base = %q, want alpine:3.20", root)
	}
	if len(stages) != 2 || stages[0].Name != "base" || stages[1].Index != 2 {
		t.Fatalf("chain = %v", stageNames(stages))
	}
	chain := df.ChainInstructions()
	if len(chain) != 2 || chain[0].Cmd != "RUN" || chain[1].Cmd != "COPY" {
		t.Errorf("chain instructions wrong: %+v", chain)
	}
}

func stageNames(stages []*Stage) []string {
	var out []string
	for _, s := range stages {
		out = append(out, s.Name)
	}
	return out
}

func TestParseNoFrom(t *testing.T) {
	if _, err := ParseReader(strings.NewReader("RUN echo hi\n")); err == nil {
		t.Fatal("expected error for Dockerfile without FROM")
	}
}
