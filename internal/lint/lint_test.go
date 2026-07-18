package lint

import (
	"strings"
	"testing"

	"github.com/AndrewKarpaty/layerblame/internal/dockerfile"
	"github.com/AndrewKarpaty/layerblame/internal/report"
)

func parseDF(t *testing.T, src string) *dockerfile.File {
	t.Helper()
	df, err := dockerfile.ParseReader(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	return df
}

func rulesFired(findings []report.LintFinding) map[string][]int {
	out := map[string][]int{}
	for _, f := range findings {
		out[f.Rule] = append(out[f.Rule], f.StartLine)
	}
	return out
}

func TestLintProblematicDockerfile(t *testing.T) {
	df := parseDF(t, `FROM node:latest
ENV API_KEY=supersecret123
COPY . /app
RUN cd /app && npm install
RUN apt-get update && apt-get install -y python3
RUN curl -sSL https://example.com/install.sh | sh
RUN npm run build
ADD config.yaml /app/config.yaml
`)
	fired := rulesFired(Lint(df, Options{}))

	want := map[string]int{
		"LB001": 1, // node:latest
		"LB002": 3, // COPY . before npm install
		"LB003": 5, // apt cache not cleaned
		"LB004": 5, // no --no-install-recommends
		"LB005": 8, // ADD for plain file
		"LB006": 1, // no USER
		"LB009": 2, // API_KEY in ENV
		"LB012": 4, // cd in RUN
		"LB013": 6, // curl | sh
		"LB014": 7, // build tools single-stage
	}
	for rule, line := range want {
		lines, ok := fired[rule]
		if !ok {
			t.Errorf("rule %s did not fire", rule)
			continue
		}
		found := false
		for _, l := range lines {
			if l == line {
				found = true
			}
		}
		if !found {
			t.Errorf("rule %s fired at %v, want line %d", rule, lines, line)
		}
	}
}

func TestLintCleanDockerfile(t *testing.T) {
	df := parseDF(t, `FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod CGO_ENABLED=0 go build -o /app .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /app /usr/local/bin/app
USER 65532
ENTRYPOINT ["app"]
`)
	findings := Lint(df, Options{})
	for _, f := range findings {
		t.Errorf("unexpected finding on clean Dockerfile: %s line %d: %s", f.Rule, f.StartLine, f.Message)
	}
}

func TestConsecutiveRuns(t *testing.T) {
	df := parseDF(t, `FROM alpine:3.20
RUN echo 1
RUN echo 2
RUN echo 3
USER 65532
`)
	fired := rulesFired(Lint(df, Options{}))
	if lines := fired["LB008"]; len(lines) != 1 || lines[0] != 2 {
		t.Errorf("LB008 = %v, want [2]", lines)
	}
}

func TestUpgradeRule(t *testing.T) {
	df := parseDF(t, `FROM debian:12
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
USER nobody
`)
	fired := rulesFired(Lint(df, Options{}))
	if _, ok := fired["LB010"]; !ok {
		t.Error("LB010 did not fire on apt-get upgrade")
	}
}

func TestMissingDockerignore(t *testing.T) {
	df := parseDF(t, `FROM alpine:3.20
COPY . /app
USER nobody
`)
	dir := t.TempDir()
	fired := rulesFired(Lint(df, Options{DockerfileDir: dir}))
	if _, ok := fired["LB015"]; !ok {
		t.Error("LB015 did not fire without .dockerignore")
	}
}
