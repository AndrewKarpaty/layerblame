# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

layerblame is a Go CLI ("git blame for container vulnerabilities") that maps every CVE in a container image back to the Dockerfile instruction — and physical line — that introduced it, ranks instructions by remediation impact, and statically lints the Dockerfile for build-speed/size/security improvements. No Docker daemon needed: image metadata is pulled straight from the registry. Module path: `github.com/AndrewKarpaty/layerblame`. Go version is pinned in `.go-version`.

## Commands

```sh
make build                            # build the binary (or: go build -o layerblame .)
make test                             # go test -race ./...
make lint                             # golangci-lint run (config: .golangci.yml)
go test ./internal/attribute/ -run TestAlign -v   # run a single test
```

CI (`.github/workflows/ci.yml`) runs build, vet, `test -race`, and golangci-lint on every PR. Pushing a `v*` tag triggers `release.yml`: GoReleaser builds binaries (version injected into `cmd.Version` via ldflags).

Local usage:

```sh
./layerblame analyze IMAGE -f Dockerfile            # scan (grype/trivy) + attribute
./layerblame analyze IMAGE --scan-file report.json  # reuse an existing scanner report
./layerblame analyze --tar img.tar -f Dockerfile    # docker-save tarball, no registry
./layerblame lint -f Dockerfile                     # offline static analysis only
```

## Architecture

The pipeline is **fetch metadata → parse Dockerfile → scan → align history → aggregate → render**:

1. `internal/registry` — pulls image config + manifest via go-containerregistry (`Fetch` for registries, `FetchTarball` for docker-save tars). Produces `Image.History`: each OCI history entry paired with its layer diffID/digest/size (non-empty entries consume diffIDs in order).
2. `internal/dockerfile` — wraps BuildKit's Dockerfile parser. Produces `Instruction`s with `StartLine`/`EndLine`, stage structure, and `BuildChain()`/`ChainInstructions()` — the FROM-chain of stages that actually contribute layers to the final image.
3. `internal/scanner` — execs grype (`registry:` source) or trivy (`--image-src remote`), or parses an existing JSON report (`Parse` sniffs the format). Normalizes to `Finding`s tagged with `LayerDiffID`.
4. `internal/attribute` — the core. `ParseCreatedBy` recovers instructions from history `created_by` strings (both classic-builder `/bin/sh -c #(nop)` and BuildKit `# buildkit` formats). `Align` walks history and the Dockerfile chain **backwards from the newest entry**, matching by instruction type; everything older than the matched region is the base image. `Run` buckets scanner findings per instruction via diffID, flags base-image findings on the root FROM line, and ranks by severity-weighted score. Unmappable findings go to `Report.Unattributed` — never guessed.
5. `internal/lint` — pure static rules (LB001–LB015) over the parsed AST: cache-busting COPY order, package caches left in layers, missing cache mounts, root user, secrets in ENV/ARG, curl|sh, single-stage build tools, etc. Each rule is a `func(*dockerfile.File, Options) []report.LintFinding`.
6. `internal/report` — the `Report`/`Instruction`/`Vuln`/`LintFinding` model and four renderers: terminal (ANSI, `NO_COLOR` aware), JSON, SARIF 2.1.0 (locations point at Dockerfile lines so GitHub code scanning annotates the Dockerfile), Markdown (PR comments). `Severity` marshals to/from strings. `Finalize()` sorts by score and computes the summary.
7. `cmd` — cobra CLI: `analyze` (also the root default), `lint`, `version`. `--fail-on SEVERITY` returns exit code 2 via `failError` for CI gating; runtime errors exit 1.

Conventions that matter when extending it:

- Tests use synthetic history entries / fixture scanner JSON (`internal/scanner/testdata/`) — no network, no daemon. `TestAlignBuildKit` / `TestAlignClassicBuilder` are the reference for history formats.
- When attribution is uncertain, prefer "unattributed" over a wrong line.
- Renderers write to an `io.Writer`; commands use `cmd.OutOrStdout()` so tests can capture output. Logs/progress go to stderr.
