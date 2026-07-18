# layerblame

**git blame for container vulnerabilities** — maps every CVE back to the Dockerfile instruction that introduced it, ranks instructions by how much a single change would remove, and statically lints your Dockerfile for build-speed, size and security wins.

No Docker daemon needed. Built for CI.

```
$ layerblame analyze ghcr.io/acme/api:latest -f Dockerfile

Instructions ranked by remediation impact

 1. FROM debian:bookworm
    Dockerfile:1  [base image]  48.2 MB in 12 layer(s)
    3 critical, 21 high, 40 medium  fixable: 12/64  impact score: 215.0
    → a base image update is the single change that removes these

 2. RUN apt-get update && apt-get install -y imagemagick libmagick…
    Dockerfile:7  102.1 MB in 1 layer(s)
    1 critical, 8 high, 11 medium  fixable: 9/20  impact score: 72.0

 3. COPY --from=builder /app /usr/local/bin/app
    Dockerfile:23  18.4 MB in 1 layer(s)
    2 high  fixable: 2/2  impact score: 10.0

Summary
  vulnerabilities: 86 total, 23 fixable — 4 critical, 31 high, 51 medium
  origin: 64 from base image, 22 from your instructions, 0 unattributed
```

## How it works

1. **Pulls the image config and layer metadata** straight from the registry via the OCI distribution API — no Docker daemon, works with any registry (Docker Hub, GHCR, ECR, GCR, ...). `--tar` reads a `docker save` tarball instead, so CI can analyze images before pushing.
2. **Parses the Dockerfile into an AST** with BuildKit's own parser, keeping physical line numbers (continuations, heredocs and multi-stage builds included).
3. **Gets vulnerability findings from Grype or Trivy** — running whichever is installed, or ingesting a report you already generated (`--scan-file`). Each finding carries the layer it lives in.
4. **Walks the OCI history array** to match layers to the instructions that created them — understanding both classic-builder (`/bin/sh -c #(nop) ...`) and BuildKit (`# buildkit`) history formats.
5. **Aligns instructions back to physical lines** in your Dockerfile, resolving multi-stage FROM chains so `COPY --from` findings land on the right line. Base-image layers are attributed to the `FROM` line and flagged, separating "update your base image" from "fix your own instructions".
6. **Aggregates and ranks**: per instruction, findings by severity, fixable counts, layer sizes, and a severity-weighted impact score — so the top of the list is always the single change that removes the most risk.

Findings that can't be confidently mapped are reported as *unattributed*, never guessed onto a line.

## Install

```sh
go install github.com/AndrewKarpaty/layerblame@latest
```

Or grab a binary from [releases](https://github.com/AndrewKarpaty/layerblame/releases).

For `analyze` you also need [grype](https://github.com/anchore/grype) or [trivy](https://github.com/aquasecurity/trivy) on the PATH (or a pre-generated report via `--scan-file`). `lint` needs nothing.

## Usage

```sh
# Scan and attribute (auto-detects grype or trivy)
layerblame analyze ghcr.io/acme/api:latest -f Dockerfile

# Reuse a scan your CI already ran — no rescan needed
trivy image --format json -o scan.json ghcr.io/acme/api:latest
layerblame analyze ghcr.io/acme/api:latest -f Dockerfile --scan-file scan.json

# Analyze an image without pushing it (docker save / buildx -o type=docker,dest=…)
layerblame analyze --tar image.tar -f Dockerfile

# Offline Dockerfile lint only — no image, no scanner
layerblame lint -f Dockerfile

# CI gating: exit 2 when findings reach the threshold
layerblame analyze IMAGE -f Dockerfile --fail-on critical

# SARIF for GitHub code scanning — CVEs annotate Dockerfile lines in PRs
layerblame analyze IMAGE -f Dockerfile -o sarif --output-file layerblame.sarif
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-f, --dockerfile` | `Dockerfile` | Dockerfile the image was built from |
| `-o, --output` | `terminal` | `terminal`, `json`, `sarif`, `markdown` |
| `--scanner` | `auto` | `grype`, `trivy`, or auto-detect |
| `--scan-file` | | reuse an existing grype/trivy JSON report |
| `--tar` | | analyze a `docker save` tarball instead of a registry image |
| `--platform` | | e.g. `linux/amd64` for multi-arch images |
| `--fail-on` | `none` | exit 2 at/above this severity: `low`, `medium`, `high`, `critical` |
| `-v, --verbose` | | list individual CVEs under each instruction |
| `--no-lint` | | skip Dockerfile static analysis during `analyze` |

Exit codes: `0` clean, `1` runtime error, `2` findings at/above `--fail-on`.

### GitHub Actions example

```yaml
- name: Build image
  run: docker buildx build -t $IMAGE --output type=docker,dest=image.tar .

- name: layerblame
  run: |
    layerblame analyze --tar image.tar -f Dockerfile \
      -o sarif --output-file layerblame.sarif --fail-on high

- name: Upload to code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: layerblame.sarif
```

CVEs then show up as PR annotations *on the Dockerfile lines that introduced them*.

## Dockerfile lint rules

`lint` (also run during `analyze`) reports improvements the AST alone can prove — build speed, image size, security:

| Rule | Severity | Finding |
|------|----------|---------|
| LB001 | high | base image not pinned to a tag/digest |
| LB002 | medium | broad `COPY` before dependency install (busts the build cache) |
| LB003 | medium | apt/apk/yum cache left in the layer |
| LB004 | low | apt install without `--no-install-recommends` |
| LB005 | low | `ADD` where `COPY` suffices |
| LB006 | high | final stage runs as root |
| LB008 | low | 3+ consecutive `RUN`s create avoidable layers |
| LB009 | critical | secret-looking `ENV`/`ARG` baked into the image |
| LB010 | medium | blanket `apt-get upgrade` in a layer |
| LB011 | low | dependency install without a BuildKit cache mount |
| LB012 | low | `cd` in `RUN` instead of `WORKDIR` |
| LB013 | high | `curl \| sh` — piping a download into a shell |
| LB014 | medium | build toolchain in a single-stage image |
| LB015 | medium | broad `COPY` with no `.dockerignore` |

## Development

```sh
make build   # build the binary
make test    # go test -race ./...
make lint    # golangci-lint run
```

## License

MIT
