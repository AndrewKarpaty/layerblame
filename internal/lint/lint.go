// Package lint statically analyzes a Dockerfile and reports build-speed,
// image-size, and security improvements.
package lint

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AndrewKarpaty/layerblame/internal/dockerfile"
	"github.com/AndrewKarpaty/layerblame/internal/report"
)

// Options configures the lint run.
type Options struct {
	// DockerfileDir is used to look for a .dockerignore next to the
	// Dockerfile; empty disables the check.
	DockerfileDir string
}

type rule func(*dockerfile.File, Options) []report.LintFinding

var rules = []rule{
	unpinnedBase,
	broadCopyBeforeInstall,
	pkgCacheNotCleaned,
	noInstallRecommends,
	addInsteadOfCopy,
	rootUser,
	consecutiveRuns,
	secretInEnv,
	pkgUpgrade,
	cacheMountHint,
	cdInsteadOfWorkdir,
	curlPipeSh,
	singleStageBuildTools,
	missingDockerignore,
}

// Lint runs every rule against the parsed Dockerfile.
func Lint(df *dockerfile.File, opts Options) []report.LintFinding {
	var out []report.LintFinding
	for _, r := range rules {
		out = append(out, r(df, opts)...)
	}
	return out
}

func finding(rule string, sev report.Severity, in *dockerfile.Instruction, msg, suggestion string) report.LintFinding {
	return report.LintFinding{
		Rule:       rule,
		Severity:   sev,
		StartLine:  in.StartLine,
		EndLine:    in.EndLine,
		Message:    msg,
		Suggestion: suggestion,
	}
}

// LB001: base image not pinned.
func unpinnedBase(df *dockerfile.File, _ Options) []report.LintFinding {
	var out []report.LintFinding
	for i := range df.Stages {
		st := &df.Stages[i]
		base := st.BaseName
		if base == "" || strings.EqualFold(base, "scratch") || df.StageByRef(base) != nil {
			continue
		}
		if strings.Contains(base, "@sha256:") {
			continue
		}
		_, tag, hasTag := strings.Cut(base, ":")
		if !hasTag || tag == "latest" {
			out = append(out, finding("LB001", report.SeverityHigh, st.From,
				fmt.Sprintf("base image %q is not pinned to a tag", base),
				"pin a specific tag (better: a digest) so builds are reproducible and base-image CVE fixes are deliberate"))
		}
	}
	return out
}

var installRe = regexp.MustCompile(`\b(apt-get install|apt install|apk add|yum install|dnf install|pip install|pip3 install|npm (ci|install)|yarn install|pnpm install|go mod download|bundle install|composer install|cargo build|poetry install|uv sync)\b`)

// LB002: broad COPY busts the dependency-install cache.
func broadCopyBeforeInstall(df *dockerfile.File, _ Options) []report.LintFinding {
	var out []report.LintFinding
	for i := range df.Stages {
		var broadCopy *dockerfile.Instruction
		for _, in := range df.Stages[i].Instructions {
			switch {
			case in.Cmd == "COPY" || in.Cmd == "ADD":
				if _, fromStage := in.FromFlag("from"); !fromStage && isBroadCopy(in.Args) {
					broadCopy = in
				}
			case in.Cmd == "RUN" && broadCopy != nil && installRe.MatchString(in.Args):
				out = append(out, finding("LB002", report.SeverityMedium, broadCopy,
					"broad COPY before dependency install invalidates the install cache on every source change",
					"COPY only dependency manifests (package.json, go.mod, requirements.txt, ...) first, install, then COPY the rest"))
				broadCopy = nil
			}
		}
	}
	return out
}

func isBroadCopy(args string) bool {
	fields := strings.Fields(args)
	if len(fields) < 2 {
		return false
	}
	for _, src := range fields[:len(fields)-1] {
		if src == "." || src == "./" || src == "*" || strings.HasPrefix(src, "--") && false {
			return true
		}
	}
	return false
}

// LB003: package manager caches left in the layer.
func pkgCacheNotCleaned(df *dockerfile.File, _ Options) []report.LintFinding {
	var out []report.LintFinding
	for _, in := range df.Instructions {
		if in.Cmd != "RUN" {
			continue
		}
		cmdText := in.Args
		switch {
		case strings.Contains(cmdText, "apt-get install") || strings.Contains(cmdText, "apt install"):
			if !strings.Contains(cmdText, "/var/lib/apt/lists") && !hasCacheMount(in) {
				out = append(out, finding("LB003", report.SeverityMedium, in,
					"apt cache is left in the layer, inflating image size",
					"append '&& rm -rf /var/lib/apt/lists/*' in the same RUN, or use RUN --mount=type=cache,target=/var/cache/apt"))
			}
		case strings.Contains(cmdText, "apk add"):
			if !strings.Contains(cmdText, "--no-cache") && !strings.Contains(cmdText, "/var/cache/apk") {
				out = append(out, finding("LB003", report.SeverityMedium, in,
					"apk cache is left in the layer, inflating image size",
					"use 'apk add --no-cache'"))
			}
		case strings.Contains(cmdText, "yum install") || strings.Contains(cmdText, "dnf install"):
			if !strings.Contains(cmdText, "clean all") {
				out = append(out, finding("LB003", report.SeverityMedium, in,
					"yum/dnf cache is left in the layer, inflating image size",
					"append '&& yum clean all' (or 'dnf clean all') in the same RUN"))
			}
		}
	}
	return out
}

// LB004: apt installs pull recommended packages.
func noInstallRecommends(df *dockerfile.File, _ Options) []report.LintFinding {
	var out []report.LintFinding
	for _, in := range df.Instructions {
		if in.Cmd != "RUN" {
			continue
		}
		if (strings.Contains(in.Args, "apt-get install") || strings.Contains(in.Args, "apt install")) &&
			!strings.Contains(in.Args, "--no-install-recommends") {
			out = append(out, finding("LB004", report.SeverityLow, in,
				"apt install without --no-install-recommends pulls extra packages (more size, more CVEs)",
				"add --no-install-recommends to the install command"))
		}
	}
	return out
}

// LB005: ADD where COPY suffices.
func addInsteadOfCopy(df *dockerfile.File, _ Options) []report.LintFinding {
	var out []report.LintFinding
	for _, in := range df.Instructions {
		if in.Cmd != "ADD" {
			continue
		}
		fields := strings.Fields(in.Args)
		if len(fields) < 2 {
			continue
		}
		src := fields[0]
		if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") || strings.HasPrefix(src, "git@") {
			continue
		}
		if isArchive(src) {
			continue
		}
		out = append(out, finding("LB005", report.SeverityLow, in,
			"ADD used for a plain local file",
			"use COPY — ADD's implicit URL fetch and archive extraction make behavior harder to predict"))
	}
	return out
}

func isArchive(s string) bool {
	for _, ext := range []string{".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".txz"} {
		if strings.HasSuffix(s, ext) {
			return true
		}
	}
	return false
}

// LB006: final stage runs as root.
func rootUser(df *dockerfile.File, _ Options) []report.LintFinding {
	final := df.FinalStage()
	// Bases like distroless :nonroot variants already set an unprivileged
	// user.
	if strings.Contains(final.BaseName, "nonroot") {
		return nil
	}
	lastUser := ""
	for _, in := range final.Instructions {
		if in.Cmd == "USER" {
			lastUser = strings.TrimSpace(in.Args)
		}
	}
	if lastUser == "" || lastUser == "root" || lastUser == "0" {
		return []report.LintFinding{finding("LB006", report.SeverityHigh, final.From,
			"final stage runs as root",
			"create an unprivileged user and add 'USER <name>' as the last USER instruction")}
	}
	return nil
}

// LB008: consecutive RUN instructions create avoidable layers.
func consecutiveRuns(df *dockerfile.File, _ Options) []report.LintFinding {
	var out []report.LintFinding
	for i := range df.Stages {
		instrs := df.Stages[i].Instructions
		runStart := -1
		count := 0
		flush := func() {
			if count >= 3 {
				out = append(out, finding("LB008", report.SeverityLow, instrs[runStart],
					fmt.Sprintf("%d consecutive RUN instructions create %d layers", count, count),
					"chain related commands with '&&' into one RUN to shrink the image and speed up pulls"))
			}
			runStart, count = -1, 0
		}
		for j, in := range instrs {
			if in.Cmd == "RUN" && !hasCacheMount(in) {
				if runStart == -1 {
					runStart = j
				}
				count++
			} else {
				flush()
			}
		}
		flush()
	}
	return out
}

var secretNameRe = regexp.MustCompile(`(?i)(secret|passwd|password|token|api_?key|private_?key|credential)`)

// LB009: secrets baked into the image config.
func secretInEnv(df *dockerfile.File, _ Options) []report.LintFinding {
	var out []report.LintFinding
	for _, in := range df.Instructions {
		if in.Cmd != "ENV" && in.Cmd != "ARG" {
			continue
		}
		// The parser yields either "KEY=val" tokens or alternating
		// KEY val tokens; handle both.
		fields := strings.Fields(in.Args)
		for i := 0; i < len(fields); i++ {
			key, val, has := strings.Cut(fields[i], "=")
			if !has && i+1 < len(fields) {
				val = fields[i+1]
				i++
			}
			if val != "" && secretNameRe.MatchString(key) {
				out = append(out, finding("LB009", report.SeverityCritical, in,
					fmt.Sprintf("%s %q looks like a secret baked into the image", in.Cmd, key),
					"pass secrets at runtime, or use 'RUN --mount=type=secret' during build — ENV/ARG values persist in image history"))
				break
			}
		}
	}
	return out
}

// LB010: blanket upgrades bloat layers and defeat pinning.
func pkgUpgrade(df *dockerfile.File, _ Options) []report.LintFinding {
	var out []report.LintFinding
	re := regexp.MustCompile(`\b(apt-get (dist-)?upgrade|apt upgrade|apk upgrade|yum update|dnf upgrade)\b`)
	for _, in := range df.Instructions {
		if in.Cmd == "RUN" && re.MatchString(in.Args) {
			out = append(out, finding("LB010", report.SeverityMedium, in,
				"blanket package upgrade in a RUN layer",
				"update the base image instead — upgrades in layers duplicate base files and make builds non-reproducible"))
		}
	}
	return out
}

var langInstallRe = regexp.MustCompile(`\b(pip3? install|npm (ci|install)|yarn install|pnpm install|go (mod download|build)|cargo (build|fetch)|bundle install|composer install|poetry install|uv sync)\b`)

// LB011: BuildKit cache mounts dramatically speed up dependency installs.
func cacheMountHint(df *dockerfile.File, _ Options) []report.LintFinding {
	var out []report.LintFinding
	for _, in := range df.Instructions {
		if in.Cmd == "RUN" && langInstallRe.MatchString(in.Args) && !hasCacheMount(in) {
			out = append(out, finding("LB011", report.SeverityLow, in,
				"dependency install without a BuildKit cache mount re-downloads packages on every build",
				"use RUN --mount=type=cache,target=<package cache dir> to persist the package cache across builds"))
		}
	}
	return out
}

func hasCacheMount(in *dockerfile.Instruction) bool {
	for _, f := range in.Flags {
		if strings.HasPrefix(f, "--mount=") && strings.Contains(f, "type=cache") {
			return true
		}
	}
	return false
}

// LB012: cd in RUN instead of WORKDIR.
func cdInsteadOfWorkdir(df *dockerfile.File, _ Options) []report.LintFinding {
	var out []report.LintFinding
	for _, in := range df.Instructions {
		if in.Cmd != "RUN" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(in.Args), "cd ") {
			out = append(out, finding("LB012", report.SeverityLow, in,
				"RUN starts with 'cd'",
				"use WORKDIR — it persists across instructions and documents intent"))
		}
	}
	return out
}

// LB013: piping a downloaded script straight into a shell.
func curlPipeSh(df *dockerfile.File, _ Options) []report.LintFinding {
	var out []report.LintFinding
	re := regexp.MustCompile(`\b(curl|wget)\b[^|;&]*\|\s*(ba)?sh\b`)
	for _, in := range df.Instructions {
		if in.Cmd == "RUN" && re.MatchString(in.Args) {
			out = append(out, finding("LB013", report.SeverityHigh, in,
				"downloaded script piped directly into a shell",
				"download to a file, verify a checksum or signature, then execute"))
		}
	}
	return out
}

var buildToolRe = regexp.MustCompile(`\b(go build|npm run build|yarn build|mvn (package|install)|gradle (build|assemble)|cargo build --release|make\b|gcc\b|g\+\+\b|dotnet publish)`)

// LB014: build toolchain in a single-stage image.
func singleStageBuildTools(df *dockerfile.File, _ Options) []report.LintFinding {
	if len(df.Stages) > 1 {
		return nil
	}
	for _, in := range df.Instructions {
		if in.Cmd == "RUN" && buildToolRe.MatchString(in.Args) {
			return []report.LintFinding{finding("LB014", report.SeverityMedium, in,
				"build toolchain runs in a single-stage image, shipping compilers and build deps to production",
				"use a multi-stage build: compile in a builder stage, COPY --from the artifact into a minimal runtime image")}
		}
	}
	return nil
}

// LB015: broad COPY without a .dockerignore.
func missingDockerignore(df *dockerfile.File, opts Options) []report.LintFinding {
	if opts.DockerfileDir == "" {
		return nil
	}
	var broad *dockerfile.Instruction
	for _, in := range df.Instructions {
		if (in.Cmd == "COPY" || in.Cmd == "ADD") && isBroadCopy(in.Args) {
			broad = in
			break
		}
	}
	if broad == nil {
		return nil
	}
	if _, err := os.Stat(filepath.Join(opts.DockerfileDir, ".dockerignore")); err == nil {
		return nil
	}
	return []report.LintFinding{finding("LB015", report.SeverityMedium, broad,
		"broad COPY without a .dockerignore sends the whole build context (including .git, secrets, node_modules) to the builder",
		"add a .dockerignore excluding .git, build artifacts, and local configuration")}
}
