package attribute

import (
	"strings"
)

// HistoryInstruction is a Dockerfile instruction recovered from an OCI
// history entry's created_by string.
type HistoryInstruction struct {
	// Cmd is the uppercase instruction name, or "" when unrecognizable.
	Cmd string
	// Text is the instruction's argument text (shell command for RUN).
	Text string
	// BuildKit is true when the entry carries the "# buildkit" marker.
	BuildKit bool
}

// ParseCreatedBy recovers the originating instruction from a created_by
// string. It understands both the classic builder format
// ("/bin/sh -c #(nop)  ENV FOO=bar", "/bin/sh -c apt-get update", with an
// optional "|N k=v" build-arg prefix) and the BuildKit format
// ("RUN /bin/sh -c apt-get update # buildkit", "COPY . /app # buildkit").
func ParseCreatedBy(s string) HistoryInstruction {
	h := HistoryInstruction{}
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutSuffix(s, "# buildkit"); ok {
		h.BuildKit = true
		s = strings.TrimSpace(rest)
	}

	// Classic builder build-arg prefix: "|2 a=b c=d /bin/sh -c cmd".
	if strings.HasPrefix(s, "|") {
		if i := strings.Index(s, "/bin/sh -c "); i >= 0 {
			s = s[i:]
		}
	}

	switch {
	case strings.HasPrefix(s, "/bin/sh -c #(nop)"):
		// Metadata or file instruction recorded by the classic builder.
		rest := strings.TrimSpace(strings.TrimPrefix(s, "/bin/sh -c #(nop)"))
		h.Cmd, h.Text = splitInstruction(rest)
	case strings.HasPrefix(s, "/bin/sh -c "):
		h.Cmd = "RUN"
		h.Text = strings.TrimSpace(strings.TrimPrefix(s, "/bin/sh -c "))
	case strings.HasPrefix(s, "cmd /S /C "):
		h.Cmd = "RUN"
		h.Text = strings.TrimSpace(strings.TrimPrefix(s, "cmd /S /C "))
	default:
		// BuildKit format: the created_by starts with the instruction name.
		cmd, text := splitInstruction(s)
		if isInstruction(cmd) {
			h.Cmd = cmd
			// BuildKit records shell-form RUN as "RUN /bin/sh -c <cmd>".
			if h.Cmd == "RUN" {
				text = strings.TrimSpace(strings.TrimPrefix(text, "/bin/sh -c "))
			}
			h.Text = text
		}
	}
	return h
}

func splitInstruction(s string) (cmd, text string) {
	s = strings.TrimSpace(s)
	name, rest, _ := strings.Cut(s, " ")
	name = strings.ToUpper(name)
	if !isInstruction(name) {
		return "", s
	}
	return name, strings.TrimSpace(rest)
}

var instructionNames = map[string]bool{
	"FROM": true, "RUN": true, "CMD": true, "LABEL": true, "MAINTAINER": true,
	"EXPOSE": true, "ENV": true, "ADD": true, "COPY": true, "ENTRYPOINT": true,
	"VOLUME": true, "USER": true, "WORKDIR": true, "ARG": true, "ONBUILD": true,
	"STOPSIGNAL": true, "HEALTHCHECK": true, "SHELL": true,
}

func isInstruction(name string) bool {
	return instructionNames[name]
}
