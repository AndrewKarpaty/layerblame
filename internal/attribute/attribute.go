// Package attribute maps image layers to Dockerfile instructions by walking
// the OCI history array, then aggregates scanner findings per instruction.
package attribute

import (
	"path/filepath"

	"github.com/AndrewKarpaty/layerblame/internal/dockerfile"
	"github.com/AndrewKarpaty/layerblame/internal/registry"
	"github.com/AndrewKarpaty/layerblame/internal/report"
	"github.com/AndrewKarpaty/layerblame/internal/scanner"
)

// Alignment is the result of matching image history against a Dockerfile.
type Alignment struct {
	// ByHistoryIndex maps a history entry index to the Dockerfile
	// instruction that produced it. Entries attributed to the base image or
	// left unmatched are absent.
	ByHistoryIndex map[int]*dockerfile.Instruction
	// BaseEntries is the number of leading history entries inherited from
	// the base image.
	BaseEntries int
}

// instructions that may not produce a history entry, depending on builder.
var mayEmitNoHistory = map[string]bool{
	"ARG":     true,
	"ONBUILD": true,
}

// Align matches history entries (oldest first) to the Dockerfile's final
// build chain, walking both sequences backwards from the newest entry. Every
// history entry before the matched region is attributed to the base image.
func Align(history []registry.HistoryEntry, df *dockerfile.File) Alignment {
	expected := df.ChainInstructions()
	a := Alignment{ByHistoryIndex: map[int]*dockerfile.Instruction{}}

	hi := len(history) - 1
	di := len(expected) - 1
	for hi >= 0 && di >= 0 {
		h := ParseCreatedBy(history[hi].CreatedBy)
		d := expected[di]
		if h.Cmd == d.Cmd {
			a.ByHistoryIndex[history[hi].Index] = d
			hi--
			di--
			continue
		}
		// The builder may not have recorded this instruction (e.g. ARG
		// under BuildKit): skip the Dockerfile side and retry.
		if mayEmitNoHistory[d.Cmd] {
			di--
			continue
		}
		// Classic builders fold HEALTHCHECK/MAINTAINER oddly; if the
		// history entry is unrecognizable, skip it rather than desync.
		if h.Cmd == "" {
			hi--
			continue
		}
		// Sequences diverged: stop matching, everything older belongs to
		// the base image (or stays unmatched).
		break
	}
	a.BaseEntries = hi + 1
	return a
}

// Run builds the full report: align layers to instructions, attribute scan
// findings, and rank instructions by remediation impact.
func Run(img *registry.Image, df *dockerfile.File, scan *scanner.Result) *report.Report {
	align := Align(img.History, df)

	rep := &report.Report{
		Dockerfile:  displayPath(df.Path),
		Image:       img.Ref,
		ImageDigest: img.Digest,
	}
	if scan != nil {
		rep.Scanner = scan.Scanner
	}

	// One report.Instruction per Dockerfile instruction that owns layers,
	// plus one for the root FROM (base image layers).
	byInstr := map[*dockerfile.Instruction]*report.Instruction{}
	stages, _ := df.BuildChain()
	rootFrom := stages[0].From

	instrFor := func(d *dockerfile.Instruction, base bool) *report.Instruction {
		if ri, ok := byInstr[d]; ok {
			return ri
		}
		ri := &report.Instruction{
			StartLine: d.StartLine,
			EndLine:   d.EndLine,
			Cmd:       d.Cmd,
			Source:    d.Original,
			BaseImage: base,
			Counts:    map[string]int{},
		}
		if d.StageIndex >= 0 && d.StageIndex < len(df.Stages) {
			ri.Stage = df.Stages[d.StageIndex].Name
		}
		byInstr[d] = ri
		return ri
	}

	// diffID → owning report.Instruction.
	byDiffID := map[string]*report.Instruction{}
	byDigest := map[string]*report.Instruction{}
	for _, h := range img.History {
		var owner *report.Instruction
		if d, ok := align.ByHistoryIndex[h.Index]; ok {
			owner = instrFor(d, false)
		} else if h.Index < align.BaseEntries {
			owner = instrFor(rootFrom, true)
		}
		if owner == nil || h.DiffID == "" {
			continue
		}
		owner.Layers = append(owner.Layers, h.DiffID)
		owner.LayerSize += h.Size
		byDiffID[h.DiffID] = owner
		if h.Digest != "" {
			byDigest[h.Digest] = owner
		}
	}

	unattributed := &report.Instruction{Cmd: "?", Source: "(unattributed)", Counts: map[string]int{}}
	if scan != nil {
		for _, f := range scan.Findings {
			v := report.Vuln{
				ID:          f.ID,
				Severity:    f.Severity,
				Package:     f.Package,
				Version:     f.Version,
				FixedIn:     f.FixedIn,
				Fixable:     f.Fixable,
				LayerDiffID: f.LayerDiffID,
				URL:         f.URL,
			}
			owner := byDiffID[f.LayerDiffID]
			if owner == nil && f.LayerDigest != "" {
				owner = byDigest[f.LayerDigest]
			}
			if owner == nil {
				unattributed.AddVuln(v)
				continue
			}
			owner.AddVuln(v)
		}
	}

	for _, ri := range byInstr {
		rep.Instructions = append(rep.Instructions, *ri)
	}
	if unattributed.Total > 0 {
		rep.Unattributed = unattributed
	}
	rep.Finalize()
	return rep
}

func displayPath(p string) string {
	if p == "" {
		return "Dockerfile"
	}
	return filepath.ToSlash(p)
}
