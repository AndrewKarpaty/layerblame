// Package dockerfile parses a Dockerfile into an instruction list that keeps
// physical line numbers and stage structure, so findings can be mapped back to
// source lines.
package dockerfile

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/parser"
)

// Instruction is one Dockerfile instruction with its source location.
type Instruction struct {
	// Cmd is the uppercase instruction name (FROM, RUN, COPY, ...).
	Cmd string
	// Args is the instruction's arguments joined with single spaces. For
	// exec-form instructions the JSON array elements are joined.
	Args string
	// Flags holds instruction flags such as --from=builder or --mount=....
	Flags []string
	// Original is the instruction as written, with continuations collapsed.
	Original  string
	StartLine int
	EndLine   int
	// StageIndex is the zero-based index of the stage the instruction
	// belongs to; -1 for instructions before the first FROM (e.g. ARG).
	StageIndex int
}

// FromFlag returns the value of a --name= flag, if present.
func (i *Instruction) FromFlag(name string) (string, bool) {
	prefix := "--" + name + "="
	for _, f := range i.Flags {
		if strings.HasPrefix(f, prefix) {
			return strings.TrimPrefix(f, prefix), true
		}
		if f == "--"+name {
			return "", true
		}
	}
	return "", false
}

// Stage is one build stage introduced by a FROM instruction.
type Stage struct {
	Index int
	// Name is the AS alias, empty if unnamed.
	Name string
	// BaseName is the FROM argument: an image reference or a previous
	// stage's name/index.
	BaseName string
	From     *Instruction
	// Instructions are the stage's instructions, excluding the FROM itself.
	Instructions []*Instruction
}

// File is a parsed Dockerfile.
type File struct {
	Path   string
	Stages []Stage
	// Instructions lists every instruction in order, including FROMs and
	// pre-stage ARGs.
	Instructions []*Instruction
}

// Parse reads and parses the Dockerfile at path.
func Parse(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	df, err := ParseReader(f)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	df.Path = path
	return df, nil
}

// ParseReader parses Dockerfile content from r.
func ParseReader(r io.Reader) (*File, error) {
	res, err := parser.Parse(r)
	if err != nil {
		return nil, err
	}
	df := &File{}
	stageIndex := -1
	for _, node := range res.AST.Children {
		inst := &Instruction{
			Cmd:       strings.ToUpper(node.Value),
			Flags:     node.Flags,
			Original:  node.Original,
			StartLine: node.StartLine,
			EndLine:   node.EndLine,
		}
		var args []string
		for n := node.Next; n != nil; n = n.Next {
			args = append(args, n.Value)
		}
		inst.Args = strings.Join(args, " ")

		if inst.Cmd == "FROM" {
			stageIndex++
			st := Stage{Index: stageIndex, From: inst}
			st.BaseName = firstArg(args)
			if len(args) >= 3 && strings.EqualFold(args[1], "AS") {
				st.Name = args[2]
			}
			df.Stages = append(df.Stages, st)
		}
		inst.StageIndex = stageIndex
		df.Instructions = append(df.Instructions, inst)
		if inst.Cmd != "FROM" && stageIndex >= 0 {
			st := &df.Stages[stageIndex]
			st.Instructions = append(st.Instructions, inst)
		}
	}
	if len(df.Stages) == 0 {
		return nil, fmt.Errorf("no FROM instruction found")
	}
	return df, nil
}

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

// FinalStage returns the last stage — the one that produces the image.
func (f *File) FinalStage() *Stage {
	return &f.Stages[len(f.Stages)-1]
}

// StageByRef resolves a stage referenced by name or numeric index, as used by
// FROM <ref> and COPY --from=<ref>. Returns nil when ref is an external image.
func (f *File) StageByRef(ref string) *Stage {
	for i := range f.Stages {
		if f.Stages[i].Name != "" && strings.EqualFold(f.Stages[i].Name, ref) {
			return &f.Stages[i]
		}
	}
	var idx int
	if _, err := fmt.Sscanf(ref, "%d", &idx); err == nil && idx >= 0 && idx < len(f.Stages) {
		return &f.Stages[idx]
	}
	return nil
}

// BuildChain returns the stages that contribute layers to the final image via
// the FROM chain, ordered base-most first, ending with the final stage. The
// returned root base name is the external image the chain starts from.
func (f *File) BuildChain() (stages []*Stage, rootBase string) {
	seen := map[int]bool{}
	st := f.FinalStage()
	for st != nil && !seen[st.Index] {
		seen[st.Index] = true
		stages = append([]*Stage{st}, stages...)
		parent := f.StageByRef(st.BaseName)
		if parent == nil {
			rootBase = st.BaseName
			break
		}
		st = parent
	}
	return stages, rootBase
}

// ChainInstructions returns every instruction of the final image's stage
// chain in build order (base-most stage first), excluding FROMs.
func (f *File) ChainInstructions() []*Instruction {
	stages, _ := f.BuildChain()
	var out []*Instruction
	for _, st := range stages {
		out = append(out, st.Instructions...)
	}
	return out
}
