// Package cmd wires the layerblame CLI.
package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/AndrewKarpaty/layerblame/internal/report"
)

var (
	flagDockerfile string
	flagOutput     string
	flagOutputFile string
	flagNoColor    bool
	flagFailOn     string
)

var rootCmd = &cobra.Command{
	Use:   "layerblame",
	Short: "git blame for container vulnerabilities — map every CVE to the Dockerfile line that introduced it",
	Long: `layerblame pulls an image's config and layer metadata straight from the
registry (no Docker daemon), runs Grype or Trivy, walks the OCI history to
match layers to Dockerfile instructions, and ranks instructions by how many
findings a single change would remove. It also statically analyzes the
Dockerfile for build-speed, image-size and security improvements.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	// Running without a subcommand analyzes the image.
	RunE: func(cmd *cobra.Command, args []string) error {
		return analyzeCmd.RunE(cmd, args)
	},
	Args: cobra.MaximumNArgs(1),
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	if err := rootCmd.Execute(); err != nil {
		if code, ok := failCode(err); ok {
			return code
		}
		rootCmd.PrintErrln("Error:", err)
		return 1
	}
	return 0
}

// failError carries the exit code for --fail-on threshold violations, so CI
// pipelines can gate on findings.
type failError struct{ code int }

func (e failError) Error() string { return "findings at or above the --fail-on threshold" }

func failCode(err error) (int, bool) {
	if fe, ok := errors.AsType[failError](err); ok {
		return fe.code, true
	}
	return 0, false
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.StringVarP(&flagDockerfile, "dockerfile", "f", "Dockerfile", "path to the Dockerfile the image was built from")
	pf.StringVarP(&flagOutput, "output", "o", "terminal", "output format: terminal, json, sarif, markdown")
	pf.StringVar(&flagOutputFile, "output-file", "", "write the report to a file instead of stdout")
	pf.StringVar(&flagFailOn, "fail-on", "none", "exit non-zero if findings reach this severity: none, low, medium, high, critical")
	pf.BoolVar(&flagNoColor, "no-color", false, "disable colored output")
}

// writeReport renders r in the selected output format, optionally to a file.
func writeReport(cmd *cobra.Command, r *report.Report, verbose bool) error {
	out := cmd.OutOrStdout()
	var closer io.Closer
	if flagOutputFile != "" {
		f, err := os.Create(flagOutputFile)
		if err != nil {
			return err
		}
		out, closer = f, f
	}

	var err error
	switch flagOutput {
	case "terminal", "":
		noColor := flagNoColor || os.Getenv("NO_COLOR") != "" || flagOutputFile != ""
		report.WriteTerminal(out, r, report.TerminalOptions{NoColor: noColor, Verbose: verbose})
	case "json":
		err = report.WriteJSON(out, r)
	case "sarif":
		err = report.WriteSARIF(out, r)
	case "markdown", "md":
		err = report.WriteMarkdown(out, r)
	default:
		return fmt.Errorf("unknown output format %q (use terminal, json, sarif or markdown)", flagOutput)
	}
	if closer != nil {
		if cerr := closer.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	if err != nil {
		return err
	}
	if flagOutputFile != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "Report written to %s\n", flagOutputFile)
	}
	return nil
}

// checkFailThreshold turns findings at/above --fail-on into a CI-gating exit
// code (2).
func checkFailThreshold(r *report.Report) error {
	if flagFailOn == "" || flagFailOn == "none" {
		return nil
	}
	threshold := report.ParseSeverity(flagFailOn)
	if threshold == report.SeverityUnknown {
		return fmt.Errorf("unknown --fail-on value %q (use none, low, medium, high or critical)", flagFailOn)
	}
	if r.MaxSeverity() >= threshold {
		return failError{code: 2}
	}
	return nil
}

func dockerfileDir() string {
	return filepath.Dir(flagDockerfile)
}
