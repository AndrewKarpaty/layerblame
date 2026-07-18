package cmd

import (
	"github.com/spf13/cobra"

	"github.com/AndrewKarpaty/layerblame/internal/dockerfile"
	"github.com/AndrewKarpaty/layerblame/internal/lint"
	"github.com/AndrewKarpaty/layerblame/internal/report"
)

var lintCmd = &cobra.Command{
	Use:   "lint",
	Short: "Statically analyze the Dockerfile (no image or scanner needed)",
	Long: `Lint parses the Dockerfile and reports build-speed, image-size and security
improvements: cache-busting COPY ordering, package caches left in layers,
missing multi-stage builds, root users, secrets in ENV, and more. Works fully
offline.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		df, err := dockerfile.Parse(flagDockerfile)
		if err != nil {
			return err
		}
		rep := &report.Report{Dockerfile: flagDockerfile}
		rep.Lint = lint.Lint(df, lint.Options{DockerfileDir: dockerfileDir()})
		rep.Finalize()

		if err := writeReport(cmd, rep, false); err != nil {
			return err
		}
		return checkFailThreshold(rep)
	},
}

func init() {
	rootCmd.AddCommand(lintCmd)
}
