package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/AndrewKarpaty/layerblame/internal/attribute"
	"github.com/AndrewKarpaty/layerblame/internal/dockerfile"
	"github.com/AndrewKarpaty/layerblame/internal/lint"
	"github.com/AndrewKarpaty/layerblame/internal/registry"
	"github.com/AndrewKarpaty/layerblame/internal/scanner"
)

var (
	flagScanner  string
	flagScanFile string
	flagPlatform string
	flagTar      string
	flagVerbose  bool
	flagNoLint   bool
	flagTimeout  time.Duration
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze IMAGE",
	Short: "Scan an image and attribute every finding to a Dockerfile instruction",
	Long: `Analyze pulls the image's config and layer metadata from the registry (or a
docker-save tarball via --tar), obtains vulnerability findings from Grype or
Trivy (or a pre-generated report via --scan-file), and maps each finding back
to the Dockerfile instruction — and physical line — that introduced it.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var image string
		if len(args) > 0 {
			image = args[0]
		}
		if image == "" && flagTar == "" {
			return fmt.Errorf("an image reference (or --tar) is required")
		}

		df, err := dockerfile.Parse(flagDockerfile)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(cmd.Context(), flagTimeout)
		defer cancel()

		var img *registry.Image
		if flagTar != "" {
			img, err = registry.FetchTarball(flagTar)
		} else {
			img, err = registry.Fetch(ctx, image, flagPlatform)
		}
		if err != nil {
			return err
		}

		scan, err := obtainScan(ctx, cmd, image)
		if err != nil {
			return err
		}

		rep := attribute.Run(img, df, scan)
		if !flagNoLint {
			rep.Lint = lint.Lint(df, lint.Options{DockerfileDir: dockerfileDir()})
		}
		rep.Finalize()

		if err := writeReport(cmd, rep, flagVerbose); err != nil {
			return err
		}
		return checkFailThreshold(rep)
	},
}

func obtainScan(ctx context.Context, cmd *cobra.Command, image string) (*scanner.Result, error) {
	if flagScanFile != "" {
		return scanner.ParseFile(flagScanFile)
	}
	name := flagScanner
	if name == "" || name == "auto" {
		detected, err := scanner.Detect()
		if err != nil {
			return nil, err
		}
		name = detected
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Scanning with %s (this may take a while on first run)...\n", name)
	return scanner.Run(ctx, name, image, flagTar, flagPlatform)
}

func init() {
	for _, c := range []*cobra.Command{analyzeCmd, rootCmd} {
		f := c.Flags()
		f.StringVar(&flagScanner, "scanner", "auto", "vulnerability scanner to run: auto, grype, trivy")
		f.StringVar(&flagScanFile, "scan-file", "", "use an existing grype/trivy JSON report instead of running a scanner")
		f.StringVar(&flagPlatform, "platform", "", "image platform, e.g. linux/amd64 (defaults to the registry's choice)")
		f.StringVar(&flagTar, "tar", "", "analyze a docker-save tarball instead of pulling from a registry")
		f.BoolVarP(&flagVerbose, "verbose", "v", false, "list individual CVEs under each instruction")
		f.BoolVar(&flagNoLint, "no-lint", false, "skip Dockerfile static analysis")
		f.DurationVar(&flagTimeout, "timeout", 10*time.Minute, "overall timeout for registry pulls and scanning")
	}
	rootCmd.AddCommand(analyzeCmd)
}
