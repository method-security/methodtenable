// Package cmd implements the CobraCLI commands for the methodtenable CLI. Subcommands for the CLI should all live within
// this package. Logic should be delegated to internal packages and functions to keep the CLI commands clean and
// focused on CLI I/O.
package cmd

import (
	// Standard
	"errors"
	"os"
	"strings"
	"time"

	// Generated
	methodtenablefern "github.com/Method-Security/methodtenable/generated/go"
	"github.com/Method-Security/methodtenable/internal/config"

	// External
	"github.com/Method-Security/pkg/signal"
	"github.com/Method-Security/pkg/writer"
	"github.com/palantir/pkg/datetime"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

// MethodTenable is the main struct for the CLI. It contains the version, output configuration, output signal, and root flags
// for the CLI. It also contains all commands and subcommands for the CLI. The output signal is used to write the output
// of the command to the desired output format after the execution of the invoked command's Run function.
type MethodTenable struct {
	Version      string
	OutputConfig writer.OutputConfig
	OutputSignal signal.Signal
	RootFlags    config.RootFlags
	RootCmd      *cobra.Command
	VersionCmd   *cobra.Command
	SecretConfig methodtenablefern.SecretConfig
}

// NewMethodTenable creates a new MethodTenable struct with the given version. It initializes the root command and all subcommands
// for the CLI. We pass the version command in here from the main.go file, where we set the version string during the
// build process.
func NewMethodTenable(version string) *MethodTenable {
	// Initialize the started at time
	startedAt := datetime.DateTime(time.Now())

	// Initialize the MethodTenable struct
	methodTenable := MethodTenable{
		Version: version,
		RootFlags: config.RootFlags{
			Quiet:   false,
			Verbose: false,
		},
		OutputConfig: writer.NewOutputConfig(nil, writer.NewFormat(writer.SIGNAL)),
		OutputSignal: signal.NewSignal(nil, &startedAt, nil, 0, nil),
	}
	return &methodTenable
}

// InitRootCommand initializes the root command for the methodtenable CLI. This function initializes the root command with a
// PersistentPreRunE function that is responsible for setting the output configuration properly, as well as a
// PersistentPostRunE function that is responsible for writing the output signal to the desired output format.
func (a *MethodTenable) InitRootCommand() {
	var outputFormat string
	var outputFile string
	a.RootCmd = &cobra.Command{
		Use:   "methodtenable",
		Short: "Perform security testing and vulnerability assessment on target(s)",
		Long:  `Perform security testing and vulnerability assessment on target(s)`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			format, err := validateOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			var outputFilePointer *string
			if outputFile != "" {
				outputFilePointer = &outputFile
			} else {
				outputFilePointer = nil
			}
			a.OutputConfig = writer.NewOutputConfig(outputFilePointer, format)
			cmd.SetContext(svc1log.WithLogger(cmd.Context(), config.InitializeLogging(cmd, &a.RootFlags)))

			// Set the API keys from the environment variables
			assetKey := os.Getenv("TENABLE_ACCESS_KEY")
			assetSecret := os.Getenv("TENABLE_SECRET_KEY")
			a.SecretConfig = methodtenablefern.SecretConfig{}
			if assetKey != "" {
				a.SecretConfig.AccessKey = &assetKey
			}
			if assetSecret != "" {
				a.SecretConfig.SecretKey = &assetSecret
			}

			return nil
		},
		PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
			completedAt := datetime.DateTime(time.Now())
			a.OutputSignal.CompletedAt = &completedAt
			return writer.Write(
				a.OutputSignal.Content,
				a.OutputConfig,
				&a.OutputSignal.StartedAt,
				a.OutputSignal.CompletedAt,
				a.OutputSignal.Status,
				a.OutputSignal.ErrorMessage,
			)
		},
	}

	a.RootCmd.PersistentFlags().BoolVarP(&a.RootFlags.Quiet, "quiet", "q", false, "Suppress output")
	a.RootCmd.PersistentFlags().BoolVarP(&a.RootFlags.Verbose, "verbose", "v", false, "Verbose output")
	a.RootCmd.PersistentFlags().StringVarP(&outputFile, "output-file", "f", "", "Path to output file. If blank, will output to STDOUT")
	a.RootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "signal", "Output format (signal, json, yaml). Default value is signal")
	// All commands inherit these flags
	a.RootCmd.PersistentFlags().String("access-key", "", "Tenable API Access Key (overrides env TENABLE_ACCESS_KEY)")
	a.RootCmd.PersistentFlags().String("secret-key", "", "Tenable API Secret Key (overrides env TENABLE_SECRET_KEY)")

	a.VersionCmd = &cobra.Command{
		Use:   "version",
		Short: "Prints the version number of methodtenable",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(a.Version)
		},
		PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
	}
	a.RootCmd.AddCommand(a.VersionCmd)
}

func validateOutputFormat(output string) (writer.Format, error) {
	var format writer.FormatValue
	switch strings.ToLower(output) {
	case "json":
		format = writer.JSON
	case "yaml":
		format = writer.YAML
	case "signal":
		format = writer.SIGNAL
	default:
		return writer.Format{}, errors.New("invalid output format. Valid formats are: json, yaml, signal")
	}
	return writer.NewFormat(format), nil
}
