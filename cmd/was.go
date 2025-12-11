package cmd

import (
	// Standard
	"errors"
	"fmt"
	"strings"
	"time"

	// Internal
	wasfindings "github.com/Method-Security/methodtenable/internal/was/findings"
	// External
	cobra "github.com/spf13/cobra"
	//Generated
	methodtenablefern "github.com/Method-Security/methodtenable/generated/go"
	wasfern "github.com/Method-Security/methodtenable/generated/go/was/findings"
)

// InitWASCommand initializes the WAS command and vulnerability export subcommand.
func (a *MethodTenable) InitWASCommand() {
	wasCmd := &cobra.Command{
		Use:   "was",
		Short: "Tenable Web Application Scanning operations",
		Long:  `Tenable Web Application Scanning operations.`,
	}

	// Findings Command
	findingsCmd := &cobra.Command{
		Use:   "findings",
		Short: "Findings management operations",
		Long:  `Findings management operations for Tenable Web Application Scanning.`,
	}

	// Findings Export Command
	findingsExportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export findings from Tenable Web Application Scanning",
		Long: `Export findings from Tenable Web Application Scanning using the WAS
Export API v1. Supports filtering by severity, and time-based fields. 
Data is returned in chunks and written locally as JSON.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Get the context
			ctx := cmd.Context()

			// Set the secret config
			secretConfig, err := a.GetTenableSecretConfig()
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			accessKey, err := cmd.Flags().GetString("access-key")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if accessKey != "" {
				secretConfig.AccessKey = &accessKey
			}
			secretKey, err := cmd.Flags().GetString("secret-key")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if secretKey != "" {
				secretConfig.SecretKey = &secretKey
			}
			if secretConfig.AccessKey == nil || secretConfig.SecretKey == nil {
				a.OutputSignal.AddError(errors.New("access key or secret key not configured"))
				return
			}

			// Parameter Flags
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			maxWaitTime, err := cmd.Flags().GetInt("max-wait-time")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			sleepTime, err := cmd.Flags().GetInt("sleep-time")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			numAssets, err := cmd.Flags().GetInt("num-assets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			sinceStr, err := cmd.Flags().GetString("since")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			var since time.Time
			if sinceStr != "" {
				since, err = time.Parse(time.RFC3339, sinceStr)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid since format: %v", err))
					return
				}
			}

			firstFoundStr, err := cmd.Flags().GetString("first-found")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			var firstFound time.Time
			if firstFoundStr != "" {
				firstFound, err = time.Parse(time.RFC3339, firstFoundStr)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid first-found format: %v", err))
					return
				}
			}

			lastFixedStr, err := cmd.Flags().GetString("last-fixed")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			var lastFixed time.Time
			if lastFixedStr != "" {
				lastFixed, err = time.Parse(time.RFC3339, lastFixedStr)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid last-fixed format: %v", err))
					return
				}
			}

			lastFoundStr, err := cmd.Flags().GetString("last-found")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			var lastFound time.Time
			if lastFoundStr != "" {
				lastFound, err = time.Parse(time.RFC3339, lastFoundStr)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid last-found format: %v", err))
					return
				}
			}
			severity, err := cmd.Flags().GetStringArray("severity")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			severityEnum := []methodtenablefern.Severity{}
			for _, severityStr := range severity {
				severityType, err := methodtenablefern.NewSeverityFromString(strings.ToUpper(severityStr))
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				severityEnum = append(severityEnum, severityType)
			}
			hideRawOutput, err := cmd.Flags().GetBool("hide-raw-output")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set config
			config := getWasFindingsExportConfig(timeout, maxWaitTime, sleepTime, numAssets, since, firstFound, lastFixed, lastFound, severityEnum, hideRawOutput)

			// Generate Report
			report := wasfindings.ExportFindings(ctx, *secretConfig, config)

			a.OutputSignal.Content = report
		},
	}

	// Add flags for findings export
	findingsExportCmd.Flags().Int("timeout", 30, "Timeout for API requests in seconds")
	findingsExportCmd.Flags().Int("max-wait-time", 0, "Maximum time to wait for export completion (seconds)")
	findingsExportCmd.Flags().Int("sleep-time", 5, "Time to sleep between status checks (seconds)")
	findingsExportCmd.Flags().Int("num-assets", 50, "Number of assets used to chunk the findings (50-5000)")
	findingsExportCmd.Flags().String("since", "", "Server-side filter: start date for data range (e.g., 2025-11-25T16:05:22Z)")
	findingsExportCmd.Flags().String("first-found", "", "Server-side filter: findings first found at or after this time (e.g., 2025-11-25T16:05:22Z)")
	findingsExportCmd.Flags().String("last-fixed", "", "Server-side filter: findings fixed at or after this time (e.g., 2025-11-25T16:05:22Z)")
	findingsExportCmd.Flags().String("last-found", "", "Server-side filter: findings last found at or after this time (e.g., 2025-11-25T16:05:22Z)")
	findingsExportCmd.Flags().StringArray("severity", []string{}, "Server-side filter: severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
	findingsExportCmd.Flags().Bool("hide-raw-output", false, "Do not include raw output in the report")

	// Add the findings export command to the findings command
	findingsCmd.AddCommand(findingsExportCmd)

	// Add the findings command to the hierarchy
	wasCmd.AddCommand(findingsCmd)

	// Add the was command to the root command
	a.RootCmd.AddCommand(wasCmd)
}

// getWasFindingsExportConfig creates a WAS findings export configuration
func getWasFindingsExportConfig(timeout, maxWaitTime, sleepTime, numAssets int, since, firstFound, lastFixed, lastFound time.Time, severity []methodtenablefern.Severity, hideRawOutput bool) wasfern.WasFindingsExportConfig {
	config := wasfern.WasFindingsExportConfig{
		IncludeUnlicensed: false,
		MaxWaitTime:       maxWaitTime,
		SleepTime:         sleepTime,
		Timeout:           timeout,
		Severity:          severity,
		HideRawOutput:     hideRawOutput,
	}

	// Set numAssets if provided
	if numAssets > 0 {
		config.NumAssets = &numAssets
	}

	// Only set datetime fields if they're not zero values
	if !since.IsZero() {
		config.Since = &since
	}
	if !firstFound.IsZero() {
		config.FirstFound = &firstFound
	}
	if !lastFixed.IsZero() {
		config.LastFixed = &lastFixed
	}
	if !lastFound.IsZero() {
		config.LastFound = &lastFound
	}

	// Set severity if provided
	if len(severity) > 0 {
		config.Severity = severity
	}

	return config
}
