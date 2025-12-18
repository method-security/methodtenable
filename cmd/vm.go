package cmd

import (
	// Standard
	"errors"
	"fmt"
	"strings"
	"time"

	// Internal
	assets "github.com/Method-Security/methodtenable/internal/vm/asset"
	vulnerabilities "github.com/Method-Security/methodtenable/internal/vm/vulnerability"

	// External
	cobra "github.com/spf13/cobra"
	//Generated
	methodtenablefern "github.com/Method-Security/methodtenable/generated/go"
	assetfern "github.com/Method-Security/methodtenable/generated/go/vm/asset"
	vulnfern "github.com/Method-Security/methodtenable/generated/go/vm/vulnerability"
)

// InitVMCommand initializes the vm command and asset export subcommand.
func (a *MethodTenable) InitVMCommand() {
	vmCmd := &cobra.Command{
		Use:   "vm",
		Short: "Tenable Vulnerability Management operations",
		Long:  `Tenable Vulnerability Management operations.`,
	}

	// Asset Command
	assetCmd := &cobra.Command{
		Use:   "asset",
		Short: "Asset management operations",
		Long:  `Asset management operations for Tenable Vulnerability Management.`,
	}

	// Asset Export Command
	assetExportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export assets from Tenable Vulnerability Management",
		Long: `Export assets from Tenable Vulnerability Management using the Asset
Export API v2. Supports filtering by time-based fields such as created_at,
updated_at, last_seen, deleted_at, and terminated_at. Also supports filtering
by tags, sources, IPv4 addresses, hostnames, and operating systems. Data is
returned in chunks and written locally as JSON.`,
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
			chunkSize, err := cmd.Flags().GetInt("chunk-size")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			createdAtStr, err := cmd.Flags().GetString("created-at")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if createdAtStr != "" {
				_, err = time.Parse(time.RFC3339, createdAtStr)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid created-at format: %v", err))
					return
				}
			}

			updatedAtStr, err := cmd.Flags().GetString("updated-at")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if updatedAtStr != "" {
				_, err = time.Parse(time.RFC3339, updatedAtStr)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid updated-at format: %v", err))
					return
				}
			}

			lastAssessedStr, err := cmd.Flags().GetString("last-assessed")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if lastAssessedStr != "" {
				_, err = time.Parse(time.RFC3339, lastAssessedStr)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid last-assessed format: %v", err))
					return
				}
			}

			deletedAtStr, err := cmd.Flags().GetString("deleted-at")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if deletedAtStr != "" {
				_, err = time.Parse(time.RFC3339, deletedAtStr)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid deleted-at format: %v", err))
					return
				}
			}
			terminatedAtStr, err := cmd.Flags().GetString("terminated-at")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if terminatedAtStr != "" {
				_, err = time.Parse(time.RFC3339, terminatedAtStr)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid terminated-at format: %v", err))
					return
				}
			}
			betweenUpdatedAtStr, err := cmd.Flags().GetString("between-updated-at")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if betweenUpdatedAtStr != "" {
				// Parse the date range format: 2025-11-25T16:05:22Z-2025-11-25T16:05:22Z
				// Split by finding the last occurrence of '-' that separates the two dates
				// We need to be careful because RFC3339 dates contain '-' characters
				lastDashIdx := -1
				// RFC3339 format is like 2025-11-25T16:05:22Z (20 chars minimum)
				// So we look for a dash that has a valid RFC3339 date before and after it
				for i := 20; i < len(betweenUpdatedAtStr)-20; i++ {
					if betweenUpdatedAtStr[i] == '-' {
						// Check if this could be the separator
						beforePart := betweenUpdatedAtStr[:i]
						afterPart := betweenUpdatedAtStr[i+1:]
						_, err1 := time.Parse(time.RFC3339, beforePart)
						_, err2 := time.Parse(time.RFC3339, afterPart)
						if err1 == nil && err2 == nil {
							lastDashIdx = i
							break
						}
					}
				}

				if lastDashIdx == -1 {
					a.OutputSignal.AddError(fmt.Errorf("invalid between-updated-at format: expected RFC3339-RFC3339 (e.g., 2025-11-25T16:05:22Z-2025-12-01T16:05:22Z)"))
					return
				}

				startDate := betweenUpdatedAtStr[:lastDashIdx]
				endDate := betweenUpdatedAtStr[lastDashIdx+1:]

				// Validate both dates
				_, err := time.Parse(time.RFC3339, startDate)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid start date in between-updated-at: %v", err))
					return
				}
				_, err = time.Parse(time.RFC3339, endDate)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid end date in between-updated-at: %v", err))
					return
				}
			}
			tags, err := cmd.Flags().GetStringSlice("tags")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			sources, err := cmd.Flags().GetStringSlice("sources")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			types, err := cmd.Flags().GetStringSlice("types")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			typesEnum := []assetfern.AssetType{}
			for _, typeStr := range types {
				assetType, err := assetfern.NewAssetTypeFromString(strings.ToUpper(typeStr))
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				typesEnum = append(typesEnum, assetType)
			}

			ipv4s, err := cmd.Flags().GetStringSlice("ipv4s")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			hostnames, err := cmd.Flags().GetStringSlice("hostnames")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			operatingSystems, err := cmd.Flags().GetStringSlice("operating-systems")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			publicIPAddressesOnly, err := cmd.Flags().GetBool("public-ip-addresses-only")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			hasAgent, err := cmd.Flags().GetBool("has-agent")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if hasAgent {
				sources = []string{"NESSUS_AGENT"}
			}
			servicenowSysid, err := cmd.Flags().GetBool("servicenow-sysid")
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
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			hideRawOutput, err := cmd.Flags().GetBool("hide-raw-output")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set configs
			sourcesEnum := []assetfern.SourceType{}
			for _, sourceStr := range sources {
				sourceType, err := assetfern.NewSourceTypeFromString(strings.ToUpper(sourceStr))
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				sourcesEnum = append(sourcesEnum, sourceType)
			}

			config := getAssetExportConfig(chunkSize, createdAtStr, updatedAtStr, lastAssessedStr, deletedAtStr, terminatedAtStr, betweenUpdatedAtStr, tags, sourcesEnum, typesEnum, ipv4s, hostnames, operatingSystems, publicIPAddressesOnly, hasAgent, servicenowSysid, maxWaitTime, timeout, sleepTime, hideRawOutput)

			// Generate Report
			report := assets.ExportAssets(ctx, *secretConfig, *config)
			a.OutputSignal.Content = report
		},
	}

	// Add all the flags for asset export command
	assetExportCmd.Flags().Int("chunk-size", 1000, "Number of assets processed per chunk (recommended max 5000)")
	assetExportCmd.Flags().String("created-at", "", "ISO datetime: only assets created at or after this time (e.g., 2025-11-25T16:05:22Z)")
	assetExportCmd.Flags().String("updated-at", "", "ISO datetime: only assets updated at or after this time (e.g., 2025-11-25T16:05:22Z)")
	assetExportCmd.Flags().String("last-assessed", "", "ISO datetime: only assets last_assessed (last seen) at or after this time (e.g., 2025-11-25T16:05:22Z)")
	assetExportCmd.Flags().String("deleted-at", "", "ISO datetime: only assets deleted at or after this time (e.g., 2025-11-25T16:05:22Z)")
	assetExportCmd.Flags().String("terminated-at", "", "ISO datetime: only assets terminated at or after this time (e.g., 2025-11-25T16:05:22Z)")
	assetExportCmd.Flags().String("between-updated-at", "", "Client-side filter: date range for updated_at in RFC3339-RFC3339 format (e.g., 2025-11-25T16:05:22Z-2025-12-01T16:05:22Z)") // Client Side filter
	assetExportCmd.Flags().StringSlice("tags", []string{}, "Filter by asset tag in format Category:Value (repeatable, comma-separated supported)")                                       // Client Side filter
	assetExportCmd.Flags().StringSlice("sources", []string{}, "Filter by asset source (e.g., NESSUS_SCAN, AWS, WAS) (comma-separated supported)")
	assetExportCmd.Flags().StringSlice("types", []string{"HOST", "WEBAPP"}, "Filter by asset type (e.g., HOST, WEBAPP) (repeatable, comma-separated supported)")
	assetExportCmd.Flags().StringSlice("ipv4s", []string{}, "Filter by IPv4 address or CIDR (repeatable, comma-separated supported)")                                            // Client Side filter
	assetExportCmd.Flags().StringSlice("hostnames", []string{}, "Filter by hostname (repeatable, comma-separated supported)")                                                    // Client Side filter
	assetExportCmd.Flags().StringSlice("operating-systems", []string{}, "Filter by operating system value (repeatable, comma-separated supported)")                              // Client Side filter
	assetExportCmd.Flags().Bool("public-ip-addresses-only", false, "Client-side filter: Include only assets with public IP addresses (excludes RFC 3330 special-use addresses)") // Client Side filter
	assetExportCmd.Flags().Bool("has-agent", false, "Include only assets scanned by a Nessus Agent. This overrides the sources filter and sets it to NESSUS_AGENT.")
	assetExportCmd.Flags().Bool("servicenow-sysid", false, "Include assets with a ServiceNow sysid")
	assetExportCmd.Flags().Int("max-wait-time", 0, "Maximum wait time for export to complete in seconds")
	assetExportCmd.Flags().Int("timeout", 30, "Timeout for Tenable API requests in seconds")
	assetExportCmd.Flags().Int("sleep-time", 5, "Sleep time between Tenable API calls in seconds")
	assetExportCmd.Flags().Bool("hide-raw-output", false, "Do not include raw output in the report")

	// Add export command to asset command
	assetCmd.AddCommand(assetExportCmd)

	// Vulnerability Command
	vulnCmd := &cobra.Command{
		Use:   "vulnerability",
		Short: "Vulnerability management operations",
		Long:  `Vulnerability management operations for Tenable Vulnerability Management.`,
	}

	// Vulnerability Export Command
	vulnExportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export vulnerabilities from Tenable Vulnerability Management",
		Long: `Export vulnerabilities from Tenable Vulnerability Management using the Vulnerability
Export API. Supports filtering by state, severity, tags, and time-based fields such
as last_found, last_fixed, and first_found. Data is returned in chunks and written
locally as JSON.`,
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
			numAssets, err := cmd.Flags().GetInt("num-assets")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			chunkSize, err := cmd.Flags().GetInt("chunk-size")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			sinceStr, err := cmd.Flags().GetString("since")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if sinceStr != "" {
				_, err = time.Parse(time.RFC3339, sinceStr)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid since format: %v", err))
					return
				}
			}

			lastFoundStr, err := cmd.Flags().GetString("last-found")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if lastFoundStr != "" {
				_, err = time.Parse(time.RFC3339, lastFoundStr)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid last-found format: %v", err))
					return
				}
			}

			lastFixedStr, err := cmd.Flags().GetString("last-fixed")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if lastFixedStr != "" {
				_, err = time.Parse(time.RFC3339, lastFixedStr)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid last-fixed format: %v", err))
					return
				}
			}

			firstFoundStr, err := cmd.Flags().GetString("first-found")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if firstFoundStr != "" {
				_, err = time.Parse(time.RFC3339, firstFoundStr)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid first-found format: %v", err))
					return
				}
			}

			indexedAtStr, err := cmd.Flags().GetString("indexed-at")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if indexedAtStr != "" {
				_, err = time.Parse(time.RFC3339, indexedAtStr)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid indexed-at format: %v", err))
					return
				}
			}
			betweenSinceStr, err := cmd.Flags().GetString("between-since")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			if betweenSinceStr != "" {
				// Parse the date range format: 2025-11-25T16:05:22Z-2025-11-25T16:05:22Z
				lastDashIdx := -1
				for i := 20; i < len(betweenSinceStr)-20; i++ {
					if betweenSinceStr[i] == '-' {
						beforePart := betweenSinceStr[:i]
						afterPart := betweenSinceStr[i+1:]
						_, err1 := time.Parse(time.RFC3339, beforePart)
						_, err2 := time.Parse(time.RFC3339, afterPart)
						if err1 == nil && err2 == nil {
							lastDashIdx = i
							break
						}
					}
				}

				if lastDashIdx == -1 {
					a.OutputSignal.AddError(fmt.Errorf("invalid between-since format: expected RFC3339-RFC3339 (e.g., 2025-11-25T16:05:22Z-2025-12-01T16:05:22Z)"))
					return
				}

				startDate := betweenSinceStr[:lastDashIdx]
				endDate := betweenSinceStr[lastDashIdx+1:]

				_, err = time.Parse(time.RFC3339, startDate)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid start date in between-since: %v", err))
					return
				}
				_, err = time.Parse(time.RFC3339, endDate)
				if err != nil {
					a.OutputSignal.AddError(fmt.Errorf("invalid end date in between-since: %v", err))
					return
				}
			}
			state, err := cmd.Flags().GetStringSlice("state")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			stateEnum := []methodtenablefern.State{}
			for _, stateStr := range state {
				stateType, err := methodtenablefern.NewStateFromString(strings.ToUpper(stateStr))
				if err != nil {
					a.OutputSignal.AddError(err)
					return
				}
				stateEnum = append(stateEnum, stateType)
			}
			severity, err := cmd.Flags().GetStringSlice("severity")
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
			includeUnlicensed, err := cmd.Flags().GetBool("include-unlicensed")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			tags, err := cmd.Flags().GetStringSlice("tag")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			maxWaitTime, err := cmd.Flags().GetInt("max-wait-time")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			timeout, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			sleepTime, err := cmd.Flags().GetInt("sleep-time")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			hideRawOutput, err := cmd.Flags().GetBool("hide-raw-output")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Set configs
			config := getVulnerabilityExportConfig(numAssets, chunkSize, sinceStr, lastFoundStr, lastFixedStr, firstFoundStr, indexedAtStr, betweenSinceStr, stateEnum, severityEnum, includeUnlicensed, tags, maxWaitTime, timeout, sleepTime, hideRawOutput)

			// Generate Report
			report := vulnerabilities.ExportVulnerabilities(ctx, *secretConfig, *config)
			a.OutputSignal.Content = report
		},
	}

	vulnExportCmd.Flags().Int("num-assets", 500, "Specifies the number of assets used to chunk the vulnerabilities. The vulnerabilities export is split up by number of asset IDs in a chunk. (recommended max 5000, min of 50)")
	vulnExportCmd.Flags().Int("chunk-size", 1000, "Number of vulnerabilities processed per chunk (recommended max 5000)")
	vulnExportCmd.Flags().String("since", "", "Server-side filter: include vulns last_found or last_fixed at or after this time (e.g., 2025-11-25T16:05:22Z)")
	vulnExportCmd.Flags().String("last-found", "", "Server-side filter: only vulnerabilities with last_found at or after this time (e.g., 2025-11-25T16:05:22Z)")
	vulnExportCmd.Flags().String("last-fixed", "", "Server-side filter: only vulnerabilities with last_fixed at or after this time (e.g., 2025-11-25T16:05:22Z)")
	vulnExportCmd.Flags().String("first-found", "", "Server-side filter: only vulnerabilities first_found at or after this time (e.g., 2025-11-25T16:05:22Z)")
	vulnExportCmd.Flags().String("indexed-at", "", "Server-side filter: only vulnerabilities indexed at or after this time (e.g., 2025-11-25T16:05:22Z)")
	vulnExportCmd.Flags().String("between-since", "", "Client-side filter: date range for since in RFC3339-RFC3339 format (e.g., 2025-11-25T16:05:22Z-2025-12-01T16:05:22Z)") // Client Side filter
	vulnExportCmd.Flags().StringSlice("state", []string{}, "Server-side filter: Vulnerability state filter (OPEN, REOPENED, FIXED) (comma-separated supported)")
	vulnExportCmd.Flags().StringSlice("severity", []string{}, "Server-side filter: Severity filter (INFO, LOW, MEDIUM, HIGH, CRITICAL) (comma-separated supported)")
	vulnExportCmd.Flags().Bool("include-unlicensed", false, "Server-side filter: Include vulnerabilities on unlicensed assets")
	vulnExportCmd.Flags().StringSlice("tag", []string{}, "Server-side filter: Filter by asset tag in format Category:Value (repeatable, comma-separated supported)")
	vulnExportCmd.Flags().Int("max-wait-time", 0, "Maximum wait time for export to complete in seconds")
	vulnExportCmd.Flags().Int("timeout", 30, "Timeout for Tenable API requests in seconds")
	vulnExportCmd.Flags().Int("sleep-time", 5, "Sleep time between Tenable API calls in seconds")
	vulnExportCmd.Flags().Bool("hide-raw-output", false, "Do not include raw output in the report")

	// Add export command to vulnerability command
	vulnCmd.AddCommand(vulnExportCmd)

	// Add asset command to VM command
	vmCmd.AddCommand(assetCmd)

	// Add vulnerability command to VM command
	vmCmd.AddCommand(vulnCmd)

	// Add VM Command to 'Root' Command
	a.RootCmd.AddCommand(vmCmd)
}

// getAssetExportConfig returns a new VmAssetExportConfig struct with the given parameters
func getAssetExportConfig(chunkSize int, createdAt string, updatedAt string, lastAssessed string, deletedAt string, terminatedAt string, betweenUpdatedAt string, tags []string, sources []assetfern.SourceType, types []assetfern.AssetType, ipv4s []string, hostnames []string, operatingSystems []string, publicIPAddressesOnly bool, hasAgent bool, servicenowSysid bool, maxWaitTime int, timeout int, sleepTime int, hideRawOutput bool) *assetfern.VmAssetExportConfig {
	config := &assetfern.VmAssetExportConfig{
		ChunkSize:             chunkSize,
		Tags:                  tags,
		Sources:               sources,
		Types:                 types,
		Ipv4S:                 ipv4s,
		Hostnames:             hostnames,
		OperatingSystems:      operatingSystems,
		PublicIpAddressesOnly: publicIPAddressesOnly,
		HasAgent:              hasAgent,
		ServicenowSysid:       servicenowSysid,
		MaxWaitTime:           maxWaitTime,
		Timeout:               timeout,
		SleepTime:             sleepTime,
		HideRawOutput:         hideRawOutput,
	}

	// Only set datetime fields if they're not zero values
	if createdAt != "" {
		config.CreatedAt = &createdAt
	}
	if updatedAt != "" {
		config.UpdatedAt = &updatedAt
	}
	if lastAssessed != "" {
		config.LastAssessed = &lastAssessed
	}
	if deletedAt != "" {
		config.DeletedAt = &deletedAt
	}
	if terminatedAt != "" {
		config.TerminatedAt = &terminatedAt
	}
	if betweenUpdatedAt != "" {
		config.BetweenUpdatedAt = &betweenUpdatedAt
	}
	return config
}

// getVulnerabilityExportConfig returns a new VmVulnerabilityExportConfig struct with the given parameters
func getVulnerabilityExportConfig(numAssets int, chunkSize int, since string, lastFound string, lastFixed string, firstFound string, indexedAt string, betweenSince string, state []methodtenablefern.State, severity []methodtenablefern.Severity, includeUnlicensed bool, tags []string, maxWaitTime int, timeout int, sleepTime int, hideRawOutput bool) *vulnfern.VmVulnerabilityExportConfig {
	config := &vulnfern.VmVulnerabilityExportConfig{
		NumAssets:         max(numAssets, 50),
		ChunkSize:         chunkSize,
		State:             state,
		Severity:          severity,
		IncludeUnlicensed: includeUnlicensed,
		Tags:              tags,
		MaxWaitTime:       maxWaitTime,
		Timeout:           timeout,
		SleepTime:         sleepTime,
		HideRawOutput:     hideRawOutput,
	}

	// Only set datetime fields if they're not zero values
	if since != "" {
		config.Since = &since
	}
	if lastFound != "" {
		config.LastFound = &lastFound
	}
	if lastFixed != "" {
		config.LastFixed = &lastFixed
	}
	if firstFound != "" {
		config.FirstFound = &firstFound
	}
	if indexedAt != "" {
		config.IndexedAt = &indexedAt
	}
	if betweenSince != "" {
		config.BetweenSince = &betweenSince
	}

	return config
}
