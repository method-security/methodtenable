package findings

import (
	// Standard
	"context"
	"regexp"
	"strings"
	"time"

	// Generated
	methodtenablefern "github.com/Method-Security/methodtenable/generated/go"
	apiwasfern "github.com/Method-Security/methodtenable/generated/go/utils/api/was/finding"
	wasfern "github.com/Method-Security/methodtenable/generated/go/was/finding"

	// Utils
	utils "github.com/Method-Security/methodtenable/utils/api/was/finding"
	// External
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func ExportFindings(ctx context.Context, secrets methodtenablefern.SecretConfig, config wasfern.WasFindingsExportConfig) *wasfern.WasFindingsExportReport {
	// Initilize the logger
	log := svc1log.FromContext(ctx)
	log.Info("Starting WAS findings export", svc1log.SafeParam("config", config))

	// Initialize the report
	report := &wasfern.WasFindingsExportReport{
		Result: &wasfern.WasFindingsExportResult{},
		Errors: []string{},
		Config: &config,
	}

	// Call the utils function to initiate the WAS findings export
	tenableAPIResult, errorStrings := utils.APIWasFindingsExport(ctx, &secrets, &config)

	// Always return success if we have a valid export UUID, even if status monitoring failed
	if tenableAPIResult != nil && tenableAPIResult.Findings != nil && tenableAPIResult.Findings.ExportUuid != nil {
		log.Info("WAS findings export completed successfully", svc1log.SafeParam("export_uuid", tenableAPIResult.Findings.ExportUuid))

		// Apply client-side filters if needed
		filteredResult := applyClientSideFilters(ctx, tenableAPIResult, &config)

		// Transform the complex API response to simplified findings format
		findings, err := transformToSimplifiedFindings(ctx, filteredResult)
		if err != nil {
			log.Error("Failed to transform findings", svc1log.SafeParam("error", err))
			report.Errors = append(report.Errors, err.Error())
			return report
		}

		// Create the finding details
		findingDetails := &wasfern.WasFindingDetails{
			ExportUuid: *tenableAPIResult.Findings.ExportUuid,
			Findings: &wasfern.WasFindingList{
				Findings: findings,
			},
		}

		// Add raw data to the report if not hidden by the user
		if !config.GetHideRawOutput() {
			findingDetails.Raw = tenableAPIResult
		}

		report.Result.Result = findingDetails
		report.Errors = errorStrings
	} else {
		// If no export UUID, something went wrong
		log.Error("WAS findings export failed - no export UUID returned")
		report.Errors = append(report.Errors, "no export UUID returned")
	}

	return report
}

// applyClientSideFilters applies filters that are not supported by the Tenable API
func applyClientSideFilters(ctx context.Context, result *apiwasfern.ApiWasFindingsExportReport, config *wasfern.WasFindingsExportConfig) *apiwasfern.ApiWasFindingsExportReport {
	logger := svc1log.FromContext(ctx)
	if result == nil || result.Findings == nil || result.Findings.Items == nil {
		return result
	}

	// Check if we need to apply client-side filters
	if config.GetBetweenSince() == nil || *config.GetBetweenSince() == "" {
		return result
	}

	totalFindingsBefore := len(result.Findings.Items)

	// Filter findings
	filteredItems := filterFindings(result.Findings.Items, config)

	// Create filtered result
	filteredResult := &apiwasfern.ApiWasFindingsExportReport{
		ExportUuid: result.ExportUuid,
		Errors:     result.Errors,
		Findings: &apiwasfern.ApiWasFindingsExportResponse{
			ExportUuid: result.Findings.ExportUuid,
			Status:     result.Findings.Status,
			Items:      filteredItems,
		},
	}

	logger.Info("Applied client-side filters",
		svc1log.SafeParam("findings_before", totalFindingsBefore),
		svc1log.SafeParam("findings_after", len(filteredItems)))

	return filteredResult
}

// filterFindings applies client-side filters to findings
func filterFindings(findings []*apiwasfern.WasFinding, config *wasfern.WasFindingsExportConfig) []*apiwasfern.WasFinding {
	var filtered []*apiwasfern.WasFinding

	for _, finding := range findings {
		if matchesBetweenSinceFilter(finding, config) {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

// matchesBetweenSinceFilter checks if finding's last_found falls within the date range
func matchesBetweenSinceFilter(finding *apiwasfern.WasFinding, config *wasfern.WasFindingsExportConfig) bool {
	betweenSince := config.GetBetweenSince()
	if betweenSince == nil || *betweenSince == "" {
		return true
	}

	// Check if finding has last_found
	if finding.LastFound == nil {
		return false
	}

	// Parse the date range
	lastDashIdx := -1
	for i := 20; i < len(*betweenSince)-20; i++ {
		if (*betweenSince)[i] == '-' {
			beforePart := (*betweenSince)[:i]
			afterPart := (*betweenSince)[i+1:]
			_, err1 := time.Parse(time.RFC3339, beforePart)
			_, err2 := time.Parse(time.RFC3339, afterPart)
			if err1 == nil && err2 == nil {
				lastDashIdx = i
				break
			}
		}
	}

	if lastDashIdx == -1 {
		return false
	}

	startDateStr := (*betweenSince)[:lastDashIdx]
	endDateStr := (*betweenSince)[lastDashIdx+1:]

	startDate, err := time.Parse(time.RFC3339, startDateStr)
	if err != nil {
		return false
	}

	endDate, err := time.Parse(time.RFC3339, endDateStr)
	if err != nil {
		return false
	}

	// Parse finding's last_found timestamp
	findingLastFound, err := time.Parse(time.RFC3339, *finding.LastFound)
	if err != nil {
		return false
	}

	// Check if the finding's last_found falls within the range (inclusive)
	return (findingLastFound.Equal(startDate) || findingLastFound.After(startDate)) &&
		(findingLastFound.Equal(endDate) || findingLastFound.Before(endDate))
}

// transformToSimplifiedFindings transforms the complex Tenable API response to the simplified findings format
func transformToSimplifiedFindings(ctx context.Context, apiResult *apiwasfern.ApiWasFindingsExportReport) ([]*wasfern.WasFindingInfo, error) {
	logger := svc1log.FromContext(ctx)

	var internalFindings []*wasfern.WasFindingInfo

	if apiResult != nil && apiResult.Findings != nil && apiResult.Findings.Items != nil {
		for _, apiFinding := range apiResult.Findings.Items {
			if apiFinding != nil {
				finding := &wasfern.WasFinding{}
				// Try to use plugin name and description if available
				if apiFinding.Plugin != nil {
					if apiFinding.Plugin.Name != nil && *apiFinding.Plugin.Name != "" {
						finding.Name = *apiFinding.Plugin.Name
					}
					if apiFinding.Plugin.Description != nil && *apiFinding.Plugin.Description != "" {
						finding.Description = *apiFinding.Plugin.Description
					}
				}

				// Map additional finding fields
				if apiFinding.Severity != nil {
					severity, err := methodtenablefern.NewSeverityFromString(*apiFinding.Severity)
					if err != nil {
						logger.Error("Failed to parse severity", svc1log.SafeParam("severity", *apiFinding.Severity), svc1log.SafeParam("error", err))
					} else {
						finding.Severity = &severity
					}
				}

				if apiFinding.State != nil {
					state, err := methodtenablefern.NewStateFromString(*apiFinding.State)
					if err != nil {
						logger.Error("Failed to parse state", svc1log.SafeParam("state", *apiFinding.State), svc1log.SafeParam("error", err))
					} else {
						finding.State = &state
					}
				}

				// Map CVE and CPE data from plugin
				if apiFinding.Plugin != nil {
					if len(apiFinding.Plugin.Cve) > 0 {
						finding.Cve = apiFinding.Plugin.Cve
					}
					if len(apiFinding.Plugin.Cpe) > 0 {
						finding.Cpe = apiFinding.Plugin.Cpe
					}
				}

				// Map output field to details
				if apiFinding.Output != nil {
					finding.Details = apiFinding.Output
				}

				// Create the asset sub-structure
				var asset *wasfern.WasAsset
				if apiFinding.Asset != nil && (apiFinding.Asset.Fqdn != nil || apiFinding.Asset.Ipv4 != nil) {
					// Extract HTTP method from output field
					httpMethod := extractHTTPMethod(apiFinding.Output)

					asset = &wasfern.WasAsset{
						Url:        *apiFinding.Url,
						HttpMethod: httpMethod,
						Fqdn:       apiFinding.Asset.Fqdn,
						Ipv4:       apiFinding.Asset.Ipv4,
					}
				}

				// Create the complete finding info with sub-structures
				findingInfo := &wasfern.WasFindingInfo{
					Finding: finding,
					Asset:   asset,
				}

				internalFindings = append(internalFindings, findingInfo)
			}
		}
	}

	logger.Info("Mapped API findings to internal structure",
		svc1log.SafeParam("api_findings_count", func() int {
			if apiResult != nil && apiResult.Findings != nil && apiResult.Findings.Items != nil {
				return len(apiResult.Findings.Items)
			}
			return 0
		}()),
		svc1log.SafeParam("internal_findings_count", len(internalFindings)))

	return internalFindings, nil
}

// extractHTTPMethod extracts HTTP request methods (GET, POST, OPTIONS, etc.) from the output field
func extractHTTPMethod(output *string) *wasfern.WasHttpMethod {
	if output == nil || *output == "" {
		return nil
	}

	// Use generated HTTP method enum values
	httpMethods := []wasfern.WasHttpMethod{
		wasfern.WasHttpMethodGet,
		wasfern.WasHttpMethodPost,
		wasfern.WasHttpMethodPut,
		wasfern.WasHttpMethodDelete,
		wasfern.WasHttpMethodHead,
		wasfern.WasHttpMethodOptions,
		wasfern.WasHttpMethodPatch,
		wasfern.WasHttpMethodConnect,
		wasfern.WasHttpMethodTrace,
	}

	// Create regex pattern to match HTTP methods at word boundaries
	for _, method := range httpMethods {
		methodStr := string(method)
		// Look for the method followed by space and a path (typical HTTP request format)
		pattern := `\b` + methodStr + `\s+/[^\s]*`
		re := regexp.MustCompile(pattern)
		if re.MatchString(*output) {
			return method.Ptr()
		}

		// Also look for method in quotes or standalone
		pattern = `\b` + methodStr + `\b`
		re = regexp.MustCompile(pattern)
		if re.MatchString(strings.ToUpper(*output)) {
			return method.Ptr()
		}
	}

	return nil
}
