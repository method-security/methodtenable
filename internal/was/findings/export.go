package findings

import (
	"context"
	"fmt"
	"time"

	// Generated
	methodtenablefern "github.com/Method-Security/methodtenable/generated/go"
	apiwasfern "github.com/Method-Security/methodtenable/generated/go/utils/api/was/findings"
	wasfern "github.com/Method-Security/methodtenable/generated/go/was/findings"
	utils "github.com/Method-Security/methodtenable/utils/api/was/findings"

	// External
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// WasFindingsExport handles the export of WAS findings data from Tenable
func WasFindingsExport(
	ctx context.Context,
	config wasfern.WasFindingsExportConfig,
	secretConfig methodtenablefern.SecretConfig,
) (*wasfern.WasFindingsExportReport, error) {
	// Initialize the logger
	logger := svc1log.FromContext(ctx)

	// Log the start of the export
	logger.Info("Starting WAS findings export", svc1log.SafeParam("config", config))

	// Start timer
	start := time.Now()
	defer func() {
		logger.Info("WAS findings export completed", svc1log.SafeParam("duration", time.Since(start)))
	}()

	// Initialize the result
	result := &wasfern.WasFindingsExportReport{
		Config: &config,
		Errors: []string{},
	}

	// Call the API to search for vulnerabilities
	apiResult, apiErrors := utils.APIWasFindingsExport(ctx, &secretConfig, &config)
	if len(apiErrors) > 0 {
		for _, apiError := range apiErrors {
			logger.Error("WAS findings export error", svc1log.SafeParam("error", apiError))
			result.Errors = append(result.Errors, apiError)
		}
	}
	if apiResult == nil {
		return result, fmt.Errorf("WAS findings export failed")
	}

	// Return the raw API result directly since it contains rich finding data
	// The API layer handles the export/status/chunks workflow and returns the complete findings
	logger.Info("WAS findings export completed successfully",
		svc1log.SafeParam("has_api_result", apiResult != nil),
		svc1log.SafeParam("has_findings", apiResult.Findings != nil),
		svc1log.SafeParam("findings_count", func() int {
			if apiResult.Findings != nil && apiResult.Findings.Items != nil {
				return len(apiResult.Findings.Items)
			}
			return 0
		}()))

	// Transform the complex API response to simplified findings format
	internalFindings, err := transformToSimplifiedFindings(ctx, apiResult)
	if err != nil {
		logger.Error("Failed to transform findings", svc1log.SafeParam("error", err))
		result.Errors = append(result.Errors, err.Error())
		return result, fmt.Errorf("WAS findings transformation failed")
	}

	// Create the finding details
	findingDetails := &wasfern.WasFindingDetails{
		ExportUuid: *apiResult.Findings.ExportUuid,
		Findings:   &wasfern.WasFindingList{Findings: internalFindings},
	}

	// Add raw data to the report if not hidden by the user
	if !config.GetHideRawOutput() {
		findingDetails.Raw = apiResult.Findings.Items // Complete rich data
	}

	// Return both structured and conditionally raw data
	result.Result = &wasfern.WasFindingsExportResult{
		Result: findingDetails,
	}

	return result, nil
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

				// Create the asset sub-structure
				var asset *wasfern.WasAsset
				if apiFinding.Asset != nil && (apiFinding.Asset.Fqdn != nil || apiFinding.Asset.Ipv4 != nil) {
					asset = &wasfern.WasAsset{
						Url:  *apiFinding.Url,
						Fqdn: apiFinding.Asset.Fqdn,
						Ipv4: apiFinding.Asset.Ipv4,
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
