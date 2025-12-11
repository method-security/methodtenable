package findings

import (
	// Standard
	"context"
	// Generated
	methodtenablefern "github.com/Method-Security/methodtenable/generated/go"
	apiwasfern "github.com/Method-Security/methodtenable/generated/go/utils/api/was/findings"
	wasfern "github.com/Method-Security/methodtenable/generated/go/was/findings"

	// Utils
	utils "github.com/Method-Security/methodtenable/utils/api/was/findings"
	// External
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func ExportFindings(ctx context.Context, secrets methodtenablefern.SecretConfig, config wasfern.WasFindingsExportConfig) *wasfern.WasFindingsExportReport {
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

		// Transform the complex API response to simplified findings format
		findings, err := transformToSimplifiedFindings(ctx, tenableAPIResult)
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
