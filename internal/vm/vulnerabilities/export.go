package vulnerabilities

import (
	// Standard
	"context"
	// Generated
	methodtenablefern "github.com/Method-Security/methodtenable/generated/go"
	apivulnfern "github.com/Method-Security/methodtenable/generated/go/utils/api/vm/vulnerabilities"
	vulnfern "github.com/Method-Security/methodtenable/generated/go/vm/vulnerabilities"

	// Utils
	utils "github.com/Method-Security/methodtenable/utils/api/vm/vulnerabilities"
	// External
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func ExportVulnerabilities(ctx context.Context, secrets *methodtenablefern.SecretConfig, config *vulnfern.VmVulnerabilityExportConfig) *vulnfern.VmVulnerabilityExportReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting vulnerability export", svc1log.SafeParam("config", config))

	// Initialize the report
	report := &vulnfern.VmVulnerabilityExportReport{
		Result: &vulnfern.VulnerabilityExportResult{},
		Errors: []string{},
		Config: config,
	}

	// Call the utils function to initiate the vulnerability export
	tenableAPIResult, errorStrings := utils.APIVmVulnerabilityExport(ctx, secrets, config)

	// Always return success if we have a valid export UUID, even if status monitoring failed
	if tenableAPIResult != nil && tenableAPIResult.ExportUuid != nil {
		log.Info("Vulnerability export completed successfully", svc1log.SafeParam("export_uuid", tenableAPIResult.ExportUuid))

		// Transform the complex API response to simplified vulnerability format
		vulnerabilities, err := transformToSimplifiedVulnerabilities(ctx, tenableAPIResult)
		if err != nil {
			log.Error("Failed to transform vulnerabilities", svc1log.SafeParam("error", err))
			report.Errors = append(report.Errors, err.Error())
			return report
		}

		// Create the vulnerability details
		vulnerabilityDetails := &vulnfern.VulnerabilityDetails{
			ExportUuid: *tenableAPIResult.ExportUuid,
			Vulnerabilities: &vulnfern.VulnerabilityList{
				Vulnerabilities: vulnerabilities,
			},
		}

		// Add raw data to the report if not hidden by the user
		if !config.GetHideRawOutput() {
			vulnerabilityDetails.Raw = tenableAPIResult
		}

		report.Result.Result = vulnerabilityDetails
		report.Errors = errorStrings
	}

	return report
}

// transformToSimplifiedVulnerabilities transforms the complex Tenable API response to the simplified vulnerability format
func transformToSimplifiedVulnerabilities(ctx context.Context, apiResult *apivulnfern.ApiVmVulnerabilityExportReport) ([]*vulnfern.Vulnerability, error) {
	log := svc1log.FromContext(ctx)

	var vulnerabilities []*vulnfern.Vulnerability

	if apiResult.Chunks != nil {
		for _, chunk := range apiResult.Chunks {
			if chunk.Vulnerabilities != nil {
				for _, apiVuln := range chunk.Vulnerabilities {
					// Transform each complex API vulnerability to nested format
					vuln := &vulnfern.Vulnerability{}

					// Create asset information
					if apiVuln.Asset != nil {
						assetInfo := &vulnfern.VulnerabilityAssetInfo{
							Hostname:        apiVuln.Asset.Hostname,
							Fqdn:            apiVuln.Asset.Fqdn,
							Ipv4:            apiVuln.Asset.Ipv4,
							Ipv6:            apiVuln.Asset.Ipv6,
							OperatingSystem: apiVuln.Asset.OperatingSystem,
							MacAddress:      apiVuln.Asset.MacAddress,
							DeviceType:      apiVuln.Asset.DeviceType,
						}

						// Extract port information
						if apiVuln.Port != nil {
							assetInfo.Port = &vulnfern.VulnerabilityPort{
								Port:     apiVuln.Port.Port,
								Protocol: &apiVuln.Port.Protocol,
								Service:  apiVuln.Port.Service,
							}
						}

						vuln.Asset = assetInfo
					}

					// Get State
					state, err := methodtenablefern.NewStateFromString(apiVuln.State)
					if err != nil {
						log.Error("Failed to parse state", svc1log.SafeParam("state", apiVuln.State), svc1log.SafeParam("error", err))
						return nil, err
					}

					// Create vulnerability information
					vulnerabilityInfo := &vulnfern.VulnerabilityInfo{
						Name:        apiVuln.Plugin.Name,
						Description: *apiVuln.Plugin.Description,
						Severity:    apiVuln.Severity,
						State:       state,
					}

					// Extract CVE information
					if apiVuln.Plugin.Cve != nil {
						vulnerabilityInfo.Cve = apiVuln.Plugin.Cve
					}

					// Extract CVSS3 base score
					if apiVuln.Plugin.Cvss3BaseScore != nil {
						vulnerabilityInfo.Cvss3BaseScore = apiVuln.Plugin.Cvss3BaseScore
					}

					// Extract VPR score from the complex VPR object
					if apiVuln.Plugin.Vpr != nil {
						if vprMap, ok := apiVuln.Plugin.Vpr.(map[string]interface{}); ok {
							if score, ok := vprMap["score"].(float64); ok {
								vulnerabilityInfo.VprScore = &score
							}
						}
					}

					// Extract exploit availability
					if apiVuln.Plugin.ExploitAvailable != nil {
						vulnerabilityInfo.ExploitAvailable = apiVuln.Plugin.ExploitAvailable
					}

					// Extract patch publication date
					if apiVuln.Plugin.PatchPublicationDate != nil {
						vulnerabilityInfo.PatchPublicationDate = apiVuln.Plugin.PatchPublicationDate
					}

					// Extract solution
					if apiVuln.Plugin.Solution != nil {
						vulnerabilityInfo.Solution = apiVuln.Plugin.Solution
					}

					vuln.Vulnerability = vulnerabilityInfo

					vulnerabilities = append(vulnerabilities, vuln)
				}
			}
		}
	}

	return vulnerabilities, nil
}
