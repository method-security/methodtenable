package assets

import (
	// Standard
	"context"
	"net"
	"strings"

	// Generated
	methodtenablefern "github.com/Method-Security/methodtenable/generated/go"
	apiassetfern "github.com/Method-Security/methodtenable/generated/go/utils/api/vm/asset"
	assetfern "github.com/Method-Security/methodtenable/generated/go/vm/asset"

	// Utils
	utils "github.com/Method-Security/methodtenable/utils/api/vm/asset"
	// External
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func ExportAssets(ctx context.Context, secrets methodtenablefern.SecretConfig, config assetfern.VmAssetExportConfig) *assetfern.VmAssetExportReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting asset export", svc1log.SafeParam("config", config))

	// Truncate keys to first 8 characters for logging
	accessKeyPreview := *secrets.AccessKey
	if len(accessKeyPreview) > 8 {
		accessKeyPreview = accessKeyPreview[:8]
	}
	secretKeyPreview := *secrets.SecretKey
	if len(secretKeyPreview) > 8 {
		secretKeyPreview = secretKeyPreview[:8]
	}
	log.Info("Tenable API Key", svc1log.SafeParam("access_key", accessKeyPreview), svc1log.SafeParam("secret_key", secretKeyPreview))

	// Initialize the report
	report := &assetfern.VmAssetExportReport{
		Result: &assetfern.AssetExportResult{},
		Errors: []string{},
		Config: &config,
	}

	// Call the utils function to initiate the export
	tenableAPIResult, errorStrings := utils.APIVmAssetV2Export(ctx, &secrets, &config)

	// Always return success if we have a valid export UUID, even if status monitoring failed
	if tenableAPIResult != nil && tenableAPIResult.ExportUuid != nil {
		log.Info("Asset export completed successfully", svc1log.SafeParam("export_uuid", tenableAPIResult.ExportUuid))

		// Apply client-side filters to get filtered assets for transformation
		filteredResult := applyClientSideFilters(ctx, tenableAPIResult, &config)

		// Transform filtered Tenable assets into our Asset structure, but keep raw as original
		assetDetails := transformTenableAssets(ctx, &config, filteredResult, tenableAPIResult)

		// Marshal Data
		report.Result = &assetfern.AssetExportResult{
			Result: assetDetails,
		}

		// Add raw data to the report if not hidden by the user
		if !config.GetHideRawOutput() {
			report.Result.Result.Raw = tenableAPIResult
		}

		// Add errors to the report
		report.Errors = errorStrings
	} else {
		// If no export UUID, something went wrong
		log.Error("asset export failed - no export UUID returned")
		report.Errors = append(report.Errors, "no export UUID returned")
	}

	return report
}

// applyClientSideFilters applies filters that are not supported by the Tenable API
// Creates a copy of the result to avoid modifying the original data
func applyClientSideFilters(ctx context.Context, result *apiassetfern.ApiVmAsssetExportReport, config *assetfern.VmAssetExportConfig) *apiassetfern.ApiVmAsssetExportReport {
	log := svc1log.FromContext(ctx)
	if result.Chunks == nil {
		return result
	}

	// Create a deep copy to avoid modifying the original result
	filteredResult := &apiassetfern.ApiVmAsssetExportReport{
		ExportUuid: result.ExportUuid,
		Errors:     make([]string, len(result.Errors)),
		Chunks:     make([]*apiassetfern.ApiVmAssetExportChunkResponse, len(result.Chunks)),
	}
	copy(filteredResult.Errors, result.Errors)

	totalAssetsBefore := 0
	for _, chunk := range result.Chunks {
		if chunk.Assets != nil {
			totalAssetsBefore += len(chunk.Assets)
		}
	}

	// Apply filters to each chunk in the copy
	for i, chunk := range result.Chunks {
		filteredResult.Chunks[i] = &apiassetfern.ApiVmAssetExportChunkResponse{}
		if chunk.Assets == nil {
			continue
		}

		filteredAssets := filterAssets(chunk.Assets, config)
		filteredResult.Chunks[i].Assets = filteredAssets
	}

	totalAssetsAfter := 0
	for _, chunk := range filteredResult.Chunks {
		if chunk.Assets != nil {
			totalAssetsAfter += len(chunk.Assets)
		}
	}

	log.Info("Applied client-side filters",
		svc1log.SafeParam("assets_before", totalAssetsBefore),
		svc1log.SafeParam("assets_after", totalAssetsAfter))

	return filteredResult
}

// filterAssets applies all client-side filters to a slice of assets
func filterAssets(assets []*apiassetfern.TenableAsset, config *assetfern.VmAssetExportConfig) []*apiassetfern.TenableAsset {
	var filtered []*apiassetfern.TenableAsset

	for _, asset := range assets {
		if matchesAllFilters(asset, config) {
			filtered = append(filtered, asset)
		}
	}

	return filtered
}

// matchesAllFilters checks if an asset matches all the specified CLIENT-SIDE-ONLY filters
// Note: Most filters are handled at API level. Only these are still client-side:
// tags, ipv4, hostname, operating_system
func matchesAllFilters(asset *apiassetfern.TenableAsset, config *assetfern.VmAssetExportConfig) bool {

	// Tag filter (not supported by API)
	if config.GetTags() != nil && len(config.GetTags()) > 0 {
		if !matchesTagFilter(asset, config.GetTags()) {
			return false
		}
	}

	// IPv4 filter (not supported by API)
	if config.GetIpv4S() != nil && len(config.GetIpv4S()) > 0 {
		if !matchesIPv4Filter(asset, config.GetIpv4S()) {
			return false
		}
	}

	// Hostname filter (not supported by API)
	if config.GetHostnames() != nil && len(config.GetHostnames()) > 0 {
		if !matchesHostnameFilter(asset, config.GetHostnames()) {
			return false
		}
	}

	// Operating System filter (not supported by API)
	if config.GetOperatingSystems() != nil && len(config.GetOperatingSystems()) > 0 {
		if !matchesOperatingSystemFilter(asset, config.GetOperatingSystems()) {
			return false
		}
	}

	return true
}

// matchesTagFilter checks if asset has any of the specified tags
func matchesTagFilter(asset *apiassetfern.TenableAsset, tags []string) bool {
	if asset.Tags == nil {
		return false
	}

	for _, filterTag := range tags {
		for _, assetTag := range asset.Tags {
			// Match against key:value format or just key
			if assetTag.Key != nil && assetTag.Value != nil {
				fullTag := *assetTag.Key + ":" + *assetTag.Value
				if fullTag == filterTag {
					return true
				}
			}
			// Also match just the key
			if assetTag.Key != nil && *assetTag.Key == filterTag {
				return true
			}
		}
	}
	return false
}

// matchesIPv4Filter checks if asset has any of the specified IPv4 addresses or CIDR ranges
func matchesIPv4Filter(asset *apiassetfern.TenableAsset, ipv4Filters []string) bool {
	if asset.Network == nil || asset.Network.Ipv4S == nil {
		return false
	}

	for _, assetIP := range asset.Network.Ipv4S {
		for _, filterIP := range ipv4Filters {
			if matchesIPOrCIDR(assetIP, filterIP) {
				return true
			}
		}
	}
	return false
}

// matchesIPOrCIDR checks if an IP matches an IP or CIDR range
func matchesIPOrCIDR(assetIP, filterIP string) bool {
	// Exact match
	if assetIP == filterIP {
		return true
	}

	// Check if filterIP is a CIDR range
	if strings.Contains(filterIP, "/") {
		_, network, err := net.ParseCIDR(filterIP)
		if err != nil {
			return false
		}
		ip := net.ParseIP(assetIP)
		if ip == nil {
			return false
		}
		return network.Contains(ip)
	}

	return false
}

// matchesHostnameFilter checks if asset has any of the specified hostnames
func matchesHostnameFilter(asset *apiassetfern.TenableAsset, hostnames []string) bool {
	if asset.Network == nil {
		return false
	}

	// Check FQDNs
	if asset.Network.Fqdns != nil {
		for _, assetFQDN := range asset.Network.Fqdns {
			for _, filterHostname := range hostnames {
				if strings.Contains(assetFQDN, filterHostname) {
					return true
				}
			}
		}
	}

	// Check hostnames
	if asset.Network.Hostnames != nil {
		for _, assetHostname := range asset.Network.Hostnames {
			for _, filterHostname := range hostnames {
				if strings.Contains(assetHostname, filterHostname) {
					return true
				}
			}
		}
	}

	return false
}

// matchesOperatingSystemFilter checks if asset has any of the specified operating systems
func matchesOperatingSystemFilter(asset *apiassetfern.TenableAsset, operatingSystems []string) bool {
	if asset.OperatingSystems == nil {
		return false
	}

	for _, assetOS := range asset.OperatingSystems {
		for _, filterOS := range operatingSystems {
			if strings.Contains(strings.ToLower(assetOS), strings.ToLower(filterOS)) {
				return true
			}
		}
	}

	return false
}

// transformTenableAssets transforms the filtered Tenable API response into our Asset structure
// Creates one Asset per IP address for each Tenable asset that has IP addresses
// Uses originalResult for raw data to preserve unfiltered state
func transformTenableAssets(ctx context.Context, config *assetfern.VmAssetExportConfig, filteredResult *apiassetfern.ApiVmAsssetExportReport, originalResult *apiassetfern.ApiVmAsssetExportReport) *assetfern.AssetDetails {
	log := svc1log.FromContext(ctx)
	assetDetails := &assetfern.AssetDetails{
		ExportUuid: *originalResult.ExportUuid,
	}

	// Add raw data to the report if not hidden by the user
	if !config.GetHideRawOutput() {
		assetDetails.Raw = originalResult
	}

	// Transform the filtered Tenable assets into our Asset structure
	var transformedAssets []*assetfern.Asset
	if filteredResult.Chunks != nil {
		for _, chunk := range filteredResult.Chunks {
			if chunk.Assets != nil {
				for _, tenableAsset := range chunk.Assets {
					// Only process assets that have IP addresses
					if tenableAsset.Network != nil && tenableAsset.Network.Ipv4S != nil && len(tenableAsset.Network.Ipv4S) > 0 {
						// Create one Asset for each IP address
						for _, ipAddress := range tenableAsset.Network.Ipv4S {
							asset := &assetfern.Asset{
								Ipaddress: ipAddress,
							}

							// Add FQDNs if available
							if tenableAsset.Network.Fqdns != nil {
								asset.Fqdns = tenableAsset.Network.Fqdns
							}

							// Add operating systems if available
							if tenableAsset.OperatingSystems != nil {
								asset.OperatingSystems = tenableAsset.OperatingSystems
							}

							// Add installed software if available
							if tenableAsset.InstalledSoftware != nil {
								asset.InstalledSoftware = tenableAsset.InstalledSoftware
							}

							transformedAssets = append(transformedAssets, asset)
						}
					}
				}
			}
		}
	}

	assetDetails.Assets = &assetfern.AssetList{
		Assets: transformedAssets,
	}

	log.Info("Transformed Tenable assets",
		svc1log.SafeParam("tenable_assets_filtered", getTotalTenableAssets(filteredResult)),
		svc1log.SafeParam("tenable_assets_original", getTotalTenableAssets(originalResult)),
		svc1log.SafeParam("output_assets_created", len(transformedAssets)))

	return assetDetails
}

// getTotalTenableAssets counts the total number of Tenable assets in the result
func getTotalTenableAssets(result *apiassetfern.ApiVmAsssetExportReport) int {
	total := 0
	if result.Chunks != nil {
		for _, chunk := range result.Chunks {
			if chunk.Assets != nil {
				total += len(chunk.Assets)
			}
		}
	}
	return total
}
