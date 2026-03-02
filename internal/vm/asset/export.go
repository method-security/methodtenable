package assets

import (
	// Standard
	"context"
	"net"
	"strings"
	"time"

	// Generated
	methodtenablefern "github.com/Method-Security/methodtenable/generated/go"
	apiassetfern "github.com/Method-Security/methodtenable/generated/go/utils/api/vm/asset"
	assetfern "github.com/Method-Security/methodtenable/generated/go/vm/asset"

	// Utils
	apiutils "github.com/Method-Security/methodtenable/utils/api"
	utils "github.com/Method-Security/methodtenable/utils/api/vm/asset"

	// External
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func ExportAssets(ctx context.Context, secrets methodtenablefern.SecretConfig, config assetfern.VmAssetExportConfig) *assetfern.VmAssetExportReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting asset export", svc1log.SafeParam("config", config))

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

		filteredAssets, parseFailures := filterAssets(chunk.Assets, config)
		if parseFailures > 0 {
			log.Warn("Some assets dropped due to unparseable timestamps during client-side filtering",
				svc1log.SafeParam("chunk_index", i),
				svc1log.SafeParam("dropped_count", parseFailures))
		}
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
// Returns the filtered list and count of items dropped due to unparseable timestamps
func filterAssets(assets []*apiassetfern.TenableAsset, config *assetfern.VmAssetExportConfig) ([]*apiassetfern.TenableAsset, int) {
	var filtered []*apiassetfern.TenableAsset
	parseFailures := 0

	for _, asset := range assets {
		matched, parseFailed := matchesAllFilters(asset, config)
		if parseFailed {
			parseFailures++
		}
		if matched {
			filtered = append(filtered, asset)
		}
	}

	return filtered, parseFailures
}

// matchesAllFilters checks if an asset matches all the specified CLIENT-SIDE-ONLY filters
// Note: Most filters are handled at API level. Only these are still client-side:
// tags, ipv4, hostname, operating_system, betweenUpdatedAt
// Note: publicIPAddressesOnly is handled during transformation (per-IP filtering)
// Returns (matches, parseFailure) where parseFailure indicates a timestamp couldn't be parsed
func matchesAllFilters(asset *apiassetfern.TenableAsset, config *assetfern.VmAssetExportConfig) (bool, bool) {

	// Tag filter (not supported by API)
	if config.GetTags() != nil && len(config.GetTags()) > 0 {
		if !matchesTagFilter(asset, config.GetTags()) {
			return false, false
		}
	}

	// IPv4 filter (not supported by API)
	if config.GetIpv4S() != nil && len(config.GetIpv4S()) > 0 {
		if !matchesIPv4Filter(asset, config.GetIpv4S()) {
			return false, false
		}
	}

	// Hostname filter (not supported by API)
	if config.GetHostnames() != nil && len(config.GetHostnames()) > 0 {
		if !matchesHostnameFilter(asset, config.GetHostnames()) {
			return false, false
		}
	}

	// Operating System filter (not supported by API)
	if config.GetOperatingSystems() != nil && len(config.GetOperatingSystems()) > 0 {
		if !matchesOperatingSystemFilter(asset, config.GetOperatingSystems()) {
			return false, false
		}
	}

	// Between Updated At filter (client-side date range filter)
	if config.GetBetweenUpdatedAt() != nil && *config.GetBetweenUpdatedAt() != "" {
		matched, parseFailed := matchesBetweenUpdatedAtFilter(asset, *config.GetBetweenUpdatedAt())
		if !matched {
			return false, parseFailed
		}
	}

	return true, false
}

// isPublicIP checks if a single IP address string is public
func isPublicIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// An IP is public if it's NOT any of these (covers RFC 3330 special-use addresses)
	return !ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() &&
		!ip.IsUnspecified() &&
		!ip.IsInterfaceLocalMulticast()
}

// filterPublicFqdns filters out internal/private FQDNs from the list
func filterPublicFqdns(fqdns []string) []string {
	var publicFqdns []string

	for _, fqdn := range fqdns {
		lowerFqdn := strings.ToLower(fqdn)

		// Skip if it contains common internal/private domain suffixes
		if strings.HasSuffix(lowerFqdn, ".internal") ||
			strings.HasSuffix(lowerFqdn, ".local") {
			continue
		}

		// Check if FQDN contains an IP address pattern (e.g., ip-10-176-61-51)
		// Extract and check if it's a private IP
		if strings.Contains(lowerFqdn, "ip-") {
			// Try to extract IP from patterns like "ip-10-176-61-51"
			ipStr := extractIPFromFQDN(lowerFqdn)
			if ipStr != "" && !isPublicIP(ipStr) {
				continue
			}
		}

		publicFqdns = append(publicFqdns, fqdn)
	}

	return publicFqdns
}

// extractIPFromFQDN attempts to extract an IP address from FQDNs like "ip-10-176-61-51.ec2.internal"
// Returns empty string if no valid IP pattern is found
func extractIPFromFQDN(fqdn string) string {
	// Look for patterns like "ip-10-176-61-51"
	parts := strings.Split(fqdn, ".")
	for _, part := range parts {
		if strings.HasPrefix(part, "ip-") {
			// Remove "ip-" prefix and replace remaining dashes with dots
			ipPart := strings.TrimPrefix(part, "ip-")
			// Replace dashes with dots to get potential IP address
			ipCandidate := strings.ReplaceAll(ipPart, "-", ".")
			// Validate it's a real IP by parsing it
			if net.ParseIP(ipCandidate) != nil {
				return ipCandidate
			}
		}
	}
	return ""
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

// matchesBetweenUpdatedAtFilter checks if asset's updated_at timestamp falls within the specified date range
// Returns (matches, parseFailure) where parseFailure indicates the asset's timestamp couldn't be parsed
func matchesBetweenUpdatedAtFilter(asset *apiassetfern.TenableAsset, betweenUpdatedAt string) (bool, bool) {
	// Check if asset has timestamps
	if asset.Timestamps == nil || asset.Timestamps.UpdatedAt == nil {
		return false, true
	}

	// Parse the date range: 2025-11-25T16:05:22Z-2025-12-01T16:05:22Z
	// Find the separator between the two RFC3339 dates
	lastDashIdx := -1
	for i := 20; i < len(betweenUpdatedAt)-20; i++ {
		if betweenUpdatedAt[i] == '-' {
			beforePart := betweenUpdatedAt[:i]
			afterPart := betweenUpdatedAt[i+1:]
			_, err1 := time.Parse(time.RFC3339, beforePart)
			_, err2 := time.Parse(time.RFC3339, afterPart)
			if err1 == nil && err2 == nil {
				lastDashIdx = i
				break
			}
		}
	}

	if lastDashIdx == -1 {
		return false, false
	}

	startDateStr := betweenUpdatedAt[:lastDashIdx]
	endDateStr := betweenUpdatedAt[lastDashIdx+1:]

	startDate, err := time.Parse(time.RFC3339, startDateStr)
	if err != nil {
		return false, false
	}

	endDate, err := time.Parse(time.RFC3339, endDateStr)
	if err != nil {
		return false, false
	}

	// Parse the asset's updated_at timestamp with flexible parsing
	assetUpdatedAt, err := apiutils.ParseFlexibleTimestamp(*asset.Timestamps.UpdatedAt)
	if err != nil {
		return false, true
	}

	// Check if the asset's updated_at falls within the range (inclusive)
	inRange := (assetUpdatedAt.Equal(startDate) || assetUpdatedAt.After(startDate)) &&
		(assetUpdatedAt.Equal(endDate) || assetUpdatedAt.Before(endDate))
	return inRange, false
}

// transformTenableAssets transforms the filtered Tenable API response into our Asset structure
// Creates one Asset per IP address for each Tenable asset that has IP addresses
// Uses originalResult for raw data to preserve unfiltered state
func transformTenableAssets(ctx context.Context, config *assetfern.VmAssetExportConfig, filteredResult *apiassetfern.ApiVmAsssetExportReport, originalResult *apiassetfern.ApiVmAsssetExportReport) *assetfern.AssetDetails {
	log := svc1log.FromContext(ctx)
	log.Info("Transform config", svc1log.SafeParam("publicIPAddressesOnly", config.GetPublicIpAddressesOnly()))
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
					if tenableAsset.Network == nil {
						continue
					}

					// Prefer IPv4; fall back to IPv6 if no IPv4s exist
					ipsToProcess := tenableAsset.Network.Ipv4S
					if len(ipsToProcess) == 0 {
						ipsToProcess = tenableAsset.Network.Ipv6S
					}

					// Only process assets that have at least one IP address (v4 or v6)
					if len(ipsToProcess) > 0 {
						for _, ipAddress := range ipsToProcess {
							// If publicIPAddressesOnly is enabled, skip private IPs during transformation
							if config.GetPublicIpAddressesOnly() {
								isPublic := isPublicIP(ipAddress)
								log.Info("Checking IP",
									svc1log.SafeParam("ip", ipAddress),
									svc1log.SafeParam("isPublic", isPublic),
									svc1log.SafeParam("publicIPsOnlyEnabled", true))
								if !isPublic {
									log.Info("Skipping private IP", svc1log.SafeParam("ip", ipAddress))
									continue
								}
							}

							asset := &assetfern.Asset{
								Ipaddress: ipAddress,
							}

							// Add FQDNs if available
							if tenableAsset.Network.Fqdns != nil {
								// If publicIPAddressesOnly is enabled, filter out internal/private FQDNs
								if config.GetPublicIpAddressesOnly() {
									asset.Fqdns = filterPublicFqdns(tenableAsset.Network.Fqdns)
								} else {
									asset.Fqdns = tenableAsset.Network.Fqdns
								}
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
