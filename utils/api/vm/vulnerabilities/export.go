package utils

import (
	// Standard
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	// Generated
	methodtenablefern "github.com/Method-Security/methodtenable/generated/go"
	apivulnfern "github.com/Method-Security/methodtenable/generated/go/utils/api/vm/vulnerabilities"
	vulnfern "github.com/Method-Security/methodtenable/generated/go/vm/vulnerabilities"

	// External
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

const TenableAPIBaseURL = "https://cloud.tenable.com"

// API Call Overview (3 API Calls):
// initiateVulnerabilityExport: Initiates a vulnerability export and returns the export UUID (POST /vulns/export)
// waitForVulnerabilityExportCompletion: Waits for the export to complete and returns the vulnerabilities (GET /vulns/export/{export_uuid}/status)
// downloadAllVulnerabilityChunks: Downloads all the export chunks from the Tenable API (GET /vulns/export/{export_uuid}/chunks)

// setTenableAPIKeyHeader sets the X-ApiKeys header with the provided secrets
func setTenableAPIKeyHeader(req *http.Request, secrets *methodtenablefern.SecretConfig) {
	req.Header.Set("X-ApiKeys", fmt.Sprintf("accessKey=%s;secretKey=%s",
		*secrets.GetAccessKey(), *secrets.GetSecretKey()))
}

// APIVmVulnerabilityExport initiates a vulnerability export and waits for it to complete
func APIVmVulnerabilityExport(ctx context.Context, secrets *methodtenablefern.SecretConfig, config *vulnfern.VmVulnerabilityExportConfig) (*apivulnfern.ApiVmVulnerabilityExportReport, []string) {
	log := svc1log.FromContext(ctx)
	errorStrings := []string{}

	exportUUID, err := initiateVulnerabilityExport(ctx, secrets, config)
	if err != nil {
		errorStrings = append(errorStrings, fmt.Sprintf("failed to initiate vulnerability export: %v", err))
		return nil, errorStrings
	}

	result := &apivulnfern.ApiVmVulnerabilityExportReport{
		ExportUuid: &exportUUID,
		Chunks:     nil,
		Errors:     []string{},
	}

	if config.GetMaxWaitTime() > 0 {
		log.Info("Waiting for vulnerability export completion", svc1log.SafeParam("export_uuid", exportUUID))
		vulnerabilities, err := waitForVulnerabilityExportCompletion(ctx, secrets, exportUUID, config)
		if err != nil {
			log.Warn("Vulnerability export completion monitoring failed, but returning export UUID anyway",
				svc1log.SafeParam("export_uuid", exportUUID),
				svc1log.SafeParam("error", err))
			// Don't return nil - still return the result with export UUID
			result.Errors = append(result.Errors, fmt.Sprintf("failed to download vulnerability chunks: %v", err))
		} else {
			result.Chunks = []*apivulnfern.ApiVmVulnerabilityExportChunkResponse{
				{
					Vulnerabilities: vulnerabilities,
				},
			}
			log.Info("Vulnerability export completed with vulnerability data", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("total_vulnerabilities", len(vulnerabilities)))
		}
	}

	log.Info("Vulnerability export operation completed", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("errors", result.Errors))
	return result, []string{}
}

// initiateVulnerabilityExport initiates a vulnerability export and returns the export UUID
func initiateVulnerabilityExport(ctx context.Context, secrets *methodtenablefern.SecretConfig, config *vulnfern.VmVulnerabilityExportConfig) (string, error) {
	log := svc1log.FromContext(ctx)

	numAssets := config.GetNumAssets()
	chunkSize := config.GetChunkSize() // Keep for internal use, not sent to API
	log.Info("Processing parameters", svc1log.SafeParam("num_assets", numAssets), svc1log.SafeParam("chunk_size_internal", chunkSize))

	// Set default num_assets if not provided or zero
	if numAssets <= 0 {
		numAssets = 500
		log.Info("Using default num_assets", svc1log.SafeParam("default_num_assets", numAssets))
	}

	// Set default chunk_size if not provided or zero
	if chunkSize <= 0 {
		chunkSize = 1000
		log.Info("Using default chunk_size", svc1log.SafeParam("default_chunk_size", chunkSize))
	}

	// Use simple struct to ensure correct JSON field names
	exportRequest := apivulnfern.ApiVmVulnerabilityExportRequest{}

	// Add num_assets if specified (optional in API)
	if numAssets > 0 {
		exportRequest.NumAssets = &numAssets
	}

	// Note: Tenable vulnerability export API doesn't support chunk_size parameter
	// We keep it in our config for consistency with asset export, but don't send it to the API

	// Create filters object if any filters need to be applied
	filters := &apivulnfern.ApiVmVulnerabilityExportFilters{}
	hasFilters := false

	// Apply timestamp filters - convert *time.Time to Unix timestamps
	if config.GetSince() != nil {
		since := config.GetSince().Unix()
		filters.Since = &since
		hasFilters = true
		log.Info("Applying since filter at API level", svc1log.SafeParam("since", config.GetSince()))
	}

	if config.GetLastFound() != nil {
		lastFound := config.GetLastFound().Unix()
		filters.LastFound = &lastFound
		hasFilters = true
		log.Info("Applying last_found filter at API level", svc1log.SafeParam("last_found", config.GetLastFound()))
	}

	if config.GetLastFixed() != nil {
		lastFixed := config.GetLastFixed().Unix()
		filters.LastFixed = &lastFixed
		hasFilters = true
		log.Info("Applying last_fixed filter at API level", svc1log.SafeParam("last_fixed", config.GetLastFixed()))
	}

	if config.GetFirstFound() != nil {
		firstFound := config.GetFirstFound().Unix()
		filters.FirstFound = &firstFound
		hasFilters = true
		log.Info("Applying first_found filter at API level", svc1log.SafeParam("first_found", config.GetFirstFound()))
	}

	if config.GetIndexedAt() != nil {
		indexedAt := config.GetIndexedAt().Unix()
		filters.IndexedAt = &indexedAt
		hasFilters = true
		log.Info("Applying indexed_at filter at API level", svc1log.SafeParam("indexed_at", config.GetIndexedAt()))
	}

	// String array filters
	if config.GetState() != nil && len(config.GetState()) > 0 {
		// Convert to uppercase as expected by API
		states := []string{}
		for _, state := range config.GetState() {
			states = append(states, string(state))
		}
		filters.State = states
		hasFilters = true
		log.Info("Applying state filter at API level", svc1log.SafeParam("state", states))
	}

	if config.GetSeverity() != nil && len(config.GetSeverity()) > 0 {
		// Convert to lowercase as expected by API
		severities := []string{}
		for _, severity := range config.GetSeverity() {
			severities = append(severities, strings.ToLower(severity))
		}
		filters.Severity = severities
		hasFilters = true
		log.Info("Applying severity filter at API level", svc1log.SafeParam("severity", severities))
	}

	// Boolean filters
	if config.GetIncludeUnlicensed() {
		includeUnlicensed := config.GetIncludeUnlicensed()
		filters.IncludeUnlicensed = &includeUnlicensed
		hasFilters = true
		log.Info("Applying include_unlicensed filter at API level", svc1log.SafeParam("include_unlicensed", config.GetIncludeUnlicensed()))
	}

	// Tag filters - these will be applied client-side as Tenable API may not support them directly
	if config.GetTags() != nil && len(config.GetTags()) > 0 {
		filters.Tag = config.GetTags()
		hasFilters = true
		log.Info("Applying tag filter at API level", svc1log.SafeParam("tags", config.GetTags()))
	}

	// Only add filters object if we have filters to apply
	if hasFilters {
		exportRequest.Filters = filters
	}

	log.Info("Final vulnerability export request", svc1log.SafeParam("num_assets", exportRequest.NumAssets))

	requestBody, err := json.Marshal(exportRequest)
	if err != nil {
		log.Error("failed to marshal vulnerability export request", svc1log.SafeParam("error", err))
		return "", fmt.Errorf("failed to marshal vulnerability export request: %w", err)
	}

	log.Info("Vulnerability export request body being sent", svc1log.SafeParam("request_body", string(requestBody)))

	req, err := http.NewRequest("POST", TenableAPIBaseURL+"/vulns/export", bytes.NewBuffer(requestBody))
	if err != nil {
		log.Error("failed to create vulnerability export request", svc1log.SafeParam("error", err))
		return "", fmt.Errorf("failed to create vulnerability export request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	setTenableAPIKeyHeader(req, secrets)

	timeout := config.GetTimeout()
	if timeout <= 0 {
		timeout = 30 // Default timeout
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("failed to execute vulnerability export request", svc1log.SafeParam("error", err))
		return "", fmt.Errorf("failed to execute vulnerability export request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Error("Vulnerability export API request failed with status", svc1log.SafeParam("status", resp.StatusCode), svc1log.SafeParam("body", string(body)))
		return "", fmt.Errorf("vulnerability export API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Read the response body to log it
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("failed to read vulnerability export response body", svc1log.SafeParam("error", err))
		return "", fmt.Errorf("failed to read vulnerability export response body: %w", err)
	}

	log.Info("Vulnerability export API response received", svc1log.SafeParam("response_body", string(responseBody)))

	// Use a simple struct to match the actual API response
	var exportResponse struct {
		ExportUUID string `json:"export_uuid"`
		Status     string `json:"status"`
	}

	if err := json.Unmarshal(responseBody, &exportResponse); err != nil {
		log.Error("failed to decode vulnerability export response", svc1log.SafeParam("error", err), svc1log.SafeParam("response", string(responseBody)))
		return "", fmt.Errorf("failed to decode vulnerability export response: %w", err)
	}

	log.Info("Parsed vulnerability export response", svc1log.SafeParam("export_uuid", exportResponse.ExportUUID), svc1log.SafeParam("status", exportResponse.Status))

	err = resp.Body.Close()
	if err != nil {
		log.Error("failed to close response body", svc1log.SafeParam("error", err))
	}

	return exportResponse.ExportUUID, nil
}

// waitForVulnerabilityExportCompletion waits for a vulnerability export to complete
func waitForVulnerabilityExportCompletion(ctx context.Context, secrets *methodtenablefern.SecretConfig, exportUUID string, config *vulnfern.VmVulnerabilityExportConfig) ([]*apivulnfern.TenableVulnerability, error) {
	log := svc1log.FromContext(ctx)

	// Use values from config with fallback to defaults
	maxWaitTime := config.GetMaxWaitTime()
	sleepTime := config.GetSleepTime()

	if maxWaitTime <= 0 {
		maxWaitTime = 600 // 10 minutes default
	}
	if sleepTime <= 0 {
		sleepTime = 5 // 5 seconds default
	}

	maxAttempts := maxWaitTime / sleepTime

	// Wait for the export to complete
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Check the export status
		status, err := checkVulnerabilityExportStatus(ctx, secrets, exportUUID, config)
		if err != nil {
			return nil, fmt.Errorf("failed to check vulnerability export status: %w", err)
		}

		switch status.Status {
		case "FINISHED":
			// Handle nil slices gracefully in logs
			chunksFinished := status.ChunksFinished
			if chunksFinished == nil {
				chunksFinished = []int{}
			}
			chunksAvailable := status.ChunksAvailable
			if chunksAvailable == nil {
				chunksAvailable = []int{}
			}

			log.Info("Vulnerability export completed successfully", svc1log.SafeParam("export_uuid", exportUUID),
				svc1log.SafeParam("chunks_finished", chunksFinished),
				svc1log.SafeParam("chunks_available", chunksAvailable))
			return downloadAllVulnerabilityChunks(ctx, secrets, exportUUID, status, config)
		case "ERROR", "CANCELLED":
			log.Error("Vulnerability export failed", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("status", status.Status))
			return nil, fmt.Errorf("vulnerability export failed with status: %s", status.Status)
		case "PROCESSING":
			log.Info("Vulnerability export in progress", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("chunks_finished", len(status.ChunksFinished)), svc1log.SafeParam("chunks_available", len(status.ChunksAvailable)))
			time.Sleep(time.Duration(sleepTime) * time.Second)
		default:
			log.Info("Vulnerability export status", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("status", status.Status))
			time.Sleep(time.Duration(sleepTime) * time.Second)
		}
	}

	log.Error("vulnerability export did not complete within timeout period", svc1log.SafeParam("export_uuid", exportUUID))
	return nil, fmt.Errorf("vulnerability export did not complete within timeout period")
}

// checkVulnerabilityExportStatus checks the status of a vulnerability export
func checkVulnerabilityExportStatus(ctx context.Context, secrets *methodtenablefern.SecretConfig, exportUUID string, config *vulnfern.VmVulnerabilityExportConfig) (*apivulnfern.ApiVmVulnerabilityExportStatusResponse, error) {
	log := svc1log.FromContext(ctx)

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/vulns/export/%s/status", TenableAPIBaseURL, exportUUID), nil)
	if err != nil {
		log.Error("failed to create vulnerability export status request", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to create vulnerability export status request: %w", err)
	}

	setTenableAPIKeyHeader(req, secrets)

	timeout := config.GetTimeout()
	if timeout <= 0 {
		timeout = 30
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("failed to execute vulnerability export status request", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to execute vulnerability export status request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Error("vulnerability export status request failed", svc1log.SafeParam("status", resp.StatusCode), svc1log.SafeParam("body", string(body)))
		return nil, fmt.Errorf("vulnerability export status request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var status apivulnfern.ApiVmVulnerabilityExportStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		log.Error("failed to decode vulnerability export status response", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to decode vulnerability export status response: %w", err)
	}

	err = resp.Body.Close()
	if err != nil {
		log.Error("failed to close response body", svc1log.SafeParam("error", err))
	}

	return &status, nil
}

// downloadAllVulnerabilityChunks downloads all the vulnerability export chunks from the Tenable API
func downloadAllVulnerabilityChunks(ctx context.Context, secrets *methodtenablefern.SecretConfig, exportUUID string, status *apivulnfern.ApiVmVulnerabilityExportStatusResponse, config *vulnfern.VmVulnerabilityExportConfig) ([]*apivulnfern.TenableVulnerability, error) {
	log := svc1log.FromContext(ctx)
	var allVulnerabilities []*apivulnfern.TenableVulnerability

	// Try chunks_finished first
	chunkIDs := status.ChunksFinished
	if len(chunkIDs) == 0 {
		// If no finished chunks, try chunks_available
		chunkIDs = status.ChunksAvailable
		log.Info("No finished vulnerability chunks, trying available chunks", svc1log.SafeParam("chunks_available", chunkIDs))
		if len(chunkIDs) == 0 {
			return nil, fmt.Errorf("no vulnerability chunks available to download")
		}
	}

	// Download listed chunks
	for _, chunkID := range chunkIDs {
		chunkData, err := downloadSingleVulnerabilityChunk(ctx, secrets, exportUUID, chunkID, config)
		if err != nil {
			log.Error("failed to download vulnerability chunk", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("chunk_id", chunkID), svc1log.SafeParam("error", err))
			return nil, err
		}
		allVulnerabilities = append(allVulnerabilities, chunkData...)
	}

	log.Info("Successfully downloaded all vulnerability chunks", svc1log.SafeParam("total_vulnerabilities", len(allVulnerabilities)), svc1log.SafeParam("chunks", len(chunkIDs)))
	return allVulnerabilities, nil
}

// downloadSingleVulnerabilityChunk downloads a single vulnerability chunk from the Tenable API
func downloadSingleVulnerabilityChunk(ctx context.Context, secrets *methodtenablefern.SecretConfig, exportUUID string, chunkID int, config *vulnfern.VmVulnerabilityExportConfig) ([]*apivulnfern.TenableVulnerability, error) {
	log := svc1log.FromContext(ctx)
	url := fmt.Sprintf("%s/vulns/export/%s/chunks/%d", TenableAPIBaseURL, exportUUID, chunkID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Error("failed to create vulnerability chunk request", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to create vulnerability chunk request: %w", err)
	}

	setTenableAPIKeyHeader(req, secrets)

	timeout := config.GetTimeout()
	if timeout <= 0 {
		timeout = 60 // Default longer timeout for chunk downloads
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("failed to execute vulnerability chunk request", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to execute vulnerability chunk request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Error("vulnerability chunk request failed", svc1log.SafeParam("status", resp.StatusCode), svc1log.SafeParam("body", string(body)))
		return nil, fmt.Errorf("vulnerability chunk request failed with status %d: %s", resp.StatusCode, string(body))
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("failed to read vulnerability chunk response body", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to read vulnerability chunk response body: %w", err)
	}

	var vulnerabilities []*apivulnfern.TenableVulnerability
	if err := json.Unmarshal(responseBody, &vulnerabilities); err != nil {
		log.Error("failed to decode vulnerability chunk response", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to decode vulnerability chunk response: %w", err)
	}

	err = resp.Body.Close()
	if err != nil {
		log.Error("failed to close response body", svc1log.SafeParam("error", err))
	}

	log.Info("Downloaded vulnerability chunk", svc1log.SafeParam("chunk_id", chunkID), svc1log.SafeParam("vulnerability_count", len(vulnerabilities)))
	return vulnerabilities, nil
}
