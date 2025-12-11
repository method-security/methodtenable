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
	apiassetfern "github.com/Method-Security/methodtenable/generated/go/utils/api/vm/assets"
	assetfern "github.com/Method-Security/methodtenable/generated/go/vm/assets"

	// Internal
	apiutils "github.com/Method-Security/methodtenable/utils/api"
	// External
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// API Call Overview (3 API Calls):
// initiateExport: Initiates an asset export and returns the export UUID (POST /assets/v2/export)
// waitForExportCompletion: Waits for the export to complete and returns the assets (GET /assets/export/{export_uuid}/status)
// downloadAllChunks: Downloads all the export chunks from the Tenable API (GET /assets/export/{export_uuid}/chunks)

// APIVmAssetV2Export initiates an asset export and waits for it to complete
func APIVmAssetV2Export(ctx context.Context, secrets *methodtenablefern.SecretConfig, config *assetfern.VmAssetExportConfig) (*apiassetfern.ApiVmAsssetExportReport, []string) {
	log := svc1log.FromContext(ctx)
	errorStrings := []string{}

	exportUUID, err := initiateExport(ctx, secrets, config)
	if err != nil {
		errorStrings = append(errorStrings, fmt.Sprintf("failed to initiate export: %v", err))
		return nil, errorStrings
	}

	result := &apiassetfern.ApiVmAsssetExportReport{
		ExportUuid: &exportUUID,
		Chunks:     nil,
		Errors:     []string{},
	}

	if config.GetMaxWaitTime() > 0 {
		log.Info("Waiting for export completion", svc1log.SafeParam("export_uuid", exportUUID))
		assets, err := waitForExportCompletion(ctx, secrets, exportUUID, config)
		if err != nil {
			log.Warn("Export completion monitoring failed, but returning export UUID anyway",
				svc1log.SafeParam("export_uuid", exportUUID),
				svc1log.SafeParam("error", err))
			// Don't return nil - still return the result with export UUID
			result.Errors = append(result.Errors, fmt.Sprintf("failed to download chunks: %v", err))
		} else {
			result.Chunks = []*apiassetfern.ApiVmAssetExportChunkResponse{
				{
					Assets: assets,
				},
			}
			log.Info("Export completed with asset data", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("total_assets", len(assets)))
		}
	}

	log.Info("Export operation completed", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("errors", result.Errors))
	return result, []string{}
}

// initiateExport initiates an asset export and returns the export UUID
func initiateExport(ctx context.Context, secrets *methodtenablefern.SecretConfig, config *assetfern.VmAssetExportConfig) (string, error) {
	log := svc1log.FromContext(ctx)

	chunkSize := config.GetChunkSize()
	log.Info("Processing chunk size", svc1log.SafeParam("original_chunk_size", chunkSize))

	// Set default chunk size if not provided or zero
	if chunkSize <= 0 {
		chunkSize = 1000
		log.Info("Using default chunk size", svc1log.SafeParam("default_chunk_size", chunkSize))
	}

	// Use simple struct to ensure correct JSON field names
	exportRequest := apiassetfern.ApiVmAssetV2ExportRequest{}

	// Add chunk_size if specified (optional in API)
	if chunkSize > 0 {
		exportRequest.ChunkSize = &chunkSize
	}

	// Create filters object if any filters need to be applied
	filters := &apiassetfern.ApiVmAssetExportFilters{}
	hasFilters := false

	// Apply ALL API-level filters supported by Tenable Export API v2
	if config.GetSources() != nil && len(config.GetSources()) > 0 {
		sources := []string{}
		for _, sourceEnum := range config.GetSources() {
			sources = append(sources, strings.ToLower(string(sourceEnum)))
		}
		filters.Sources = sources
		hasFilters = true
		log.Info("Applying sources filter at API level", svc1log.SafeParam("sources", config.GetSources()))
	}

	if config.GetTypes() != nil && len(config.GetTypes()) > 0 {
		types := []string{}
		for _, typeEnum := range config.GetTypes() {
			types = append(types, strings.ToLower(string(typeEnum)))
		}
		filters.Types = types
		hasFilters = true
		log.Info("Applying types filter at API level", svc1log.SafeParam("types", config.GetTypes()))
	}

	// Timestamp filters - convert *time.Time to Unix timestamps
	if config.GetCreatedAt() != nil {
		createdAt := int(config.GetCreatedAt().Unix())
		filters.CreatedAt = &createdAt
		hasFilters = true
		log.Info("Applying created_at filter at API level", svc1log.SafeParam("created_at", config.GetCreatedAt()))
	}

	if config.GetUpdatedAt() != nil {
		updatedAt := int(config.GetUpdatedAt().Unix())
		filters.UpdatedAt = &updatedAt
		hasFilters = true
		log.Info("Applying updated_at filter at API level", svc1log.SafeParam("updated_at", config.GetUpdatedAt()))
	}

	if config.GetTerminatedAt() != nil {
		terminatedAt := int(config.GetTerminatedAt().Unix())
		filters.TerminatedAt = &terminatedAt
		hasFilters = true
		log.Info("Applying terminated_at filter at API level", svc1log.SafeParam("terminated_at", config.GetTerminatedAt()))
	}

	if config.GetDeletedAt() != nil {
		deletedAt := int(config.GetDeletedAt().Unix())
		filters.DeletedAt = &deletedAt
		hasFilters = true
		log.Info("Applying deleted_at filter at API level", svc1log.SafeParam("deleted_at", config.GetDeletedAt()))
	}

	if config.GetLastAssessed() != nil {
		lastAssessed := int(config.GetLastAssessed().Unix())
		filters.LastAssessed = &lastAssessed
		hasFilters = true
		log.Info("Applying last_assessed filter at API level", svc1log.SafeParam("last_assessed", config.GetLastAssessed()))
	}

	// Boolean filters
	if config.GetServicenowSysid() {
		// servicenow_sysid=true means return assets WITH ServiceNow sysid
		servicenowSysid := config.GetServicenowSysid()
		filters.ServicenowSysid = &servicenowSysid
		hasFilters = true
		log.Info("Applying servicenow_sysid filter at API level", svc1log.SafeParam("servicenow_sysid", config.GetServicenowSysid()))
	}

	// Only add filters object if we have filters to apply
	if hasFilters {
		exportRequest.Filters = filters
	}

	// Note: Only client-side filters remaining: tags, ipv4, hostname, operating_system
	// All other filters (including last_assessed) are now applied at API level for maximum efficiency

	log.Info("Final export request", svc1log.SafeParam("chunk_size", exportRequest.ChunkSize))

	requestBody, err := json.Marshal(exportRequest)
	if err != nil {
		log.Error("failed to marshal request", svc1log.SafeParam("error", err))
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	log.Info("Request body being sent", svc1log.SafeParam("request_body", string(requestBody)))

	req, err := http.NewRequest("POST", apiutils.TenableAPIBaseURL+"/assets/v2/export", bytes.NewBuffer(requestBody))
	if err != nil {
		log.Error("failed to create request", svc1log.SafeParam("error", err))
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	apiutils.SetTenableAPIKeyHeader(req, secrets)

	client := &http.Client{Timeout: time.Duration(config.GetTimeout()) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("failed to execute request", svc1log.SafeParam("error", err))
		return "", fmt.Errorf("failed to execute request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Error("API request failed with status", svc1log.SafeParam("status", resp.StatusCode), svc1log.SafeParam("body", string(body)))
		return "", fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Read the response body to log it
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("failed to read response body", svc1log.SafeParam("error", err))
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	log.Info("API response received", svc1log.SafeParam("response_body", string(responseBody)))

	// Use a simple struct to match the actual API response
	var exportResponse struct {
		ExportUUID string `json:"export_uuid"`
		Status     string `json:"status"`
	}

	if err := json.Unmarshal(responseBody, &exportResponse); err != nil {
		log.Error("failed to decode response", svc1log.SafeParam("error", err), svc1log.SafeParam("response", string(responseBody)))
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	log.Info("Parsed export response", svc1log.SafeParam("export_uuid", exportResponse.ExportUUID), svc1log.SafeParam("status", exportResponse.Status))

	err = resp.Body.Close()
	if err != nil {
		log.Error("failed to close response body", svc1log.SafeParam("error", err))
	}

	return exportResponse.ExportUUID, nil
}

// waitForExportCompletion waits for an asset export to complete
func waitForExportCompletion(ctx context.Context, secrets *methodtenablefern.SecretConfig, exportUUID string, config *assetfern.VmAssetExportConfig) ([]*apiassetfern.TenableAsset, error) {
	log := svc1log.FromContext(ctx)

	// Calculate the maximum number of attempts based on the maximum wait time and sleep time
	maxAttempts := config.GetMaxWaitTime() / config.GetSleepTime()

	// Wait for the export to complete
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Check the export status
		status, err := checkExportStatus(ctx, secrets, exportUUID, config)
		if err != nil {
			return nil, fmt.Errorf("failed to check export status: %w", err)
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

			log.Info("Export completed successfully", svc1log.SafeParam("export_uuid", exportUUID),
				svc1log.SafeParam("chunks_finished", chunksFinished),
				svc1log.SafeParam("chunks_available", chunksAvailable))
			return downloadAllChunks(ctx, secrets, exportUUID, status, config)
		case "ERROR", "CANCELLED":
			log.Error("Export failed", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("status", status.Status))
			return nil, fmt.Errorf("export failed with status: %s", status.Status)
		case "PROCESSING":
			log.Info("Export in progress", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("chunks_finished", len(status.ChunksFinished)), svc1log.SafeParam("chunks_available", len(status.ChunksAvailable)))
			time.Sleep(time.Duration(config.GetSleepTime()) * time.Second)
		default:
			log.Info("Export status", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("status", status.Status))
			time.Sleep(time.Duration(config.GetSleepTime()) * time.Second)
		}
	}

	log.Error("export did not complete within timeout period", svc1log.SafeParam("export_uuid", exportUUID))
	return nil, fmt.Errorf("export did not complete within timeout period")
}

// checkExportStatus checks the status of an asset export
func checkExportStatus(ctx context.Context, secrets *methodtenablefern.SecretConfig, exportUUID string, config *assetfern.VmAssetExportConfig) (*apiassetfern.ApiVmAssetExportStatusResponse, error) {
	log := svc1log.FromContext(ctx)

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/assets/export/%s/status", apiutils.TenableAPIBaseURL, exportUUID), nil)
	if err != nil {
		log.Error("failed to create status request", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to create status request: %w", err)
	}

	apiutils.SetTenableAPIKeyHeader(req, secrets)

	client := &http.Client{Timeout: time.Duration(config.GetTimeout()) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("failed to execute status request", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to execute status request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Error("status request failed", svc1log.SafeParam("status", resp.StatusCode), svc1log.SafeParam("body", string(body)))
		return nil, fmt.Errorf("status request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var status apiassetfern.ApiVmAssetExportStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		log.Error("failed to decode status response", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to decode status response: %w", err)
	}

	err = resp.Body.Close()
	if err != nil {
		log.Error("failed to close response body", svc1log.SafeParam("error", err))
	}

	return &status, nil
}

// downloadAllChunks downloads all the export chunks from the Tenable API
func downloadAllChunks(ctx context.Context, secrets *methodtenablefern.SecretConfig, exportUUID string, status *apiassetfern.ApiVmAssetExportStatusResponse, config *assetfern.VmAssetExportConfig) ([]*apiassetfern.TenableAsset, error) {
	log := svc1log.FromContext(ctx)
	var allAssets []*apiassetfern.TenableAsset

	// Try chunks_finished first
	chunkIDs := status.ChunksFinished
	if len(chunkIDs) == 0 {
		// If no finished chunks, try chunks_available
		chunkIDs = status.ChunksAvailable
		log.Info("No finished chunks, trying available chunks", svc1log.SafeParam("chunks_available", chunkIDs))
		if len(chunkIDs) == 0 {
			return nil, fmt.Errorf("no chunks available to download")
		}
	}

	// Download listed chunks
	for _, chunkID := range chunkIDs {
		chunkData, err := downloadSingleChunk(ctx, secrets, exportUUID, chunkID, config)
		if err != nil {
			log.Error("failed to download chunk", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("chunk_id", chunkID), svc1log.SafeParam("error", err))
			return nil, err
		}
		allAssets = append(allAssets, chunkData...)
	}

	log.Info("Successfully downloaded all chunks", svc1log.SafeParam("total_assets", len(allAssets)), svc1log.SafeParam("chunks", len(chunkIDs)))
	return allAssets, nil
}

// downloadSingleChunk downloads a single chunk from the Tenable API
func downloadSingleChunk(ctx context.Context, secrets *methodtenablefern.SecretConfig, exportUUID string, chunkID int, config *assetfern.VmAssetExportConfig) ([]*apiassetfern.TenableAsset, error) {
	log := svc1log.FromContext(ctx)
	url := fmt.Sprintf("%s/assets/export/%s/chunks/%d", apiutils.TenableAPIBaseURL, exportUUID, chunkID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Error("failed to create chunk request", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to create chunk request: %w", err)
	}

	apiutils.SetTenableAPIKeyHeader(req, secrets)

	client := &http.Client{Timeout: time.Duration(config.GetTimeout()) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("failed to execute chunk request", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to execute chunk request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Error("chunk request failed", svc1log.SafeParam("status", resp.StatusCode), svc1log.SafeParam("body", string(body)))
		return nil, fmt.Errorf("chunk request failed with status %d: %s", resp.StatusCode, string(body))
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("failed to read chunk response body", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to read chunk response body: %w", err)
	}

	var assets []*apiassetfern.TenableAsset
	if err := json.Unmarshal(responseBody, &assets); err != nil {
		log.Error("failed to decode chunk response", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to decode chunk response: %w", err)
	}

	err = resp.Body.Close()
	if err != nil {
		log.Error("failed to close response body", svc1log.SafeParam("error", err))
	}

	log.Info("Downloaded chunk", svc1log.SafeParam("chunk_id", chunkID), svc1log.SafeParam("asset_count", len(assets)))
	return assets, nil
}
