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
	apiwasfern "github.com/Method-Security/methodtenable/generated/go/utils/api/was/finding"
	wasfern "github.com/Method-Security/methodtenable/generated/go/was/finding"

	// Internal
	apiutils "github.com/Method-Security/methodtenable/utils/api"
	// External
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// API Call Overview (3 API Calls):
// initiateWasFindingsExport: Initiates a WAS findings export and returns the export UUID (POST /was/v1/export/vulns)
// waitForWasFindingsExportCompletion: Waits for the export to complete (GET /was/v1/export/vulns/{export_uuid}/status)
// downloadAllWasFindingsChunks: Downloads all the export chunks from the Tenable API (GET /was/v1/export/vulns/{export_uuid}/chunks/{chunk_id})

// APIWasFindingsExport initiates a WAS findings export and waits for it to complete
func APIWasFindingsExport(ctx context.Context, secrets *methodtenablefern.SecretConfig, config *wasfern.WasFindingsExportConfig) (*apiwasfern.ApiWasFindingsExportReport, []string) {
	log := svc1log.FromContext(ctx)
	errorStrings := []string{}

	exportUUID, initErrors := initiateWasFindingsExport(ctx, secrets, config)
	if len(initErrors) > 0 {
		errorStrings = append(errorStrings, initErrors...)
	}
	if exportUUID == "" {
		return nil, errorStrings
	}

	result := &apiwasfern.ApiWasFindingsExportReport{
		Findings: &apiwasfern.ApiWasFindingsExportResponse{
			ExportUuid: &exportUUID,
			Items:      nil,
		},
		Errors: []string{},
	}

	if config.GetMaxWaitTime() > 0 {
		log.Info("Waiting for WAS findings export completion", svc1log.SafeParam("export_uuid", exportUUID))
		findings, err := waitForWasFindingsExportCompletion(ctx, secrets, exportUUID, config)
		if err != nil {
			log.Warn("WAS findings export completion monitoring failed, but returning export UUID anyway",
				svc1log.SafeParam("export_uuid", exportUUID),
				svc1log.SafeParam("error", err))
			result.Errors = append(result.Errors, fmt.Sprintf("failed to download WAS findings chunks (potentially because no findings were found using the current filter): %v", err))
		} else {
			result.Findings.Items = findings
			log.Info("WAS findings export completed", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("total_findings", len(findings)))
		}
	}

	log.Info("WAS findings export operation completed", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("errors", result.Errors))
	// Return accumulated errors in the signal
	if len(result.Errors) > 0 {
		errorStrings = append(errorStrings, result.Errors...)
	}
	return result, errorStrings
}

// initiateWasFindingsExport initiates a WAS findings export and returns the export UUID
func initiateWasFindingsExport(ctx context.Context, secrets *methodtenablefern.SecretConfig, config *wasfern.WasFindingsExportConfig) (string, []string) {
	log := svc1log.FromContext(ctx)
	errorStrings := []string{}

	// Build the request payload for WAS findings export
	exportRequest := apiwasfern.ApiWasFindingsExportRequest{}

	// Set num_assets in the request body (not in filters)
	if config.NumAssets != nil {
		exportRequest.NumAssets = config.NumAssets
		log.Info("Setting num_assets", svc1log.SafeParam("num_assets", *config.NumAssets))
	}

	// Build filters based on config
	filters := apiwasfern.ApiWasFindingsExportFilters{}
	hasFilters := false

	if config.Since != nil {
		t, err := time.Parse(time.RFC3339, *config.Since)
		if err != nil {
			errMsg := fmt.Sprintf("failed to parse since: %v", err)
			log.Error(errMsg, svc1log.SafeParam("error", err))
			errorStrings = append(errorStrings, errMsg)
		} else {
			since := t.Unix()
			filters.Since = &since
			hasFilters = true
			log.Info("Applying since filter", svc1log.SafeParam("since", config.Since))
		}
	}

	if config.FirstFound != nil {
		t, err := time.Parse(time.RFC3339, *config.FirstFound)
		if err != nil {
			errMsg := fmt.Sprintf("failed to parse first_found: %v", err)
			log.Error(errMsg, svc1log.SafeParam("error", err))
			errorStrings = append(errorStrings, errMsg)
		} else {
			firstFound := t.Unix()
			filters.FirstFound = &firstFound
			hasFilters = true
			log.Info("Applying first_found filter", svc1log.SafeParam("first_found", config.FirstFound))
		}
	}

	if config.LastFixed != nil {
		t, err := time.Parse(time.RFC3339, *config.LastFixed)
		if err != nil {
			errMsg := fmt.Sprintf("failed to parse last_fixed: %v", err)
			log.Error(errMsg, svc1log.SafeParam("error", err))
			errorStrings = append(errorStrings, errMsg)
		} else {
			lastFixed := t.Unix()
			filters.LastFixed = &lastFixed
			hasFilters = true
			log.Info("Applying last_fixed filter", svc1log.SafeParam("last_fixed", config.LastFixed))
		}
	}

	if config.LastFound != nil {
		t, err := time.Parse(time.RFC3339, *config.LastFound)
		if err != nil {
			errMsg := fmt.Sprintf("failed to parse last_found: %v", err)
			log.Error(errMsg, svc1log.SafeParam("error", err))
			errorStrings = append(errorStrings, errMsg)
		} else {
			lastFound := t.Unix()
			filters.LastFound = &lastFound
			hasFilters = true
			log.Info("Applying last_found filter", svc1log.SafeParam("last_found", config.LastFound))
		}
	}

	if len(config.GetSeverity()) > 0 {
		// Convert to lowercase as expected by API
		severities := []string{}
		for _, severity := range config.Severity {
			severities = append(severities, string(severity))
		}
		filters.Severity = severities
		hasFilters = true
		log.Info("Applying severity filter", svc1log.SafeParam("severity", severities))
	}

	// Only add filters if we have any
	if hasFilters {
		exportRequest.Filters = &filters
	}

	log.Info("WAS findings export request", svc1log.SafeParam("filters", hasFilters))

	requestBody, err := json.Marshal(exportRequest)
	if err != nil {
		errMsg := fmt.Sprintf("failed to marshal WAS findings export request: %v", err)
		log.Error(errMsg, svc1log.SafeParam("error", err))
		errorStrings = append(errorStrings, errMsg)
		return "", errorStrings
	}

	log.Info("WAS findings export request body", svc1log.SafeParam("request_body", string(requestBody)))

	req, err := http.NewRequest("POST", apiutils.TenableAPIBaseURL+"/was/v1/export/vulns", bytes.NewBuffer(requestBody))
	if err != nil {
		errMsg := fmt.Sprintf("failed to create WAS findings export request: %v", err)
		log.Error(errMsg, svc1log.SafeParam("error", err))
		errorStrings = append(errorStrings, errMsg)
		return "", errorStrings
	}

	req.Header.Set("Content-Type", "application/json")
	apiutils.SetTenableAPIKeyHeader(req, secrets)

	timeout := config.GetTimeout()
	if timeout <= 0 {
		timeout = 30 // Default timeout
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		errMsg := fmt.Sprintf("failed to execute WAS findings export request: %v", err)
		log.Error(errMsg, svc1log.SafeParam("error", err))
		errorStrings = append(errorStrings, errMsg)
		return "", errorStrings
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("WAS findings export API request failed with status %d: %s", resp.StatusCode, string(body))
		log.Error(errMsg, svc1log.SafeParam("status", resp.StatusCode), svc1log.SafeParam("body", string(body)))
		errorStrings = append(errorStrings, errMsg)
		return "", errorStrings
	}

	// Read the response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		errMsg := fmt.Sprintf("failed to read WAS findings export response body: %v", err)
		log.Error(errMsg, svc1log.SafeParam("error", err))
		errorStrings = append(errorStrings, errMsg)
		return "", errorStrings
	}

	log.Info("WAS findings export API response", svc1log.SafeParam("response_body", string(responseBody)))

	// Parse response - WAS export returns export_uuid like VM export
	var exportResponse struct {
		ExportUUID string `json:"export_uuid"`
	}

	if err := json.Unmarshal(responseBody, &exportResponse); err != nil {
		errMsg := fmt.Sprintf("failed to decode WAS findings export response: %v", err)
		log.Error(errMsg, svc1log.SafeParam("error", err), svc1log.SafeParam("response", string(responseBody)))
		errorStrings = append(errorStrings, errMsg)
		return "", errorStrings
	}

	log.Info("Parsed WAS findings export response", svc1log.SafeParam("export_uuid", exportResponse.ExportUUID))

	err = resp.Body.Close()
	if err != nil {
		log.Error("failed to close response body", svc1log.SafeParam("error", err))
	}

	return exportResponse.ExportUUID, errorStrings
}

// waitForWasFindingsExportCompletion waits for a WAS findings export to complete
func waitForWasFindingsExportCompletion(ctx context.Context, secrets *methodtenablefern.SecretConfig, exportUUID string, config *wasfern.WasFindingsExportConfig) ([]*apiwasfern.WasFinding, error) {
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
		status, err := checkWasFindingsExportStatus(ctx, secrets, exportUUID, config)
		if err != nil {
			return nil, fmt.Errorf("failed to check WAS findings export status: %w", err)
		}

		switch status.Status {
		case "FINISHED":
			log.Info("WAS findings export completed successfully", svc1log.SafeParam("export_uuid", exportUUID))
			return downloadAllWasFindingsChunks(ctx, secrets, exportUUID, status, config)
		case "ERROR", "CANCELLED":
			log.Error("WAS findings export failed", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("status", status.Status))
			return nil, fmt.Errorf("WAS findings export failed with status: %s", status.Status)
		case "PROCESSING":
			log.Info("WAS findings export in progress", svc1log.SafeParam("export_uuid", exportUUID))
			time.Sleep(time.Duration(sleepTime) * time.Second)
		default:
			log.Info("WAS findings export status", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("status", status.Status))
			time.Sleep(time.Duration(sleepTime) * time.Second)
		}
	}

	log.Error("WAS findings export did not complete within timeout period", svc1log.SafeParam("export_uuid", exportUUID))
	return nil, fmt.Errorf("WAS findings export did not complete within timeout period")
}

// checkWasFindingsExportStatus checks the status of a WAS findings export
func checkWasFindingsExportStatus(ctx context.Context, secrets *methodtenablefern.SecretConfig, exportUUID string, config *wasfern.WasFindingsExportConfig) (*apiwasfern.ApiWasFindingsExportStatusResponse, error) {
	log := svc1log.FromContext(ctx)

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/was/v1/export/vulns/%s/status", apiutils.TenableAPIBaseURL, exportUUID), nil)
	if err != nil {
		log.Error("failed to create WAS findings export status request", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to create WAS findings export status request: %w", err)
	}

	apiutils.SetTenableAPIKeyHeader(req, secrets)

	timeout := config.GetTimeout()
	if timeout <= 0 {
		timeout = 30
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("failed to execute WAS findings export status request", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to execute WAS findings export status request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Error("WAS findings export status request failed", svc1log.SafeParam("status", resp.StatusCode), svc1log.SafeParam("body", string(body)))
		return nil, fmt.Errorf("WAS findings export status request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var status apiwasfern.ApiWasFindingsExportStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		log.Error("failed to decode WAS findings export status response", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to decode WAS findings export status response: %w", err)
	}

	err = resp.Body.Close()
	if err != nil {
		log.Error("failed to close response body", svc1log.SafeParam("error", err))
	}

	return &status, nil
}

// downloadAllWasFindingsChunks downloads all the WAS findings export chunks from the Tenable API
func downloadAllWasFindingsChunks(ctx context.Context, secrets *methodtenablefern.SecretConfig, exportUUID string, status *apiwasfern.ApiWasFindingsExportStatusResponse, config *wasfern.WasFindingsExportConfig) ([]*apiwasfern.WasFinding, error) {
	log := svc1log.FromContext(ctx)
	var allFindings []*apiwasfern.WasFinding

	// Get the list of available chunks from the status response
	var availableChunks []int
	if len(status.ChunksAvailable) > 0 {
		availableChunks = status.ChunksAvailable
		log.Info("Got available chunks from status", svc1log.SafeParam("chunks", availableChunks))
	} else {
		log.Error("No chunks available for WAS findings export",
			svc1log.SafeParam("export_uuid", exportUUID),
			svc1log.SafeParam("status", status.Status))
		return nil, fmt.Errorf("no chunks available to download for export %s (potentially because no findings were found using the current filter)", exportUUID)
	}

	// Download each available chunk
	for _, chunkID := range availableChunks {
		chunkData, err := downloadSingleWasFindingsChunk(ctx, secrets, exportUUID, chunkID, config)
		if err != nil {
			log.Error("failed to download WAS findings chunk", svc1log.SafeParam("export_uuid", exportUUID), svc1log.SafeParam("chunk_id", chunkID), svc1log.SafeParam("error", err))
			return nil, err
		}

		if len(chunkData) > 0 {
			allFindings = append(allFindings, chunkData...)
			log.Info("Downloaded WAS findings chunk", svc1log.SafeParam("chunk_id", chunkID), svc1log.SafeParam("findings_count", len(chunkData)))
		}
	}

	log.Info("Successfully downloaded all WAS findings chunks", svc1log.SafeParam("total_findings", len(allFindings)), svc1log.SafeParam("chunks", len(availableChunks)))
	return allFindings, nil
}

// downloadSingleWasFindingsChunk downloads a single WAS findings chunk from the Tenable API
func downloadSingleWasFindingsChunk(ctx context.Context, secrets *methodtenablefern.SecretConfig, exportUUID string, chunkID int, config *wasfern.WasFindingsExportConfig) ([]*apiwasfern.WasFinding, error) {
	log := svc1log.FromContext(ctx)
	url := fmt.Sprintf("%s/was/v1/export/vulns/%s/chunks/%d", apiutils.TenableAPIBaseURL, exportUUID, chunkID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Error("failed to create WAS findings chunk request", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to create WAS findings chunk request: %w", err)
	}

	req.Header.Set("Accept", "application/octet-stream")
	apiutils.SetTenableAPIKeyHeader(req, secrets)

	timeout := config.GetTimeout()
	if timeout <= 0 {
		timeout = 60 // Default longer timeout for chunk downloads
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error("failed to execute WAS findings chunk request", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to execute WAS findings chunk request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Error("WAS findings chunk request failed", svc1log.SafeParam("status", resp.StatusCode), svc1log.SafeParam("body", string(body)))
		return nil, fmt.Errorf("WAS findings chunk request failed with status %d: %s", resp.StatusCode, string(body))
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("failed to read WAS findings chunk response body", svc1log.SafeParam("error", err))
		return nil, fmt.Errorf("failed to read WAS findings chunk response body: %w", err)
	}

	// WAS chunks return application/octet-stream which is typically JSON data
	// Try to parse as JSON array first
	var findings []*apiwasfern.WasFinding
	if err := json.Unmarshal(responseBody, &findings); err != nil {
		log.Error("failed to decode WAS findings chunk response as JSON array",
			svc1log.SafeParam("error", err))

		// Try parsing as newline-delimited JSON (NDJSON)
		lines := strings.Split(string(responseBody), "\n")
		findings = []*apiwasfern.WasFinding{}

		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue // Skip empty lines
			}

			var finding *apiwasfern.WasFinding
			if err := json.Unmarshal([]byte(line), &finding); err != nil {
				log.Error("failed to decode WAS finding line",
					svc1log.SafeParam("line_number", i+1),
					svc1log.SafeParam("error", err),
					svc1log.SafeParam("line_content", line))
				continue // Skip malformed lines
			}
			findings = append(findings, finding)
		}

		if len(findings) == 0 {
			log.Error("no valid findings found in chunk response",
				svc1log.SafeParam("response_body", string(responseBody)))
			return nil, fmt.Errorf("no valid findings found in chunk response")
		}

		log.Info("Successfully parsed NDJSON findings",
			svc1log.SafeParam("findings_count", len(findings)))
	}

	err = resp.Body.Close()
	if err != nil {
		log.Error("failed to close response body", svc1log.SafeParam("error", err))
	}

	log.Info("Downloaded WAS findings chunk", svc1log.SafeParam("chunk_id", chunkID), svc1log.SafeParam("findings_count", len(findings)))
	return findings, nil
}
