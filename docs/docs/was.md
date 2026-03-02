# WAS

The `methodtenable was` command provides comprehensive integration with Tenable Web Application Scanning for exporting findings data.

## Usage
```bash
methodtenable was [command]
```

## Available Commands

- **finding**: Export findings data from web application scans

## Commands

### Finding Commands

Export findings from Tenable Web Application Scanning with comprehensive filtering options.

#### Export
```bash
methodtenable was finding export --severity CRITICAL --severity HIGH --since 2025-01-01T00:00:00Z
```

##### Help Text
```bash
methodtenable was finding export -h
Export findings from Tenable Web Application Scanning using the WAS
Export API v1. Supports filtering by severity, and time-based fields.
Data is returned in chunks and written locally as JSON.

Usage:
  methodtenable was finding export [flags]

Flags:
      --between-since string     Client-side filter: date range for last_found in RFC3339-RFC3339 format (e.g., 2025-11-25T16:05:22Z-2025-12-01T16:05:22Z)
      --first-found string       Server-side filter: findings first found at or after this time (e.g., 2025-11-25T16:05:22Z)
      --hide-raw-output          Do not include raw output in the report
      --last-fixed string        Server-side filter: findings fixed at or after this time (e.g., 2025-11-25T16:05:22Z)
      --last-found string        Server-side filter: findings last found at or after this time (e.g., 2025-11-25T16:05:22Z)
      --max-wait-time int        Maximum time to wait for export completion in seconds (default 600)
      --num-assets int           Number of assets used to chunk the findings (50-5000) (default 50)
      --severity stringSlice     Server-side filter: severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO) (comma-separated supported)
      --since string             Server-side filter: start date for data range (e.g., 2025-11-25T16:05:22Z)
      --sleep-time int           Time to sleep between status checks in seconds (default 5)
      --timeout int              Timeout for API requests in seconds (default 30)

Global Flags:
      --access-key string    Tenable API Access Key (overrides env TENABLE_ACCESS_KEY)
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --secret-key string    Tenable API Secret Key (overrides env TENABLE_SECRET_KEY)
  -v, --verbose              Verbose output
```
