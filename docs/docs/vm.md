# VM

The `methodtenable vm` command provides comprehensive integration with Tenable Vulnerability Management for exporting vulnerability and asset data.

## Usage
```bash
methodtenable vm [command]
```

## Available Commands

- **asset**: Export asset data with network and system information
- **vulnerability**: Export vulnerability data with asset context

## Commands

### Asset Commands

Export detailed asset information from Tenable Vulnerability Management.

#### Export
```bash
methodtenable vm asset export --has-agent
```

##### Help Text
```bash
methodtenable vm asset export -h
Export assets from Tenable Vulnerability Management using the Asset
Export API v2. Supports filtering by time-based fields such as created_at,
updated_at, last_seen, deleted_at, and terminated_at. Also supports filtering
by tags, sources, IPv4 addresses, hostnames, and operating systems. Data is
returned in chunks and written locally as JSON.

Usage:
  methodtenable vm asset export [flags]

Flags:
      --between-updated-at string    Client-side filter: date range for updated_at in RFC3339-RFC3339 format (e.g., 2025-11-25T16:05:22Z-2025-12-01T16:05:22Z)
      --chunk-size int               Number of assets processed per chunk (recommended max 5000) (default 1000)
      --created-at string            ISO datetime: only assets created at or after this time (e.g., 2025-11-25T16:05:22Z)
      --deleted-at string            ISO datetime: only assets deleted at or after this time (e.g., 2025-11-25T16:05:22Z)
      --has-agent                    Server-side filter: Include only assets scanned by a Nessus Agent. This overrides the sources filter and sets it to NESSUS_AGENT.
      --hide-raw-output              Do not include raw output in the report
      --hostnames stringSlice        Client-side filter: Filter by hostname (repeatable, comma-separated supported)
      --ips stringSlice               Client-side filter: Filter by IP address or CIDR, supports both IPv4 and IPv6 (repeatable, comma-separated supported)
      --last-assessed string         ISO datetime: only assets last_assessed (last seen) at or after this time (e.g., 2025-11-25T16:05:22Z)
      --max-wait-time int            Maximum wait time for export to complete in seconds (default 600)
      --operating-systems stringSlice Client-side filter: Filter by operating system value (repeatable, comma-separated supported)
      --public-ip-addresses-only     Client-side filter: Include only assets with public IP addresses (excludes RFC 3330 special-use addresses)
      --servicenow-sysid             Server-side filter: Include assets with a ServiceNow sysid
      --sleep-time int               Sleep time between Tenable API calls in seconds (default 5)
      --sources stringSlice          Client-side filter: Filter by asset source (e.g., NESSUS_SCAN, AWS, WAS) (comma-separated supported)
      --tags stringSlice             Client-side filter: Filter by asset tag in format Category:Value (repeatable, comma-separated supported)
      --terminated-at string         ISO datetime: only assets terminated at or after this time (e.g., 2025-11-25T16:05:22Z)
      --timeout int                  Timeout for Tenable API requests in seconds (default 30)
      --types stringSlice            Server-side filter: Filter by asset type (e.g., HOST, WEBAPP) (repeatable, comma-separated supported) (default [HOST,WEBAPP])
      --updated-at string            ISO datetime: only assets updated at or after this time (e.g., 2025-11-25T16:05:22Z)

Global Flags:
      --access-key string    Tenable API Access Key (overrides env TENABLE_ACCESS_KEY)
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --secret-key string    Tenable API Secret Key (overrides env TENABLE_SECRET_KEY)
  -v, --verbose              Verbose output
```

### Vulnerability Commands

Export comprehensive vulnerability data with full asset context from Tenable Vulnerability Management.

#### Export
```bash
methodtenable vm vulnerability export --severity critical --severity high --state OPEN
```

##### Help Text
```bash
methodtenable vm vulnerability export -h
Export vulnerabilities from Tenable Vulnerability Management using the Vulnerability
Export API. Supports filtering by state, severity, tags, and time-based fields such
as last_found, last_fixed, and first_found. Data is returned in chunks and written
locally as JSON.

Usage:
  methodtenable vm vulnerability export [flags]

Flags:
      --between-since string     Client-side filter: date range for since in RFC3339-RFC3339 format (e.g., 2025-11-25T16:05:22Z-2025-12-01T16:05:22Z)
      --chunk-size int           Number of vulnerabilities processed per chunk (recommended max 5000) (default 1000)
      --first-found string       Server-side filter: only vulnerabilities first_found at or after this time (e.g., 2025-11-25T16:05:22Z)
      --hide-raw-output          Do not include raw output in the report
      --include-unlicensed       Server-side filter: Include vulnerabilities on unlicensed assets
      --indexed-at string        Server-side filter: only vulnerabilities indexed at or after this time (e.g., 2025-11-25T16:05:22Z)
      --last-fixed string        Server-side filter: only vulnerabilities with last_fixed at or after this time (e.g., 2025-11-25T16:05:22Z)
      --last-found string        Server-side filter: only vulnerabilities with last_found at or after this time (e.g., 2025-11-25T16:05:22Z)
      --max-wait-time int        Maximum wait time for export to complete in seconds (default 600)
      --num-assets int           Specifies the number of assets used to chunk the vulnerabilities (recommended max 5000, min of 50) (default 500)
      --severity stringSlice     Server-side filter: Severity filter (INFO, LOW, MEDIUM, HIGH, CRITICAL) (comma-separated supported)
      --since string             Server-side filter: include vulns last_found or last_fixed at or after this time (e.g., 2025-11-25T16:05:22Z)
      --sleep-time int           Sleep time between Tenable API calls in seconds (default 5)
      --state stringSlice        Server-side filter: Vulnerability state filter (OPEN, REOPENED, FIXED) (comma-separated supported)
      --tag stringSlice          Server-side filter: Filter by asset tag in format Category:Value (repeatable, comma-separated supported)
      --timeout int              Timeout for Tenable API requests in seconds (default 30)

Global Flags:
      --access-key string    Tenable API Access Key (overrides env TENABLE_ACCESS_KEY)
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
      --secret-key string    Tenable API Secret Key (overrides env TENABLE_SECRET_KEY)
  -v, --verbose              Verbose output
```
