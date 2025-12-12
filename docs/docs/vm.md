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
methodtenable vm asset export --is-licensed --has-agent
```

##### Help Text
```bash
methodtenable vm asset export -h
Export asset data with network and system information

Usage:
  methodtenable vm asset export [flags]

Flags:
      --chunk-size int               Number of assets processed per chunk (recommended max 5000) (default 1000)
      --created-at string            ISO datetime: only assets created at or after this time
      --deleted-at string            ISO datetime: only assets deleted at or after this time  
      --has-agent                    Include only assets with agents
      --hide-raw-output              Hide raw API response data from output
      --hostnames stringArray        Hostname filter (repeatable)
      --ipv4s stringArray           IPv4 address filter (repeatable)
      --is-licensed                 Include only licensed assets
      --last-assessed string        ISO datetime: only assets last_assessed at or after this time
      --max-wait-time int           Maximum wait time for export to complete in seconds
      --operating-systems stringArray Operating system filter (repeatable)
      --servicenow-sysid            Include ServiceNow system ID information
      --sleep-time int              Sleep time between Tenable API calls in seconds (default 5)
      --sources stringArray         Source filter (NESSUS, NESSUS_AGENT, WAS, etc.)
      --tags stringArray            Filter by asset tag in format Category:Value (repeatable)
      --terminated-at string        ISO datetime: only assets terminated at or after this time
      --timeout int                 Timeout for Tenable API requests in seconds (default 30)
      --types stringArray           Asset type filter (WORKSTATION, SERVER, SCANNER, etc.)
      --updated-at string           ISO datetime: only assets updated at or after this time

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
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
Export vulnerability data with asset context

Usage:
  methodtenable vm vulnerability export [flags]

Flags:
      --access-key string        Tenable API Access Key (overrides env TENABLE_ACCESS_KEY)
      --first-found string       Server-side filter: only vulnerabilities first_found at or after this time (e.g., 2025-11-25T16:05:22Z)
      --include-unlicensed       Server-side filter: Include vulnerabilities on unlicensed assets
      --indexed-at string        Server-side filter: only vulnerabilities indexed at or after this time (e.g., 2025-11-25T16:05:22Z)
      --last-fixed string        Server-side filter: only vulnerabilities with last_fixed at or after this time (e.g., 2025-11-25T16:05:22Z)
      --last-found string        Server-side filter: only vulnerabilities with last_found at or after this time (e.g., 2025-11-25T16:05:22Z)
      --max-wait-time int        Client-side config: Maximum wait time for export to complete in seconds
      --num-assets int           Number of assets processed per chunk (recommended max 5000) (default 500)
      --secret-key string        Tenable API Secret Key (overrides env TENABLE_SECRET_KEY)
      --severity stringArray     Server-side filter: Severity filter (low, medium, high, critical)
      --since string             Server-side filter: include vulns last_found or last_fixed at or after this time (e.g., 2025-11-25T16:05:22Z)
      --sleep-time int           Client-side config: Sleep time between Tenable API calls in seconds (default 5)
      --state stringArray        Server-side filter: Vulnerability state filter (OPEN, REOPENED, FIXED)
      --tag stringArray          Server-side filter: Filter by asset tag in format Category:Value (repeatable)
      --timeout int              Client-side config: Timeout for Tenable API requests in seconds (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
