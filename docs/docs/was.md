# WAS

The `methodtenable was` command provides comprehensive integration with Tenable Web Application Scanning for exporting findings data.

## Usage
```bash
methodtenable was [command]
```

## Available Commands

- **findings**: Export findings data from web application scans

## Commands

### Findings Commands

Export findings from Tenable Web Application Scanning with comprehensive filtering options.

#### Export
```bash
methodtenable was findings export --severity CRITICAL --severity HIGH --since 1609459200
```

##### Help Text
```bash
methodtenable was findings export -h
Export findings from Tenable Web Application Scanning

Usage:
  methodtenable was findings export [flags]

Flags:
      --access-key string        Tenable API Access Key (overrides env TENABLE_ACCESS_KEY)
      --first-found string       Server-side filter: findings first found at or after this Unix timestamp (e.g., 1609459200)
      --last-fixed string        Server-side filter: findings fixed at or after this Unix timestamp (e.g., 1609459200)
      --last-found string        Server-side filter: findings last found at or after this Unix timestamp (e.g., 1609459200)
      --max-wait-time int        Maximum time to wait for export completion (seconds)
      --num-assets int           Number of assets used to chunk the findings (50-5000) (default 50)
      --secret-key string        Tenable API Secret Key (overrides env TENABLE_SECRET_KEY)
      --severity stringSlice     Server-side filter: severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
      --since string             Server-side filter: start date for data range in Unix timestamp (e.g., 1609459200)
      --sleep-time int           Time to sleep between status checks (seconds) (default 5)
      --timeout int              Timeout for API requests in seconds (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```