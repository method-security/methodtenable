# methodtenable Documentation

## Overview

methodtenable is designed as a simple, easy to use Tenable Vulnerability Management integration tool that security teams can use to automate the collection and export of vulnerability data. Designed with data-modeling and data-integration needs in mind, methodtenable can be used on its own as an interactive CLI, orchestrated as part of a broader data pipeline, or leveraged from within the Method Platform.

The tool provides comprehensive vulnerability export capabilities from Tenable Vulnerability Management, transforming complex API responses into clean, structured data suitable for analysis, reporting, and integration with other security tools.

## Key Features

### Vulnerability Management
- **Comprehensive Export**: Export vulnerability data with full asset context
- **Server-side Filtering**: Efficient filtering at the Tenable API level (severity, state, time-based)
- **Client-side Filtering**: Date-range filtering for precise data selection
- **Structured Output**: Clean, nested JSON format for easy integration
- **Time-based Filtering**: Filter by discovery dates, patch dates, and modification times
- **State Management**: Track vulnerability lifecycle (OPEN, REOPENED, FIXED)

### Asset Management
- **Asset Export**: Export detailed asset information including network data
- **Device Classification**: Support for various device types and operating systems
- **Network Context**: IPv4 addresses, FQDNs, hostnames, and network segmentation
- **Public IP Filtering**: Filter to only include assets with public-facing IP addresses
- **Client-side Filtering**: Filter by tags, hostnames, IPv4/CIDR, operating systems, and date ranges

### Web Application Scanning
- **Findings Export**: Export WAS findings with severity and time-based filtering
- **Server-side Filtering**: Filter by severity, discovery dates, and fix dates
- **Client-side Filtering**: Date-range filtering for precise data selection

### Risk Assessment
- **CVSS Scoring**: Support for CVSS v3 base scores
- **VPR Integration**: Tenable's Vulnerability Priority Rating for better prioritization
- **Exploit Intelligence**: Track exploit availability
- **Patch Management**: Publication dates and remediation guidance

## Command Structure

methodtenable follows the standard CLI Development Conventions with clear organization:

```
methodtenable
├── vm
│   ├── asset export          # Export asset data
│   └── vulnerability export  # Export vulnerability data
└── was
    └── finding export        # Export WAS findings data
```

### Vulnerability Export

The vulnerability export command provides comprehensive filtering and export capabilities:

```bash
methodtenable vm vulnerability export [flags]
```

#### Server-side Filters (Applied at Tenable API)
- `--severity` - Filter by vulnerability severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)
- `--state` - Filter by vulnerability state (OPEN, REOPENED, FIXED)
- `--since` - Include vulnerabilities found or fixed after specified time
- `--last-found` - Filter by last detection time
- `--last-fixed` - Filter by remediation time
- `--first-found` - Filter by initial discovery time
- `--indexed-at` - Filter by indexing time
- `--include-unlicensed` - Include vulnerabilities on unlicensed assets
- `--tag` - Filter by asset tags (Category:Value format)

#### Client-side Filters
- `--between-since` - Date range filter for last_found (RFC3339-RFC3339 format)

#### Configuration
- `--max-wait-time` - Maximum time to wait for export completion (default 600s)
- `--timeout` - HTTP request timeout for API calls (default 30s)
- `--sleep-time` - Delay between API status checks (default 5s)
- `--num-assets` - Number of assets processed per chunk (default 500)
- `--chunk-size` - Number of vulnerabilities per chunk (default 1000)
- `--hide-raw-output` - Exclude raw Tenable API response from output

### Asset Export

Export detailed asset information:

```bash
methodtenable vm asset export [flags]
```

#### Server-side Filters (Applied at Tenable API)
- `--created-at` - Filter by asset creation time
- `--updated-at` - Filter by asset update time
- `--last-assessed` - Filter by last assessment time
- `--deleted-at` - Filter by deletion time
- `--terminated-at` - Filter by termination time
- `--types` - Filter by asset type (default: HOST, WEBAPP)
- `--has-agent` - Include only Nessus Agent assets (overrides --sources)
- `--servicenow-sysid` - Include assets with ServiceNow sysid

#### Client-side Filters
- `--between-updated-at` - Date range filter for updated_at (RFC3339-RFC3339 format)
- `--tags` - Filter by asset tags (Category:Value format)
- `--sources` - Filter by asset source (NESSUS_SCAN, AWS, WAS, etc.)
- `--ips` - Filter by IP address or CIDR range (supports IPv4 and IPv6)
- `--hostnames` - Filter by hostname
- `--operating-systems` - Filter by operating system
- `--public-ip-addresses-only` - Include only assets with public IPs

#### Configuration
- `--max-wait-time` - Maximum time to wait for export completion (default 600s)
- `--timeout` - HTTP request timeout for API calls (default 30s)
- `--sleep-time` - Delay between API status checks (default 5s)
- `--chunk-size` - Number of assets per chunk (default 1000)
- `--hide-raw-output` - Exclude raw Tenable API response from output

### WAS Finding Export

Export web application scanning findings:

```bash
methodtenable was finding export [flags]
```

#### Server-side Filters
- `--severity` - Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- `--since` - Start date for data range
- `--first-found` - Findings first found at or after this time
- `--last-fixed` - Findings fixed at or after this time
- `--last-found` - Findings last found at or after this time

#### Client-side Filters
- `--between-since` - Date range filter for last_found (RFC3339-RFC3339 format)

#### Configuration
- `--max-wait-time` - Maximum time to wait for export completion (default 600s)
- `--timeout` - HTTP request timeout (default 30s)
- `--sleep-time` - Delay between status checks (default 5s)
- `--num-assets` - Number of assets per chunk (default 50)
- `--hide-raw-output` - Exclude raw API response from output

## Output Format

methodtenable exports data in a clean, structured format optimized for analysis and integration:

```json
{
  "asset": {
    "hostname": "web-server-01",
    "fqdn": "web-server-01.company.com",
    "ipv4": "192.168.1.100",
    "ipv6": "2001:db8::1",
    "operating_system": ["Ubuntu 20.04 LTS"],
    "mac_address": "00:50:56:a6:22:93",
    "device_type": "general-purpose",
    "port": {
      "port": 443,
      "protocol": "TCP",
      "service": "https"
    }
  },
  "vulnerability": {
    "name": "SSL Certificate Expiration Check",
    "cve": ["CVE-2023-12345"],
    "description": "The SSL certificate is approaching expiration",
    "severity": "medium",
    "state": "OPEN",
    "cvss3_base_score": 5.3,
    "vpr_score": 6.2,
    "exploit_available": false,
    "patch_publication_date": "2023-12-01T00:00:00Z",
    "solution": "Renew the SSL certificate before expiration date"
  }
}
```

## Configuration

### Authentication

methodtenable supports multiple authentication methods:

**Environment Variables:**
```bash
export TENABLE_ACCESS_KEY="your-access-key"
export TENABLE_SECRET_KEY="your-secret-key"
```

**Command Line Flags:**
```bash
methodtenable vm vulnerability export \
  --access-key "your-access-key" \
  --secret-key "your-secret-key"
```

### Output Options

- **Format**: JSON, YAML, or Signal format (`-o json`, `-o yaml`, `-o signal`)
- **File Output**: Save to file (`-f output.json`) or output to STDOUT (default)
- **Quiet Mode**: Suppress verbose output (`-q`)
- **Verbose Mode**: Enhanced logging and debugging information (`-v`)

## Integration

methodtenable is designed for seamless integration into security workflows:

- **Data Pipelines**: Structured JSON output for automated processing
- **SIEM Integration**: Compatible with major SIEM platforms
- **Ticketing Systems**: Formatted data for vulnerability management workflows
- **Reporting Tools**: Clean data structure for dashboard and report generation
- **Method Platform**: Native integration with Method Security's platform

## Performance Considerations

- **Server-side Filtering**: Reduces network traffic and processing time
- **Chunked Processing**: Handles large datasets efficiently
- **Rate Limiting**: Built-in delays to respect API limits
- **Timeout Management**: Configurable timeouts for different network conditions
- **Error Handling**: Robust error handling with detailed logging
- **Data Integrity**: Warnings for failed/cancelled chunks and unparseable timestamps

## Next Steps

- [Installation Guide](../getting-started/installation.md) - Get started with methodtenable
- [Basic Usage](../getting-started/basic-usage.md) - Learn common usage patterns
- [Community](../community/community.md) - Connect with other users and contributors
