# methodtenable

## Overview

methodtenable is designed as a simple, easy to use Tenable Vulnerability Management integration tool that security teams can use to automate the collection and export of vulnerability data. Designed with data-modeling and data-integration needs in mind, methodtenable can be used on its own as an interactive CLI, orchestrated as part of a broader data pipeline, or leveraged from within the Method Platform.

The tool provides comprehensive vulnerability export capabilities from Tenable Vulnerability Management, transforming complex API responses into clean, structured data suitable for analysis, reporting, and integration with other security tools.

## Quick Start

### Installation

For the full list of available installation options, please see the [Installation](./getting-started/installation.md) page. For convenience, here are some of the most commonly used options:

- `docker run methodsecurity/methodtenable`
- `docker run ghcr.io/method-security/methodtenable`
- Download the latest binary from the [Github Releases](https://github.com/Method-Security/methodtenable/releases/latest) page

### Basic Usage

Export critical and high severity vulnerabilities:

```bash
methodtenable vm vulnerability export --severity critical --severity high --state OPEN
```

Export vulnerabilities for specific assets with time filtering:

```bash
methodtenable vm vulnerability export --num-assets 100 --since 2025-01-01T00:00:00Z --severity medium --severity high --severity critical
```

Export asset information:

```bash
methodtenable vm asset export --chunk-size 1000 --has-agent --is-licensed
```

## Key Features

- **Server-side Filtering**: Efficient filtering at the Tenable API level reduces network traffic
- **Structured Output**: Clean, nested JSON format perfect for integration with other tools
- **Comprehensive Data**: Full asset context including network information, OS details, and device classification
- **Risk Intelligence**: CVSS scores, VPR ratings, exploit availability, and patch information
- **Time-based Filtering**: Filter by discovery dates, patch publication dates, and modification times
- **Method Platform Integration**: Native compatibility with Method Security's broader platform

## Command Structure

methodtenable follows standard CLI conventions with clear organization:

```
methodtenable vm
├── asset export          # Export asset data with network and system information
└── vulnerability export  # Export vulnerability data with asset context
```

## Authentication

Set your Tenable API credentials:

```bash
export TENABLE_ACCESS_KEY="your-access-key"
export TENABLE_SECRET_KEY="your-secret-key"
```

Or provide them via command line flags:

```bash
methodtenable vm vulnerability export \
  --access-key "your-access-key" \
  --secret-key "your-secret-key" \
  --severity critical
```

## Output Format

methodtenable exports data in a clean, structured format:

```json
{
  "asset": {
    "hostname": "web-server-01",
    "fqdn": "web-server-01.company.com",
    "ipv4": "192.168.1.100",
    "operating_system": ["Ubuntu 20.04 LTS"],
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
    "severity": "medium",
    "state": "OPEN",
    "cvss3_base_score": 5.3,
    "vpr_score": 6.2,
    "exploit_available": false,
    "solution": "Renew the SSL certificate before expiration date"
  }
}
```

## Next Steps

- **[Installation](./getting-started/installation.md)** - Get started with methodtenable
- **[Basic Usage](./getting-started/basic-usage.md)** - Learn common usage patterns  
- **[Documentation](./docs/index.md)** - Comprehensive documentation and examples
- **[Contributing](./community/community.md)** - Join the community and contribute

## Community

methodtenable is a Method Security open source project. Learn more about Method's open source work by checking out our other projects [here](https://github.com/Method-Security) or our organization wide documentation [here](https://method-security.github.io).

Have an idea for a tool to contribute? Open a discussion [here](https://github.com/Method-Security/Method-Security.github.io/discussions).