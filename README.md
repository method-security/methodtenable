<div align="center">
<h1>methodtenable</h1>

[![GitHub Release][release-img]][release]
[![Verify][verify-img]][verify]
[![Go Report Card][go-report-img]][go-report]
[![License: Apache-2.0][license-img]][license]

[![GitHub Downloads][github-downloads-img]][release]
[![Docker Pulls][docker-pulls-img]][docker-pull]

</div>

methodtenable is designed as a simple, easy to use Tenable Vulnerability Management integration tool that security teams can use to automate the collection and export of vulnerability data. Designed with data-modeling and data-integration needs in mind, methodtenable can be used on its own as an interactive CLI, orchestrated as part of a broader data pipeline, or leveraged from within the Method Platform.

The tool provides comprehensive vulnerability export capabilities from Tenable Vulnerability Management, transforming complex API responses into clean, structured data suitable for analysis, reporting, and integration with other security tools.

To learn more about methodtenable, please see the [Documentation site](https://method-security.github.io/methodtenable/) for the most detailed information.

## Quick Start

### Get methodtenable

For the full list of available installation options, please see the [Installation](./docs/getting-started/installation.md) page. For convenience, here are some of the most commonly used options:

- `docker run methodsecurity/methodtenable`
- `docker run ghcr.io/method-security/methodtenable`
- Download the latest binary from the [Github Releases](https://github.com/Method-Security/methodtenable/releases/latest) page
- [Installation documentation](./docs/getting-started/installation.md)

### Examples

```bash
# Export all critical and high severity vulnerabilities
methodtenable vm vulnerability export --severity critical --severity high --state OPEN
```

```bash
# Export vulnerabilities for specific assets with time filtering
methodtenable vm vulnerability export --num-assets 100 --since 2025-01-01T00:00:00Z --severity medium --severity high --severity critical
```

```bash
# Export vulnerabilities with comprehensive filtering
methodtenable vm vulnerability export \
  --severity critical \
  --state OPEN \
  --include-unlicensed \
  --first-found 2024-01-01T00:00:00Z \
  --num-assets 500 \
  -o json \
  -f vulnerabilities.json
```

```bash
# Export asset information
methodtenable vm asset export --chunk-size 1000 --has-agent --is-licensed
```

```bash
# Use custom API credentials
methodtenable vm vulnerability export \
  --access-key "your-access-key" \
  --secret-key "your-secret-key" \
  --severity critical \
  --state OPEN
```

```bash
# Export with wait time and timeout configuration
methodtenable vm vulnerability export \
  --severity high \
  --state OPEN \
  --max-wait-time 300 \
  --timeout 60 \
  --sleep-time 10
```

### Server-side vs Client-side Filtering

methodtenable uses server-side filtering for efficient data retrieval:

**Server-side filters** (applied at Tenable API level):
- `--severity` - Filter by vulnerability severity (low, medium, high, critical)
- `--state` - Filter by vulnerability state (OPEN, REOPENED, FIXED)
- `--since`, `--last-found`, `--first-found` - Time-based filtering
- `--include-unlicensed` - Include vulnerabilities on unlicensed assets
- `--tag` - Filter by asset tags

**Client-side configuration** (controls export behavior):
- `--max-wait-time` - Maximum time to wait for export completion
- `--timeout` - HTTP request timeout for API calls
- `--sleep-time` - Delay between API status checks

### Building a Statically Compiled Container for Local Testing

1. Build the binary: `go build -o methodtenable .`
2. Build container: `docker build -t methodtenable:local .`
3. Run container: `docker run methodtenable:local vm vulnerability export --help`

### Configuration

methodtenable supports multiple ways to provide Tenable API credentials:

- Environment variables: `TENABLE_ACCESS_KEY` and `TENABLE_SECRET_KEY`
- Command line flags: `--access-key` and `--secret-key`
- Configuration files (see documentation for details)

### Output Formats

Vulnerability data is exported in a clean, structured format:

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

## Contributing

Interested in contributing to methodtenable? Please see our organization wide [Contribution](https://method-security.github.io/community/contribute/discussions.html) page.

## Want More?

If you're looking for an easy way to tie methodtenable into your broader cybersecurity workflows, or want to leverage some autonomy to improve your overall security posture, you'll love the broader Method Platform.

For more information, visit us [here](https://method.security)

## Community

methodtenable is a Method Security open source project.

Learn more about Method's open source source work by checking out our other projects [here](https://github.com/Method-Security) or our organization wide documentation [here](https://method-security.github.io).

Have an idea for a Tool to contribute? Open a Discussion [here](https://github.com/Method-Security/Method-Security.github.io/discussions).

[verify]: https://github.com/Method-Security/methodtenable/actions/workflows/verify.yml
[verify-img]: https://github.com/Method-Security/methodtenable/actions/workflows/verify.yml/badge.svg
[go-report]: https://goreportcard.com/report/github.com/Method-Security/methodtenable
[go-report-img]: https://goreportcard.com/badge/github.com/Method-Security/methodtenable
[release]: https://github.com/Method-Security/methodtenable/releases
[releases]: https://github.com/Method-Security/methodtenable/releases/latest
[release-img]: https://img.shields.io/github/release/Method-Security/methodtenable.svg?logo=github
[github-downloads-img]: https://img.shields.io/github/downloads/Method-Security/methodtenable/total?logo=github
[docker-pulls-img]: https://img.shields.io/docker/pulls/methodsecurity/methodtenable?logo=docker&label=docker%20pulls%20%2F%20methodtenable
[docker-pull]: https://hub.docker.com/r/methodsecurity/methodtenable
[license]: https://github.com/Method-Security/methodtenable/blob/main/LICENSE
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg