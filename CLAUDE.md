# methodtenable Project Context

## Overview

**methodtenable** is a CLI tool for automating the collection and export of vulnerability data from Tenable Vulnerability Management (VM) and Web Application Scanning (WAS). It's designed for security teams to integrate Tenable data into broader data pipelines, analysis workflows, and the Method Security Platform.

**Key Capabilities:**
- Export VM vulnerabilities with comprehensive filtering (severity, state, time-based)
- Export VM asset information with agent and licensing filters
- Export WAS findings
- Multiple output formats (JSON, YAML, Signal format)
- Server-side filtering for efficient API usage
- Configurable timeouts, retries, and polling behavior

**Language:** Go 1.24.4  
**Organization:** Method Security (open source)  
**License:** Apache 2.0

---

## Architecture & Structure

### High-Level Architecture

```
┌─────────────────┐
│   main.go       │ - Entry point, version injection
└────────┬────────┘
         │
         v
┌─────────────────┐
│   cmd/          │ - Cobra CLI commands (root, vm, was)
│                 │ - Flag parsing, I/O handling
│                 │ - Pre-run/Post-run hooks
└────────┬────────┘
         │
         v
┌─────────────────┐
│   internal/     │ - Core business logic
│                 │ - API orchestration
│                 │ - Data processing
└────────┬────────┘
         │
         v
┌─────────────────┐
│   utils/api/    │ - Tenable API client wrappers
│                 │ - HTTP request/response handling
└────────┬────────┘
         │
         v
┌─────────────────┐
│   generated/    │ - Fern-generated code (Go, Python SDKs)
│                 │ - Type definitions, API clients
└─────────────────┘
```

### Directory Structure

```
.
├── cmd/                    # CLI commands (Cobra-based)
│   ├── root.go            # Root command, output config, credential setup
│   ├── vm.go              # VM vulnerability/asset export commands
│   └── was.go             # WAS finding export commands
│
├── internal/              # Core business logic (NOT imported externally)
│   ├── config/           # Configuration management, logging
│   ├── vm/               # VM-specific export logic
│   │   ├── asset/
│   │   └── vulnerability/
│   └── was/              # WAS-specific export logic
│       └── finding/
│
├── utils/api/             # API client utilities
│   ├── constants.go      # API endpoints, defaults
│   ├── vm/               # VM API wrappers
│   │   ├── asset/
│   │   └── vulnerability/
│   └── was/              # WAS API wrappers
│       └── finding/
│
├── generated/             # Fern-generated code (DO NOT EDIT MANUALLY)
│   ├── go/               # Go SDK
│   └── python/           # Python SDK
│
├── fern/                  # Fern API definitions
│   └── definition/       # YAML API specs
│       ├── vm/
│       └── was/
│
├── docs/                  # Documentation (MkDocs)
└── vendor/                # Go vendored dependencies
```

---

## Key Concepts & Patterns

### 1. **Pre-run → Run → Post-run Pattern**

Every Cobra command follows this lifecycle (defined in `cmd/root.go`):

- **`PersistentPreRunE`**: Initialize output configuration, set up logging, load credentials from environment/flags
- **`Run`**: Execute command logic, populate `OutputSignal.Content` with results
- **`PersistentPostRunE`**: Write output to file/STDOUT in the specified format

**Important:** All commands MUST write their results to `a.OutputSignal.Content` for proper output handling.

### 2. **Separation: cmd vs internal**

- **`cmd/`**: Focus on CLI concerns (flag parsing, validation, I/O)
- **`internal/`**: Focus on business logic (API calls, data transformation, orchestration)

**Rule:** Keep `cmd/*.go` files thin. Delegate heavy lifting to `internal/` packages.

### 3. **Credential Management**

Credentials are loaded in priority order (highest to lowest):
1. Command-line flags (`--access-key`, `--secret-key`)
2. Environment variables (`TENABLE_ACCESS_KEY`, `TENABLE_SECRET_KEY`)

Credentials are stored in `a.SecretConfig` and retrieved via `a.GetTenableSecretConfig()`.

### 4. **Server-side vs Client-side Filtering**

- **Server-side filters**: Applied at Tenable API level (e.g., `--severity`, `--state`, `--since`)
- **Client-side config**: Controls tool behavior (e.g., `--max-wait-time`, `--timeout`, `--sleep-time`)

### 5. **Output Formats**

Supported formats (via `--output` or `-o` flag):
- **`signal`** (default): Method Security's structured signal format (includes `started_at`, `completed_at`, `status`, `content`)
- **`json`**: Raw JSON output
- **`yaml`**: YAML output

Output can go to STDOUT (default) or a file (`--output-file` or `-f` flag).

### 6. **Error Handling**

- Use `svc1log` (witchcraft-go-logging) for structured logging
- Return errors from `RunE` functions (Cobra handles exit codes)
- Set `a.OutputSignal.ErrorMessage` for errors that should be in output signal

---

## Code Organization

### Command Structure (cmd/)

**`cmd/root.go`:**
- Root command initialization
- Global flags (`--quiet`, `--verbose`, `--output`, `--output-file`, `--access-key`, `--secret-key`)
- Output configuration and signal management
- Version command

**`cmd/vm.go`:**
- VM parent command
- Subcommands:
  - `vm vulnerability export`: Export vulnerabilities with filtering
  - `vm asset export`: Export asset data

**`cmd/was.go`:**
- WAS parent command
- Subcommands:
  - `was finding export`: Export web app findings

### Internal Logic (internal/)

**`internal/config/`:**
- `config.go`: Root flags, configuration structs
- `initialization.go`: Logging setup

**`internal/vm/`:**
- `asset/export.go`: Asset export orchestration
- `vulnerability/export.go`: Vulnerability export orchestration

**`internal/was/`:**
- `finding/export.go`: WAS finding export orchestration

### API Utilities (utils/api/)

**`utils/api/constants.go`:**
- API base URLs
- Default values (timeouts, retry limits)

**`utils/api/vm/` and `utils/api/was/`:**
- Thin wrappers around generated Fern clients
- Handle pagination, polling, export status checks
- Transform API responses into tool output format

### Generated Code (generated/)

**DO NOT EDIT MANUALLY**

Generated from Fern API definitions in `fern/definition/`:
- `generated/go/`: Go SDK (types, client)
- `generated/python/`: Python SDK

To regenerate:
```bash
# Typically done via CI/CD or Fern CLI
fern generate
```

---

## Development Guidelines

### Adding a New Command

1. **Define API spec** in `fern/definition/` (if new endpoint)
2. **Regenerate code** with `fern generate`
3. **Add command** in `cmd/` (e.g., `cmd/vm.go`)
4. **Implement logic** in `internal/` (e.g., `internal/vm/newfeature/export.go`)
5. **Add API wrapper** in `utils/api/` (e.g., `utils/api/vm/newfeature/export.go`)
6. **Update docs** in `docs/` (MkDocs)

### Coding Standards

- **Go formatting**: Use `gofmt` or `godel format`
- **Linting**: Run `godel check` (configured in `godel/config/`)
- **Testing**: Write tests for `internal/` logic (unit tests)
- **Vendor management**: Use `go mod vendor` to keep `vendor/` in sync

### Common Patterns

**Polling for export completion:**
```go
for {
    status, err := checkExportStatus(exportUUID)
    if err != nil {
        return err
    }
    if status == "FINISHED" {
        break
    }
    time.Sleep(sleepDuration)
}
```

**Pagination:**
```go
for hasMore {
    response, err := client.GetPage(offset, limit)
    if err != nil {
        return err
    }
    results = append(results, response.Items...)
    offset += limit
    hasMore = response.HasMore
}
```

---

## Common Tasks & Workflows

### Building the Binary

```bash
go build -o methodtenable .
```

### Running Tests

```bash
go test ./...
# or using godel
./godelw test
```

### Building Docker Image

```bash
# Production image
docker build -t methodtenable:local .

# Builder image (multi-stage)
docker build -f Dockerfile.builder -t methodtenable:builder .
```

### Running Locally

```bash
# Export vulnerabilities
export TENABLE_ACCESS_KEY="your-key"
export TENABLE_SECRET_KEY="your-secret"
./methodtenable vm vulnerability export --severity critical --state OPEN

# Export assets
./methodtenable vm asset export --has-agent --is-licensed -o json
```

### Updating Documentation

```bash
cd docs
pip install -r build/requirements.txt
mkdocs serve  # Preview at http://localhost:8000
mkdocs build  # Generate static site in site/
```

---

## Testing & Quality

### Test Files

- Unit tests: `*_test.go` files alongside implementation
- Example: `generated/go/client/client_test.go`

### Quality Tools (godel)

Configured in `godel/config/`:
- **Format**: `./godelw format` (gofmt)
- **Check**: `./godelw check` (linting)
- **Test**: `./godelw test`
- **Build**: `./godelw build`

### CI/CD

- **Verify workflow**: `.github/workflows/verify.yml` (likely)
- Runs on PRs: build, test, lint
- Release workflow: Builds binaries, Docker images, publishes to GitHub Releases & S3

---

## Important Files & Directories

### Configuration Files

- **`go.mod`**: Go module definition, dependencies
- **`godel/config/`**: Build/test/lint configuration
- **`fern/fern.config.json`**: Fern code generation config
- **`mkdocs.yml`**: Documentation site configuration
- **`Dockerfile`**: Production container image
- **`Dockerfile.builder`**: Multi-stage builder image

### Documentation

- **`README.md`**: User-facing README (installation, examples)
- **`docs/`**: MkDocs documentation source
  - `getting-started/`: Installation, basic usage
  - `development/`: Development setup, principles, adding features
  - `docs/`: Command-specific docs (vm.md, was.md)
- **`site/`**: Generated static documentation site (DO NOT EDIT)

### Scripts

- **`scripts/upload-release-to-s3.sh`**: Release artifact upload

### Vendor

- **`vendor/`**: Go dependencies (vendored)
- **`vendor/modules.txt`**: Vendor manifest

---

## API Credentials & Secrets

### Required Environment Variables

```bash
export TENABLE_ACCESS_KEY="your-access-key"
export TENABLE_SECRET_KEY="your-secret-key"
```

### Command-Line Override

```bash
methodtenable vm vulnerability export \
  --access-key "override-key" \
  --secret-key "override-secret" \
  --severity critical
```

### Secret Configuration

Managed in `cmd/root.go`:
```go
a.SecretConfig = methodtenablefern.SecretConfig{
    AccessKey: &assetKey,
    SecretKey: &assetSecret,
}
```

---

## Key Dependencies

### External Libraries

- **Cobra** (`spf13/cobra`): CLI framework
- **Witchcraft-go-logging** (`palantir/witchcraft-go-logging`): Structured logging
- **Method Security pkg** (`Method-Security/pkg`): Shared utilities (writer, signal)
- **UUID** (`google/uuid`): UUID generation

### Internal Generated Code

- **Fern-generated SDK** (`generated/go`): Type-safe API client

---

## Troubleshooting & Gotchas

### Common Issues

1. **"access key or secret key not configured"**
   - Ensure `TENABLE_ACCESS_KEY` and `TENABLE_SECRET_KEY` are set
   - Or pass `--access-key` and `--secret-key` flags

2. **Export timeout**
   - Increase `--max-wait-time` (default varies by command)
   - Increase `--timeout` for individual HTTP requests

3. **Rate limiting**
   - Adjust `--sleep-time` (delay between status checks)
   - Reduce `--chunk-size` for asset exports

4. **Empty output**
   - Check filters (e.g., `--severity`, `--state`)
   - Verify credentials have proper permissions
   - Use `--verbose` for detailed logging

### Debugging Tips

- **Enable verbose logging**: `--verbose` or `-v`
- **Check Tenable API status**: https://status.tenable.com
- **Inspect raw API responses**: Add debug logging in `utils/api/` wrappers

---

## Contributing

See organization-wide contribution guidelines:
- **Discussions**: https://github.com/Method-Security/Method-Security.github.io/discussions
- **Community docs**: https://method-security.github.io

### Pull Request Checklist

- [ ] Run `./godelw format` and `./godelw check`
- [ ] Add/update tests for new functionality
- [ ] Update documentation in `docs/`
- [ ] Verify builds: `go build -o methodtenable .`
- [ ] Test Docker image: `docker build -t methodtenable:test .`

---

## Additional Resources

- **Documentation Site**: https://method-security.github.io/methodtenable/
- **GitHub Repository**: https://github.com/Method-Security/methodtenable
- **Method Security**: https://method.security
- **Tenable API Docs**: https://developer.tenable.com

---

## Notes for AI Assistants

When working on this codebase:

1. **Respect the cmd/internal separation**: Keep CLI logic in `cmd/`, business logic in `internal/`
2. **Follow the pre-run/run/post-run pattern**: Always populate `OutputSignal.Content` in command `Run` functions
3. **Never edit generated code**: Files in `generated/` are auto-generated from Fern definitions
4. **Use structured logging**: Import and use `svc1log` for logging, not `fmt.Println`
5. **Handle errors gracefully**: Return errors from `RunE`, set `OutputSignal.ErrorMessage` for output
6. **Test API interactions**: Consider adding integration tests for new API wrappers
7. **Update docs**: If you add/change commands, update `docs/` and regenerate with `mkdocs build`
8. **Vendor dependencies**: Run `go mod vendor` after adding new dependencies

**Key Files to Reference:**
- Command structure: `cmd/root.go`, `cmd/vm.go`
- Config/logging: `internal/config/config.go`, `internal/config/initialization.go`
- API patterns: `utils/api/vm/vulnerability/export.go`
- Data models: `generated/go/` (read-only reference)
