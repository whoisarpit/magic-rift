# Rift Tests

This directory contains automated tests for cross-platform compatibility, with a focus on Windows.

## Running Tests Locally

```bash
# Install dev dependencies
uv sync --dev

# Run all tests
uv run pytest tests/ -v

# Run with coverage
uv run pytest tests/ --cov=rift --cov-report=term-missing
```

## Test Structure

### `test_platform_compat.py`
Cross-platform compatibility tests for Windows, Linux, and macOS:

- **Config & Cert Directory Creation**: Validates path handling across different OS file systems
- **File Path Validation**: Tests long path handling and file validation
- **Network Functions**: Local IP detection, gateway discovery (with platform-specific fallbacks)
- **Port Forwarding Methods**: Validates all connection methods can be instantiated
- **Rate Limiting**: Cross-platform security features
- **Logging & Color Support**: Terminal output compatibility

## GitHub Actions

The `.github/workflows/test.yml` workflow automatically tests on:
- **Ubuntu Latest** (Python 3.8, 3.12)
- **Windows Latest** (Python 3.8, 3.12)
- **macOS Latest** (Python 3.8, 3.12)

This ensures rift.py works correctly across all major platforms.

## Key Windows Compatibility Concerns

1. **Config Directory**: Uses `~/.config/rift/` on Unix, needs to work with Windows paths
2. **Gateway Detection**: Falls back from `/proc/net/route` (Linux) to `netstat` (cross-platform)
3. **File Permissions**: Uses `chmod` with appropriate fallback handling
4. **Path Separators**: All paths use `pathlib.Path` for cross-platform compatibility
5. **ANSI Colors**: Properly detects Windows terminal capabilities
