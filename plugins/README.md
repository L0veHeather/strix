# Strix Built-in Plugins

This directory contains the built-in security scanner plugins for Strix.

## Plugin Structure

Each plugin consists of:
- `manifest.yaml` - Plugin metadata, parameters, and configuration
- `plugin.py` - Python implementation

## Available Plugins

### Reconnaissance Phase
- **httpx** - HTTP probe and web server detection

### Enumeration Phase
- **ffuf** - Fast web fuzzer for content discovery
- **katana** - Web crawler for URL discovery

### Vulnerability Scanning Phase
- **nuclei** - Template-based vulnerability scanner
- **sqlmap** - SQL injection detection and exploitation

## Adding New Plugins

1. Create a new directory under `plugins/`
2. Add `manifest.yaml` with plugin metadata
3. Implement `plugin.py` extending `BasePlugin`
4. The plugin will be auto-discovered on startup
