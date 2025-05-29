# AUR Version Checker

A Go CLI utility that checks if your local Arch User Repository (AUR) packages have newer versions available in their upstream repositories.

## Purpose

This tool helps maintainers and users of AUR packages to:
- Scan local directories containing PKGBUILD files
- Extract version information from the PKGBUILDs
- Check upstream repositories (primarily GitHub) for newer versions
- Report which packages need updating and what versions are available

## Features

- Parses PKGBUILD files to extract package name and version
- Queries GitHub repositories to find the latest available version
- Supports semantic versioning comparison
- Handles multiple AUR package directories in a workspace
- Provides clear reports on which packages need updates

## Usage

```bash
# Check all AUR packages in the current directory
aur-checker

# Check specific AUR package directories
aur-checker /path/to/package1 /path/to/package2

# Show detailed version information
aur-checker --verbose

# Display help
aur-checker --help
```

## Installation

```bash
go install github.com/brianrobt/aur-version-checker/cmd/aur-checker@latest
```

## License

MIT

