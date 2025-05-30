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

## Example output

```bash
AUR Version Checker
==================
Finding PKGBUILD files...
Warning: Could not parse PKGBUILD in /Users/brian/workspace/aur/rapidyaml-aur: missing required fields in PKGBUILD (pkgname or pkgver)
Found 18 packages. Checking for updates...

Updates Available:
------------------
• openmohaa: 0.81.1.r386.gfa18824 → main-44d745d (https://github.com/openmoh/openmohaa)
• proton-pass: 1.23.0 → 1.23.1 (https://proton.me/download/PassDesktop/linux/x64/proton-pass_1.23.1_amd64.deb)
• python-conda: 25.3.1 → 25.5.0 (https://github.com/conda/conda)
• python-conda-libmamba-solver: 25.4.0 → 25.5.0 (https://github.com/conda/conda)
• python-typed-ast: 1.5.5 → do-3.9-builds-for-1.4.1 (https://github.com/python/typed_ast)
• rot8: 1.0.0+r109+g6a51f7cdf → master-6a51f7c (https://github.com/efernau/rot8)
• stable-diffusion.cpp-vulkan: r191.d46ed5e → main-21f890f (https://github.com/CompVis/stable-diffusion)

Errors:
-------
• kpeople5: unable to determine upstream repository
• python-npyscreen: failed to get BitBucket version: BitBucket API returned status code 404

Up-to-date Packages:
-------------------
• arduino-avr-core: 1.8.6
• gnome-shell-extension-panel-osd: 1.0
• micromamba: 2.1.1
• outwiker: 3.3.0
• python-${_pkg,,}: 0.5.0
• python-hunspell: 0.5.5
• python-jproperties: 2.1.2
• python-libmamba: 2.1.1
• python-pytest-freezegun: 0.4.2

Summary:
• 18 packages checked
• 7 updates available
• 9 packages up-to-date
• 2 errors
```

## Installation

```bash
go install github.com/brianrobt/aur-version-checker/cmd/aur-checker@latest
```

## License

MIT

