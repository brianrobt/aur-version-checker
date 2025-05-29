package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/brianrobt/aur-version-checker/internal/pkgbuild"
	"github.com/brianrobt/aur-version-checker/internal/versioncheck"
)

func main() {
	verbose := flag.Bool("verbose", false, "Show detailed information about version checking")
	flag.Parse()

	// Get directories to check, default to current directory if none specified
	dirs := flag.Args()
	if len(dirs) == 0 {
		currentDir, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to get current directory: %v\n", err)
			os.Exit(1)
		}
		dirs = []string{currentDir}
	}

	fmt.Println("AUR Version Checker")
	fmt.Println("==================")
	fmt.Println("Checking for updates in AUR packages...")

	// TODO: Implement the actual checking logic
	// 1. Find all directories containing PKGBUILD files
	// 2. Parse each PKGBUILD to get package name and version
	// 3. Check upstream repositories for newer versions
	// 4. Report results

	fmt.Println("\nNot yet implemented. The completed version will:")
	fmt.Println("- Scan directories for PKGBUILD files")
	fmt.Println("- Extract version information")
	fmt.Println("- Compare with upstream repositories")
	fmt.Println("- Report which packages need updates")
}

