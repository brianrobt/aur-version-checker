package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/brianrobt/aur-version-checker/internal/pkgbuild"
	"github.com/brianrobt/aur-version-checker/internal/versioncheck"
)

const helpText = `AUR Version Checker
==================
Checks AUR packages for available updates.

Environment Variables:
  GITHUB_TOKEN    GitHub API token to avoid rate limiting
`

// Result holds the version checking result for a package
type Result struct {
	PackageName     string
	LocalVersion    string
	UpstreamVersion string
	NeedsUpdate     bool
	UpstreamURL     string
	Error           error
}

func main() {
	// Parse command-line flags
	verbose := flag.Bool("verbose", false, "Show detailed information about version checking")
	concurrent := flag.Int("concurrent", 5, "Number of concurrent version checks")
	help := flag.Bool("help", false, "Show help information")
	flag.Parse()

	// Show help if requested
	if *help {
		fmt.Println(helpText)
		flag.PrintDefaults()
		os.Exit(0)
	}

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

	// Resolve any relative paths to absolute paths
	for i, dir := range dirs {
		if !filepath.IsAbs(dir) {
			absDir, err := filepath.Abs(dir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not resolve absolute path for %s: %v\n", dir, err)
				continue
			}
			dirs[i] = absDir
		}
	}

	fmt.Println("AUR Version Checker")
	fmt.Println("==================")
	
	// Step 1: Find all packages
	fmt.Println("Finding PKGBUILD files...")
	packages, err := pkgbuild.ListPackages(dirs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to list packages: %v\n", err)
		os.Exit(1)
	}

	if len(packages) == 0 {
		fmt.Println("No PKGBUILD files found in the specified directories.")
		os.Exit(0)
	}

	fmt.Printf("Found %d packages. Checking for updates...\n\n", len(packages))

	// Step 2: Check for updates
	results := checkVersions(packages, *concurrent)
	
	// Step 3: Display results
	displayResults(results, *verbose)
}

// checkVersions checks if there are newer versions available for each package
func checkVersions(packages map[string]*pkgbuild.Package, concurrency int) []Result {
	results := make([]Result, 0, len(packages))
	resultsChan := make(chan Result, len(packages))
	var wg sync.WaitGroup

	// Create a worker pool
	jobs := make(chan *pkgbuild.Package, len(packages))

	// Start workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pkg := range jobs {
				versionInfo, err := versioncheck.CheckVersion(pkg)
				if err != nil {
					resultsChan <- Result{
						PackageName:  pkg.Name,
						LocalVersion: pkg.Version,
						Error:        err,
					}
					continue
				}

				resultsChan <- Result{
					PackageName:     pkg.Name,
					LocalVersion:    pkg.Version,
					UpstreamVersion: versionInfo.UpstreamVersion,
					NeedsUpdate:     versionInfo.NeedsUpdate,
					UpstreamURL:     versionInfo.UpstreamURL,
					Error:           nil,
				}
			}
		}()
	}

	// Send jobs to workers
	for _, pkg := range packages {
		jobs <- pkg
	}
	close(jobs)

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	for result := range resultsChan {
		results = append(results, result)
	}

	// Sort results by package name for consistent output
	sort.Slice(results, func(i, j int) bool {
		return results[i].PackageName < results[j].PackageName
	})

	return results
}

// displayResults shows the results of the version checks
func displayResults(results []Result, verbose bool) {
	var updatesAvailable, errors, upToDate int

	// Count statistics
	for _, result := range results {
		if result.Error != nil {
			errors++
		} else if result.NeedsUpdate {
			updatesAvailable++
		} else {
			upToDate++
		}
	}

	// Display update information
	if updatesAvailable > 0 {
		fmt.Println("Updates Available:")
		fmt.Println("------------------")
		for _, result := range results {
			if result.Error == nil && result.NeedsUpdate {
				fmt.Printf("• %s: %s → %s", 
					result.PackageName, 
					result.LocalVersion, 
					result.UpstreamVersion)
				
				if verbose {
					fmt.Printf(" (%s)", result.UpstreamURL)
				}
				fmt.Println()
			}
		}
		fmt.Println()
	}

	// Display errors if any
	if errors > 0 && verbose {
		fmt.Println("Errors:")
		fmt.Println("-------")
		for _, result := range results {
			if result.Error != nil {
				fmt.Printf("• %s: %v\n", result.PackageName, result.Error)
			}
		}
		fmt.Println()
	}

	// Display up-to-date packages if verbose
	if upToDate > 0 && verbose {
		fmt.Println("Up-to-date Packages:")
		fmt.Println("-------------------")
		for _, result := range results {
			if result.Error == nil && !result.NeedsUpdate {
				fmt.Printf("• %s: %s\n", result.PackageName, result.LocalVersion)
			}
		}
		fmt.Println()
	}

	// Display summary
	fmt.Println("Summary:")
	fmt.Printf("• %d packages checked\n", len(results))
	fmt.Printf("• %d updates available\n", updatesAvailable)
	fmt.Printf("• %d packages up-to-date\n", upToDate)
	if errors > 0 {
		fmt.Printf("• %d errors\n", errors)
		if !verbose {
			fmt.Println("\nRun with --verbose for error details")
		}
	}
}

