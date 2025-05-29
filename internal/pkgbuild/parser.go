package pkgbuild

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Package represents the parsed information from a PKGBUILD file
type Package struct {
	Name             string
	Version          string
	URL              string
	Description      string
	SourceRepository string // Derived from URL or source fields
}

// Parse reads a PKGBUILD file and extracts relevant information
func Parse(pkgbuildPath string) (*Package, error) {
	file, err := os.Open(pkgbuildPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	pkg := &Package{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "pkgname=") {
			pkg.Name = extractValue(line, "pkgname=")
		} else if strings.HasPrefix(line, "pkgver=") {
			pkg.Version = extractValue(line, "pkgver=")
		} else if strings.HasPrefix(line, "url=") {
			pkg.URL = extractValue(line, "url=")
		} else if strings.HasPrefix(line, "pkgdesc=") {
			pkg.Description = extractValue(line, "pkgdesc=")
		}
		
		// TODO: Add logic to derive source repository from URL or source fields
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if pkg.Name == "" || pkg.Version == "" {
		return nil, errors.New("missing required fields in PKGBUILD (pkgname or pkgver)")
	}

	return pkg, nil
}

// FindPkgbuildDirs finds all directories containing PKGBUILD files
func FindPkgbuildDirs(baseDir string) ([]string, error) {
	var dirs []string

	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && info.Name() == "PKGBUILD" {
			dirs = append(dirs, filepath.Dir(path))
		}
		return nil
	})

	return dirs, err
}

// Helper function to extract values from key=value pairs
func extractValue(line, prefix string) string {
	value := strings.TrimPrefix(line, prefix)
	
	// Remove quotes if present
	value = strings.Trim(value, "\"'")
	
	return value
}

