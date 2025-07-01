package pkgbuild

import (
	"bufio"
	"errors"
	"fmt"
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
	RawName          string // Original name before cleanup
	Variables        map[string]string // Variables defined in the PKGBUILD
	HasPkgverFunc    bool   // Whether the PKGBUILD contains a pkgver() function
	PkgverFunc       string // The content of the pkgver() function
}

// Parse reads a PKGBUILD file and extracts relevant information
func Parse(pkgbuildPath string) (*Package, error) {
	file, err := os.Open(pkgbuildPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open PKGBUILD at %s: %w", pkgbuildPath, err)
	}
	defer file.Close()

	pkg := &Package{
		Variables: make(map[string]string),
	}
	sourceLines := []string{}
	inMultiLine := false
	currentVar := ""
	multiLineBuffer := ""
	inPkgverFunc := false
	pkgverFuncBuffer := ""

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		originalLine := line
		line = strings.TrimSpace(line)

		// Handle pkgver() function detection
		if inPkgverFunc {
			pkgverFuncBuffer += originalLine + "\n"
			if line == "}" {
				inPkgverFunc = false
				pkg.PkgverFunc = pkgverFuncBuffer
			}
			continue
		}

		// Check for start of pkgver() function
		if strings.HasPrefix(line, "pkgver()") && strings.Contains(line, "{") {
			inPkgverFunc = true
			pkg.HasPkgverFunc = true
			pkgverFuncBuffer = originalLine + "\n"
			if line == "pkgver() {" || strings.HasSuffix(line, " {") {
				// Function continues on next lines
				continue
			} else {
				// Single-line function (unlikely but possible)
				if strings.HasSuffix(line, "}") {
					inPkgverFunc = false
					pkg.PkgverFunc = pkgverFuncBuffer
				}
				continue
			}
		}

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle multi-line values
		if inMultiLine {
			multiLineBuffer += originalLine + "\n"
			if strings.Contains(line, ")") && !strings.Contains(line, "(") {
				inMultiLine = false
				
				// Process the complete multi-line value
				if currentVar == "source" {
					sourceLines = append(sourceLines, multiLineBuffer)
				}
				
				currentVar = ""
				multiLineBuffer = ""
			}
			continue
		}

		// Check for beginning of multi-line values
		if (strings.Contains(line, "=(") || strings.HasSuffix(line, "=(")) && !strings.Contains(line, ")") {
			inMultiLine = true
			currentVar = strings.Split(line, "=")[0]
			multiLineBuffer = originalLine + "\n"
			continue
		}
		// Check for variable assignments
		if strings.Contains(line, "=") && !strings.HasPrefix(line, "if ") && !strings.HasPrefix(line, "for ") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				varName := strings.TrimSpace(parts[0])
				varValue := extractValue(line, varName+"=")
				
				// Store variables in the map
				pkg.Variables[varName] = varValue
			}
		}

		// Process specific package fields
		if strings.HasPrefix(line, "pkgname=") {
			pkg.Name = extractValue(line, "pkgname=")
			pkg.RawName = pkg.Name
		} else if strings.HasPrefix(line, "pkgver=") {
			pkg.Version = extractValue(line, "pkgver=")
		} else if strings.HasPrefix(line, "url=") {
			pkg.URL = extractValue(line, "url=")
		} else if strings.HasPrefix(line, "pkgdesc=") {
			pkg.Description = extractValue(line, "pkgdesc=")
		} else if strings.HasPrefix(line, "source=") {
			sourceLines = append(sourceLines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning PKGBUILD: %w", err)
	}

	// Expand variables in all fields
	pkg.Name = expandVariables(pkg.Name, pkg.Variables)
	pkg.Version = expandVariables(pkg.Version, pkg.Variables)
	pkg.URL = expandVariables(pkg.URL, pkg.Variables)
	pkg.Description = expandVariables(pkg.Description, pkg.Variables)
	
	// If pkgname is still empty, try common variable patterns
	if pkg.Name == "" {
		// Check for _pkgname, _name, _pkg variables which are commonly used
		for _, varName := range []string{"_pkgname", "_name", "_pkg"} {
			if value, ok := pkg.Variables[varName]; ok && value != "" {
				pkg.Name = value
				break
			}
		}
	}

	if pkg.Name == "" || pkg.Version == "" {
		return nil, errors.New("missing required fields in PKGBUILD (pkgname or pkgver)")
	}

	// Try to determine the source repository
	if pkg.URL != "" {
		pkg.SourceRepository = deriveRepoFromURL(pkg.URL)
	}

	// If no repository found from URL, try to extract it from source lines
	if pkg.SourceRepository == "" && len(sourceLines) > 0 {
		// Expand variables in source lines before extracting repo
		expandedSourceLines := make([]string, len(sourceLines))
		for i, line := range sourceLines {
			expandedSourceLines[i] = expandVariables(line, pkg.Variables)
		}
		pkg.SourceRepository = extractRepoFromSource(expandedSourceLines)
	}

	// Clean up the package name if it contains "-bin" or "-git" suffixes
	pkg.Name = cleanPackageName(pkg.Name)

	return pkg, nil
}

// deriveRepoFromURL attempts to extract a GitHub/GitLab repository URL from the package URL
func deriveRepoFromURL(url string) string {
	// Common patterns for GitHub and GitLab URLs
	patterns := []string{
		`github\.com/([^/]+/[^/]+)`,
		`gitlab\.com/([^/]+/[^/]+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(url)
		if len(matches) > 1 {
			repoPath := strings.TrimSuffix(matches[1], ".git")
			// Remove any additional path components or query parameters
			if idx := strings.Index(repoPath, "/archive/"); idx > 0 {
				repoPath = repoPath[:idx]
			}
			if idx := strings.Index(repoPath, "/releases/"); idx > 0 {
				repoPath = repoPath[:idx]
			}
			if idx := strings.Index(repoPath, "?"); idx > 0 {
				repoPath = repoPath[:idx]
			}
			return repoPath
		}
	}

	return ""
}

// extractRepoFromSource tries to find a GitHub/GitLab repository URL in source lines
func extractRepoFromSource(sourceLines []string) string {
	// Common patterns for repository URLs in source lines
	patterns := []string{
		`github\.com/([^/]+/[^/]+)`,
		`gitlab\.com/([^/]+/[^/]+)`,
		`https://github\.com/([^/]+/[^/]+)`,
		`https://gitlab\.com/([^/]+/[^/]+)`,
		`git://github\.com/([^/]+/[^/]+)`,
		`git://gitlab\.com/([^/]+/[^/]+)`,
		`https://api\.github\.com/repos/([^/]+/[^/]+)`,
		`https://codeload\.github\.com/([^/]+/[^/]+)`,
		`https://raw\.githubusercontent\.com/([^/]+/[^/]+)`,
		`git\+https://github\.com/([^/]+/[^/]+)`,
		`git\+https://gitlab\.com/([^/]+/[^/]+)`,
	}

	for _, line := range sourceLines {
		for _, pattern := range patterns {
			re := regexp.MustCompile(pattern)
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				repoPath := strings.TrimSuffix(matches[1], ".git")
				// Remove any additional path components or query parameters
				if idx := strings.Index(repoPath, "/archive/"); idx > 0 {
					repoPath = repoPath[:idx]
				}
				if idx := strings.Index(repoPath, "/releases/"); idx > 0 {
					repoPath = repoPath[:idx]
				}
				if idx := strings.Index(repoPath, "/tags/"); idx > 0 {
					repoPath = repoPath[:idx]
				}
				if idx := strings.Index(repoPath, "?"); idx > 0 {
					repoPath = repoPath[:idx]
				}
				return repoPath
			}
		}
	}
	
	// Handle GitHub archive download URLs
	archivePattern := regexp.MustCompile(`/([^/]+)/([^/]+)/archive/.*\.(?:zip|tar\.gz|tgz)`)
	for _, line := range sourceLines {
		if matches := archivePattern.FindStringSubmatch(line); len(matches) > 2 {
			return matches[1] + "/" + matches[2]
		}
	}

	return ""
}

// cleanPackageName removes common suffixes from package names
func cleanPackageName(name string) string {
	suffixes := []string{"-bin", "-git", "-svn", "-hg", "-bzr", "-arch", "-aur"}
	
	for _, suffix := range suffixes {
		if strings.HasSuffix(name, suffix) {
			return strings.TrimSuffix(name, suffix)
		}
	}
	
	return name
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

// expandVariables replaces ${var} and $var with their values from the variables map
func expandVariables(input string, variables map[string]string) string {
	if input == "" {
		return input
	}

	// First handle ${var} syntax
	braceVarRegex := regexp.MustCompile(`\${([a-zA-Z0-9_]+)}`)
	result := braceVarRegex.ReplaceAllStringFunc(input, func(match string) string {
		// Extract variable name without ${ and }
		varName := match[2 : len(match)-1]
		if value, ok := variables[varName]; ok {
			return value
		}
		return match // Keep original if variable not found
	})

	// Then handle $var syntax (only when var is followed by non-alphanumeric char or end of string)
	simpleVarRegex := regexp.MustCompile(`\$([a-zA-Z0-9_]+)([^a-zA-Z0-9_]|$)`)
	result = simpleVarRegex.ReplaceAllStringFunc(result, func(match string) string {
		// Find the first non-alphanumeric character after the variable name
		endPos := len(match)
		for i := 1; i < len(match); i++ {
			if !isAlphaNumOrUnderscore(match[i]) {
				endPos = i
				break
			}
		}
		
		varName := match[1:endPos]
		suffix := ""
		if endPos < len(match) {
			suffix = match[endPos:]
		}
		
		if value, ok := variables[varName]; ok {
			return value + suffix
		}
		return match // Keep original if variable not found
	})

	return result
}

// isAlphaNumOrUnderscore checks if a byte is alphanumeric or underscore
func isAlphaNumOrUnderscore(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

// Helper function to extract values from key=value pairs
func extractValue(line, prefix string) string {
	value := strings.TrimPrefix(line, prefix)
	
	// Remove quotes if present
	value = strings.Trim(value, "\"'")
	
	// Handle arrays by extracting the first element
	if strings.HasPrefix(value, "(") && strings.HasSuffix(value, ")") {
		// Remove parentheses and split by whitespace
		value = strings.Trim(value, "()")
		elements := strings.Fields(value)
		if len(elements) > 0 {
			// Get the first element and remove quotes
			return strings.Trim(elements[0], "\"'")
		}
		return ""
	}
	
	return value
}

// ParseFile is a convenience function that combines filepath.Join and Parse
func ParseFile(baseDir, fileName string) (*Package, error) {
	path := filepath.Join(baseDir, fileName)
	return Parse(path)
}

// ListPackages finds and parses all PKGBUILD files in the given directories
func ListPackages(dirs []string) (map[string]*Package, error) {
	packages := make(map[string]*Package)
	
	for _, dir := range dirs {
		pkgbuildDirs, err := FindPkgbuildDirs(dir)
		if err != nil {
			return nil, fmt.Errorf("error finding PKGBUILDs in %s: %w", dir, err)
		}
		
		for _, pkgbuildDir := range pkgbuildDirs {
			pkg, err := Parse(filepath.Join(pkgbuildDir, "PKGBUILD"))
			if err != nil {
				fmt.Printf("Warning: Could not parse PKGBUILD in %s: %v\n", pkgbuildDir, err)
				continue
			}
			
			// Use directory name as key if package name is empty
			key := pkg.Name
			if key == "" {
				key = filepath.Base(pkgbuildDir)
			}
			
			packages[key] = pkg
		}
	}
	
	return packages, nil
}

