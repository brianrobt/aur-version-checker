package versioncheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/brianrobt/aur-version-checker/internal/pkgbuild"
)

// VersionPattern represents a pattern extracted from a source URL that can be used
// to check for newer versions
type VersionPattern struct {
	URLTemplate string // URL with version placeholder
	Prefix      string // Text before version number
	Suffix      string // Text after version number
}

// VersionInfo holds information about package versions
type VersionInfo struct {
	PackageName      string
	LocalVersion     string
	UpstreamVersion  string
	NeedsUpdate      bool
	UpstreamURL      string
	Error            error
}

// Repository types
const (
	GitHub    = "github"
	GitLab    = "gitlab"
	BitBucket = "bitbucket"
	Unknown   = "unknown"
)

// HTTP client with timeout
var (
	httpClient = &http.Client{
		Timeout: 10 * time.Second,
	}
	// GitHub token from environment
	githubToken = os.Getenv("GITHUB_TOKEN")
)

// addGitHubAuth adds authentication headers to GitHub API requests
func addGitHubAuth(req *http.Request) {
	if githubToken != "" {
		req.Header.Set("Authorization", "token "+githubToken)
	}
	req.Header.Set("User-Agent", "AUR-Version-Checker")
}

// GitHub API response structures
type githubRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
}

type githubTag struct {
	Name   string `json:"name"`
	Commit struct {
		SHA string `json:"sha"`
		URL string `json:"url"`
	} `json:"commit"`
}

// GitLab API response structures
type gitlabRelease struct {
	Name        string    `json:"name"`
	TagName     string    `json:"tag_name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	ReleasedAt  time.Time `json:"released_at"`
}

type gitlabTag struct {
	Name    string `json:"name"`
	Message string `json:"message"`
	Commit  struct {
		ID string `json:"id"`
	} `json:"commit"`
}

// BitBucket API response structures
type bitbucketTag struct {
	Name string `json:"name"`
	Date string `json:"date"`
}

type bitbucketTagsResponse struct {
	Values []bitbucketTag `json:"values"`
}

// checkSourceURLs attempts to find newer versions by analyzing the package's source URLs
func checkSourceURLs(pkg *pkgbuild.Package) (VersionInfo, bool) {
	info := VersionInfo{
		PackageName:  pkg.Name,
		LocalVersion: pkg.Version,
	}

	// Get source URLs from pkg.Variables["source"]
	sourceVar, ok := pkg.Variables["source"]
	if !ok || sourceVar == "" {
		return info, false
	}

	var sourceURLs []string
	
	// Handle array format: (url1 url2)
	if strings.HasPrefix(sourceVar, "(") && strings.HasSuffix(sourceVar, ")") {
		// Remove parentheses and split
		trimmed := strings.Trim(sourceVar, "()")
		// Split by whitespace but respect quotes
		sourceURLs = splitRespectQuotes(trimmed)
	} else {
		// Single URL case
		sourceURLs = []string{sourceVar}
	}

	// Expand all variables in source URLs
	var expandedSources []string
	for _, source := range sourceURLs {
		// Remove quotes if present
		source = strings.Trim(source, "'\"")
		expanded := expandVariables(source, pkg.Variables)
		expandedSources = append(expandedSources, expanded)
	}

	// Extract version patterns from all source URLs
	for _, sourceURL := range expandedSources {
		if pattern := extractVersionPattern(sourceURL, pkg.Version); pattern != nil {
			// Try to find a newer version
			newVersion, err := findNewerVersion(pattern, pkg.Version)
			if err != nil {
				continue
			}

			// Construct the new URL with the updated version
			newURL := pattern.Prefix + newVersion + pattern.Suffix

			info.UpstreamVersion = newVersion
			info.UpstreamURL = newURL
			info.NeedsUpdate = true
			return info, true
		}
	}

	return info, false
}

// extractVersionPattern analyzes a source URL with a known version to create a pattern
func extractVersionPattern(url string, knownVersion string) *VersionPattern {
	if url == "" || knownVersion == "" {
		return nil
	}

	// Common version patterns in URLs
	possibleVersions := []string{
		knownVersion,
		"v" + knownVersion,
		strings.ReplaceAll(knownVersion, ".", "_"),
	}

	for _, version := range possibleVersions {
		idx := strings.Index(url, version)
		if idx != -1 {
			return &VersionPattern{
				Prefix: url[:idx],
				Suffix: url[idx+len(version):],
			}
		}
	}

	return nil
}

// findNewerVersion attempts to find a newer version using the version pattern
func findNewerVersion(pattern *VersionPattern, currentVersion string) (string, error) {
	// Try several version incrementing strategies
	candidateVersions := []string{
		incrementLastComponent(currentVersion),
		incrementMinorVersion(currentVersion),
		incrementMajorVersion(currentVersion),
	}

	for _, newVersion := range candidateVersions {
		// Skip if we got the same version back
		if newVersion == currentVersion {
			continue
		}

		// Construct URL with candidate version
		candidateURL := pattern.Prefix + newVersion + pattern.Suffix

		// Check if the URL exists
		if checkURLExists(candidateURL) {
			return newVersion, nil
		}
	}

	return "", errors.New("no newer version found")
}

// checkURLExists makes a HEAD request to check if a URL exists and is accessible
func checkURLExists(url string) bool {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", "AUR-Version-Checker")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// expandVariables replaces ${var} and $var in a string with values from the variables map
func expandVariables(s string, variables map[string]string) string {
	result := s

	// Replace ${var} style variables
	re := regexp.MustCompile(`\${([A-Za-z0-9_]+)}`)
	result = re.ReplaceAllStringFunc(result, func(match string) string {
		varName := match[2 : len(match)-1]
		if val, ok := variables[varName]; ok {
			return val
		}
		return match
	})

	// Replace $var style variables
	re = regexp.MustCompile(`\$([A-Za-z0-9_]+)`)
	result = re.ReplaceAllStringFunc(result, func(match string) string {
		varName := match[1:]
		if val, ok := variables[varName]; ok {
			return val
		}
		return match
	})

	return result
}

// incrementLastComponent increments the last numeric component of a version string
func incrementLastComponent(version string) string {
	// Handle versions with pre-release suffixes
	parts := strings.SplitN(version, "-", 2)
	baseVersion := parts[0]

	components := strings.Split(baseVersion, ".")
	if len(components) == 0 {
		return version
	}

	// Try to increment the last component
	lastIdx := len(components) - 1
	lastNum, err := strconv.Atoi(components[lastIdx])
	if err != nil {
		return version
	}

	components[lastIdx] = strconv.Itoa(lastNum + 1)
	result := strings.Join(components, ".")

	// Add back pre-release suffix if it existed
	if len(parts) > 1 {
		result += "-" + parts[1]
	}

	return result
}

// incrementMinorVersion increments the minor version component
func incrementMinorVersion(version string) string {
	semVer, err := parseSemVer(version)
	if err != nil {
		return version
	}

	semVer.Minor++
	semVer.Patch = 0 // Reset patch when incrementing minor

	// Reconstruct version string
	result := fmt.Sprintf("%d.%d.%d", semVer.Major, semVer.Minor, semVer.Patch)
	if semVer.PreRelease != "" {
		result += "-" + semVer.PreRelease
	}
	if semVer.BuildMeta != "" {
		result += "+" + semVer.BuildMeta
	}

	return result
}

// incrementMajorVersion increments the major version component
func incrementMajorVersion(version string) string {
	semVer, err := parseSemVer(version)
	if err != nil {
		return version
	}

	semVer.Major++
	semVer.Minor = 0 // Reset minor when incrementing major
	semVer.Patch = 0 // Reset patch when incrementing major

	// Reconstruct version string
	result := fmt.Sprintf("%d.%d.%d", semVer.Major, semVer.Minor, semVer.Patch)
	if semVer.PreRelease != "" {
		result += "-" + semVer.PreRelease
	}
	if semVer.BuildMeta != "" {
		result += "+" + semVer.BuildMeta
	}

	return result
}

// splitRespectQuotes splits a string by whitespace while respecting quoted strings
func splitRespectQuotes(s string) []string {
	var result []string
	var current string
	inQuotes := false
	quoteChar := rune(0)

	for _, r := range s {
		switch {
		case r == '"' || r == '\'':
			if !inQuotes {
				inQuotes = true
				quoteChar = r
			} else if r == quoteChar {
				inQuotes = false
				quoteChar = 0
			} else {
				current += string(r)
			}
		case (r == ' ' || r == '\t') && !inQuotes:
			if current != "" {
				result = append(result, current)
				current = ""
			}
		default:
			current += string(r)
		}
	}

	if current != "" {
		result = append(result, current)
	}

	return result
}

// CheckVersion checks if there's a newer version available for the package
func CheckVersion(pkg *pkgbuild.Package) (VersionInfo, error) {
	info := VersionInfo{
		PackageName:  pkg.Name,
		LocalVersion: pkg.Version,
	}

	// First, try checking source URLs for new versions
	if sourceInfo, found := checkSourceURLs(pkg); found {
		return sourceInfo, nil
	}

	// If source URL checking fails, try guessing from package name first (using commonRepos)
	var repoType, owner, repo string
	repoType, owner, repo = guessRepositoryFromName(pkg.Name)

	// If that fails, try using the SourceRepository field
	if repoType == Unknown && pkg.SourceRepository != "" {
		parts := strings.Split(pkg.SourceRepository, "/")
		if len(parts) >= 2 {
			// Determine repository type from SourceRepository
			if strings.Contains(pkg.URL, "github.com") {
				repoType = GitHub
			} else if strings.Contains(pkg.URL, "gitlab.com") {
				repoType = GitLab
			} else if strings.Contains(pkg.URL, "bitbucket.org") {
				repoType = BitBucket
			} else {
				// Default to GitHub if we can't determine the type
				repoType = GitHub
			}
			owner = parts[0]
			repo = parts[1]
		}
	}

	// If we still don't have a repository, try with URL
	if repoType == Unknown {
		repoType, owner, repo = determineRepository(pkg.URL)
	}

	// If still unknown after all attempts, return an error
	if repoType == Unknown {
		info.Error = errors.New("unable to determine upstream repository")
		return info, info.Error
	}



	// Check version based on repository type
	switch repoType {
	case GitHub:
		return checkGitHubVersion(pkg, owner, repo)
	case GitLab:
		return checkGitLabVersion(pkg, owner, repo)
	case BitBucket:
		return checkBitBucketVersion(pkg, owner, repo)
	default:
		info.Error = errors.New("unsupported repository type")
		return info, info.Error
	}
}

// executePkgverFunction executes the pkgver() function from a PKGBUILD to get the latest version
func executePkgverFunction(pkg *pkgbuild.Package, repoURL string) (string, error) {
	if !pkg.HasPkgverFunc || pkg.PkgverFunc == "" {
		return "", errors.New("no pkgver() function found")
	}

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "aur-version-check-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Clone the repository
	gitURL := repoURL
	if !strings.HasSuffix(gitURL, ".git") {
		gitURL += ".git"
	}

	// Try different clone URLs if the first one fails
	cloneURLs := []string{
		gitURL,
	}
	
	// If the URL doesn't start with http/https, assume it's a GitHub repo
	if !strings.HasPrefix(gitURL, "http") {
		cloneURLs = append(cloneURLs, "https://github.com/"+gitURL)
	}

	var cloneDir string
	var cloneErr error
	for _, url := range cloneURLs {
		cloneDir = filepath.Join(tmpDir, "repo")
		cmd := exec.Command("git", "clone", "--depth", "1", url, cloneDir)
		cloneErr = cmd.Run()
		if cloneErr == nil {
			break
		}
	}

	if cloneErr != nil {
		return "", fmt.Errorf("failed to clone repository: %w", cloneErr)
	}

	// Create a temporary script that sets up the environment and executes pkgver()
	scriptPath := filepath.Join(tmpDir, "pkgver_script.sh")
	scriptContent := fmt.Sprintf(`#!/bin/bash
set -e
cd "%s"

# Source the variables from the original PKGBUILD
%s

# Define common variables that might be used in pkgver()
srcdir="%s"
pkgdir=""

# Execute the pkgver function
%s
`, cloneDir, generateVariableExports(pkg.Variables), cloneDir, pkg.PkgverFunc)

	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		return "", fmt.Errorf("failed to create pkgver script: %w", err)
	}

	// Execute the script
	cmd := exec.Command("bash", scriptPath)
	cmd.Dir = cloneDir
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute pkgver function: %w", err)
	}

	version := strings.TrimSpace(string(output))
	if version == "" {
		return "", errors.New("pkgver function returned empty version")
	}

	return version, nil
}

// generateVariableExports creates bash export statements for PKGBUILD variables
func generateVariableExports(variables map[string]string) string {
	var exports []string
	for key, value := range variables {
		// Skip certain variables that shouldn't be exported or might cause issues
		if key == "source" || key == "pkgver" || key == "pkgrel" || strings.HasPrefix(key, "_") {
			continue
		}
		// Properly quote the value to handle special characters
		quotedValue := fmt.Sprintf("'%s'", strings.ReplaceAll(value, "'", "'\"'\"'"))
		exports = append(exports, fmt.Sprintf("export %s=%s", key, quotedValue))
	}
	return strings.Join(exports, "\n")
}

func checkGitHubVersion(pkg *pkgbuild.Package, owner, repo string) (VersionInfo, error) {
	info := VersionInfo{
		PackageName:  pkg.Name,
		LocalVersion: pkg.Version,
	}
	
	info.UpstreamURL = fmt.Sprintf("https://github.com/%s/%s", owner, repo)

	// If this is a -git package, use pkgver() function if available
	if strings.HasSuffix(pkg.RawName, "-git") {
		if pkg.HasPkgverFunc {
			// Use the pkgver() function to get the latest version
			upstreamVersion, err := executePkgverFunction(pkg, info.UpstreamURL)
			if err != nil {
				// Fall back to commit-based checking if pkgver() fails
				commit, branch, err := getGitHubLatestCommit(owner, repo)
				if err != nil {
					info.Error = fmt.Errorf("failed to execute pkgver() and get GitHub commit: %w", err)
					return info, info.Error
				}
				info.UpstreamVersion = fmt.Sprintf("%s-%s", branch, commit[:7])
			} else {
				info.UpstreamVersion = upstreamVersion
			}
		} else {
			// Fall back to old commit-based checking
			commit, branch, err := getGitHubLatestCommit(owner, repo)
			if err != nil {
				info.Error = fmt.Errorf("failed to get GitHub commit: %w", err)
				return info, info.Error
			}
			info.UpstreamVersion = fmt.Sprintf("%s-%s", branch, commit[:7])
		}
		
		// Compare versions
		info.NeedsUpdate = info.UpstreamVersion != pkg.Version
		
		return info, nil
	}

	// For normal packages, first try the releases/latest API endpoint
	version, err := getGitHubLatestRelease(owner, repo)
	
	// If that fails, try getting tags
	if err != nil {
		var tagErr error
		version, tagErr = getGitHubTags(owner, repo)
		if tagErr != nil {
			// If all strategies fail, return the original error
			info.Error = fmt.Errorf("failed to get GitHub version: %w", err)
			return info, info.Error
		}
	}

	info.UpstreamVersion = version
	
	// Compare versions using semantic version comparison
	needsUpdate, err := compareVersions(pkg.Version, version)
	if err != nil {
		// Fall back to simple string comparison if semantic comparison fails
		needsUpdate = version != pkg.Version
	}
	info.NeedsUpdate = needsUpdate

	return info, nil
}

// getGitHubLatestRelease gets the latest release from GitHub
func getGitHubLatestRelease(owner, repo string) (string, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
	
	// Make HTTP request to GitHub API
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	
	// Add authentication and user agent headers
	addGitHubAuth(req)
	
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Handle rate limiting
	if resp.StatusCode == 403 && resp.Header.Get("X-RateLimit-Remaining") == "0" {
		resetTime := resp.Header.Get("X-RateLimit-Reset")
		resetTimeInt, err := strconv.ParseInt(resetTime, 10, 64)
		if err == nil {
			resetTimeFormatted := time.Unix(resetTimeInt, 0).Format(time.RFC3339)
			return "", fmt.Errorf("GitHub API rate limit exceeded. Resets at %s", resetTimeFormatted)
		}
		return "", fmt.Errorf("GitHub API rate limit exceeded")
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status code %d", resp.StatusCode)
	}

	// Parse API response
	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("failed to parse GitHub API response: %w", err)
	}

	// Extract version from tag name (remove 'v' prefix if present)
	version := release.TagName
	if strings.HasPrefix(version, "v") {
		version = version[1:]
	}

	return version, nil
}

// getGitHubTags gets tags from GitHub as a fallback
func getGitHubTags(owner, repo string) (string, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/tags", owner, repo)
	
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	
	addGitHubAuth(req)
	
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub tags API returned status code %d", resp.StatusCode)
	}

	// Read the entire response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read GitHub API response: %w", err)
	}

	// Parse tags response
	var tags []githubTag
	if err := json.Unmarshal(body, &tags); err != nil {
		return "", fmt.Errorf("failed to parse GitHub tags API response: %w", err)
	}

	if len(tags) == 0 {
		return "", fmt.Errorf("no tags found for %s/%s", owner, repo)
	}

	// Sort tags to find the latest
	sort.Slice(tags, func(i, j int) bool {
		// Try to compare as semantic versions first
		iVersion := cleanVersionString(tags[i].Name)
		jVersion := cleanVersionString(tags[j].Name)
		
		// If semantic comparison fails, fall back to string comparison
		iSemVer, iErr := parseSemVer(iVersion)
		jSemVer, jErr := parseSemVer(jVersion)
		
		if iErr == nil && jErr == nil {
			return semVerGreaterThan(iSemVer, jSemVer)
		}
		
		// Fall back to string comparison
		return strings.Compare(iVersion, jVersion) > 0
	})

	// Get the latest tag
	latestTag := tags[0].Name
	if strings.HasPrefix(latestTag, "v") {
		latestTag = latestTag[1:]
	}

	return latestTag, nil
}

// getGitHubLatestCommit gets the latest commit from GitHub
func getGitHubLatestCommit(owner, repo string) (string, string, error) {
    // First check if the repository exists and get its default branch
    defaultBranch, err := getGitHubDefaultBranch(owner, repo)
    if err == nil {
        // Try the default branch
        commit, err := getGitHubBranchCommit(owner, repo, defaultBranch)
        if err == nil {
            return commit, defaultBranch, nil
        }
    }

    // If we can't get the default branch or it fails, try common branches
    for _, branch := range []string{"main", "master", "develop"} {
        commit, err := getGitHubBranchCommit(owner, repo, branch)
        if err == nil {
            return commit, branch, nil
        }
    }

    return "", "", fmt.Errorf("failed to get commit from any branch for %s/%s", owner, repo)
}

// getGitHubDefaultBranch gets the default branch of a repository
func getGitHubDefaultBranch(owner, repo string) (string, error) {
    apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
    
    req, err := http.NewRequest("GET", apiURL, nil)
    if err != nil {
        return "", err
    }
    
    addGitHubAuth(req)
    
    resp, err := httpClient.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusForbidden {
        // Check if it's a rate limit issue
        if resp.Header.Get("X-RateLimit-Remaining") == "0" {
            resetTime := resp.Header.Get("X-RateLimit-Reset")
            resetTimeInt, err := strconv.ParseInt(resetTime, 10, 64)
            if err == nil {
                resetTimeFormatted := time.Unix(resetTimeInt, 0).Format(time.RFC3339)
                return "", fmt.Errorf("GitHub API rate limit exceeded. Resets at %s", resetTimeFormatted)
            }
            return "", fmt.Errorf("GitHub API rate limit exceeded")
        }
    }

    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("GitHub API returned status code %d", resp.StatusCode)
    }

    var repoInfo struct {
        DefaultBranch string `json:"default_branch"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&repoInfo); err != nil {
        return "", fmt.Errorf("failed to parse GitHub API response: %w", err)
    }

    return repoInfo.DefaultBranch, nil
}

// getGitHubBranchCommit gets the latest commit from a specific branch
func getGitHubBranchCommit(owner, repo, branch string) (string, error) {
    apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s", owner, repo, branch)
    
    req, err := http.NewRequest("GET", apiURL, nil)
    if err != nil {
        return "", err
    }
    
    addGitHubAuth(req)
    
    resp, err := httpClient.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusNotFound {
        return "", fmt.Errorf("branch %s not found", branch)
    }
    
    if resp.StatusCode == http.StatusForbidden {
        // Check if it's a rate limit issue
        if resp.Header.Get("X-RateLimit-Remaining") == "0" {
            resetTime := resp.Header.Get("X-RateLimit-Reset")
            resetTimeInt, err := strconv.ParseInt(resetTime, 10, 64)
            if err == nil {
                resetTimeFormatted := time.Unix(resetTimeInt, 0).Format(time.RFC3339)
                return "", fmt.Errorf("GitHub API rate limit exceeded. Resets at %s", resetTimeFormatted)
            }
            return "", fmt.Errorf("GitHub API rate limit exceeded")
        }
        return "", fmt.Errorf("access forbidden to %s/%s", owner, repo)
    }
    
    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("GitHub commits API returned status code %d for branch %s", resp.StatusCode, branch)
    }

    var commit struct {
        SHA string `json:"sha"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&commit); err != nil {
        return "", fmt.Errorf("failed to parse GitHub commits API response: %w", err)
    }

    return commit.SHA, nil
}

func checkGitLabVersion(pkg *pkgbuild.Package, owner, repo string) (VersionInfo, error) {
	info := VersionInfo{
		PackageName:  pkg.Name,
		LocalVersion: pkg.Version,
	}
	
	info.UpstreamURL = fmt.Sprintf("https://gitlab.com/%s/%s", owner, repo)

	// If this is a -git package, use pkgver() function if available
	if strings.HasSuffix(pkg.RawName, "-git") {
		if pkg.HasPkgverFunc {
			// Use the pkgver() function to get the latest version
			upstreamVersion, err := executePkgverFunction(pkg, info.UpstreamURL)
			if err != nil {
				info.Error = fmt.Errorf("failed to execute pkgver() for GitLab package: %w", err)
				return info, info.Error
			}
			info.UpstreamVersion = upstreamVersion
		} else {
			// For GitLab -git packages without pkgver(), we can't easily get commit info
			// So we'll just use tags/releases as a fallback
			version, err := getGitLabLatestRelease(owner, repo)
			if err != nil {
				var tagErr error
				version, tagErr = getGitLabTags(owner, repo)
				if tagErr != nil {
					info.Error = fmt.Errorf("failed to get GitLab version: %w", err)
					return info, info.Error
				}
			}
			info.UpstreamVersion = version
		}
		
		// Compare versions
		info.NeedsUpdate = info.UpstreamVersion != pkg.Version
		return info, nil
	}

	// For normal packages, first try releases
	version, err := getGitLabLatestRelease(owner, repo)
	
	// If that fails, try tags
	if err != nil {
		var tagErr error
		version, tagErr = getGitLabTags(owner, repo)
		if tagErr != nil {
			info.Error = fmt.Errorf("failed to get GitLab version: %w", err)
			return info, info.Error
		}
	}

	info.UpstreamVersion = version
	
	// Compare versions
	needsUpdate, err := compareVersions(pkg.Version, version)
	if err != nil {
		// Fall back to simple string comparison
		needsUpdate = version != pkg.Version
	}
	info.NeedsUpdate = needsUpdate

	return info, nil
}

// getGitLabLatestRelease gets the latest release from GitLab
func getGitLabLatestRelease(owner, repo string) (string, error) {
	// URL encode the owner/repo path
	path := fmt.Sprintf("%s%%2F%s", owner, strings.ReplaceAll(repo, "/", "%2F"))
	apiURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%s/releases", path)
	
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitLab API returned status code %d", resp.StatusCode)
	}

	// Parse API response
	var releases []gitlabRelease
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", fmt.Errorf("failed to parse GitLab API response: %w", err)
	}

	if len(releases) == 0 {
		return "", fmt.Errorf("no releases found for %s/%s", owner, repo)
	}

	// Sort releases by created date
	sort.Slice(releases, func(i, j int) bool {
		return releases[i].CreatedAt.After(releases[j].CreatedAt)
	})

	// Extract version from tag name
	version := releases[0].TagName
	if strings.HasPrefix(version, "v") {
		version = version[1:]
	}

	return version, nil
}

// getGitLabTags gets tags from GitLab as a fallback
func getGitLabTags(owner, repo string) (string, error) {
	// URL encode the owner/repo path
	path := fmt.Sprintf("%s%%2F%s", owner, strings.ReplaceAll(repo, "/", "%2F"))
	apiURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%s/repository/tags", path)
	
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitLab tags API returned status code %d", resp.StatusCode)
	}

	// Parse tags response
	var tags []gitlabTag
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "", fmt.Errorf("failed to parse GitLab tags API response: %w", err)
	}

	if len(tags) == 0 {
		return "", fmt.Errorf("no tags found for %s/%s", owner, repo)
	}

	// Find the latest tag (assuming the API returns them in order)
	latestTag := tags[0].Name
	if strings.HasPrefix(latestTag, "v") {
		latestTag = latestTag[1:]
	}

	return latestTag, nil
}

func checkBitBucketVersion(pkg *pkgbuild.Package, owner, repo string) (VersionInfo, error) {
	info := VersionInfo{
		PackageName:  pkg.Name,
		LocalVersion: pkg.Version,
	}
	
	info.UpstreamURL = fmt.Sprintf("https://bitbucket.org/%s/%s", owner, repo)

	// Get tags from BitBucket
	version, err := getBitBucketTags(owner, repo)
	if err != nil {
		info.Error = fmt.Errorf("failed to get BitBucket version: %w", err)
		return info, info.Error
	}

	info.UpstreamVersion = version
	
	// Compare versions
	needsUpdate, err := compareVersions(pkg.Version, version)
	if err != nil {
		// Fall back to simple string comparison
		needsUpdate = version != pkg.Version
	}
	info.NeedsUpdate = needsUpdate

	return info, nil
}

// getBitBucketTags gets tags from BitBucket
func getBitBucketTags(owner, repo string) (string, error) {
	apiURL := fmt.Sprintf("https://api.bitbucket.org/2.0/repositories/%s/%s/refs/tags", owner, repo)
	
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("BitBucket API returned status code %d", resp.StatusCode)
	}

	// Parse API response
	var tagsResponse bitbucketTagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&tagsResponse); err != nil {
		return "", fmt.Errorf("failed to parse BitBucket API response: %w", err)
	}

	if len(tagsResponse.Values) == 0 {
		return "", fmt.Errorf("no tags found for %s/%s", owner, repo)
	}

	// Sort tags to find the latest (based on date)
	sort.Slice(tagsResponse.Values, func(i, j int) bool {
		return tagsResponse.Values[i].Date > tagsResponse.Values[j].Date
	})

	// Get the latest tag
	latestTag := tagsResponse.Values[0].Name
	if strings.HasPrefix(latestTag, "v") {
		latestTag = latestTag[1:]
	}

	return latestTag, nil
}
// determineRepository tries to extract owner and repo from URL
func determineRepository(url string) (repoType, owner, repo string) {
	if url == "" {
		return Unknown, "", ""
	}

	// Handle trailing slashes
	url = strings.TrimRight(url, "/")

	// GitHub patterns
	githubPatterns := []string{
		`github\.com[/:]([^/]+)/([^/]+)`,
		`api\.github\.com/repos/([^/]+)/([^/]+)`,
		`raw\.githubusercontent\.com/([^/]+)/([^/]+)`,
	}

	for _, pattern := range githubPatterns {
		re := regexp.MustCompile(pattern)
		if matches := re.FindStringSubmatch(url); matches != nil {
			return GitHub, matches[1], cleanRepoName(matches[2])
		}
	}

	// GitLab pattern
	gitlabPattern := regexp.MustCompile(`gitlab\.com[/:]([^/]+)/([^/]+)`)
	if matches := gitlabPattern.FindStringSubmatch(url); matches != nil {
		return GitLab, matches[1], cleanRepoName(matches[2])
	}

	// BitBucket pattern
	bitbucketPattern := regexp.MustCompile(`bitbucket\.org[/:]([^/]+)/([^/]+)`)
	if matches := bitbucketPattern.FindStringSubmatch(url); matches != nil {
		return BitBucket, matches[1], cleanRepoName(matches[2])
	}

	return Unknown, "", ""
}

// cleanRepoName removes common suffixes and query parameters from repo names
func cleanRepoName(repoName string) string {
	repoName = strings.TrimSuffix(repoName, ".git")
	
	// Remove any path components after the repo name
	if idx := strings.Index(repoName, "/"); idx > 0 {
		repoName = repoName[:idx]
	}
	
	// Remove query parameters
	if idx := strings.Index(repoName, "?"); idx > 0 {
		repoName = repoName[:idx]
	}
	
	return repoName
}

// guessRepositoryFromName tries to guess the repository from the package name
func guessRepositoryFromName(pkgName string) (repoType, owner, repo string) {
	// Some common repositories that match their package names
	commonRepos := map[string]struct {
		repoType string
		owner    string
		repo     string
	}{
		"proton-pass": {GitHub, "ProtonMail", "proton-pass"},
		"python-conda": {GitHub, "conda", "conda"},
		"micromamba": {GitHub, "mamba-org", "mamba"},
		"stable-diffusion": {GitHub, "CompVis", "stable-diffusion"},
		"python-m2crypto": {GitLab, "m2crypto", "m2crypto"},
		// Add more common mappings here
	}

	// Try direct matches first
	if repo, ok := commonRepos[pkgName]; ok {
		return repo.repoType, repo.owner, repo.repo
	}

	// Try partial matches
	for name, repo := range commonRepos {
		if strings.Contains(pkgName, name) {
			return repo.repoType, repo.owner, repo.repo
		}
	}

	return Unknown, "", ""
}

// Types for semantic versioning
type SemVer struct {
	Major      int
	Minor      int
	Patch      int
	PreRelease string
	BuildMeta  string
}

// parseSemVer parses a semantic version string
func parseSemVer(version string) (SemVer, error) {
	var semver SemVer

	// Remove 'v' prefix if present
	if strings.HasPrefix(version, "v") {
		version = version[1:]
	}

	// Handle build metadata
	parts := strings.SplitN(version, "+", 2)
	version = parts[0]
	if len(parts) > 1 {
		semver.BuildMeta = parts[1]
	}

	// Handle pre-release
	parts = strings.SplitN(version, "-", 2)
	version = parts[0]
	if len(parts) > 1 {
		semver.PreRelease = parts[1]
	}

	// Parse version components
	versionParts := strings.Split(version, ".")
	if len(versionParts) < 1 {
		return semver, fmt.Errorf("invalid version format: %s", version)
	}

	// Parse major version
	major, err := strconv.Atoi(versionParts[0])
	if err != nil {
		return semver, fmt.Errorf("invalid major version: %s", versionParts[0])
	}
	semver.Major = major

	// Parse minor version if available
	if len(versionParts) > 1 {
		minor, err := strconv.Atoi(versionParts[1])
		if err != nil {
			return semver, fmt.Errorf("invalid minor version: %s", versionParts[1])
		}
		semver.Minor = minor
	}

	// Parse patch version if available
	if len(versionParts) > 2 {
		patch, err := strconv.Atoi(versionParts[2])
		if err != nil {
			return semver, fmt.Errorf("invalid patch version: %s", versionParts[2])
		}
		semver.Patch = patch
	}

	return semver, nil
}

// semVerGreaterThan checks if v1 > v2
func semVerGreaterThan(v1, v2 SemVer) bool {
	if v1.Major != v2.Major {
		return v1.Major > v2.Major
	}
	if v1.Minor != v2.Minor {
		return v1.Minor > v2.Minor
	}
	if v1.Patch != v2.Patch {
		return v1.Patch > v2.Patch
	}
	
	// Pre-release versions are lower than the normal version
	if v1.PreRelease == "" && v2.PreRelease != "" {
		return true
	}
	if v1.PreRelease != "" && v2.PreRelease == "" {
		return false
	}
	
	// Compare pre-release versions
	return v1.PreRelease > v2.PreRelease
}

// compareVersions compares two version strings
func compareVersions(localVer, upstreamVer string) (bool, error) {
	// Clean up version strings
	localVer = cleanVersionString(localVer)
	upstreamVer = cleanVersionString(upstreamVer)
	
	// Parse versions
	localSemVer, localErr := parseSemVer(localVer)
	upstreamSemVer, upstreamErr := parseSemVer(upstreamVer)
	
	// If both parsed successfully, compare them
	if localErr == nil && upstreamErr == nil {
		return semVerGreaterThan(upstreamSemVer, localSemVer), nil
	}
	
	// Special handling for git versions (e.g., r191.d46ed5e vs master-10feacf or main-10feacf)
	localGitPattern := regexp.MustCompile(`^r\d+\.([a-f0-9]+)$`)
	upstreamGitPattern := regexp.MustCompile(`^(master|main)-([a-f0-9]+)$`)
	
	if localGitPattern.MatchString(localVer) && upstreamGitPattern.MatchString(upstreamVer) {
		// Extract commit hashes
		localMatch := localGitPattern.FindStringSubmatch(localVer)
		upstreamMatch := upstreamGitPattern.FindStringSubmatch(upstreamVer)
		if len(localMatch) > 1 && len(upstreamMatch) > 2 {
			// Different commit hashes mean an update is needed
			return localMatch[1] != upstreamMatch[2], nil
		}
	}
	
	// Handle git commit hash style versions
	isLocalHash := isGitHash(localVer)
	isUpstreamHash := isGitHash(upstreamVer)
	
	if isLocalHash && isUpstreamHash {
		// Can't reliably compare two git hashes
		return localVer != upstreamVer, nil
	}
	
	if isLocalHash && !isUpstreamHash {
		// Upstream is a regular version, so it's newer
		return true, nil
	}
	
	if !isLocalHash && isUpstreamHash {
		// Local is a regular version, upstream is a hash
		return false, nil
	}
	
	// Fall back to string comparison if semantic versioning fails
	return localVer != upstreamVer, fmt.Errorf("could not compare versions semantically")
}

// cleanVersionString cleans up a version string for comparison
func cleanVersionString(version string) string {
	// Remove 'v' prefix if present
	if strings.HasPrefix(version, "v") {
		version = version[1:]
	}
	
	// Handle git-style versions (e.g., r123.abcdef)
	gitVersionPattern := regexp.MustCompile(`^r\d+\.[a-f0-9]+$`)
	if gitVersionPattern.MatchString(version) {
		parts := strings.Split(version, ".")
		if len(parts) == 2 {
			// Just return the commit hash part
			return parts[1]
		}
	}
	
	// Handle version with git hash (e.g., 1.0.0+r109+g6a51f7cdf)
	gitHashPattern := regexp.MustCompile(`\+r\d+\+g[a-f0-9]+$`)
	version = gitHashPattern.ReplaceAllString(version, "")
	
	// Handle "-stable" suffix
	version = strings.TrimSuffix(version, "-stable")
	
	return version
}

// isGitHash checks if a string looks like a git commit hash
func isGitHash(s string) bool {
	// Check if it's a full or shortened git hash
	gitHashPattern := regexp.MustCompile(`^[a-f0-9]{7,40}$`)
	return gitHashPattern.MatchString(s)
}

