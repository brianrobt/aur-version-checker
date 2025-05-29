package versioncheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/brianrobt/aur-version-checker/internal/pkgbuild"
)

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
	GitHub = "github"
	GitLab = "gitlab"
	Unknown = "unknown"
)

// GitHub API response structure for releases
type githubRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
}

// CheckVersion checks if there's a newer version available for the package
func CheckVersion(pkg *pkgbuild.Package) (VersionInfo, error) {
	info := VersionInfo{
		PackageName:  pkg.Name,
		LocalVersion: pkg.Version,
	}

	// Determine repository type and owner/repo
	repoType, owner, repo := determineRepository(pkg.URL)
	if repoType == Unknown {
		info.Error = errors.New("unable to determine upstream repository")
		return info, info.Error
	}

	// Check version based on repository type
	switch repoType {
	case GitHub:
		return checkGitHubVersion(pkg, owner, repo)
	case GitLab:
		// TODO: Implement GitLab version checking
		info.Error = errors.New("GitLab version checking not implemented yet")
		return info, info.Error
	default:
		info.Error = errors.New("unsupported repository type")
		return info, info.Error
	}
}

func checkGitHubVersion(pkg *pkgbuild.Package, owner, repo string) (VersionInfo, error) {
	info := VersionInfo{
		PackageName:  pkg.Name,
		LocalVersion: pkg.Version,
	}

	// GitHub API URL for latest release
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
	info.UpstreamURL = fmt.Sprintf("https://github.com/%s/%s", owner, repo)

	// Make HTTP request to GitHub API
	resp, err := http.Get(apiURL)
	if err != nil {
		info.Error = fmt.Errorf("failed to query GitHub API: %w", err)
		return info, info.Error
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		info.Error = fmt.Errorf("GitHub API returned status code %d", resp.StatusCode)
		return info, info.Error
	}

	// Parse API response
	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		info.Error = fmt.Errorf("failed to parse GitHub API response: %w", err)
		return info, info.Error
	}

	// Extract version from tag name (remove 'v' prefix if present)
	version := release.TagName
	if strings.HasPrefix(version, "v") {
		version = version[1:]
	}

	info.UpstreamVersion = version
	
	// TODO: Implement proper semantic version comparison
	// For now, just using string comparison which may not be accurate for all versioning schemes
	info.NeedsUpdate = version != pkg.Version

	return info, nil
}

// determineRepository tries to extract owner and repo from URL
func determineRepository(url string) (repoType, owner, repo string) {
	// GitHub pattern
	githubPattern := regexp.MustCompile(`github\.com[/:]([^/]+)/([^/]+)`)
	if matches := githubPattern.FindStringSubmatch(url); matches != nil {
		return GitHub, matches[1], strings.TrimSuffix(matches[2], ".git")
	}

	// GitLab pattern
	gitlabPattern := regexp.MustCompile(`gitlab\.com[/:]([^/]+)/([^/]+)`)
	if matches := gitlabPattern.FindStringSubmatch(url); matches != nil {
		return GitLab, matches[1], strings.TrimSuffix(matches[2], ".git")
	}

	return Unknown, "", ""
}

