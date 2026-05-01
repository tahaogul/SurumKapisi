package sbom

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CycloneDX structures

type CycloneDXBOM struct {
	BOMFormat    string             `json:"bomFormat"`
	SpecVersion  string             `json:"specVersion"`
	SerialNumber string             `json:"serialNumber"`
	Version      int                `json:"version"`
	Metadata     CycloneDXMetadata  `json:"metadata"`
	Components   []CycloneDXComponent `json:"components"`
}

type CycloneDXMetadata struct {
	Timestamp string            `json:"timestamp"`
	Tools     []CycloneDXTool   `json:"tools,omitempty"`
	Component *CycloneDXComponent `json:"component,omitempty"`
}

type CycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CycloneDXComponent struct {
	Type     string              `json:"type"`
	Name     string              `json:"name"`
	Version  string              `json:"version"`
	PURL     string              `json:"purl,omitempty"`
	Licenses []CycloneDXLicense  `json:"licenses,omitempty"`
}

type CycloneDXLicense struct {
	License CycloneDXLicenseID `json:"license"`
}

type CycloneDXLicenseID struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// SPDX structures (minimal)

type SPDXBOM struct {
	SPDXVersion       string        `json:"spdxVersion"`
	DataLicense       string        `json:"dataLicense"`
	SPDXID            string        `json:"SPDXID"`
	DocumentName      string        `json:"name"`
	DocumentNamespace string        `json:"documentNamespace"`
	CreationInfo      SPDXCreation  `json:"creationInfo"`
	Packages          []SPDXPackage `json:"packages"`
}

type SPDXCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type SPDXPackage struct {
	SPDXID           string `json:"SPDXID"`
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo"`
	DownloadLocation string `json:"downloadLocation"`
	LicenseConcluded string `json:"licenseConcluded,omitempty"`
	LicenseDeclared  string `json:"licenseDeclared,omitempty"`
}

// Component is our internal representation
type Component struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
	License   string `json:"license,omitempty"`
	Direct    bool   `json:"direct"`
}

// GenerateResult holds the result of SBOM generation
type GenerateResult struct {
	Components []Component
	Format     string
	RawJSON    []byte
	SHA256Hash string
}

// Generate scans a project directory and produces an SBOM
func Generate(projectPath string) (*GenerateResult, error) {
	var components []Component

	// Detect and parse NPM
	npmComps, err := parseNPM(projectPath)
	if err == nil && len(npmComps) > 0 {
		components = append(components, npmComps...)
	}

	// Detect and parse Python
	pyComps, err := parsePython(projectPath)
	if err == nil && len(pyComps) > 0 {
		components = append(components, pyComps...)
	}

	// Detect and parse Maven
	mvnComps, err := parseMaven(projectPath)
	if err == nil && len(mvnComps) > 0 {
		components = append(components, mvnComps...)
	}

	// Detect and parse Gradle
	gradleComps, err := parseGradle(projectPath)
	if err == nil && len(gradleComps) > 0 {
		components = append(components, gradleComps...)
	}

	bom := buildCycloneDX(projectPath, components)
	rawJSON, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SBOM: %w", err)
	}

	hash := sha256.Sum256(rawJSON)

	return &GenerateResult{
		Components: components,
		Format:     "CycloneDX",
		RawJSON:    rawJSON,
		SHA256Hash: fmt.Sprintf("%x", hash),
	}, nil
}

// ConvertToSPDX converts a CycloneDX SBOM to SPDX format
func ConvertToSPDX(cdxJSON []byte) ([]byte, error) {
	var cdx CycloneDXBOM
	if err := json.Unmarshal(cdxJSON, &cdx); err != nil {
		return nil, fmt.Errorf("failed to parse CycloneDX: %w", err)
	}

	spdx := SPDXBOM{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		DocumentName:      "surumkapisi-sbom",
		DocumentNamespace: fmt.Sprintf("https://surumkapisi.dev/spdx/%s", cdx.SerialNumber),
		CreationInfo: SPDXCreation{
			Created:  cdx.Metadata.Timestamp,
			Creators: []string{"Tool: SurumKapisi-1.0.0"},
		},
	}

	for i, comp := range cdx.Components {
		license := ""
		if len(comp.Licenses) > 0 {
			license = comp.Licenses[0].License.ID
			if license == "" {
				license = comp.Licenses[0].License.Name
			}
		}
		spdx.Packages = append(spdx.Packages, SPDXPackage{
			SPDXID:           fmt.Sprintf("SPDXRef-Package-%d", i+1),
			Name:             comp.Name,
			VersionInfo:      comp.Version,
			DownloadLocation: "NOASSERTION",
			LicenseConcluded: license,
			LicenseDeclared:  license,
		})
	}

	return json.MarshalIndent(spdx, "", "  ")
}

func buildCycloneDX(projectPath string, components []Component) CycloneDXBOM {
	projectName := filepath.Base(projectPath)

	bom := CycloneDXBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: fmt.Sprintf("urn:uuid:%d", time.Now().UnixNano()),
		Version:      1,
		Metadata: CycloneDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []CycloneDXTool{
				{Vendor: "SurumKapisi", Name: "surumkapisi-agent", Version: "1.0.0"},
			},
			Component: &CycloneDXComponent{
				Type:    "application",
				Name:    projectName,
				Version: "0.0.0",
			},
		},
	}

	for _, comp := range components {
		cdxComp := CycloneDXComponent{
			Type:    "library",
			Name:    comp.Name,
			Version: comp.Version,
			PURL:    comp.PURL,
		}
		if comp.License != "" {
			cdxComp.Licenses = []CycloneDXLicense{
				{License: CycloneDXLicenseID{ID: comp.License}},
			}
		}
		bom.Components = append(bom.Components, cdxComp)
	}

	return bom
}

// parseNPM reads package-lock.json
func parseNPM(projectPath string) ([]Component, error) {
	lockPath := filepath.Join(projectPath, "package-lock.json")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		// Try npm-shrinkwrap.json
		lockPath = filepath.Join(projectPath, "npm-shrinkwrap.json")
		data, err = os.ReadFile(lockPath)
		if err != nil {
			return nil, err
		}
	}

	var lockFile struct {
		Packages map[string]struct {
			Version  string `json:"version"`
			Resolved string `json:"resolved"`
			License  interface{} `json:"license"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version  string `json:"version"`
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}

	if err := json.Unmarshal(data, &lockFile); err != nil {
		return nil, fmt.Errorf("failed to parse package-lock.json: %w", err)
	}

	var components []Component

	// Parse v2/v3 format (packages)
	for key, pkg := range lockFile.Packages {
		if key == "" {
			continue // skip root
		}
		name := strings.TrimPrefix(key, "node_modules/")
		if name == "" || pkg.Version == "" {
			continue
		}

		license := ""
		switch v := pkg.License.(type) {
		case string:
			license = v
		}

		components = append(components, Component{
			Name:      name,
			Version:   pkg.Version,
			Ecosystem: "npm",
			PURL:      fmt.Sprintf("pkg:npm/%s@%s", name, pkg.Version),
			License:   license,
			Direct:    !strings.Contains(key, "node_modules/"),
		})
	}

	// Fallback to v1 format (dependencies)
	if len(components) == 0 {
		for name, dep := range lockFile.Dependencies {
			components = append(components, Component{
				Name:      name,
				Version:   dep.Version,
				Ecosystem: "npm",
				PURL:      fmt.Sprintf("pkg:npm/%s@%s", name, dep.Version),
				Direct:    true,
			})
		}
	}

	return components, nil
}

// parsePython reads requirements.txt or poetry.lock
func parsePython(projectPath string) ([]Component, error) {
	// Try requirements.txt first
	reqPath := filepath.Join(projectPath, "requirements.txt")
	data, err := os.ReadFile(reqPath)
	if err != nil {
		// Try poetry.lock
		poetryPath := filepath.Join(projectPath, "poetry.lock")
		data, err = os.ReadFile(poetryPath)
		if err != nil {
			return nil, err
		}
		return parsePoetryLock(data)
	}

	return parseRequirementsTxt(data)
}

func parseRequirementsTxt(data []byte) ([]Component, error) {
	var components []Component
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Handle various formats: pkg==version, pkg>=version, pkg~=version
		var name, version string
		for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">"} {
			if parts := strings.SplitN(line, sep, 2); len(parts) == 2 {
				name = strings.TrimSpace(parts[0])
				version = strings.TrimSpace(parts[1])
				// Remove any extras like [security]
				if idx := strings.Index(name, "["); idx != -1 {
					name = name[:idx]
				}
				break
			}
		}

		if name == "" {
			// Just a package name without version
			name = strings.TrimSpace(line)
			if idx := strings.Index(name, "["); idx != -1 {
				name = name[:idx]
			}
			version = "unknown"
		}

		if name != "" {
			components = append(components, Component{
				Name:      name,
				Version:   version,
				Ecosystem: "pypi",
				PURL:      fmt.Sprintf("pkg:pypi/%s@%s", name, version),
				Direct:    true,
			})
		}
	}

	return components, nil
}

func parsePoetryLock(data []byte) ([]Component, error) {
	var components []Component
	lines := strings.Split(string(data), "\n")

	var currentName, currentVersion string
	inPackage := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "[[package]]" {
			if currentName != "" {
				components = append(components, Component{
					Name:      currentName,
					Version:   currentVersion,
					Ecosystem: "pypi",
					PURL:      fmt.Sprintf("pkg:pypi/%s@%s", currentName, currentVersion),
					Direct:    true,
				})
			}
			currentName = ""
			currentVersion = ""
			inPackage = true
			continue
		}

		if inPackage {
			if strings.HasPrefix(line, "name = ") {
				currentName = strings.Trim(strings.TrimPrefix(line, "name = "), "\"")
			} else if strings.HasPrefix(line, "version = ") {
				currentVersion = strings.Trim(strings.TrimPrefix(line, "version = "), "\"")
			}
		}
	}

	// Don't forget the last package
	if currentName != "" {
		components = append(components, Component{
			Name:      currentName,
			Version:   currentVersion,
			Ecosystem: "pypi",
			PURL:      fmt.Sprintf("pkg:pypi/%s@%s", currentName, currentVersion),
			Direct:    true,
		})
	}

	return components, nil
}

// parseMaven reads pom.xml (best-effort)
func parseMaven(projectPath string) ([]Component, error) {
	pomPath := filepath.Join(projectPath, "pom.xml")
	data, err := os.ReadFile(pomPath)
	if err != nil {
		return nil, err
	}

	return parsePomXML(string(data))
}

func parsePomXML(content string) ([]Component, error) {
	var components []Component

	// Simple regex-free XML parsing for dependencies
	depSections := extractBetween(content, "<dependencies>", "</dependencies>")
	for _, section := range depSections {
		deps := extractBetween(section, "<dependency>", "</dependency>")
		for _, dep := range deps {
			groupID := extractFirstTag(dep, "groupId")
			artifactID := extractFirstTag(dep, "artifactId")
			version := extractFirstTag(dep, "version")
			scope := extractFirstTag(dep, "scope")

			if artifactID == "" {
				continue
			}
			if scope == "test" {
				continue
			}

			name := artifactID
			if groupID != "" {
				name = groupID + ":" + artifactID
			}
			if version == "" {
				version = "unknown"
			}

			// Skip property references like ${project.version}
			if strings.HasPrefix(version, "${") {
				version = "managed"
			}

			components = append(components, Component{
				Name:      name,
				Version:   version,
				Ecosystem: "maven",
				PURL:      fmt.Sprintf("pkg:maven/%s/%s@%s", groupID, artifactID, version),
				Direct:    true,
			})
		}
	}

	return components, nil
}

// parseGradle reads gradle.lockfile or build.gradle
func parseGradle(projectPath string) ([]Component, error) {
	lockPath := filepath.Join(projectPath, "gradle.lockfile")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return nil, err
	}

	return parseGradleLockfile(data)
}

func parseGradleLockfile(data []byte) ([]Component, error) {
	var components []Component
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Format: group:artifact:version=configuration
		parts := strings.SplitN(line, "=", 2)
		gav := parts[0]
		gavParts := strings.SplitN(gav, ":", 3)
		if len(gavParts) < 3 {
			continue
		}

		groupID := gavParts[0]
		artifactID := gavParts[1]
		version := gavParts[2]

		components = append(components, Component{
			Name:      groupID + ":" + artifactID,
			Version:   version,
			Ecosystem: "maven",
			PURL:      fmt.Sprintf("pkg:maven/%s/%s@%s", groupID, artifactID, version),
			Direct:    true,
		})
	}

	return components, nil
}

// Helper functions for simple XML parsing
func extractBetween(s, start, end string) []string {
	var results []string
	remaining := s
	for {
		startIdx := strings.Index(remaining, start)
		if startIdx == -1 {
			break
		}
		remaining = remaining[startIdx+len(start):]
		endIdx := strings.Index(remaining, end)
		if endIdx == -1 {
			break
		}
		results = append(results, remaining[:endIdx])
		remaining = remaining[endIdx+len(end):]
	}
	return results
}

func extractFirstTag(s, tag string) string {
	start := "<" + tag + ">"
	end := "</" + tag + ">"
	startIdx := strings.Index(s, start)
	if startIdx == -1 {
		return ""
	}
	s = s[startIdx+len(start):]
	endIdx := strings.Index(s, end)
	if endIdx == -1 {
		return ""
	}
	return strings.TrimSpace(s[:endIdx])
}
