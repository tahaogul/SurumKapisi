package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateNPM(t *testing.T) {
	// Create temp dir with package-lock.json
	dir := t.TempDir()
	lockContent := `{
		"name": "test-app",
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "test-app", "version": "1.0.0"},
			"node_modules/express": {"version": "4.18.2", "license": "MIT"},
			"node_modules/lodash": {"version": "4.17.21", "license": "MIT"},
			"node_modules/axios": {"version": "1.5.0", "license": "MIT"}
		}
	}`
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockContent), 0644)

	result, err := Generate(dir)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(result.Components) != 3 {
		t.Errorf("expected 3 components, got %d", len(result.Components))
	}

	if result.Format != "CycloneDX" {
		t.Errorf("expected CycloneDX format, got %s", result.Format)
	}

	if result.SHA256Hash == "" {
		t.Error("expected non-empty SHA256Hash")
	}

	// Verify CycloneDX structure
	var bom CycloneDXBOM
	if err := json.Unmarshal(result.RawJSON, &bom); err != nil {
		t.Fatalf("Invalid CycloneDX JSON: %v", err)
	}
	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("expected BOMFormat CycloneDX, got %s", bom.BOMFormat)
	}
	if bom.SpecVersion != "1.5" {
		t.Errorf("expected SpecVersion 1.5, got %s", bom.SpecVersion)
	}

	// Check component ecosystem
	for _, c := range result.Components {
		if c.Ecosystem != "npm" {
			t.Errorf("expected npm ecosystem, got %s", c.Ecosystem)
		}
	}
}

func TestGeneratePython(t *testing.T) {
	dir := t.TempDir()
	reqContent := `
flask==2.3.3
requests==2.28.0
# Comment line
django>=4.2.7
numpy~=1.26.0
-r other.txt
`
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(reqContent), 0644)

	result, err := Generate(dir)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if len(result.Components) != 4 {
		t.Errorf("expected 4 components, got %d", len(result.Components))
		for _, c := range result.Components {
			t.Logf("  - %s@%s (%s)", c.Name, c.Version, c.Ecosystem)
		}
	}

	for _, c := range result.Components {
		if c.Ecosystem != "pypi" {
			t.Errorf("expected pypi ecosystem for %s, got %s", c.Name, c.Ecosystem)
		}
	}
}

func TestGenerateMaven(t *testing.T) {
	dir := t.TempDir()
	pomContent := `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>6.1.0</version>
        </dependency>
        <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava</artifactId>
            <version>32.1.3-jre</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>`
	os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pomContent), 0644)

	result, err := Generate(dir)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Should skip test-scoped dependency
	if len(result.Components) != 2 {
		t.Errorf("expected 2 components (excluding test scope), got %d", len(result.Components))
		for _, c := range result.Components {
			t.Logf("  - %s@%s", c.Name, c.Version)
		}
	}
}

func TestGenerateGradle(t *testing.T) {
	dir := t.TempDir()
	lockContent := `# This is a gradle lockfile
com.google.guava:guava:32.1.3-jre=compileClasspath
org.slf4j:slf4j-api:2.0.9=compileClasspath
`
	os.WriteFile(filepath.Join(dir, "gradle.lockfile"), []byte(lockContent), 0644)

	result, err := Generate(dir)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(result.Components) != 2 {
		t.Errorf("expected 2 components, got %d", len(result.Components))
	}
}

func TestConvertToSPDX(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.3.3\ndjango==4.2.7"), 0644)

	result, err := Generate(dir)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	spdxData, err := ConvertToSPDX(result.RawJSON)
	if err != nil {
		t.Fatalf("ConvertToSPDX failed: %v", err)
	}

	var spdx SPDXBOM
	if err := json.Unmarshal(spdxData, &spdx); err != nil {
		t.Fatalf("Invalid SPDX JSON: %v", err)
	}

	if spdx.SPDXVersion != "SPDX-2.3" {
		t.Errorf("expected SPDX-2.3, got %s", spdx.SPDXVersion)
	}
	if spdx.DataLicense != "CC0-1.0" {
		t.Errorf("expected CC0-1.0, got %s", spdx.DataLicense)
	}
	if len(spdx.Packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(spdx.Packages))
	}
}

func TestGenerateEmpty(t *testing.T) {
	dir := t.TempDir()
	result, err := Generate(dir)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if len(result.Components) != 0 {
		t.Errorf("expected 0 components for empty dir, got %d", len(result.Components))
	}
}

func TestGenerateMultiEcosystem(t *testing.T) {
	dir := t.TempDir()

	// NPM
	os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"name": "test"},
			"node_modules/express": {"version": "4.18.2"}
		}
	}`), 0644)

	// Python
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.3.3"), 0644)

	result, err := Generate(dir)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	ecosystems := map[string]int{}
	for _, c := range result.Components {
		ecosystems[c.Ecosystem]++
	}

	if ecosystems["npm"] != 1 {
		t.Errorf("expected 1 npm component, got %d", ecosystems["npm"])
	}
	if ecosystems["pypi"] != 1 {
		t.Errorf("expected 1 pypi component, got %d", ecosystems["pypi"])
	}
}
