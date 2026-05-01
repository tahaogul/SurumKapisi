package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/surumkapisi/surumkapisi/internal/sbom"
	"github.com/surumkapisi/surumkapisi/internal/signing"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "sbom":
		cmdSBOM()
	case "evaluate":
		cmdEvaluate()
	case "sign":
		cmdSign()
	case "report":
		cmdReport()
	case "version":
		fmt.Println("surumkapisi v1.0.0")
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Bilinmeyen komut: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`SürümKapısı CLI — Yazılım Tedarik Zinciri Güvenlik Ajanı

Kullanım:
  surumkapisi sbom      --project PATH [--out FILE] [--format cyclonedx|spdx]
  surumkapisi evaluate  --sbom FILE --server URL --token TOKEN [--policy FILE]
  surumkapisi sign      --artifact PATH --server URL --token TOKEN --build-id ID
  surumkapisi report    --build ID --server URL --token TOKEN [--format json|html]
  surumkapisi version
  surumkapisi help

Ortam Değişkenleri:
  SK_SERVER_URL    Sunucu URL (örn: http://localhost:8080)
  SK_TOKEN         API token
  SK_PROJECT_ID    Proje ID`)
}

func cmdSBOM() {
	projectPath := flagValue("--project", ".")
	outFile := flagValue("--out", "sbom.json")
	format := flagValue("--format", "cyclonedx")

	absPath, _ := filepath.Abs(projectPath)
	fmt.Printf("📦 SBOM oluşturuluyor: %s\n", absPath)

	result, err := sbom.Generate(absPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ SBOM oluşturma hatası: %v\n", err)
		os.Exit(1)
	}

	outputData := result.RawJSON

	if strings.ToLower(format) == "spdx" {
		spdxData, err := sbom.ConvertToSPDX(result.RawJSON)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ SPDX dönüşüm hatası: %v\n", err)
			os.Exit(1)
		}
		outputData = spdxData
		fmt.Println("📋 Format: SPDX JSON")
	} else {
		fmt.Println("📋 Format: CycloneDX JSON")
	}

	if err := os.WriteFile(outFile, outputData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Dosya yazma hatası: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ SBOM oluşturuldu: %s\n", outFile)
	fmt.Printf("   Bileşen sayısı: %d\n", len(result.Components))
	fmt.Printf("   SHA256: %s\n", result.SHA256Hash)

	// Print ecosystem breakdown
	ecosystems := map[string]int{}
	for _, c := range result.Components {
		ecosystems[c.Ecosystem]++
	}
	for eco, count := range ecosystems {
		fmt.Printf("   %s: %d paket\n", eco, count)
	}
}

func cmdEvaluate() {
	sbomFile := flagValue("--sbom", "sbom.json")
	serverURL := flagValue("--server", getEnv("SK_SERVER_URL", "http://localhost:8080"))
	token := flagValue("--token", getEnv("SK_TOKEN", ""))
	policyFile := flagValue("--policy", "")
	projectID := flagValue("--project-id", getEnv("SK_PROJECT_ID", ""))
	buildID := flagValue("--build-id", "")

	if token == "" {
		fmt.Fprintf(os.Stderr, "❌ Token gerekli (--token veya SK_TOKEN)\n")
		os.Exit(1)
	}

	// Read SBOM
	sbomData, err := os.ReadFile(sbomFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ SBOM dosyası okunamadı: %v\n", err)
		os.Exit(1)
	}

	// Create build if none specified
	if buildID == "" && projectID != "" {
		gitCommit := getGitCommit()
		gitBranch := getGitBranch()

		fmt.Printf("🔨 Yapı kaydı oluşturuluyor...\n")
		build := apiPost(serverURL+"/api/builds", token, map[string]string{
			"project_id": projectID,
			"git_commit": gitCommit,
			"git_branch": gitBranch,
		})
		if id, ok := build["id"].(string); ok {
			buildID = id
			fmt.Printf("   Yapı ID: %s\n", buildID)
		} else {
			fmt.Fprintf(os.Stderr, "❌ Yapı oluşturulamadı: %v\n", build)
			os.Exit(1)
		}
	}

	if buildID == "" {
		fmt.Fprintf(os.Stderr, "❌ Build ID gerekli (--build-id veya --project-id)\n")
		os.Exit(1)
	}

	// Upload SBOM
	fmt.Println("📤 SBOM yükleniyor...")
	var sbomJSON json.RawMessage = sbomData
	apiPost(serverURL+"/api/sboms", token, map[string]interface{}{
		"build_id": buildID,
		"format":   "cyclonedx",
		"content":  sbomJSON,
	})
	fmt.Println("   ✅ SBOM yüklendi")

	// Build evaluate request
	evalReq := map[string]interface{}{
		"build_id": buildID,
	}

	// Include inline policy if specified
	if policyFile != "" {
		policyData, err := os.ReadFile(policyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Politika dosyası okunamadı: %v\n", err)
			os.Exit(1)
		}
		evalReq["policy"] = string(policyData)
	}

	// Evaluate
	fmt.Println("📋 Politika değerlendiriliyor...")
	result := apiPost(serverURL+"/api/evaluate", token, evalReq)

	decision, _ := result["decision"].(string)
	totalRules := int(result["total_rules"].(float64))
	passedRules := int(result["passed_rules"].(float64))
	failedRules := int(result["failed_rules"].(float64))

	fmt.Printf("\n🏁 KARAR: %s\n", decision)
	fmt.Printf("   Toplam kural: %d | Geçen: %d | Kalan: %d\n", totalRules, passedRules, failedRules)

	// Print rule results
	if results, ok := result["results"].([]interface{}); ok {
		for _, r := range results {
			rm := r.(map[string]interface{})
			status := "✅"
			if !rm["passed"].(bool) {
				status = "❌"
			}
			if waived, ok := rm["waived"].(bool); ok && waived {
				status = "⚠️"
			}
			fmt.Printf("   %s %s: %s\n", status, rm["rule_type"], rm["message"])
		}
	}

	if decision == "FAIL" {
		fmt.Println("\n❌ Pipeline ENGELLENDI — güvenlik gereksinimleri karşılanmadı.")
		os.Exit(2)
	}

	fmt.Printf("\n✅ Pipeline GEÇTİ — build ID: %s\n", buildID)
	// Store build ID for subsequent commands
	os.WriteFile(".surumkapisi-build-id", []byte(buildID), 0644)
}

func cmdSign() {
	artifactPath := flagValue("--artifact", "")
	serverURL := flagValue("--server", getEnv("SK_SERVER_URL", "http://localhost:8080"))
	token := flagValue("--token", getEnv("SK_TOKEN", ""))
	buildID := flagValue("--build-id", "")

	if token == "" {
		fmt.Fprintf(os.Stderr, "❌ Token gerekli\n")
		os.Exit(1)
	}
	if artifactPath == "" {
		fmt.Fprintf(os.Stderr, "❌ Artifact yolu gerekli (--artifact)\n")
		os.Exit(1)
	}

	// Read build ID from file if not specified
	if buildID == "" {
		if data, err := os.ReadFile(".surumkapisi-build-id"); err == nil {
			buildID = strings.TrimSpace(string(data))
		}
	}
	if buildID == "" {
		fmt.Fprintf(os.Stderr, "❌ Build ID gerekli (--build-id)\n")
		os.Exit(1)
	}

	// Hash artifact
	sha256Hash, err := signing.HashFileSHA256(artifactPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Artifact hash hesaplanamadı: %v\n", err)
		os.Exit(1)
	}

	fi, _ := os.Stat(artifactPath)
	size := int64(0)
	if fi != nil {
		size = fi.Size()
	}

	fmt.Printf("✍️ Artifact imzalanıyor: %s\n", artifactPath)
	fmt.Printf("   SHA256: %s\n", sha256Hash)

	result := apiPost(serverURL+"/api/sign", token, map[string]interface{}{
		"build_id":      buildID,
		"artifact_name": filepath.Base(artifactPath),
		"artifact_type": detectArtifactType(artifactPath),
		"sha256_hash":   sha256Hash,
		"size_bytes":    size,
	})

	if sig, ok := result["signature"].(string); ok {
		fmt.Printf("✅ İmzalandı!\n")
		fmt.Printf("   İmza: %s...\n", sig[:40])

		// Write signature to file
		sigFile := artifactPath + ".sig"
		os.WriteFile(sigFile, []byte(sig), 0644)
		fmt.Printf("   İmza dosyası: %s\n", sigFile)
	} else {
		fmt.Fprintf(os.Stderr, "❌ İmzalama başarısız: %v\n", result)
		os.Exit(1)
	}
}

func cmdReport() {
	buildID := flagValue("--build", "")
	serverURL := flagValue("--server", getEnv("SK_SERVER_URL", "http://localhost:8080"))
	token := flagValue("--token", getEnv("SK_TOKEN", ""))
	format := flagValue("--format", "json")

	if token == "" {
		fmt.Fprintf(os.Stderr, "❌ Token gerekli\n")
		os.Exit(1)
	}
	if buildID == "" {
		if data, err := os.ReadFile(".surumkapisi-build-id"); err == nil {
			buildID = strings.TrimSpace(string(data))
		}
	}
	if buildID == "" {
		fmt.Fprintf(os.Stderr, "❌ Build ID gerekli (--build)\n")
		os.Exit(1)
	}

	url := fmt.Sprintf("%s/api/reports/%s", serverURL, buildID)
	if format == "html" {
		url += "/html"
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Rapor alınamadı: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	outFile := fmt.Sprintf("report-%s.%s", buildID[:8], format)
	os.WriteFile(outFile, body, 0644)
	fmt.Printf("📊 Rapor kaydedildi: %s\n", outFile)

	if format == "json" {
		var pretty bytes.Buffer
		json.Indent(&pretty, body, "", "  ")
		fmt.Println(pretty.String())
	}
}

// Helpers

func flagValue(name, defaultVal string) string {
	for i, arg := range os.Args {
		if arg == name && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return defaultVal
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func apiPost(url, token string, body interface{}) map[string]interface{} {
	jsonData, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ API hatası: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode >= 400 {
		fmt.Fprintf(os.Stderr, "❌ API hatası (%d): %v\n", resp.StatusCode, result)
		os.Exit(1)
	}

	return result
}

func getGitCommit() string {
	out, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func getGitBranch() string {
	out, err := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func detectArtifactType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".jar":
		return "java-archive"
	case ".war":
		return "java-webapp"
	case ".tar", ".gz", ".tgz":
		return "archive"
	case ".zip":
		return "archive"
	case ".deb":
		return "debian-package"
	case ".rpm":
		return "rpm-package"
	case ".exe", ".msi":
		return "windows-binary"
	case ".whl":
		return "python-wheel"
	case ".json":
		return "json-file"
	default:
		return "binary"
	}
}
