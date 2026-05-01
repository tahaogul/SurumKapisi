package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/surumkapisi/surumkapisi/internal/audit"
	"github.com/surumkapisi/surumkapisi/internal/models"
	"github.com/surumkapisi/surumkapisi/internal/policy"
	"github.com/surumkapisi/surumkapisi/internal/signing"
	"github.com/surumkapisi/surumkapisi/internal/store"
)

// Handler holds API dependencies
type Handler struct {
	Store      *store.Store
	AuditLog   *audit.Logger
	KeyPair    *signing.KeyPair
	AdminToken string
}

// RegisterRoutes sets up all API routes
func (h *Handler) RegisterRoutes(r *mux.Router) {
	api := r.PathPrefix("/api").Subrouter()
	api.Use(h.authMiddleware)

	api.HandleFunc("/projects", h.CreateProject).Methods("POST")
	api.HandleFunc("/projects", h.ListProjects).Methods("GET")
	api.HandleFunc("/projects/{id}", h.GetProject).Methods("GET")

	api.HandleFunc("/builds", h.CreateBuild).Methods("POST")
	api.HandleFunc("/builds/{id}", h.GetBuild).Methods("GET")

	api.HandleFunc("/sboms", h.UploadSBOM).Methods("POST")
	api.HandleFunc("/sboms/{buildId}", h.GetSBOM).Methods("GET")

	api.HandleFunc("/evaluate", h.Evaluate).Methods("POST")

	api.HandleFunc("/sign", h.Sign).Methods("POST")

	api.HandleFunc("/reports/{buildId}", h.GetReport).Methods("GET")
	api.HandleFunc("/reports/{buildId}/html", h.GetReportHTML).Methods("GET")

	api.HandleFunc("/audit", h.GetAuditEvents).Methods("GET")

	api.HandleFunc("/exceptions", h.CreateException).Methods("POST")

	api.HandleFunc("/vulnerabilities/import", h.ImportVulnerabilities).Methods("POST")
}

// authMiddleware checks the bearer token
func (h *Handler) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")

		if token == "" {
			token = r.URL.Query().Get("token")
		}

		if token != h.AdminToken {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- Project Endpoints ---

func (h *Handler) CreateProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Slug        string `json:"slug"`
		RepoURL     string `json:"repo_url"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	orgID, _ := h.Store.GetDefaultOrg()

	project, err := h.Store.CreateProject(orgID, req.Name, req.Slug, req.RepoURL, req.Description)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.AuditLog.Log(audit.Event{
		ProjectID: project.ID, OrgID: orgID, Actor: "api",
		Action: "project.created", ResourceType: "project", ResourceID: project.ID,
		Details: map[string]interface{}{"name": req.Name, "slug": req.Slug},
	})

	writeJSON(w, http.StatusCreated, project)
}

func (h *Handler) ListProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := h.Store.ListAllProjects()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if projects == nil {
		projects = []models.Project{}
	}
	writeJSON(w, http.StatusOK, projects)
}

func (h *Handler) GetProject(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	project, err := h.Store.GetProject(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "project not found"})
		return
	}
	writeJSON(w, http.StatusOK, project)
}

// --- Build Endpoints ---

func (h *Handler) CreateBuild(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProjectID string `json:"project_id"`
		GitCommit string `json:"git_commit"`
		GitBranch string `json:"git_branch"`
		GitTag    string `json:"git_tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	build, err := h.Store.CreateBuild(req.ProjectID, req.GitCommit, req.GitBranch, req.GitTag)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.AuditLog.Log(audit.Event{
		ProjectID: req.ProjectID, Actor: "api",
		Action: "build.created", ResourceType: "build", ResourceID: build.ID,
		Details: map[string]interface{}{"build_number": build.BuildNumber, "git_commit": req.GitCommit},
	})

	writeJSON(w, http.StatusCreated, build)
}

func (h *Handler) GetBuild(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	build, err := h.Store.GetBuild(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "build not found"})
		return
	}
	writeJSON(w, http.StatusOK, build)
}

// --- SBOM Endpoints ---

func (h *Handler) UploadSBOM(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BuildID    string          `json:"build_id"`
		Format     string          `json:"format"`
		Content    json.RawMessage `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	if req.Format == "" {
		req.Format = "cyclonedx"
	}

	contentStr := string(req.Content)
	hash := sha256.Sum256(req.Content)
	sha256Hash := fmt.Sprintf("%x", hash)

	// Count components
	componentCount := 0
	var bom struct {
		Components []interface{} `json:"components"`
		Packages   []interface{} `json:"packages"`
	}
	json.Unmarshal(req.Content, &bom)
	componentCount = len(bom.Components) + len(bom.Packages)

	sbomRecord, err := h.Store.CreateSBOM(req.BuildID, req.Format, "1.5", contentStr, sha256Hash, componentCount)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Extract and store dependencies
	var cdx struct {
		Components []struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			PURL     string `json:"purl"`
			Licenses []struct {
				License struct {
					ID string `json:"id"`
				} `json:"license"`
			} `json:"licenses"`
		} `json:"components"`
	}
	if json.Unmarshal(req.Content, &cdx) == nil {
		var deps []models.Dependency
		for _, c := range cdx.Components {
			license := ""
			if len(c.Licenses) > 0 {
				license = c.Licenses[0].License.ID
			}
			ecosystem := "unknown"
			if strings.Contains(c.PURL, "pkg:npm/") {
				ecosystem = "npm"
			} else if strings.Contains(c.PURL, "pkg:pypi/") {
				ecosystem = "pypi"
			} else if strings.Contains(c.PURL, "pkg:maven/") {
				ecosystem = "maven"
			}
			deps = append(deps, models.Dependency{
				Name: c.Name, Version: c.Version, Ecosystem: ecosystem,
				PURL: c.PURL, License: license, Direct: true,
			})
		}
		h.Store.CreateDependencies(sbomRecord.ID, deps)
	}

	h.AuditLog.Log(audit.Event{
		Actor: "api", Action: "sbom.uploaded", ResourceType: "sbom", ResourceID: sbomRecord.ID,
		Details: map[string]interface{}{"build_id": req.BuildID, "format": req.Format, "components": componentCount},
	})

	writeJSON(w, http.StatusCreated, sbomRecord)
}

func (h *Handler) GetSBOM(w http.ResponseWriter, r *http.Request) {
	buildID := mux.Vars(r)["buildId"]
	sbomRecord, err := h.Store.GetSBOMByBuild(buildID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "sbom not found"})
		return
	}
	writeJSON(w, http.StatusOK, sbomRecord)
}

// --- Evaluation Endpoint ---

func (h *Handler) Evaluate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BuildID string `json:"build_id"`
		Policy  string `json:"policy,omitempty"` // Optional inline policy YAML
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	// Get build
	build, err := h.Store.GetBuild(req.BuildID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "build not found"})
		return
	}

	// Get or parse policy
	var pf *policy.PolicyFile
	var policyVersionID string

	if req.Policy != "" {
		pf, err = policy.ParsePolicyYAML([]byte(req.Policy))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid policy: " + err.Error()})
			return
		}
		policyVersionID = "inline-" + uuid.New().String()[:8]
	} else {
		pv, err := h.Store.GetDefaultPolicyVersion(build.ProjectID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no policy found for project"})
			return
		}
		policyVersionID = pv.ID
		pf, err = policy.ParsePolicyJSON([]byte(pv.Content))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to parse stored policy"})
			return
		}
	}

	// Build evaluation context
	ctx := &policy.EvalContext{}

	// Check SBOM
	sbomRecord, err := h.Store.GetSBOMByBuild(req.BuildID)
	if err == nil && sbomRecord != nil {
		ctx.HasSBOM = true
		deps, _ := h.Store.GetDependencies(sbomRecord.ID)
		for _, d := range deps {
			ctx.Dependencies = append(ctx.Dependencies, policy.DepInfo{
				Name: d.Name, Version: d.Version, Ecosystem: d.Ecosystem, License: d.License,
			})
		}

		// Match vulnerabilities
		vulns, _ := h.Store.MatchVulnerabilities(deps)
		for _, v := range vulns {
			ctx.Vulns = append(ctx.Vulns, policy.VulnMatch{
				VulnID: v.VulnID, Severity: v.Severity, CVSSScore: v.CVSSScore,
				PackageName: v.PackageName, Description: v.Description,
			})
		}
	}

	// Check signatures
	artifacts, _ := h.Store.GetArtifactsByBuild(req.BuildID)
	for _, a := range artifacts {
		if a.Signed {
			ctx.HasSignature = true
			break
		}
	}

	// Check provenance
	prov, err := h.Store.GetProvenance(req.BuildID)
	if err == nil && prov != nil {
		ctx.Provenance = &policy.ProvenanceInfo{
			GitCommit: prov.GitCommit,
			BuildTime: prov.BuildTime.Format(time.RFC3339),
			SBOMHash:  prov.SBOMHash,
		}
	}

	// Get active exceptions
	exceptions, _ := h.Store.GetActiveExceptions(build.ProjectID)
	for _, e := range exceptions {
		ctx.Exceptions = append(ctx.Exceptions, policy.ExceptionInfo{
			RuleType: e.RuleType, RuleValue: e.RuleValue,
			Reason: e.Reason, ExpiresAt: e.ExpiresAt,
		})
	}

	// Run evaluation
	evalResult := policy.Evaluate(pf, ctx)

	// Store evaluation
	h.Store.CreateEvaluation(req.BuildID, policyVersionID, evalResult.Decision,
		evalResult.DecisionHash, evalResult.Results, evalResult.Results, evalResult.ExceptionsUsed)

	// Update build decision
	reason := fmt.Sprintf("%d/%d rules passed", evalResult.PassedRules, evalResult.TotalRules)
	h.Store.UpdateBuildDecision(req.BuildID, "completed", evalResult.Decision, reason)

	// Audit log
	h.AuditLog.Log(audit.Event{
		ProjectID: build.ProjectID, Actor: "api",
		Action: "build.evaluated", ResourceType: "build", ResourceID: req.BuildID,
		Details: map[string]interface{}{
			"decision":      evalResult.Decision,
			"total_rules":   evalResult.TotalRules,
			"passed_rules":  evalResult.PassedRules,
			"failed_rules":  evalResult.FailedRules,
			"waived_rules":  evalResult.WaivedRules,
			"decision_hash": evalResult.DecisionHash,
		},
	})

	writeJSON(w, http.StatusOK, evalResult)
}

// --- Sign Endpoint ---

func (h *Handler) Sign(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BuildID      string `json:"build_id"`
		ArtifactName string `json:"artifact_name"`
		ArtifactType string `json:"artifact_type"`
		SHA256Hash   string `json:"sha256_hash"`
		SizeBytes    int64  `json:"size_bytes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	// Create artifact record
	artifact, err := h.Store.CreateArtifact(req.BuildID, req.ArtifactName, req.ArtifactType, req.SHA256Hash, req.SizeBytes)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Sign the hash
	sig, err := signing.SignData(h.KeyPair.PrivateKey, []byte(req.SHA256Hash))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "signing failed: " + err.Error()})
		return
	}

	// Update artifact
	h.Store.SignArtifact(artifact.ID, sig)

	// Create provenance record
	build, _ := h.Store.GetBuild(req.BuildID)
	sbomRecord, _ := h.Store.GetSBOMByBuild(req.BuildID)
	eval, _ := h.Store.GetEvaluationByBuild(req.BuildID)

	sbomHash := ""
	if sbomRecord != nil {
		sbomHash = sbomRecord.SHA256Hash
	}
	decisionHash := ""
	policyVersion := ""
	if eval != nil {
		decisionHash = eval.DecisionHash
		policyVersion = eval.PolicyVersionID
	}
	gitCommit := ""
	gitBranch := ""
	gitTag := ""
	if build != nil {
		gitCommit = build.GitCommit
		gitBranch = build.GitBranch
		gitTag = build.GitTag
	}

	h.Store.CreateProvenance(req.BuildID, gitCommit, gitBranch, gitTag, sbomHash, policyVersion, decisionHash, "surumkapisi-server", nil, sig)

	h.AuditLog.Log(audit.Event{
		Actor: "api", Action: "artifact.signed", ResourceType: "artifact", ResourceID: artifact.ID,
		Details: map[string]interface{}{"build_id": req.BuildID, "sha256": req.SHA256Hash},
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"artifact_id": artifact.ID,
		"signature":   sig,
		"signed_at":   time.Now().UTC().Format(time.RFC3339),
		"public_key":  h.KeyPair.PublicPEM,
	})
}

// --- Report Endpoint ---

func (h *Handler) GetReport(w http.ResponseWriter, r *http.Request) {
	buildID := mux.Vars(r)["buildId"]
	report, err := h.buildReport(buildID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (h *Handler) GetReportHTML(w http.ResponseWriter, r *http.Request) {
	buildID := mux.Vars(r)["buildId"]
	report, err := h.buildReport(buildID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	renderReportHTML(w, report)
}

type Report struct {
	Build          *models.Build          `json:"build"`
	Project        *models.Project        `json:"project,omitempty"`
	SBOM           *SBOMSummary           `json:"sbom_summary"`
	Vulnerabilities []VulnSummary         `json:"vulnerabilities"`
	Licenses       []LicenseSummary       `json:"licenses"`
	Evaluation     *EvalSummary           `json:"evaluation"`
	Provenance     *models.ProvenanceRecord `json:"provenance,omitempty"`
	Artifacts      []models.Artifact      `json:"artifacts"`
	ExceptionsUsed []string               `json:"exceptions_used,omitempty"`
	FinalDecision  string                 `json:"final_decision"`
	GeneratedAt    string                 `json:"generated_at"`
}

type SBOMSummary struct {
	Format         string `json:"format"`
	ComponentCount int    `json:"component_count"`
	SHA256Hash     string `json:"sha256_hash"`
}

type VulnSummary struct {
	VulnID      string  `json:"vuln_id"`
	Severity    string  `json:"severity"`
	CVSSScore   float64 `json:"cvss_score"`
	PackageName string  `json:"package_name"`
	Description string  `json:"description"`
}

type LicenseSummary struct {
	License string `json:"license"`
	Count   int    `json:"count"`
}

type EvalSummary struct {
	Decision     string `json:"decision"`
	DecisionHash string `json:"decision_hash"`
	TotalRules   int    `json:"total_rules"`
	PassedRules  int    `json:"passed_rules"`
	FailedRules  int    `json:"failed_rules"`
	WaivedRules  int    `json:"waived_rules"`
}

func (h *Handler) buildReport(buildID string) (*Report, error) {
	build, err := h.Store.GetBuild(buildID)
	if err != nil {
		return nil, fmt.Errorf("build not found")
	}

	report := &Report{
		Build:         build,
		FinalDecision: build.Decision,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	// Project
	project, err := h.Store.GetProject(build.ProjectID)
	if err == nil {
		report.Project = project
	}

	// SBOM
	sbomRecord, err := h.Store.GetSBOMByBuild(buildID)
	if err == nil && sbomRecord != nil {
		report.SBOM = &SBOMSummary{
			Format: sbomRecord.Format, ComponentCount: sbomRecord.ComponentCount,
			SHA256Hash: sbomRecord.SHA256Hash,
		}

		// Dependencies for license summary
		deps, _ := h.Store.GetDependencies(sbomRecord.ID)
		licenseCounts := map[string]int{}
		for _, d := range deps {
			if d.License != "" {
				licenseCounts[d.License]++
			} else {
				licenseCounts["unknown"]++
			}
		}
		for lic, count := range licenseCounts {
			report.Licenses = append(report.Licenses, LicenseSummary{License: lic, Count: count})
		}

		// Vulnerability matches
		vulns, _ := h.Store.MatchVulnerabilities(deps)
		for _, v := range vulns {
			report.Vulnerabilities = append(report.Vulnerabilities, VulnSummary{
				VulnID: v.VulnID, Severity: v.Severity, CVSSScore: v.CVSSScore,
				PackageName: v.PackageName, Description: v.Description,
			})
		}
	}

	// Evaluation
	eval, err := h.Store.GetEvaluationByBuild(buildID)
	if err == nil && eval != nil {
		var results []policy.RuleResult
		json.Unmarshal([]byte(eval.Results), &results)

		passed, failed, waived := 0, 0, 0
		for _, r := range results {
			if r.Passed && !r.Waived {
				passed++
			} else if r.Waived {
				waived++
			} else {
				failed++
			}
		}

		report.Evaluation = &EvalSummary{
			Decision: eval.Decision, DecisionHash: eval.DecisionHash,
			TotalRules: len(results), PassedRules: passed,
			FailedRules: failed, WaivedRules: waived,
		}

		var exceptions []string
		json.Unmarshal([]byte(eval.ExceptionsUsed), &exceptions)
		report.ExceptionsUsed = exceptions
	}

	// Provenance
	prov, err := h.Store.GetProvenance(buildID)
	if err == nil {
		report.Provenance = prov
	}

	// Artifacts
	artifacts, _ := h.Store.GetArtifactsByBuild(buildID)
	report.Artifacts = artifacts

	return report, nil
}

func renderReportHTML(w io.Writer, report *Report) {
	projectName := "N/A"
	if report.Project != nil {
		projectName = report.Project.Name
	}

	decisionColor := "#28a745"
	if report.FinalDecision == "FAIL" {
		decisionColor = "#dc3545"
	} else if report.FinalDecision == "pending" {
		decisionColor = "#ffc107"
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SürümKapısı Rapor — Build #%d</title>
<style>
body{font-family:'Segoe UI',Arial,sans-serif;max-width:900px;margin:20px auto;padding:0 20px;background:#f8f9fa;color:#333}
h1{color:#1a1a2e;border-bottom:3px solid #16213e;padding-bottom:10px}
h2{color:#16213e;margin-top:30px}
.badge{display:inline-block;padding:6px 16px;border-radius:4px;color:#fff;font-weight:bold;font-size:1.1em}
table{width:100%%;border-collapse:collapse;margin:10px 0}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #ddd}
th{background:#16213e;color:#fff}
tr:hover{background:#e2e6ea}
.section{background:#fff;border-radius:8px;padding:20px;margin:15px 0;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
.severity-critical{color:#dc3545;font-weight:bold}
.severity-high{color:#e67e22;font-weight:bold}
.severity-medium{color:#f39c12}
.severity-low{color:#27ae60}
footer{text-align:center;color:#999;margin-top:40px;padding:20px}
</style>
</head><body>
<h1>🔐 SürümKapısı — Yapı Raporu</h1>
<div class="section">
<h2>Genel Bilgiler</h2>
<table>
<tr><td><strong>Proje</strong></td><td>%s</td></tr>
<tr><td><strong>Yapı No</strong></td><td>#%d</td></tr>
<tr><td><strong>Git Commit</strong></td><td><code>%s</code></td></tr>
<tr><td><strong>Karar</strong></td><td><span class="badge" style="background:%s">%s</span></td></tr>
<tr><td><strong>Rapor Tarihi</strong></td><td>%s</td></tr>
</table>
</div>`, report.Build.BuildNumber, projectName, report.Build.BuildNumber,
		report.Build.GitCommit, decisionColor, report.FinalDecision, report.GeneratedAt)

	// SBOM Summary
	if report.SBOM != nil {
		fmt.Fprintf(w, `<div class="section"><h2>📦 SBOM Özeti</h2>
<table><tr><td><strong>Format</strong></td><td>%s</td></tr>
<tr><td><strong>Bileşen Sayısı</strong></td><td>%d</td></tr>
<tr><td><strong>SHA256</strong></td><td><code>%s</code></td></tr></table></div>`,
			report.SBOM.Format, report.SBOM.ComponentCount, report.SBOM.SHA256Hash)
	}

	// Vulnerabilities
	fmt.Fprintf(w, `<div class="section"><h2>🛡️ Güvenlik Açıkları (%d)</h2>`, len(report.Vulnerabilities))
	if len(report.Vulnerabilities) > 0 {
		fmt.Fprint(w, `<table><tr><th>CVE</th><th>Önem</th><th>CVSS</th><th>Paket</th><th>Açıklama</th></tr>`)
		for _, v := range report.Vulnerabilities {
			fmt.Fprintf(w, `<tr><td>%s</td><td class="severity-%s">%s</td><td>%.1f</td><td>%s</td><td>%s</td></tr>`,
				v.VulnID, strings.ToLower(v.Severity), strings.ToUpper(v.Severity), v.CVSSScore, v.PackageName, v.Description)
		}
		fmt.Fprint(w, `</table>`)
	} else {
		fmt.Fprint(w, `<p>✅ Eşleşen bilinen güvenlik açığı bulunamadı.</p>`)
	}
	fmt.Fprint(w, `</div>`)

	// Licenses
	fmt.Fprintf(w, `<div class="section"><h2>📜 Lisans Dağılımı</h2>`)
	if len(report.Licenses) > 0 {
		fmt.Fprint(w, `<table><tr><th>Lisans</th><th>Adet</th></tr>`)
		for _, l := range report.Licenses {
			fmt.Fprintf(w, `<tr><td>%s</td><td>%d</td></tr>`, l.License, l.Count)
		}
		fmt.Fprint(w, `</table>`)
	}
	fmt.Fprint(w, `</div>`)

	// Policy Evaluation
	if report.Evaluation != nil {
		fmt.Fprintf(w, `<div class="section"><h2>📋 Politika Değerlendirmesi</h2>
<table>
<tr><td><strong>Karar</strong></td><td><span class="badge" style="background:%s">%s</span></td></tr>
<tr><td><strong>Toplam Kural</strong></td><td>%d</td></tr>
<tr><td><strong>Geçen</strong></td><td>%d</td></tr>
<tr><td><strong>Kalan</strong></td><td>%d</td></tr>
<tr><td><strong>Muaf</strong></td><td>%d</td></tr>
<tr><td><strong>Karar Hash</strong></td><td><code>%s</code></td></tr>
</table></div>`,
			decisionColor, report.Evaluation.Decision,
			report.Evaluation.TotalRules, report.Evaluation.PassedRules,
			report.Evaluation.FailedRules, report.Evaluation.WaivedRules,
			report.Evaluation.DecisionHash)
	}

	// Provenance
	if report.Provenance != nil {
		fmt.Fprintf(w, `<div class="section"><h2>🔗 Provenance (Kanıt Kaydı)</h2>
<table>
<tr><td><strong>Git Commit</strong></td><td><code>%s</code></td></tr>
<tr><td><strong>SBOM Hash</strong></td><td><code>%s</code></td></tr>
<tr><td><strong>Karar Hash</strong></td><td><code>%s</code></td></tr>
<tr><td><strong>Oluşturulma</strong></td><td>%s</td></tr>
</table></div>`,
			report.Provenance.GitCommit, report.Provenance.SBOMHash,
			report.Provenance.DecisionHash, report.Provenance.CreatedAt.Format(time.RFC3339))
	}

	// Artifacts
	if len(report.Artifacts) > 0 {
		fmt.Fprint(w, `<div class="section"><h2>📎 Artefaktlar</h2>
<table><tr><th>Ad</th><th>Tür</th><th>SHA256</th><th>İmzalı</th></tr>`)
		for _, a := range report.Artifacts {
			signed := "❌"
			if a.Signed {
				signed = "✅"
			}
			fmt.Fprintf(w, `<tr><td>%s</td><td>%s</td><td><code>%.16s...</code></td><td>%s</td></tr>`,
				a.Name, a.ArtifactType, a.SHA256Hash, signed)
		}
		fmt.Fprint(w, `</table></div>`)
	}

	fmt.Fprint(w, `<footer>SürümKapısı — Software Supply Chain Security Platform<br>Bu rapor otomatik olarak oluşturulmuştur.</footer></body></html>`)
}

// --- Audit Endpoint ---

func (h *Handler) GetAuditEvents(w http.ResponseWriter, r *http.Request) {
	projectID := r.URL.Query().Get("projectId")
	events, err := h.AuditLog.GetEvents(projectID, 200)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if events == nil {
		events = []map[string]interface{}{}
	}
	writeJSON(w, http.StatusOK, events)
}

// --- Exception Endpoint ---

func (h *Handler) CreateException(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProjectID      string `json:"project_id"`
		RuleType       string `json:"rule_type"`
		RuleValue      string `json:"rule_value"`
		Reason         string `json:"reason"`
		ApprovedByRole string `json:"approved_by_role"`
		DurationDays   int    `json:"duration_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	if req.ApprovedByRole == "" {
		req.ApprovedByRole = "Security"
	}
	if req.DurationDays <= 0 {
		req.DurationDays = 30
	}

	expiresAt := time.Now().Add(time.Duration(req.DurationDays) * 24 * time.Hour)

	exc, err := h.Store.CreateException(req.ProjectID, req.RuleType, req.RuleValue, req.Reason, req.ApprovedByRole, expiresAt)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	h.AuditLog.Log(audit.Event{
		ProjectID: req.ProjectID, Actor: "api",
		Action: "exception.created", ResourceType: "exception", ResourceID: exc.ID,
		Details: map[string]interface{}{
			"rule_type": req.RuleType, "rule_value": req.RuleValue,
			"reason": req.Reason, "expires_at": expiresAt.Format(time.RFC3339),
		},
	})

	writeJSON(w, http.StatusCreated, exc)
}

// --- Vulnerability Import ---

func (h *Handler) ImportVulnerabilities(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read body"})
		return
	}

	count, err := h.Store.ImportVulnBundle(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	h.AuditLog.Log(audit.Event{
		Actor: "api", Action: "vulns.imported", ResourceType: "vulnerability",
		Details: map[string]interface{}{"count": count},
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"imported": count,
		"message":  fmt.Sprintf("%d vulnerability records imported/updated", count),
	})
}

// Helper

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// Ensure Handler implements all methods
var _ http.Handler = http.DefaultServeMux
var _ = (*Handler)(nil)
// Ensure we use sql package
var _ = (*sql.DB)(nil)
