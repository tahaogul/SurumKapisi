package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/surumkapisi/surumkapisi/internal/api"
	"github.com/surumkapisi/surumkapisi/internal/audit"
	"github.com/surumkapisi/surumkapisi/internal/database"
	"github.com/surumkapisi/surumkapisi/internal/models"
	"github.com/surumkapisi/surumkapisi/internal/policy"
	"github.com/surumkapisi/surumkapisi/internal/signing"
	"github.com/surumkapisi/surumkapisi/internal/store"
)

var startTime = time.Now()

// Breadcrumb for navigation
type Breadcrumb struct {
	Label string
	URL   string
}

// TemplateData is the base data passed to all templates
type TemplateData struct {
	Title       string
	ActivePage  string
	Breadcrumbs []Breadcrumb
}

func main() {
	log.Println("🔐 SürümKapısı Server v1.0.0 başlatılıyor...")
	log.Printf("   Go %s | %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)

	// Config from env
	dbCfg := database.Config{
		Host:     getEnv("SK_DB_HOST", "localhost"),
		Port:     getEnv("SK_DB_PORT", "5432"),
		Name:     getEnv("SK_DB_NAME", "surumkapisi"),
		User:     getEnv("SK_DB_USER", "skuser"),
		Password: getEnv("SK_DB_PASSWORD", "skpass123"),
		SSLMode:  getEnv("SK_DB_SSLMODE", "disable"),
	}
	adminToken := getEnv("SK_ADMIN_TOKEN", "sk-admin-token-2024")
	listenAddr := getEnv("SK_LISTEN_ADDR", ":8080")
	keyPath := getEnv("SK_SIGNING_KEY_PATH", "./keys")

	// Connect to database
	db, err := database.Connect(dbCfg)
	if err != nil {
		log.Fatalf("Database connection failed: %v", err)
	}
	defer db.Close()
	log.Println("✅ Veritabanı bağlantısı kuruldu")

	// Initialize store
	s := store.New(db)

	// Initialize audit logger
	auditLog := audit.NewLogger(db)

	// Initialize signing keys
	kp, err := signing.LoadOrCreateKeyPair(keyPath)
	if err != nil {
		log.Fatalf("Failed to initialize signing keys: %v", err)
	}
	log.Println("✅ İmzalama anahtarları hazır")

	// Ensure default org has signing keys
	orgID, err := s.GetDefaultOrg()
	if err == nil {
		_, err := s.GetActiveSigningKey(orgID)
		if err != nil {
			s.CreateSigningKey(orgID, "default-key", "RSA-2048", kp.PublicPEM, kp.PrivatePEM)
		}
	}

	// Setup router
	r := mux.NewRouter()

	// CORS middleware
	r.Use(corsMiddleware)

	// Health endpoints
	r.HandleFunc("/health", healthHandler(db)).Methods("GET")
	r.HandleFunc("/ready", readyHandler(db)).Methods("GET")

	// API handler
	h := &api.Handler{
		Store:      s,
		AuditLog:   auditLog,
		KeyPair:    kp,
		AdminToken: adminToken,
	}
	h.RegisterRoutes(r)

	// Web UI routes
	tmplDir := findDir("web/templates", "/app/web/templates")
	staticDir := findDir("web/static", "/app/web/static")

	// Parse all templates with layout
	tmplFuncs := template.FuncMap{
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "…"
		},
		"toLower": strings.ToLower,
		"toUpper": strings.ToUpper,
		"formatTime": func(t interface{}) string {
			switch v := t.(type) {
			case time.Time:
				return v.Format(time.RFC3339)
			case string:
				return v
			default:
				return fmt.Sprint(v)
			}
		},
		"formatBytes": func(b int64) string {
			if b < 1024 {
				return fmt.Sprintf("%d B", b)
			} else if b < 1024*1024 {
				return fmt.Sprintf("%.1f KB", float64(b)/1024)
			}
			return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
		},
		"printf": fmt.Sprintf,
		"index": func(m map[string]interface{}, key string) string {
			if v, ok := m[key]; ok {
				return fmt.Sprint(v)
			}
			return ""
		},
	}

	loadTemplate := func(name string) *template.Template {
		layoutPath := filepath.Join(tmplDir, "layout.html")
		pagePath := filepath.Join(tmplDir, name+".html")
		t, err := template.New("layout.html").Funcs(tmplFuncs).ParseFiles(layoutPath, pagePath)
		if err != nil {
			log.Printf("⚠️ Template yükleme hatası [%s]: %v", name, err)
			return nil
		}
		return t
	}

	render := func(w http.ResponseWriter, tmplName string, data map[string]interface{}) {
		t := loadTemplate(tmplName)
		if t == nil {
			http.Error(w, "Template error", 500)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := t.ExecuteTemplate(w, "layout", data); err != nil {
			log.Printf("Template execute error [%s]: %v", tmplName, err)
		}
	}

	// ---- Dashboard ----
	r.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		projects, _ := s.ListAllProjects()
		type ProjectView struct {
			ID, Name, Slug, RepoURL string
			Builds                  int
			PassRate                string
			PassCount, FailCount    int
		}
		var pviews []ProjectView
		totalBuilds, passedBuilds, failedBuilds := 0, 0, 0
		for _, p := range projects {
			stats, _ := s.GetBuildStats(p.ID)
			pv := ProjectView{ID: p.ID, Name: p.Name, Slug: p.Slug, RepoURL: p.RepoURL}
			if stats != nil {
				pv.Builds = stats.Total
				pv.PassCount = stats.Pass
				pv.FailCount = stats.Fail
				totalBuilds += stats.Total
				passedBuilds += stats.Pass
				failedBuilds += stats.Fail
				if stats.Total > 0 {
					pv.PassRate = fmt.Sprintf("%.0f%%", float64(stats.Pass)/float64(stats.Total)*100)
				} else {
					pv.PassRate = "—"
				}
			}
			pviews = append(pviews, pv)
		}

		// Recent builds (all projects, last 10)
		type BuildView struct {
			ID, ProjectName, GitCommit, Decision, CreatedAt string
			BuildNumber                                     int
		}
		var recentBuilds []BuildView
		for _, p := range projects {
			builds, _ := s.ListBuilds(p.ID)
			for _, b := range builds {
				if len(recentBuilds) >= 10 {
					break
				}
				recentBuilds = append(recentBuilds, BuildView{
					ID: b.ID, ProjectName: p.Name, GitCommit: b.GitCommit,
					Decision: b.Decision, BuildNumber: b.BuildNumber,
					CreatedAt: b.CreatedAt.Format(time.RFC3339),
				})
			}
		}

		render(w, "dashboard", map[string]interface{}{
			"Title":         "Dashboard",
			"ActivePage":    "dashboard",
			"Breadcrumbs":   []Breadcrumb{{Label: "Dashboard"}},
			"TotalProjects": len(projects),
			"TotalBuilds":   totalBuilds,
			"PassedBuilds":  passedBuilds,
			"FailedBuilds":  failedBuilds,
			"Projects":      pviews,
			"RecentBuilds":  recentBuilds,
		})
	}).Methods("GET")

	// ---- Projects ----
	r.HandleFunc("/projects", func(w http.ResponseWriter, req *http.Request) {
		projects, _ := s.ListAllProjects()
		type ProjectView struct {
			ID, Name, Slug, RepoURL string
			Builds                  int
			PassRate                string
			PassCount, FailCount    int
		}
		var pviews []ProjectView
		for _, p := range projects {
			stats, _ := s.GetBuildStats(p.ID)
			pv := ProjectView{ID: p.ID, Name: p.Name, Slug: p.Slug, RepoURL: p.RepoURL}
			if stats != nil {
				pv.Builds = stats.Total
				pv.PassCount = stats.Pass
				pv.FailCount = stats.Fail
				if stats.Total > 0 {
					pv.PassRate = fmt.Sprintf("%.0f%%", float64(stats.Pass)/float64(stats.Total)*100)
				} else {
					pv.PassRate = "—"
				}
			}
			pviews = append(pviews, pv)
		}
		render(w, "projects", map[string]interface{}{
			"Title":       "Projeler",
			"ActivePage":  "projects",
			"Breadcrumbs": []Breadcrumb{{Label: "Dashboard", URL: "/"}, {Label: "Projeler"}},
			"Projects":    pviews,
		})
	}).Methods("GET")

	// ---- Builds ----
	r.HandleFunc("/projects/{id}/builds", func(w http.ResponseWriter, req *http.Request) {
		id := mux.Vars(req)["id"]
		project, err := s.GetProject(id)
		if err != nil {
			http.Error(w, "Project not found", 404)
			return
		}
		builds, _ := s.ListBuilds(id)
		stats, _ := s.GetBuildStats(id)
		render(w, "builds", map[string]interface{}{
			"Title":      fmt.Sprintf("Yapılar — %s", project.Name),
			"ActivePage": "projects",
			"Breadcrumbs": []Breadcrumb{
				{Label: "Dashboard", URL: "/"},
				{Label: "Projeler", URL: "/projects"},
				{Label: project.Name},
			},
			"Project": project,
			"Builds":  builds,
			"Stats":   stats,
		})
	}).Methods("GET")

	// ---- Build Detail ----
	r.HandleFunc("/builds/{id}", func(w http.ResponseWriter, req *http.Request) {
		id := mux.Vars(req)["id"]
		build, err := s.GetBuild(id)
		if err != nil {
			http.Error(w, "Build not found", 404)
			return
		}
		project, _ := s.GetProject(build.ProjectID)
		sbomRecord, _ := s.GetSBOMByBuild(id)
		eval, _ := s.GetEvaluationByBuild(id)
		prov, _ := s.GetProvenance(id)
		artifacts, _ := s.GetArtifactsByBuild(id)

		// Dependencies
		var deps []models.Dependency
		if sbomRecord != nil {
			deps, _ = s.GetDependencies(sbomRecord.ID)
		}

		// Vulnerability count
		vulnCount := 0
		if deps != nil {
			vulns, _ := s.MatchVulnerabilities(deps)
			vulnCount = len(vulns)
		}

		// Parse evaluation results for display
		var evalResults []policy.RuleResult
		if eval != nil {
			json.Unmarshal([]byte(eval.Results), &evalResults)
		}

		render(w, "build_detail", map[string]interface{}{
			"Title":      fmt.Sprintf("Yapı #%d", build.BuildNumber),
			"ActivePage": "projects",
			"Breadcrumbs": []Breadcrumb{
				{Label: "Dashboard", URL: "/"},
				{Label: project.Name, URL: "/projects/" + project.ID + "/builds"},
				{Label: fmt.Sprintf("Yapı #%d", build.BuildNumber)},
			},
			"Build":        build,
			"Project":      project,
			"SBOM":         sbomRecord,
			"Evaluation":   eval,
			"EvalResults":  evalResults,
			"Provenance":   prov,
			"Artifacts":    artifacts,
			"Dependencies": deps,
			"VulnCount":    vulnCount,
		})
	}).Methods("GET")

	// ---- Audit Log ----
	r.HandleFunc("/audit", func(w http.ResponseWriter, req *http.Request) {
		events, _ := auditLog.GetEvents("", 200)

		// Check chain integrity
		chainValid := true
		chainStatus := ""
		orgID, err := s.GetDefaultOrg()
		if err == nil {
			projects, _ := s.ListProjects(orgID)
			for _, p := range projects {
				valid, msg, _ := auditLog.VerifyChain(p.ID)
				if !valid {
					chainValid = false
					chainStatus = msg
					break
				}
				chainStatus = msg
			}
		}
		if chainStatus == "" {
			chainStatus = "Zincir kontrolü için veri yok"
		}

		render(w, "audit", map[string]interface{}{
			"Title":       "Denetim Günlüğü",
			"ActivePage":  "audit",
			"Breadcrumbs": []Breadcrumb{{Label: "Dashboard", URL: "/"}, {Label: "Denetim Günlüğü"}},
			"Events":      events,
			"ChainValid":  chainValid,
			"ChainStatus": chainStatus,
		})
	}).Methods("GET")

	// ---- Vulnerabilities ----
	r.HandleFunc("/vulnerabilities", func(w http.ResponseWriter, req *http.Request) {
		var vulns []models.Vulnerability
		rows, err := db.Query(`
			SELECT id, vuln_id, source, severity, COALESCE(cvss_score,0), package_name,
			       COALESCE(affected_versions,''), COALESCE(fixed_version,''),
			       COALESCE(description,''), COALESCE(reference_url,'')
			FROM vulnerabilities ORDER BY cvss_score DESC`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var v models.Vulnerability
				rows.Scan(&v.ID, &v.VulnID, &v.Source, &v.Severity, &v.CVSSScore,
					&v.PackageName, &v.AffectedVersions, &v.FixedVersion,
					&v.Description, &v.ReferenceURL)
				vulns = append(vulns, v)
			}
		}
		render(w, "vulnerabilities", map[string]interface{}{
			"Title":       "Güvenlik Açıkları",
			"ActivePage":  "vulnerabilities",
			"Breadcrumbs": []Breadcrumb{{Label: "Dashboard", URL: "/"}, {Label: "Güvenlik Açıkları"}},
			"Vulns":       vulns,
		})
	}).Methods("GET")

	// ---- Exceptions ----
	r.HandleFunc("/exceptions", func(w http.ResponseWriter, req *http.Request) {
		type ExcView struct {
			ProjectName    string
			RuleType       string
			RuleValue      string
			Reason         string
			ApprovedByRole string
			ExpiresAt      time.Time
			IsExpired      bool
		}
		var excViews []ExcView
		rows, err := db.Query(`
			SELECT e.rule_type, e.rule_value, e.reason, e.approved_by_role, e.expires_at,
			       COALESCE(p.name, 'N/A')
			FROM exceptions e
			LEFT JOIN projects p ON p.id = e.project_id
			WHERE e.active = TRUE
			ORDER BY e.created_at DESC`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var ev ExcView
				rows.Scan(&ev.RuleType, &ev.RuleValue, &ev.Reason, &ev.ApprovedByRole, &ev.ExpiresAt, &ev.ProjectName)
				ev.IsExpired = ev.ExpiresAt.Before(time.Now())
				excViews = append(excViews, ev)
			}
		}
		render(w, "exceptions", map[string]interface{}{
			"Title":       "İstisnalar",
			"ActivePage":  "exceptions",
			"Breadcrumbs": []Breadcrumb{{Label: "Dashboard", URL: "/"}, {Label: "İstisnalar"}},
			"Exceptions":  excViews,
		})
	}).Methods("GET")

	// ---- API Docs ----
	r.HandleFunc("/api-docs", func(w http.ResponseWriter, req *http.Request) {
		type Endpoint struct {
			Method, Path, Description, MethodClass string
			RequestBody, ResponseBody              string
		}
		endpoints := []Endpoint{
			{"POST", "/api/projects", "Yeni proje oluştur", "badge-pass",
				`{
  "name": "My Web App",
  "slug": "my-web-app",
  "repo_url": "https://github.com/org/app",
  "description": "Açıklama"
}`,
				`{
  "id": "uuid",
  "org_id": "uuid",
  "name": "My Web App",
  "slug": "my-web-app",
  "created_at": "2024-01-01T00:00:00Z"
}`},
			{"GET", "/api/projects", "Tüm projeleri listele", "badge-info", "", ""},
			{"POST", "/api/builds", "Yeni yapı kaydı oluştur", "badge-pass",
				`{
  "project_id": "uuid",
  "git_commit": "abc123def456",
  "git_branch": "main",
  "git_tag": "v1.0.0"
}`,
				`{
  "id": "uuid",
  "build_number": 1,
  "decision": "pending",
  "status": "pending"
}`},
			{"POST", "/api/sboms", "SBOM yükle", "badge-pass",
				`{
  "build_id": "uuid",
  "format": "cyclonedx",
  "content": { ... CycloneDX JSON ... }
}`, ""},
			{"POST", "/api/evaluate", "Politika değerlendir", "badge-pass",
				`{
  "build_id": "uuid",
  "policy": "... optional inline YAML ..."
}`,
				`{
  "decision": "PASS",
  "total_rules": 5,
  "passed_rules": 5,
  "failed_rules": 0,
  "decision_hash": "sha256..."
}`},
			{"POST", "/api/sign", "Artifact imzala", "badge-pass",
				`{
  "build_id": "uuid",
  "artifact_name": "app.jar",
  "artifact_type": "java-archive",
  "sha256_hash": "abc123...",
  "size_bytes": 1048576
}`,
				`{
  "artifact_id": "uuid",
  "signature": "base64...",
  "signed_at": "2024-01-01T00:00:00Z",
  "public_key": "-----BEGIN PUBLIC KEY-----..."
}`},
			{"GET", "/api/reports/{buildId}", "Yapı raporu (JSON)", "badge-info", "", ""},
			{"GET", "/api/reports/{buildId}/html", "Yapı raporu (HTML)", "badge-info", "", ""},
			{"GET", "/api/audit?projectId=...", "Denetim günlüğü", "badge-info", "", ""},
			{"POST", "/api/exceptions", "İstisna/muafiyet oluştur", "badge-pass",
				`{
  "project_id": "uuid",
  "rule_type": "block_critical_cves",
  "rule_value": "CVE-2024-0001",
  "reason": "Güvenlik ekibi onayladı",
  "approved_by_role": "Security",
  "duration_days": 30
}`, ""},
			{"POST", "/api/vulnerabilities/import", "Güvenlik açığı verisi içe aktar", "badge-pass",
				`{
  "format": "surumkapisi-vuln-bundle",
  "version": "1.0",
  "vulnerabilities": [...]
}`, ""},
			{"GET", "/health", "Sağlık kontrolü", "badge-info", "", `{"status": "ok"}`},
		}

		render(w, "api_docs", map[string]interface{}{
			"Title":       "API Dokümantasyonu",
			"ActivePage":  "api-docs",
			"Breadcrumbs": []Breadcrumb{{Label: "Dashboard", URL: "/"}, {Label: "API Dokümantasyonu"}},
			"Endpoints":   endpoints,
		})
	}).Methods("GET")

	// ---- Settings ----
	r.HandleFunc("/settings", func(w http.ResponseWriter, req *http.Request) {
		uptime := time.Since(startTime)
		uptimeStr := fmt.Sprintf("%dd %dh %dm", int(uptime.Hours())/24, int(uptime.Hours())%24, int(uptime.Minutes())%60)
		render(w, "settings", map[string]interface{}{
			"Title":       "Ayarlar",
			"ActivePage":  "settings",
			"Breadcrumbs": []Breadcrumb{{Label: "Dashboard", URL: "/"}, {Label: "Ayarlar"}},
			"GoVersion":   runtime.Version(),
			"ListenAddr":  listenAddr,
			"Uptime":      uptimeStr,
		})
	}).Methods("GET")

	// Static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))

	log.Println("═══════════════════════════════════════════════")
	log.Printf("🚀 SürümKapısı dinleniyor: %s", listenAddr)
	log.Printf("🌐 Web UI:       http://localhost%s", listenAddr)
	log.Printf("📡 REST API:     http://localhost%s/api/", listenAddr)
	log.Printf("📖 API Docs:     http://localhost%s/api-docs", listenAddr)
	log.Printf("❤️  Health:       http://localhost%s/health", listenAddr)
	log.Printf("🔑 Admin Token:  %s", adminToken)
	log.Println("═══════════════════════════════════════════════")

	if err := http.ListenAndServe(listenAddr, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

// ---- Health ----

func healthHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		status := "ok"
		if err := db.Ping(); err != nil {
			status = "degraded"
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    status,
			"version":   "1.0.0",
			"uptime":    time.Since(startTime).String(),
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"go":        runtime.Version(),
		})
	}
}

func readyHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := db.Ping(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"ready": "false", "error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"ready": "true"})
	}
}

// ---- CORS ----

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- Helpers ----

func findDir(paths ...string) string {
	for _, dir := range paths {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}
	return paths[0]
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
