package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/surumkapisi/surumkapisi/internal/models"
)

// Store provides data access operations
type Store struct {
	DB *sql.DB
}

// New creates a new Store
func New(db *sql.DB) *Store {
	return &Store{DB: db}
}

// --- Projects ---

func (s *Store) CreateProject(orgID, name, slug, repoURL, description string) (*models.Project, error) {
	id := uuid.New().String()
	_, err := s.DB.Exec(`
		INSERT INTO projects (id, org_id, name, slug, repo_url, description)
		VALUES ($1, $2, $3, $4, $5, $6)`, id, orgID, name, slug, repoURL, description)
	if err != nil {
		return nil, err
	}
	return s.GetProject(id)
}

func (s *Store) GetProject(id string) (*models.Project, error) {
	p := &models.Project{}
	err := s.DB.QueryRow(`
		SELECT id, org_id, name, slug, COALESCE(repo_url,''), COALESCE(description,''), created_at
		FROM projects WHERE id = $1`, id).Scan(&p.ID, &p.OrgID, &p.Name, &p.Slug, &p.RepoURL, &p.Description, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Store) ListProjects(orgID string) ([]models.Project, error) {
	rows, err := s.DB.Query(`
		SELECT id, org_id, name, slug, COALESCE(repo_url,''), COALESCE(description,''), created_at
		FROM projects WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []models.Project
	for rows.Next() {
		var p models.Project
		if err := rows.Scan(&p.ID, &p.OrgID, &p.Name, &p.Slug, &p.RepoURL, &p.Description, &p.CreatedAt); err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	return projects, nil
}

func (s *Store) ListAllProjects() ([]models.Project, error) {
	rows, err := s.DB.Query(`
		SELECT id, org_id, name, slug, COALESCE(repo_url,''), COALESCE(description,''), created_at
		FROM projects ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []models.Project
	for rows.Next() {
		var p models.Project
		if err := rows.Scan(&p.ID, &p.OrgID, &p.Name, &p.Slug, &p.RepoURL, &p.Description, &p.CreatedAt); err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	return projects, nil
}

// --- Builds ---

func (s *Store) CreateBuild(projectID, gitCommit, gitBranch, gitTag string) (*models.Build, error) {
	id := uuid.New().String()

	// Get next build number
	var maxNum sql.NullInt64
	s.DB.QueryRow(`SELECT MAX(build_number) FROM builds WHERE project_id = $1`, projectID).Scan(&maxNum)
	buildNum := 1
	if maxNum.Valid {
		buildNum = int(maxNum.Int64) + 1
	}

	_, err := s.DB.Exec(`
		INSERT INTO builds (id, project_id, build_number, git_commit, git_branch, git_tag, status, decision)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending', 'pending')`,
		id, projectID, buildNum, gitCommit, gitBranch, gitTag)
	if err != nil {
		return nil, err
	}
	return s.GetBuild(id)
}

func (s *Store) GetBuild(id string) (*models.Build, error) {
	b := &models.Build{}
	err := s.DB.QueryRow(`
		SELECT id, project_id, build_number, COALESCE(git_commit,''), COALESCE(git_branch,''),
		       COALESCE(git_tag,''), status, decision, COALESCE(decision_reason,''), build_time, created_at
		FROM builds WHERE id = $1`, id).Scan(
		&b.ID, &b.ProjectID, &b.BuildNumber, &b.GitCommit, &b.GitBranch,
		&b.GitTag, &b.Status, &b.Decision, &b.DecisionReason, &b.BuildTime, &b.CreatedAt)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (s *Store) ListBuilds(projectID string) ([]models.Build, error) {
	rows, err := s.DB.Query(`
		SELECT id, project_id, build_number, COALESCE(git_commit,''), COALESCE(git_branch,''),
		       COALESCE(git_tag,''), status, decision, COALESCE(decision_reason,''), build_time, created_at
		FROM builds WHERE project_id = $1 ORDER BY build_number DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var builds []models.Build
	for rows.Next() {
		var b models.Build
		if err := rows.Scan(&b.ID, &b.ProjectID, &b.BuildNumber, &b.GitCommit, &b.GitBranch,
			&b.GitTag, &b.Status, &b.Decision, &b.DecisionReason, &b.BuildTime, &b.CreatedAt); err != nil {
			return nil, err
		}
		builds = append(builds, b)
	}
	return builds, nil
}

func (s *Store) UpdateBuildDecision(id, status, decision, reason string) error {
	_, err := s.DB.Exec(`
		UPDATE builds SET status = $2, decision = $3, decision_reason = $4, updated_at = NOW()
		WHERE id = $1`, id, status, decision, reason)
	return err
}

// --- SBOMs ---

func (s *Store) CreateSBOM(buildID, format, version, content, sha256Hash string, componentCount int) (*models.SBOM, error) {
	id := uuid.New().String()
	_, err := s.DB.Exec(`
		INSERT INTO sboms (id, build_id, format, version, content, sha256_hash, component_count)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)`,
		id, buildID, format, version, content, sha256Hash, componentCount)
	if err != nil {
		return nil, err
	}
	return &models.SBOM{
		ID: id, BuildID: buildID, Format: format, Version: version,
		Content: content, SHA256Hash: sha256Hash, ComponentCount: componentCount,
		CreatedAt: time.Now(),
	}, nil
}

func (s *Store) GetSBOMByBuild(buildID string) (*models.SBOM, error) {
	sb := &models.SBOM{}
	err := s.DB.QueryRow(`
		SELECT id, build_id, format, COALESCE(version,''), content::text, sha256_hash, component_count, created_at
		FROM sboms WHERE build_id = $1 ORDER BY created_at DESC LIMIT 1`, buildID).Scan(
		&sb.ID, &sb.BuildID, &sb.Format, &sb.Version, &sb.Content, &sb.SHA256Hash, &sb.ComponentCount, &sb.CreatedAt)
	if err != nil {
		return nil, err
	}
	return sb, nil
}

// --- Dependencies ---

func (s *Store) CreateDependencies(sbomID string, deps []models.Dependency) error {
	for _, dep := range deps {
		id := uuid.New().String()
		_, err := s.DB.Exec(`
			INSERT INTO dependencies (id, sbom_id, name, version, ecosystem, purl, license, direct)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			id, sbomID, dep.Name, dep.Version, dep.Ecosystem, dep.PURL, dep.License, dep.Direct)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetDependencies(sbomID string) ([]models.Dependency, error) {
	rows, err := s.DB.Query(`
		SELECT id, sbom_id, name, COALESCE(version,''), COALESCE(ecosystem,''),
		       COALESCE(purl,''), COALESCE(license,''), direct
		FROM dependencies WHERE sbom_id = $1 ORDER BY name`, sbomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deps []models.Dependency
	for rows.Next() {
		var d models.Dependency
		if err := rows.Scan(&d.ID, &d.SBOMID, &d.Name, &d.Version, &d.Ecosystem,
			&d.PURL, &d.License, &d.Direct); err != nil {
			return nil, err
		}
		deps = append(deps, d)
	}
	return deps, nil
}

// --- Vulnerabilities ---

func (s *Store) MatchVulnerabilities(deps []models.Dependency) ([]models.Vulnerability, error) {
	var matched []models.Vulnerability

	for _, dep := range deps {
		rows, err := s.DB.Query(`
			SELECT id, vuln_id, source, severity, COALESCE(cvss_score,0), package_name,
			       COALESCE(affected_versions,''), COALESCE(fixed_version,''),
			       COALESCE(description,''), COALESCE(reference_url,'')
			FROM vulnerabilities WHERE LOWER(package_name) = LOWER($1)`, dep.Name)
		if err != nil {
			continue
		}

		for rows.Next() {
			var v models.Vulnerability
			if err := rows.Scan(&v.ID, &v.VulnID, &v.Source, &v.Severity, &v.CVSSScore,
				&v.PackageName, &v.AffectedVersions, &v.FixedVersion,
				&v.Description, &v.ReferenceURL); err != nil {
				continue
			}
			matched = append(matched, v)
		}
		rows.Close()
	}

	return matched, nil
}

func (s *Store) ImportVulnerabilities(vulns []models.Vulnerability) (int, error) {
	count := 0
	for _, v := range vulns {
		if v.ID == "" {
			v.ID = uuid.New().String()
		}
		_, err := s.DB.Exec(`
			INSERT INTO vulnerabilities (id, vuln_id, source, severity, cvss_score, package_name,
			                             affected_versions, fixed_version, description, reference_url)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (vuln_id) DO UPDATE SET
				severity = EXCLUDED.severity,
				cvss_score = EXCLUDED.cvss_score,
				affected_versions = EXCLUDED.affected_versions,
				fixed_version = EXCLUDED.fixed_version,
				description = EXCLUDED.description,
				updated_at = NOW()`,
			v.ID, v.VulnID, v.Source, v.Severity, v.CVSSScore, v.PackageName,
			v.AffectedVersions, v.FixedVersion, v.Description, v.ReferenceURL)
		if err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// --- Artifacts ---

func (s *Store) CreateArtifact(buildID, name, artifactType, sha256Hash string, sizeBytes int64) (*models.Artifact, error) {
	id := uuid.New().String()
	_, err := s.DB.Exec(`
		INSERT INTO artifacts (id, build_id, name, artifact_type, sha256_hash, size_bytes)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		id, buildID, name, artifactType, sha256Hash, sizeBytes)
	if err != nil {
		return nil, err
	}
	return &models.Artifact{ID: id, BuildID: buildID, Name: name, ArtifactType: artifactType,
		SHA256Hash: sha256Hash, SizeBytes: sizeBytes, CreatedAt: time.Now()}, nil
}

func (s *Store) SignArtifact(id, signature string) error {
	_, err := s.DB.Exec(`
		UPDATE artifacts SET signed = TRUE, signature = $2, signed_at = NOW()
		WHERE id = $1`, id, signature)
	return err
}

func (s *Store) GetArtifactsByBuild(buildID string) ([]models.Artifact, error) {
	rows, err := s.DB.Query(`
		SELECT id, build_id, name, artifact_type, sha256_hash, COALESCE(size_bytes,0),
		       signed, COALESCE(signature,''), signed_at, created_at
		FROM artifacts WHERE build_id = $1`, buildID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var artifacts []models.Artifact
	for rows.Next() {
		var a models.Artifact
		var signedAt sql.NullTime
		if err := rows.Scan(&a.ID, &a.BuildID, &a.Name, &a.ArtifactType, &a.SHA256Hash,
			&a.SizeBytes, &a.Signed, &a.Signature, &signedAt, &a.CreatedAt); err != nil {
			return nil, err
		}
		if signedAt.Valid {
			a.SignedAt = &signedAt.Time
		}
		artifacts = append(artifacts, a)
	}
	return artifacts, nil
}

// --- Evaluations ---

func (s *Store) CreateEvaluation(buildID, policyVersionID, decision, decisionHash string, results, violations, exceptionsUsed interface{}) (*models.Evaluation, error) {
	id := uuid.New().String()
	resultsJSON, _ := json.Marshal(results)
	violationsJSON, _ := json.Marshal(violations)
	exceptionsJSON, _ := json.Marshal(exceptionsUsed)

	_, err := s.DB.Exec(`
		INSERT INTO evaluations (id, build_id, policy_version_id, decision, decision_hash, results, violations, exceptions_used)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8::jsonb)`,
		id, buildID, policyVersionID, decision, decisionHash,
		string(resultsJSON), string(violationsJSON), string(exceptionsJSON))
	if err != nil {
		return nil, err
	}
	return &models.Evaluation{
		ID: id, BuildID: buildID, PolicyVersionID: policyVersionID,
		Decision: decision, DecisionHash: decisionHash,
		EvaluatedAt: time.Now(),
	}, nil
}

func (s *Store) GetEvaluationByBuild(buildID string) (*models.Evaluation, error) {
	e := &models.Evaluation{}
	err := s.DB.QueryRow(`
		SELECT id, build_id, policy_version_id, decision, COALESCE(decision_hash,''),
		       results::text, COALESCE(violations::text,'[]'), COALESCE(exceptions_used::text,'[]'), evaluated_at
		FROM evaluations WHERE build_id = $1 ORDER BY evaluated_at DESC LIMIT 1`, buildID).Scan(
		&e.ID, &e.BuildID, &e.PolicyVersionID, &e.Decision, &e.DecisionHash,
		&e.Results, &e.Violations, &e.ExceptionsUsed, &e.EvaluatedAt)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// --- Exceptions ---

func (s *Store) CreateException(projectID, ruleType, ruleValue, reason, approvedByRole string, expiresAt time.Time) (*models.Exception, error) {
	id := uuid.New().String()
	_, err := s.DB.Exec(`
		INSERT INTO exceptions (id, project_id, rule_type, rule_value, reason, approved_by_role, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, projectID, ruleType, ruleValue, reason, approvedByRole, expiresAt)
	if err != nil {
		return nil, err
	}
	return &models.Exception{
		ID: id, ProjectID: projectID, RuleType: ruleType, RuleValue: ruleValue,
		Reason: reason, ApprovedByRole: approvedByRole, ExpiresAt: expiresAt,
		Active: true, CreatedAt: time.Now(),
	}, nil
}

func (s *Store) GetActiveExceptions(projectID string) ([]models.Exception, error) {
	rows, err := s.DB.Query(`
		SELECT id, project_id, rule_type, rule_value, reason, approved_by_role, expires_at, active, created_at
		FROM exceptions
		WHERE project_id = $1 AND active = TRUE AND expires_at > NOW()
		ORDER BY created_at DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exceptions []models.Exception
	for rows.Next() {
		var e models.Exception
		if err := rows.Scan(&e.ID, &e.ProjectID, &e.RuleType, &e.RuleValue, &e.Reason,
			&e.ApprovedByRole, &e.ExpiresAt, &e.Active, &e.CreatedAt); err != nil {
			return nil, err
		}
		exceptions = append(exceptions, e)
	}
	return exceptions, nil
}

// --- Provenance ---

func (s *Store) CreateProvenance(buildID, gitCommit, gitBranch, gitTag, sbomHash, policyVersion, decisionHash, builderID string, env map[string]string, signature string) (*models.ProvenanceRecord, error) {
	id := uuid.New().String()
	envJSON, _ := json.Marshal(env)
	_, err := s.DB.Exec(`
		INSERT INTO provenance_records (id, build_id, git_commit, git_branch, git_tag, build_time,
		                                sbom_hash, policy_version, decision_hash, builder_id, environment, signature)
		VALUES ($1, $2, $3, $4, $5, NOW(), $6, $7, $8, $9, $10::jsonb, $11)`,
		id, buildID, gitCommit, gitBranch, gitTag, sbomHash, policyVersion, decisionHash, builderID, string(envJSON), signature)
	if err != nil {
		return nil, err
	}
	return &models.ProvenanceRecord{
		ID: id, BuildID: buildID, GitCommit: gitCommit, SBOMHash: sbomHash,
		DecisionHash: decisionHash, CreatedAt: time.Now(),
	}, nil
}

func (s *Store) GetProvenance(buildID string) (*models.ProvenanceRecord, error) {
	p := &models.ProvenanceRecord{}
	err := s.DB.QueryRow(`
		SELECT id, build_id, COALESCE(git_commit,''), COALESCE(git_branch,''), COALESCE(git_tag,''),
		       build_time, COALESCE(sbom_hash,''), COALESCE(policy_version,''),
		       COALESCE(decision_hash,''), COALESCE(builder_id,''),
		       COALESCE(environment::text,'{}'), COALESCE(signature,''), created_at
		FROM provenance_records WHERE build_id = $1 ORDER BY created_at DESC LIMIT 1`, buildID).Scan(
		&p.ID, &p.BuildID, &p.GitCommit, &p.GitBranch, &p.GitTag,
		&p.BuildTime, &p.SBOMHash, &p.PolicyVersion,
		&p.DecisionHash, &p.BuilderID,
		&p.Environment, &p.Signature, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// --- Policy ---

func (s *Store) GetDefaultPolicyVersion(projectID string) (*models.PolicyVersion, error) {
	pv := &models.PolicyVersion{}
	err := s.DB.QueryRow(`
		SELECT pv.id, pv.policy_id, pv.version, pv.content::text, pv.content_hash, pv.active, pv.created_at
		FROM policy_versions pv
		JOIN policies p ON p.id = pv.policy_id
		WHERE (p.project_id = $1 OR p.is_default = TRUE)
		  AND pv.active = TRUE
		ORDER BY p.project_id IS NOT NULL DESC, pv.version DESC
		LIMIT 1`, projectID).Scan(
		&pv.ID, &pv.PolicyID, &pv.Version, &pv.Content, &pv.ContentHash, &pv.Active, &pv.CreatedAt)
	if err != nil {
		return nil, err
	}
	return pv, nil
}

// --- Signing Keys ---

func (s *Store) GetActiveSigningKey(orgID string) (*models.SigningKey, error) {
	sk := &models.SigningKey{}
	err := s.DB.QueryRow(`
		SELECT id, org_id, name, algorithm, public_key, private_key_encrypted, active, created_at
		FROM signing_keys WHERE org_id = $1 AND active = TRUE
		ORDER BY created_at DESC LIMIT 1`, orgID).Scan(
		&sk.ID, &sk.OrgID, &sk.Name, &sk.Algorithm, &sk.PublicKey,
		&sk.PrivateKeyEncrypted, &sk.Active, &sk.CreatedAt)
	if err != nil {
		return nil, err
	}
	return sk, nil
}

func (s *Store) CreateSigningKey(orgID, name, algorithm, publicKey, privateKeyEnc string) (*models.SigningKey, error) {
	id := uuid.New().String()
	_, err := s.DB.Exec(`
		INSERT INTO signing_keys (id, org_id, name, algorithm, public_key, private_key_encrypted)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		id, orgID, name, algorithm, publicKey, privateKeyEnc)
	if err != nil {
		return nil, err
	}
	return &models.SigningKey{ID: id, OrgID: orgID, Name: name, Algorithm: algorithm,
		PublicKey: publicKey, Active: true, CreatedAt: time.Now()}, nil
}

// --- Org Helpers ---

func (s *Store) GetDefaultOrg() (string, error) {
	var orgID string
	err := s.DB.QueryRow(`SELECT id FROM organizations ORDER BY created_at LIMIT 1`).Scan(&orgID)
	return orgID, err
}

func (s *Store) GetProjectBySlug(slug string) (*models.Project, error) {
	p := &models.Project{}
	err := s.DB.QueryRow(`
		SELECT id, org_id, name, slug, COALESCE(repo_url,''), COALESCE(description,''), created_at
		FROM projects WHERE slug = $1`, slug).Scan(&p.ID, &p.OrgID, &p.Name, &p.Slug, &p.RepoURL, &p.Description, &p.CreatedAt)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// GetBuildCountByProject returns the number of builds for a project
func (s *Store) GetBuildCountByProject(projectID string) (int, error) {
	var count int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM builds WHERE project_id = $1`, projectID).Scan(&count)
	return count, err
}

// GetOrgByProject returns the org_id for a project
func (s *Store) GetOrgByProject(projectID string) (string, error) {
	var orgID string
	err := s.DB.QueryRow(`SELECT org_id FROM projects WHERE id = $1`, projectID).Scan(&orgID)
	return orgID, err
}

// GetBuildStats returns build statistics
type BuildStats struct {
	Total  int
	Pass   int
	Fail   int
	Pending int
}

func (s *Store) GetBuildStats(projectID string) (*BuildStats, error) {
	stats := &BuildStats{}
	err := s.DB.QueryRow(`
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE decision = 'PASS'),
			COUNT(*) FILTER (WHERE decision = 'FAIL'),
			COUNT(*) FILTER (WHERE decision = 'pending')
		FROM builds WHERE project_id = $1`, projectID).Scan(
		&stats.Total, &stats.Pass, &stats.Fail, &stats.Pending)
	return stats, err
}

// Vulnerability bundle import
type VulnBundle struct {
	Format  string                `json:"format"`
	Version string                `json:"version"`
	Vulns   []models.Vulnerability `json:"vulnerabilities"`
}

func (s *Store) ImportVulnBundle(data []byte) (int, error) {
	var bundle VulnBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return 0, fmt.Errorf("invalid bundle format: %w", err)
	}
	return s.ImportVulnerabilities(bundle.Vulns)
}
