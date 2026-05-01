package models

import (
	"time"
)

// Organization represents a tenant organization
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

// User represents a platform user
type User struct {
	ID       string `json:"id"`
	OrgID    string `json:"org_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

// Project represents a software project being tracked
type Project struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	RepoURL     string    `json:"repo_url,omitempty"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Build represents a single build/release attempt
type Build struct {
	ID             string    `json:"id"`
	ProjectID      string    `json:"project_id"`
	BuildNumber    int       `json:"build_number"`
	GitCommit      string    `json:"git_commit,omitempty"`
	GitBranch      string    `json:"git_branch,omitempty"`
	GitTag         string    `json:"git_tag,omitempty"`
	Status         string    `json:"status"`
	Decision       string    `json:"decision"`
	DecisionReason string    `json:"decision_reason,omitempty"`
	BuildTime      time.Time `json:"build_time"`
	CreatedAt      time.Time `json:"created_at"`
}

// Artifact represents a build artifact that may be signed
type Artifact struct {
	ID           string     `json:"id"`
	BuildID      string     `json:"build_id"`
	Name         string     `json:"name"`
	ArtifactType string     `json:"artifact_type"`
	SHA256Hash   string     `json:"sha256_hash"`
	SizeBytes    int64      `json:"size_bytes,omitempty"`
	Signed       bool       `json:"signed"`
	Signature    string     `json:"signature,omitempty"`
	SignedAt     *time.Time `json:"signed_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// SBOM represents a Software Bill of Materials
type SBOM struct {
	ID             string    `json:"id"`
	BuildID        string    `json:"build_id"`
	Format         string    `json:"format"`
	Version        string    `json:"version,omitempty"`
	Content        string    `json:"content"`
	SHA256Hash     string    `json:"sha256_hash"`
	ComponentCount int       `json:"component_count"`
	CreatedAt      time.Time `json:"created_at"`
}

// Dependency represents a single dependency found in an SBOM
type Dependency struct {
	ID        string `json:"id"`
	SBOMID    string `json:"sbom_id"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	PURL      string `json:"purl,omitempty"`
	License   string `json:"license,omitempty"`
	Direct    bool   `json:"direct"`
}

// Vulnerability represents a known security vulnerability
type Vulnerability struct {
	ID               string  `json:"id"`
	VulnID           string  `json:"vuln_id"`
	Source            string  `json:"source"`
	Severity         string  `json:"severity"`
	CVSSScore        float64 `json:"cvss_score,omitempty"`
	PackageName      string  `json:"package_name"`
	AffectedVersions string  `json:"affected_versions,omitempty"`
	FixedVersion     string  `json:"fixed_version,omitempty"`
	Description      string  `json:"description,omitempty"`
	ReferenceURL     string  `json:"reference_url,omitempty"`
}

// Policy represents a security policy
type Policy struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"project_id,omitempty"`
	OrgID       string    `json:"org_id,omitempty"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	IsDefault   bool      `json:"is_default"`
	CreatedAt   time.Time `json:"created_at"`
}

// PolicyVersion represents a versioned policy config
type PolicyVersion struct {
	ID          string    `json:"id"`
	PolicyID    string    `json:"policy_id"`
	Version     int       `json:"version"`
	Content     string    `json:"content"`
	ContentHash string    `json:"content_hash"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
}

// Evaluation represents a policy evaluation result for a build
type Evaluation struct {
	ID              string    `json:"id"`
	BuildID         string    `json:"build_id"`
	PolicyVersionID string    `json:"policy_version_id"`
	Decision        string    `json:"decision"`
	DecisionHash    string    `json:"decision_hash,omitempty"`
	Results         string    `json:"results"`
	Violations      string    `json:"violations,omitempty"`
	ExceptionsUsed  string    `json:"exceptions_used,omitempty"`
	EvaluatedAt     time.Time `json:"evaluated_at"`
}

// Exception represents a time-bound policy waiver
type Exception struct {
	ID             string    `json:"id"`
	ProjectID      string    `json:"project_id"`
	RuleType       string    `json:"rule_type"`
	RuleValue      string    `json:"rule_value"`
	Reason         string    `json:"reason"`
	ApprovedByRole string    `json:"approved_by_role"`
	ExpiresAt      time.Time `json:"expires_at"`
	Active         bool      `json:"active"`
	CreatedAt      time.Time `json:"created_at"`
}

// SigningKey represents a cryptographic signing key
type SigningKey struct {
	ID                  string    `json:"id"`
	OrgID               string    `json:"org_id"`
	Name                string    `json:"name"`
	Algorithm           string    `json:"algorithm"`
	PublicKey           string    `json:"public_key"`
	PrivateKeyEncrypted string    `json:"-"`
	Active              bool      `json:"active"`
	CreatedAt           time.Time `json:"created_at"`
}

// ProvenanceRecord represents build provenance attestation
type ProvenanceRecord struct {
	ID            string    `json:"id"`
	BuildID       string    `json:"build_id"`
	GitCommit     string    `json:"git_commit,omitempty"`
	GitBranch     string    `json:"git_branch,omitempty"`
	GitTag        string    `json:"git_tag,omitempty"`
	BuildTime     time.Time `json:"build_time"`
	SBOMHash      string    `json:"sbom_hash,omitempty"`
	PolicyVersion string    `json:"policy_version,omitempty"`
	DecisionHash  string    `json:"decision_hash,omitempty"`
	BuilderID     string    `json:"builder_id,omitempty"`
	Environment   string    `json:"environment,omitempty"`
	Signature     string    `json:"signature,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// AuditEvent represents an immutable audit log entry
type AuditEvent struct {
	ID           int64     `json:"id"`
	EventID      string    `json:"event_id"`
	ProjectID    string    `json:"project_id,omitempty"`
	OrgID        string    `json:"org_id,omitempty"`
	Actor        string    `json:"actor"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id,omitempty"`
	Details      string    `json:"details,omitempty"`
	PrevHash     string    `json:"prev_hash,omitempty"`
	CurrentHash  string    `json:"current_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

// Decision constants
const (
	DecisionPending = "pending"
	DecisionPass    = "PASS"
	DecisionFail    = "FAIL"
	DecisionWarn    = "WARN"
)

// BuildStatus constants
const (
	StatusPending    = "pending"
	StatusEvaluating = "evaluating"
	StatusCompleted  = "completed"
	StatusFailed     = "failed"
)
