package policy

import (
	"testing"
	"time"
)

func TestBlockCriticalCVEs_Pass(t *testing.T) {
	pf := &PolicyFile{
		Version: "1",
		Rules: []Rule{
			{Type: "block_critical_cves", Enabled: true, SeverityThreshold: "critical"},
		},
	}
	ctx := &EvalContext{
		Vulns: []VulnMatch{
			{VulnID: "CVE-2024-0001", Severity: "medium", CVSSScore: 5.0, PackageName: "foo"},
		},
		HasSBOM: true,
	}
	result := Evaluate(pf, ctx)
	if result.Decision != "PASS" {
		t.Errorf("expected PASS, got %s", result.Decision)
	}
}

func TestBlockCriticalCVEs_Fail(t *testing.T) {
	pf := &PolicyFile{
		Version: "1",
		Rules: []Rule{
			{Type: "block_critical_cves", Enabled: true, SeverityThreshold: "critical"},
		},
	}
	ctx := &EvalContext{
		Vulns: []VulnMatch{
			{VulnID: "CVE-2024-0001", Severity: "critical", CVSSScore: 9.8, PackageName: "lodash"},
		},
	}
	result := Evaluate(pf, ctx)
	if result.Decision != "FAIL" {
		t.Errorf("expected FAIL, got %s", result.Decision)
	}
	if result.FailedRules != 1 {
		t.Errorf("expected 1 failed rule, got %d", result.FailedRules)
	}
}

func TestBlockForbiddenLicenses_Fail(t *testing.T) {
	pf := &PolicyFile{
		Version: "1",
		Rules: []Rule{
			{Type: "block_forbidden_licenses", Enabled: true, Licenses: []string{"GPL-3.0-only", "AGPL-3.0-only"}},
		},
	}
	ctx := &EvalContext{
		Dependencies: []DepInfo{
			{Name: "mylib", Version: "1.0.0", License: "GPL-3.0-only"},
			{Name: "safelib", Version: "2.0.0", License: "MIT"},
		},
	}
	result := Evaluate(pf, ctx)
	if result.Decision != "FAIL" {
		t.Errorf("expected FAIL, got %s", result.Decision)
	}
}

func TestBlockForbiddenLicenses_Pass(t *testing.T) {
	pf := &PolicyFile{
		Version: "1",
		Rules: []Rule{
			{Type: "block_forbidden_licenses", Enabled: true, Licenses: []string{"GPL-3.0-only"}},
		},
	}
	ctx := &EvalContext{
		Dependencies: []DepInfo{
			{Name: "safelib", Version: "2.0.0", License: "MIT"},
			{Name: "another", Version: "1.0.0", License: "Apache-2.0"},
		},
	}
	result := Evaluate(pf, ctx)
	if result.Decision != "PASS" {
		t.Errorf("expected PASS, got %s", result.Decision)
	}
}

func TestRequireSBOM_Fail(t *testing.T) {
	pf := &PolicyFile{
		Version: "1",
		Rules: []Rule{
			{Type: "require_sbom", Enabled: true},
		},
	}
	ctx := &EvalContext{HasSBOM: false}
	result := Evaluate(pf, ctx)
	if result.Decision != "FAIL" {
		t.Errorf("expected FAIL, got %s", result.Decision)
	}
}

func TestRequireSBOM_Pass(t *testing.T) {
	pf := &PolicyFile{
		Version: "1",
		Rules: []Rule{
			{Type: "require_sbom", Enabled: true},
		},
	}
	ctx := &EvalContext{HasSBOM: true}
	result := Evaluate(pf, ctx)
	if result.Decision != "PASS" {
		t.Errorf("expected PASS, got %s", result.Decision)
	}
}

func TestRequireSignature(t *testing.T) {
	pf := &PolicyFile{
		Version: "1",
		Rules: []Rule{
			{Type: "require_signature", Enabled: true},
		},
	}
	ctx := &EvalContext{HasSignature: false}
	result := Evaluate(pf, ctx)
	if result.Decision != "FAIL" {
		t.Errorf("expected FAIL for missing signature, got %s", result.Decision)
	}

	ctx.HasSignature = true
	result = Evaluate(pf, ctx)
	if result.Decision != "PASS" {
		t.Errorf("expected PASS for present signature, got %s", result.Decision)
	}
}

func TestRequireProvenance(t *testing.T) {
	pf := &PolicyFile{
		Version: "1",
		Rules: []Rule{
			{Type: "require_provenance", Enabled: true, Fields: []string{"git_commit", "build_time", "sbom_hash"}},
		},
	}
	ctx := &EvalContext{
		Provenance: &ProvenanceInfo{
			GitCommit: "abc123",
			BuildTime: "2024-01-01T00:00:00Z",
			SBOMHash:  "deadbeef",
		},
	}
	result := Evaluate(pf, ctx)
	if result.Decision != "PASS" {
		t.Errorf("expected PASS, got %s", result.Decision)
	}

	// Missing field
	ctx.Provenance.SBOMHash = ""
	result = Evaluate(pf, ctx)
	if result.Decision != "FAIL" {
		t.Errorf("expected FAIL for missing sbom_hash, got %s", result.Decision)
	}
}

func TestExceptionWaiver(t *testing.T) {
	pf := &PolicyFile{
		Version: "1",
		Rules: []Rule{
			{Type: "block_critical_cves", Enabled: true, SeverityThreshold: "critical"},
		},
	}
	ctx := &EvalContext{
		Vulns: []VulnMatch{
			{VulnID: "CVE-2024-0001", Severity: "critical", CVSSScore: 9.8, PackageName: "lodash"},
		},
		Exceptions: []ExceptionInfo{
			{
				RuleType:  "block_critical_cves",
				RuleValue: "CVE-2024-0001",
				Reason:    "Approved by security team for 30 days",
				ExpiresAt: time.Now().Add(24 * time.Hour),
			},
		},
	}
	result := Evaluate(pf, ctx)
	if result.Decision != "PASS" {
		t.Errorf("expected PASS with waiver, got %s", result.Decision)
	}
	if result.WaivedRules != 1 {
		t.Errorf("expected 1 waived rule, got %d", result.WaivedRules)
	}
}

func TestMultipleRules(t *testing.T) {
	pf := &PolicyFile{
		Version: "1",
		Rules: []Rule{
			{Type: "block_critical_cves", Enabled: true, SeverityThreshold: "critical"},
			{Type: "block_forbidden_licenses", Enabled: true, Licenses: []string{"GPL-3.0-only"}},
			{Type: "require_sbom", Enabled: true},
			{Type: "require_signature", Enabled: true},
			{Type: "require_provenance", Enabled: true, Fields: []string{"git_commit"}},
		},
	}
	ctx := &EvalContext{
		HasSBOM:      true,
		HasSignature: true,
		Dependencies: []DepInfo{
			{Name: "safe", Version: "1.0.0", License: "MIT"},
		},
		Provenance: &ProvenanceInfo{
			GitCommit: "abc123",
			BuildTime: "2024-01-01T00:00:00Z",
		},
	}
	result := Evaluate(pf, ctx)
	if result.Decision != "PASS" {
		t.Errorf("expected PASS, got %s (failed: %d)", result.Decision, result.FailedRules)
		for _, r := range result.Results {
			if !r.Passed {
				t.Logf("  FAIL: %s — %s", r.RuleType, r.Message)
			}
		}
	}
	if result.TotalRules != 5 {
		t.Errorf("expected 5 rules, got %d", result.TotalRules)
	}
}

func TestParsePolicyYAML(t *testing.T) {
	yamlData := `
version: "1"
rules:
  - type: block_critical_cves
    enabled: true
    severity_threshold: critical
  - type: block_forbidden_licenses
    enabled: true
    licenses:
      - GPL-3.0-only
      - AGPL-3.0-only
  - type: require_sbom
    enabled: true
`
	pf, err := ParsePolicyYAML([]byte(yamlData))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(pf.Rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(pf.Rules))
	}
	if pf.Rules[1].Licenses[0] != "GPL-3.0-only" {
		t.Errorf("wrong license: %s", pf.Rules[1].Licenses[0])
	}
}

func TestDecisionHash_Deterministic(t *testing.T) {
	pf := &PolicyFile{
		Rules: []Rule{
			{Type: "require_sbom", Enabled: true},
		},
	}
	ctx := &EvalContext{HasSBOM: true}

	r1 := Evaluate(pf, ctx)
	r2 := Evaluate(pf, ctx)

	if r1.DecisionHash != r2.DecisionHash {
		t.Errorf("decision hash not deterministic: %s != %s", r1.DecisionHash, r2.DecisionHash)
	}
}
