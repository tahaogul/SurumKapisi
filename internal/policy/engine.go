package policy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// PolicyFile represents the .surumkapisi.yml file
type PolicyFile struct {
	Version string `yaml:"version" json:"version"`
	Rules   []Rule `yaml:"rules" json:"rules"`
}

// Rule represents a single policy rule
type Rule struct {
	Type              string   `yaml:"type" json:"type"`
	Enabled           bool     `yaml:"enabled" json:"enabled"`
	SeverityThreshold string   `yaml:"severity_threshold,omitempty" json:"severity_threshold,omitempty"`
	Licenses          []string `yaml:"licenses,omitempty" json:"licenses,omitempty"`
	Fields            []string `yaml:"fields,omitempty" json:"fields,omitempty"`
}

// EvalContext holds all data needed for policy evaluation
type EvalContext struct {
	Dependencies []DepInfo
	Vulns        []VulnMatch
	HasSBOM      bool
	HasSignature bool
	Provenance   *ProvenanceInfo
	Exceptions   []ExceptionInfo
}

// DepInfo describes a dependency in the evaluation context
type DepInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	License   string `json:"license"`
}

// VulnMatch describes a matched vulnerability
type VulnMatch struct {
	VulnID      string  `json:"vuln_id"`
	Severity    string  `json:"severity"`
	CVSSScore   float64 `json:"cvss_score"`
	PackageName string  `json:"package_name"`
	Description string  `json:"description"`
}

// ProvenanceInfo holds provenance data for evaluation
type ProvenanceInfo struct {
	GitCommit string `json:"git_commit"`
	BuildTime string `json:"build_time"`
	SBOMHash  string `json:"sbom_hash"`
}

// ExceptionInfo describes an active exception/waiver
type ExceptionInfo struct {
	RuleType  string    `json:"rule_type"`
	RuleValue string    `json:"rule_value"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RuleResult holds the result of evaluating a single rule
type RuleResult struct {
	RuleType   string   `json:"rule_type"`
	Passed     bool     `json:"passed"`
	Message    string   `json:"message"`
	Violations []string `json:"violations,omitempty"`
	Waived     bool     `json:"waived,omitempty"`
	WaiverInfo string   `json:"waiver_info,omitempty"`
}

// EvalResult is the complete evaluation result
type EvalResult struct {
	Decision       string       `json:"decision"`
	DecisionHash   string       `json:"decision_hash"`
	Results        []RuleResult `json:"results"`
	TotalRules     int          `json:"total_rules"`
	PassedRules    int          `json:"passed_rules"`
	FailedRules    int          `json:"failed_rules"`
	WaivedRules    int          `json:"waived_rules"`
	ExceptionsUsed []string     `json:"exceptions_used,omitempty"`
}

// ParsePolicyYAML parses a YAML policy file
func ParsePolicyYAML(data []byte) (*PolicyFile, error) {
	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("policy YAML parse error: %w", err)
	}
	if pf.Version == "" {
		pf.Version = "1"
	}
	return &pf, nil
}

// ParsePolicyJSON parses a JSON policy (from DB)
func ParsePolicyJSON(data []byte) (*PolicyFile, error) {
	var pf PolicyFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("policy JSON parse error: %w", err)
	}
	return &pf, nil
}

// Evaluate runs all policy rules against the context
func Evaluate(policy *PolicyFile, ctx *EvalContext) *EvalResult {
	result := &EvalResult{
		Decision: "PASS",
	}

	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}
		result.TotalRules++

		rr := evaluateRule(rule, ctx)

		// Check if there's a waiver for this rule
		if !rr.Passed {
			if waiver, found := findException(rule, ctx.Exceptions); found {
				rr.Passed = true
				rr.Waived = true
				rr.WaiverInfo = fmt.Sprintf("Exception: %s (expires %s)", waiver.Reason, waiver.ExpiresAt.Format(time.RFC3339))
				result.WaivedRules++
				result.ExceptionsUsed = append(result.ExceptionsUsed, waiver.RuleValue)
			}
		}

		if rr.Passed {
			result.PassedRules++
		} else {
			result.FailedRules++
			result.Decision = "FAIL"
		}

		result.Results = append(result.Results, rr)
	}

	// Compute decision hash
	hashData, _ := json.Marshal(result.Results)
	hash := sha256.Sum256(hashData)
	result.DecisionHash = fmt.Sprintf("%x", hash)

	return result
}

func evaluateRule(rule Rule, ctx *EvalContext) RuleResult {
	switch rule.Type {
	case "block_critical_cves":
		return evalBlockCriticalCVEs(rule, ctx)
	case "block_forbidden_licenses":
		return evalBlockForbiddenLicenses(rule, ctx)
	case "require_sbom":
		return evalRequireSBOM(ctx)
	case "require_signature":
		return evalRequireSignature(ctx)
	case "require_provenance":
		return evalRequireProvenance(rule, ctx)
	default:
		return RuleResult{
			RuleType: rule.Type,
			Passed:   true,
			Message:  fmt.Sprintf("Unknown rule type '%s', skipping", rule.Type),
		}
	}
}

func evalBlockCriticalCVEs(rule Rule, ctx *EvalContext) RuleResult {
	rr := RuleResult{RuleType: "block_critical_cves", Passed: true}

	threshold := strings.ToLower(rule.SeverityThreshold)
	if threshold == "" {
		threshold = "critical"
	}

	severityOrder := map[string]int{
		"low": 1, "medium": 2, "high": 3, "critical": 4,
	}
	thresholdLevel := severityOrder[threshold]

	for _, v := range ctx.Vulns {
		vulnLevel, ok := severityOrder[strings.ToLower(v.Severity)]
		if !ok {
			continue
		}
		if vulnLevel >= thresholdLevel {
			rr.Passed = false
			rr.Violations = append(rr.Violations,
				fmt.Sprintf("%s: %s (%s, CVSS %.1f) in %s",
					v.VulnID, v.Description, v.Severity, v.CVSSScore, v.PackageName))
		}
	}

	if rr.Passed {
		rr.Message = fmt.Sprintf("No vulnerabilities at or above '%s' severity found", threshold)
	} else {
		rr.Message = fmt.Sprintf("%d vulnerability(ies) at or above '%s' severity found", len(rr.Violations), threshold)
	}

	return rr
}

func evalBlockForbiddenLicenses(rule Rule, ctx *EvalContext) RuleResult {
	rr := RuleResult{RuleType: "block_forbidden_licenses", Passed: true}

	forbiddenSet := make(map[string]bool)
	for _, l := range rule.Licenses {
		forbiddenSet[strings.ToUpper(l)] = true
	}

	for _, dep := range ctx.Dependencies {
		if dep.License != "" && forbiddenSet[strings.ToUpper(dep.License)] {
			rr.Passed = false
			rr.Violations = append(rr.Violations,
				fmt.Sprintf("%s@%s uses forbidden license '%s'", dep.Name, dep.Version, dep.License))
		}
	}

	if rr.Passed {
		rr.Message = "No forbidden licenses found"
	} else {
		rr.Message = fmt.Sprintf("%d dependency(ies) with forbidden licenses", len(rr.Violations))
	}

	return rr
}

func evalRequireSBOM(ctx *EvalContext) RuleResult {
	rr := RuleResult{RuleType: "require_sbom"}
	if ctx.HasSBOM {
		rr.Passed = true
		rr.Message = "SBOM is present"
	} else {
		rr.Passed = false
		rr.Message = "SBOM is required but not found"
		rr.Violations = []string{"No SBOM submitted for this build"}
	}
	return rr
}

func evalRequireSignature(ctx *EvalContext) RuleResult {
	rr := RuleResult{RuleType: "require_signature"}
	if ctx.HasSignature {
		rr.Passed = true
		rr.Message = "Artifact signature is present"
	} else {
		rr.Passed = false
		rr.Message = "Artifact signature is required but not found"
		rr.Violations = []string{"No artifact signature found"}
	}
	return rr
}

func evalRequireProvenance(rule Rule, ctx *EvalContext) RuleResult {
	rr := RuleResult{RuleType: "require_provenance", Passed: true}

	if ctx.Provenance == nil {
		rr.Passed = false
		rr.Message = "Provenance is required but not found"
		rr.Violations = []string{"No provenance record submitted"}
		return rr
	}

	for _, field := range rule.Fields {
		switch field {
		case "git_commit":
			if ctx.Provenance.GitCommit == "" {
				rr.Passed = false
				rr.Violations = append(rr.Violations, "Missing provenance field: git_commit")
			}
		case "build_time":
			if ctx.Provenance.BuildTime == "" {
				rr.Passed = false
				rr.Violations = append(rr.Violations, "Missing provenance field: build_time")
			}
		case "sbom_hash":
			if ctx.Provenance.SBOMHash == "" {
				rr.Passed = false
				rr.Violations = append(rr.Violations, "Missing provenance field: sbom_hash")
			}
		}
	}

	if rr.Passed {
		rr.Message = "All required provenance fields present"
	} else {
		rr.Message = fmt.Sprintf("%d provenance field(s) missing", len(rr.Violations))
	}

	return rr
}

func findException(rule Rule, exceptions []ExceptionInfo) (*ExceptionInfo, bool) {
	now := time.Now()
	for i, exc := range exceptions {
		if exc.RuleType == rule.Type && exc.ExpiresAt.After(now) {
			return &exceptions[i], true
		}
	}
	return nil, false
}
