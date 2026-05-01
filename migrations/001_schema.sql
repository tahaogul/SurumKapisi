-- 001_schema.sql
-- SürümKapısı Database Schema

-- Organizations
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    slug VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Users
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(org_id, username),
    UNIQUE(org_id, email)
);

CREATE INDEX idx_users_org ON users(org_id);

-- Projects
CREATE TABLE IF NOT EXISTS projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    repo_url VARCHAR(500),
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(org_id, slug)
);

CREATE INDEX idx_projects_org ON projects(org_id);

-- Builds
CREATE TABLE IF NOT EXISTS builds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id),
    build_number INTEGER NOT NULL,
    git_commit VARCHAR(64),
    git_branch VARCHAR(255),
    git_tag VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    decision VARCHAR(20) NOT NULL DEFAULT 'pending',
    decision_reason TEXT,
    build_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(project_id, build_number)
);

CREATE INDEX idx_builds_project ON builds(project_id);
CREATE INDEX idx_builds_status ON builds(status);

-- Artifacts
CREATE TABLE IF NOT EXISTS artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    build_id UUID NOT NULL REFERENCES builds(id),
    name VARCHAR(500) NOT NULL,
    artifact_type VARCHAR(100) NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    size_bytes BIGINT,
    signed BOOLEAN DEFAULT FALSE,
    signature TEXT,
    signed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_artifacts_build ON artifacts(build_id);
CREATE INDEX idx_artifacts_hash ON artifacts(sha256_hash);

-- SBOMs
CREATE TABLE IF NOT EXISTS sboms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    build_id UUID NOT NULL REFERENCES builds(id),
    format VARCHAR(50) NOT NULL DEFAULT 'cyclonedx',
    version VARCHAR(20),
    content JSONB NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    component_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_sboms_build ON sboms(build_id);

-- Dependencies
CREATE TABLE IF NOT EXISTS dependencies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id UUID NOT NULL REFERENCES sboms(id),
    name VARCHAR(500) NOT NULL,
    version VARCHAR(100),
    ecosystem VARCHAR(50),
    purl VARCHAR(1000),
    license VARCHAR(255),
    direct BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_dependencies_sbom ON dependencies(sbom_id);
CREATE INDEX idx_dependencies_name_ver ON dependencies(name, version);
CREATE INDEX idx_dependencies_ecosystem ON dependencies(ecosystem);

-- Vulnerabilities
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vuln_id VARCHAR(100) NOT NULL UNIQUE,
    source VARCHAR(100) NOT NULL DEFAULT 'manual',
    severity VARCHAR(20) NOT NULL,
    cvss_score NUMERIC(4,1),
    package_name VARCHAR(500) NOT NULL,
    affected_versions VARCHAR(500),
    fixed_version VARCHAR(100),
    description TEXT,
    reference_url VARCHAR(1000),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_vulns_package ON vulnerabilities(package_name);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);

-- Licenses
CREATE TABLE IF NOT EXISTS licenses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    spdx_id VARCHAR(100) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(50) NOT NULL DEFAULT 'permissive',
    osi_approved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Policies
CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id),
    org_id UUID REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_policies_project ON policies(project_id);
CREATE INDEX idx_policies_org ON policies(org_id);

-- Policy Versions
CREATE TABLE IF NOT EXISTS policy_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES policies(id),
    version INTEGER NOT NULL DEFAULT 1,
    content JSONB NOT NULL,
    content_hash VARCHAR(64) NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(policy_id, version)
);

CREATE INDEX idx_policy_versions_policy ON policy_versions(policy_id);

-- Evaluations
CREATE TABLE IF NOT EXISTS evaluations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    build_id UUID NOT NULL REFERENCES builds(id),
    policy_version_id UUID NOT NULL REFERENCES policy_versions(id),
    decision VARCHAR(20) NOT NULL,
    decision_hash VARCHAR(64),
    results JSONB NOT NULL,
    violations JSONB,
    exceptions_used JSONB,
    evaluated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_evaluations_build ON evaluations(build_id);

-- Exceptions (Waivers)
CREATE TABLE IF NOT EXISTS exceptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id),
    rule_type VARCHAR(100) NOT NULL,
    rule_value VARCHAR(500) NOT NULL,
    reason TEXT NOT NULL,
    approved_by UUID REFERENCES users(id),
    approved_by_role VARCHAR(50) NOT NULL DEFAULT 'Security',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_exceptions_project ON exceptions(project_id);
CREATE INDEX idx_exceptions_active ON exceptions(active, expires_at);

-- Signing Keys
CREATE TABLE IF NOT EXISTS signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    algorithm VARCHAR(50) NOT NULL DEFAULT 'RSA-2048',
    public_key TEXT NOT NULL,
    private_key_encrypted TEXT NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_signing_keys_org ON signing_keys(org_id);

-- Provenance Records
CREATE TABLE IF NOT EXISTS provenance_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    build_id UUID NOT NULL REFERENCES builds(id),
    git_commit VARCHAR(64),
    git_branch VARCHAR(255),
    git_tag VARCHAR(255),
    build_time TIMESTAMP WITH TIME ZONE,
    sbom_hash VARCHAR(64),
    policy_version VARCHAR(100),
    decision_hash VARCHAR(64),
    builder_id VARCHAR(255),
    environment JSONB,
    signature TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_provenance_build ON provenance_records(build_id);

-- Audit Events (append-only, hash-chained)
CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    project_id UUID REFERENCES projects(id),
    org_id UUID REFERENCES organizations(id),
    actor VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255),
    details JSONB,
    prev_hash VARCHAR(64),
    current_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_audit_project ON audit_events(project_id);
CREATE INDEX idx_audit_org ON audit_events(org_id);
CREATE INDEX idx_audit_action ON audit_events(action);
CREATE INDEX idx_audit_created ON audit_events(created_at);

-- PREVENT DELETE/UPDATE on audit_events
CREATE OR REPLACE FUNCTION prevent_audit_mutation() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_events table is append-only. Modifications are not allowed.';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_no_update
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
