-- 002_seed_data.sql
-- Demo organization, project, user, policy, licenses, and sample vulnerabilities

-- Demo Organization
INSERT INTO organizations (id, name, slug) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'Demo Şirket A.Ş.', 'demo-sirket')
ON CONFLICT (id) DO NOTHING;

-- Demo User (password: admin123 — bcrypt hash placeholder, MVP uses token auth)
INSERT INTO users (id, org_id, username, email, password_hash, role) VALUES
    ('b0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001',
     'admin', 'admin@demo.local', '$2a$10$placeholder', 'admin'),
    ('b0000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001',
     'security', 'security@demo.local', '$2a$10$placeholder', 'security')
ON CONFLICT DO NOTHING;

-- Demo Project
INSERT INTO projects (id, org_id, name, slug, repo_url, description) VALUES
    ('c0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001',
     'demo-web-app', 'demo-web-app', 'https://github.com/demo/web-app',
     'Demo web uygulaması — SürümKapısı test projesi')
ON CONFLICT DO NOTHING;

-- Default Policy
INSERT INTO policies (id, project_id, org_id, name, description, is_default) VALUES
    ('d0000000-0000-0000-0000-000000000001', 'c0000000-0000-0000-0000-000000000001',
     'a0000000-0000-0000-0000-000000000001', 'Varsayılan Güvenlik Politikası',
     'Kritik CVE engelleme, yasak lisans kontrolü, SBOM ve imza zorunluluğu', TRUE)
ON CONFLICT DO NOTHING;

-- Default Policy Version
INSERT INTO policy_versions (id, policy_id, version, content, content_hash, active) VALUES
    ('e0000000-0000-0000-0000-000000000001', 'd0000000-0000-0000-0000-000000000001', 1,
     '{
       "rules": [
         {"type": "block_critical_cves", "enabled": true, "severity_threshold": "critical"},
         {"type": "block_forbidden_licenses", "enabled": true, "licenses": ["GPL-3.0-only", "AGPL-3.0-only", "GPL-2.0-only"]},
         {"type": "require_sbom", "enabled": true},
         {"type": "require_signature", "enabled": true},
         {"type": "require_provenance", "enabled": true, "fields": ["git_commit", "build_time", "sbom_hash"]}
       ]
     }',
     'seed-policy-hash-v1', TRUE)
ON CONFLICT DO NOTHING;

-- Common Licenses
INSERT INTO licenses (spdx_id, name, category, osi_approved) VALUES
    ('MIT', 'MIT License', 'permissive', TRUE),
    ('Apache-2.0', 'Apache License 2.0', 'permissive', TRUE),
    ('BSD-2-Clause', 'BSD 2-Clause', 'permissive', TRUE),
    ('BSD-3-Clause', 'BSD 3-Clause', 'permissive', TRUE),
    ('ISC', 'ISC License', 'permissive', TRUE),
    ('MPL-2.0', 'Mozilla Public License 2.0', 'weak-copyleft', TRUE),
    ('LGPL-2.1-only', 'GNU LGPL v2.1 only', 'weak-copyleft', TRUE),
    ('GPL-2.0-only', 'GNU GPL v2.0 only', 'copyleft', TRUE),
    ('GPL-3.0-only', 'GNU GPL v3.0 only', 'copyleft', TRUE),
    ('AGPL-3.0-only', 'GNU AGPL v3.0 only', 'copyleft', TRUE),
    ('Unlicense', 'The Unlicense', 'public-domain', TRUE)
ON CONFLICT DO NOTHING;

-- Sample Vulnerabilities
INSERT INTO vulnerabilities (vuln_id, source, severity, cvss_score, package_name, affected_versions, fixed_version, description, reference_url) VALUES
    ('CVE-2024-0001', 'manual', 'critical', 9.8, 'lodash', '<4.17.21', '4.17.21', 'Prototype Pollution in lodash', 'https://nvd.nist.gov/vuln/detail/CVE-2024-0001'),
    ('CVE-2024-0002', 'manual', 'high', 7.5, 'express', '<4.18.2', '4.18.2', 'Open redirect in express', 'https://nvd.nist.gov/vuln/detail/CVE-2024-0002'),
    ('CVE-2024-0003', 'manual', 'critical', 9.1, 'log4j-core', '<2.17.1', '2.17.1', 'Remote code execution in Log4j', 'https://nvd.nist.gov/vuln/detail/CVE-2024-0003'),
    ('CVE-2024-0004', 'manual', 'medium', 5.3, 'requests', '<2.31.0', '2.31.0', 'SSRF vulnerability in requests', 'https://nvd.nist.gov/vuln/detail/CVE-2024-0004'),
    ('CVE-2024-0005', 'manual', 'low', 3.1, 'axios', '<1.6.0', '1.6.0', 'ReDoS in axios', 'https://nvd.nist.gov/vuln/detail/CVE-2024-0005')
ON CONFLICT DO NOTHING;
