package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// lastReleaseMigration is the number of embedded migrations the last release
// shipped: v0.5.0 shipped 0001 to 0006. The upgrade test builds a database of
// that release and upgrades it to the current migrations. The release
// procedure raises it when a release ships a new migration.
const lastReleaseMigration = 6

// upgradeSeedStep is what the upgrade test needs to know about one migration.
// Every embedded migration has one, so every migration pull request brings
// its own.
type upgradeSeedStep struct {
	// checksum is the SHA-256 of the migration file. Applied migrations are
	// immutable, so the test fails when the file no longer matches it.
	checksum string
	// seed runs right after the migration while the test builds the last
	// release's database. It writes synthetic rows using only the tables and
	// columns that exist at that point, so an old step never breaks: rows in
	// the tables the migration creates, and values in the columns it adds.
	// Example domains, documentation address ranges and made-up names, never
	// real data.
	seed string
	// added states, per table, what rows written before the migration hold in
	// each column it adds, as the column's to_jsonb value. A column added with
	// a default lists that default (for example `"UTC"`); a nullable column
	// without one lists null. The test reads it only while the migration is
	// newer than the last release: Migrate then runs it on the seeded rows.
	added map[string]map[string]string
}

// upgradeSeedSteps holds one step per embedded migration, keyed by file name.
var upgradeSeedSteps = map[string]upgradeSeedStep{
	"0001_init.sql": {
		checksum: "055c9e0422bf1b907601b68441b965e81653a3b14ea2ce8feb020c2b7827fc96",
		seed: `
UPDATE app_settings
   SET retention_enabled = true,
       scan_retention_days = 90,
       retention_include_adhoc = true,
       updated_by = 'zoe.admin@example.com',
       updated_at = '2026-09-30 17:04:11.250731+00';

INSERT INTO users (id, subject, email, name, roles, created_at, last_login_at) VALUES
  ('10844a2e-333d-409e-b48e-86beac6b97b9', 'kc|4f1d8a90-77e2-4c55-9a0e-1c2b3d4e5f60', 'zoe.admin@example.com',
   'Zoë Ångström-Müller', '{admin,operator}', '2026-08-01 09:00:00+02', '2026-10-02 22:41:07.000123+02'),
  ('6eb97686-4b9a-4bfa-9c5a-910c68458048', 'kc|viewer-only-7731', NULL, NULL, '{}',
   '2026-08-15 12:30:00+00', '2026-08-15 12:30:00+00');

INSERT INTO sessions (id, subject, email, name, roles, created_at, expires_at) VALUES
  ('s3ss10n-synthetic-0001-aaaaaaaaaaaaaaaaaaaa', 'kc|4f1d8a90-77e2-4c55-9a0e-1c2b3d4e5f60', 'zoe.admin@example.com',
   'Zoë Ångström-Müller', '{admin,operator}', '2026-10-02 22:41:07.000123+02', '2026-10-03 06:41:07.000123+02'),
  ('s3ss10n-synthetic-0002-bbbbbbbbbbbbbbbbbbbb', 'kc|viewer-only-7731', NULL, NULL, '{}',
   '2026-10-01 08:00:00+00', '2026-10-01 16:00:00+00');

INSERT INTO auth_flows (state, nonce, pkce_verifier, return_to, created_at, expires_at) VALUES
  ('st-synthetic-6f2c', 'nonce-synthetic-91ab', 'pkce-synthetic-verifier-0123456789abcdefghijklmnopqrstuvwxyz',
   '/findings?severity=high&q=caf%C3%A9', '2026-10-02 22:40:00+02', '2026-10-02 22:50:00+02'),
  ('st-synthetic-7a3d', 'nonce-synthetic-02cd', 'pkce-synthetic-verifier-zyxwvutsrqponmlkjihgfedcba9876543210',
   NULL, '2026-10-02 23:00:00+02', '2026-10-02 23:10:00+02');

INSERT INTO service_accounts (id, name, role, token_hash, token_prefix, created_by, created_at, expires_at, last_used_at) VALUES
  ('963c7bcc-7f9a-4d9b-8085-89188d6b44af', 'ci-pipeline-exporter', 'viewer',
   '9d4f0c4b6a1e2f3d5c7b9a8e6f4d2c1b0a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c', 'nsc_Ab3d',
   'zoe.admin@example.com', '2026-09-01 10:00:00+00', '2027-03-01 00:00:00+00', '2026-10-02 03:15:00.5+00'),
  ('8dd22695-237b-4eed-9137-a2acec492ce9', 'Überwachung – nightly', 'operator',
   '1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809', 'nsc_Zz09',
   NULL, '2026-09-05 10:00:00+00', NULL, NULL);

INSERT INTO scanner_nodes (id, name, endpoint, token, cidrs, tags, created_by, created_at, updated_at,
                           tls_server_ca, tls_client_cert, tls_client_key, templates_synced_at, max_concurrent_scans) VALUES
  ('dcfddfaf-b417-417d-8f7f-d67650349614', 'default', 'http://scanner:8081', 'synthetic-node-token-000000000000000001',
   '{}', '{}', NULL, '2026-08-01 09:00:00+00', '2026-08-01 09:00:00+00', '', '', '', NULL, 20),
  ('b27e6209-d9aa-423b-b3b5-86d688874b08', 'dmz-frankfurt-1', 'https://scanner-dmz.example.net:8443',
   'synthetic-node-token-000000000000000002', '{10.20.0.0/16,198.51.100.0/24}', '{eu-central,dmz,"Zone Süd"}',
   'zoe.admin@example.com', '2026-08-20 14:00:00+00', '2026-09-28 18:22:33.444555+00',
   'synthetic test CA placeholder', 'synthetic client certificate placeholder', 'synthetic client key placeholder',
   '2026-10-02 04:00:12.345678+00', 4);

INSERT INTO templates (id, source, path, yaml, content_sha256, name, author, severity, description, tags,
                       upstream_ref, revision, availability, created_by, created_at, updated_at) VALUES
  ('http-missing-security-headers', 'upstream', 'http/misconfiguration/http-missing-security-headers.yaml',
   E'id: http-missing-security-headers\ninfo:\n  name: HTTP Missing Security Headers\n  severity: info\n',
   'b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184', 'HTTP Missing Security Headers',
   'synthetic-author', 'info', 'Checks for missing security headers.', '{misconfig,headers,generic}',
   'v10.2.7', 3, 'active', NULL, '2026-08-01 09:05:00+00', '2026-09-30 04:00:00+00'),
  ('custom-login-panel-ümlaut', 'custom', 'custom/login-panel-ümlaut.yaml',
   E'id: custom-login-panel-ümlaut\ninfo:\n  name: Anmeldeseite – Prüfung\n  severity: medium\n',
   'c2a5e7f9b1d3c5e7f9a1b3d5c7e9f1a3b5d7c9e1f3a5b7d9c1e3f5a7b9d1c3e5', 'Anmeldeseite – Prüfung 🌙',
   '', 'medium', '', '{}', NULL, 1, 'active', 'zoe.admin@example.com',
   '2026-09-10 11:11:11.111111+00', '2026-09-10 11:11:11.111111+00'),
  ('cve-2099-0001-retired', 'upstream', 'http/cves/2099/CVE-2099-0001.yaml',
   E'id: cve-2099-0001-retired\ninfo:\n  name: Retired synthetic CVE\n  severity: high\n',
   'd3b07384d113edec49eaa6238ad5ff00d3b07384d113edec49eaa6238ad5ff00', 'Retired synthetic CVE',
   'synthetic-author', 'high', 'Removed upstream; kept for history.', '{cve,cve2099}',
   'v10.2.6', 2, 'unavailable', NULL, '2026-08-01 09:05:00+00', '2026-09-15 04:00:00+00');

INSERT INTO template_sets (id, name, created_by, created_at, updated_at, mode) VALUES
  ('a67806ce-f4cc-4ba7-acb1-c0e6e7db0d58', 'Web baseline', 'zoe.admin@example.com',
   '2026-08-02 10:00:00+00', '2026-09-10 11:12:00+00', 'exact'),
  ('809150bd-2cd1-4e06-9171-bf16e0c95e1d', 'Alles außer Retired', NULL,
   '2026-08-03 10:00:00+00', '2026-08-03 10:00:00+00', 'exclude');

INSERT INTO template_set_members (template_set_id, template_id, added_by, added_at) VALUES
  ('a67806ce-f4cc-4ba7-acb1-c0e6e7db0d58', 'http-missing-security-headers', 'zoe.admin@example.com', '2026-08-02 10:00:00+00'),
  ('a67806ce-f4cc-4ba7-acb1-c0e6e7db0d58', 'custom-login-panel-ümlaut', NULL, '2026-09-10 11:12:00+00');

INSERT INTO template_set_exclusions (template_set_id, template_id, added_by, added_at) VALUES
  ('809150bd-2cd1-4e06-9171-bf16e0c95e1d', 'cve-2099-0001-retired', NULL, '2026-08-03 10:00:00+00');

INSERT INTO template_sync_runs (id, started_at, finished_at, status, ref_before, ref_after,
                                added, removed, updated, skipped, error, templates_commit, template_count) VALUES
  ('d5ee9992-d4ae-43d4-a17a-dfa4879fe43b', '2026-09-30 04:00:00+00', '2026-09-30 04:01:42.987654+00', 'success',
   'v10.2.6', 'v10.2.7', 12, 1, 37, 2, NULL, '5f0c1d2e3a4b5c6d7e8f90a1b2c3d4e5f6a7b8c9', 3),
  ('ea46deeb-f87e-41b6-8630-0516f95da1dd', '2026-10-01 04:00:00+00', NULL, 'running',
   'v10.2.7', NULL, 0, 0, 0, 0, NULL, NULL, NULL);

INSERT INTO targets (id, name, hosts, tags, created_by, created_at, updated_at) VALUES
  ('e5518069-8a40-480d-bb6b-d26895a3c142', 'Shop – Produktion', '{app.example.com,198.51.100.0/28}',
   '{prod,"Kunden-Portal",東京}', 'zoe.admin@example.com', '2026-08-04 08:00:00+00', '2026-09-01 08:00:00+00'),
  ('7fbfe5f3-ab71-414c-9117-84cc90897fae', 'legacy-api', '{https://203.0.113.7:8443/api}', '{}',
   NULL, '2026-08-05 08:00:00+00', '2026-08-05 08:00:00+00');

INSERT INTO scan_policies (id, name, template_set_id, rate_limit, concurrency, timeout_sec, max_host_error,
                           created_by, created_at, updated_at, discovery_enabled, discovery_ports,
                           discovery_timeout_sec, discovery_rate, discovery_probe_timeout_ms, discovery_retries,
                           discovery_scan_type, discovery_host_discovery) VALUES
  ('ff78a637-51a2-4f4c-84d7-efd8ca16ece9', 'Nächtlich – Web', 'a67806ce-f4cc-4ba7-acb1-c0e6e7db0d58',
   150, 25, 10, 30, 'zoe.admin@example.com', '2026-08-06 08:00:00+00', '2026-10-01 08:00:00.000001+00',
   true, '80,443,8000-8443', 600, 1000, 1500, 2, 'connect', false),
  ('ff25dfda-cd65-4239-9807-49803cca89bb', 'ad-hoc defaults', '809150bd-2cd1-4e06-9171-bf16e0c95e1d',
   NULL, NULL, NULL, NULL, NULL, '2026-08-07 08:00:00+00', '2026-08-07 08:00:00+00',
   false, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

INSERT INTO schedules (id, name, cron, enabled, next_run_at, last_run_at, last_scan_id, created_by,
                       created_at, updated_at, scan_policy_id, target_id) VALUES
  ('38affc28-4c01-4b31-a0b4-201867f8a20e', 'Werktags 03:00', '0 3 * * 1-5', true,
   '2026-10-05 01:00:00+00', '2026-10-02 01:00:00.004321+00', NULL, 'zoe.admin@example.com',
   '2026-08-08 08:00:00+00', '2026-09-20 08:00:00+00',
   'ff78a637-51a2-4f4c-84d7-efd8ca16ece9', 'e5518069-8a40-480d-bb6b-d26895a3c142'),
  ('d1887995-ae89-4dc6-a5bc-fde7807a2594', 'paused legacy sweep', '30 2 1 * *', false,
   NULL, NULL, NULL, NULL, '2026-08-09 08:00:00+00', '2026-08-09 08:00:00+00',
   'ff25dfda-cd65-4239-9807-49803cca89bb', '7fbfe5f3-ab71-414c-9117-84cc90897fae');

INSERT INTO scans (id, node_scan_id, state, spec, nuclei_version, templates_commit, error, created_at,
                   started_at, finished_at, target_id, template_set_id, source, schedule_id, raw_object_key,
                   log_object_key, node_id, scan_policy_id, discovered_targets, covered_endpoints,
                   coverage_warning, skipped_finding_count, coverage_origin) VALUES
  ('cfc3a63a-5eb6-4004-ada1-3d124a6c1781', 'node-run-0001', 'complete',
   '{"hosts": ["app.example.com", "198.51.100.0/28"], "rate_limit": 150, "templates": ["http-missing-security-headers", "custom-login-panel-ümlaut"], "discovery": {"ports": "80,443,8000-8443", "enabled": true}}',
   'v3.4.10', '5f0c1d2e3a4b5c6d7e8f90a1b2c3d4e5f6a7b8c9', NULL,
   '2026-10-02 01:00:00.004321+00', '2026-10-02 01:00:02+00', '2026-10-02 01:17:45.678901+00',
   'e5518069-8a40-480d-bb6b-d26895a3c142', 'a67806ce-f4cc-4ba7-acb1-c0e6e7db0d58', 'schedule',
   '38affc28-4c01-4b31-a0b4-201867f8a20e', 'scans/cfc3a63a-5eb6-4004-ada1-3d124a6c1781/raw.jsonl',
   'scans/cfc3a63a-5eb6-4004-ada1-3d124a6c1781/log.txt', 'b27e6209-d9aa-423b-b3b5-86d688874b08',
   'ff78a637-51a2-4f4c-84d7-efd8ca16ece9', '{app.example.com:443,198.51.100.5:8443}',
   '[{"endpoint": "app.example.com:443", "template_id": "http-missing-security-headers"}, {"endpoint": "198.51.100.5:8443", "template_id": "custom-login-panel-ümlaut"}]',
   NULL, 1, 'node'),
  ('47df5ac5-9906-4999-b147-fd30f25a51f6', NULL, 'failed',
   '{"hosts": ["https://203.0.113.7:8443/api"], "templates": []}',
   NULL, NULL, 'Scanner nicht erreichbar: connection refused (Ü-Test)',
   '2026-10-01 12:00:00+00', NULL, '2026-10-01 12:00:30+00',
   '7fbfe5f3-ab71-414c-9117-84cc90897fae', '809150bd-2cd1-4e06-9171-bf16e0c95e1d', 'adhoc',
   NULL, NULL, NULL, NULL, 'ff25dfda-cd65-4239-9807-49803cca89bb', NULL, NULL,
   NULL, 0, 'import_untrusted'),
  ('8cf6a182-5e43-4d8e-b60a-494f19e7d9e1', NULL, 'complete',
   '{"hosts": ["https://203.0.113.7:8443/api"], "imported": true, "bundle": {"format": "goodnightsec/nsc/scan-bundle", "version": 1}}',
   'v3.4.9', NULL, NULL,
   '2026-09-20 09:00:00+00', '2026-09-20 09:00:00+00', '2026-09-20 09:00:00+00',
   '7fbfe5f3-ab71-414c-9117-84cc90897fae', NULL, 'import',
   NULL, NULL, NULL, 'dcfddfaf-b417-417d-8f7f-d67650349614', NULL, '{}', '[]',
   'Trace incomplete for 2 requests', 0, 'import_trusted');

UPDATE schedules SET last_scan_id = 'cfc3a63a-5eb6-4004-ada1-3d124a6c1781'
 WHERE id = '38affc28-4c01-4b31-a0b4-201867f8a20e';

INSERT INTO finding_lifecycle (id, dedup_key, template_id, name, severity, host, matched_at, type, cve, tags,
                               first_seen_scan, last_seen_scan, first_seen_at, last_seen_at, latest_occurrence_id,
                               disposition_note, disposition_by, disposition_at, disposition, accept_expires_at,
                               recast_severity, times_mitigated, recast_note, recast_by, recast_at,
                               last_covering_scan, result_discriminator, endpoint_key) VALUES
  (1, 'dk-synthetic-0001', 'http-missing-security-headers', 'HTTP Missing Security Headers', 'info',
   'app.example.com', 'https://app.example.com/', 'http', '{}', '{misconfig,headers,generic}',
   'cfc3a63a-5eb6-4004-ada1-3d124a6c1781', 'cfc3a63a-5eb6-4004-ada1-3d124a6c1781',
   '2026-10-02 01:05:00+00', '2026-10-02 01:05:00+00', NULL,
   'Akzeptiert bis zum Relaunch – siehe Ticket „WEB-42“', 'zoe.admin@example.com', '2026-10-02 09:30:00+02',
   'accepted', '2026-12-31 23:59:59.999999+01', 'low', 2, 'Nur intern erreichbar', 'zoe.admin@example.com',
   '2026-10-02 09:31:00+02', 'cfc3a63a-5eb6-4004-ada1-3d124a6c1781',
   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'app.example.com:443'),
  (2, 'dk-synthetic-0002', 'custom-login-panel-ümlaut', NULL, NULL, NULL, NULL, NULL,
   '{CVE-2099-0002}', '{}', NULL, NULL,
   '2026-09-20 09:00:00+00', '2026-09-20 09:00:00+00', NULL,
   NULL, NULL, NULL, 'none', NULL, NULL, 0, NULL, NULL, NULL, NULL, '', '');

INSERT INTO findings (id, scan_id, template_id, name, severity, host, matched_at, type, raw, created_at,
                      cve, tags, target_id, dedup_key, finding_id, raw_line, result_discriminator) VALUES
  (1, 'cfc3a63a-5eb6-4004-ada1-3d124a6c1781', 'http-missing-security-headers', 'HTTP Missing Security Headers',
   'info', 'app.example.com', 'https://app.example.com/', 'http',
   '{"host": "app.example.com", "info": {"name": "HTTP Missing Security Headers", "tags": ["misconfig", "headers"], "severity": "info"}, "type": "http", "matched-at": "https://app.example.com/", "template-id": "http-missing-security-headers", "matcher-name": "x-frame-options"}',
   '2026-10-02 01:05:00+00', '{}', '{misconfig,headers}', 'e5518069-8a40-480d-bb6b-d26895a3c142',
   'dk-synthetic-0001', 1,
   '{"template-id":"http-missing-security-headers","host":"app.example.com","matcher-name":"x-frame-options"}',
   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
  (2, 'cfc3a63a-5eb6-4004-ada1-3d124a6c1781', 'http-missing-security-headers', 'HTTP Missing Security Headers',
   'info', 'app.example.com', 'https://app.example.com/', 'http',
   '{"host": "app.example.com", "info": {"name": "HTTP Missing Security Headers", "severity": "info"}, "type": "http", "matched-at": "https://app.example.com/", "template-id": "http-missing-security-headers", "matcher-name": "strict-transport-security", "meta": {"note": "Prüfung 🌙", "empty": null, "ratio": 0.25}}',
   '2026-10-02 01:05:00.000001+00', '{}', '{misconfig,headers,generic}', 'e5518069-8a40-480d-bb6b-d26895a3c142',
   'dk-synthetic-0001', 1, NULL,
   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
  (3, '8cf6a182-5e43-4d8e-b60a-494f19e7d9e1', 'custom-login-panel-ümlaut', NULL, NULL, NULL, NULL, NULL,
   '{"template-id": "custom-login-panel-ümlaut", "extractor-name": "version", "extracted-results": ["2.4.1", "β-release"]}',
   '2026-09-20 09:00:00+00', '{CVE-2099-0002}', '{}', '7fbfe5f3-ab71-414c-9117-84cc90897fae',
   'dk-synthetic-0002', 2, NULL, '');

UPDATE finding_lifecycle SET latest_occurrence_id = 2 WHERE id = 1;
UPDATE finding_lifecycle SET latest_occurrence_id = 3 WHERE id = 2;
SELECT setval('findings_id_seq', 3);
SELECT setval('finding_lifecycle_id_seq', 2);
`,
	},
	"0002_add_scan_policy_response_limits.sql": {
		checksum: "61405adb7a97b09c18fb1e4b200600fefb2b44eb5a71f1e3c0a1635d3fa85ff0",
		seed: `
UPDATE scan_policies SET response_size_read = 4194304, response_size_save = 524288
 WHERE id = 'ff78a637-51a2-4f4c-84d7-efd8ca16ece9';
`,
		added: map[string]map[string]string{
			"scan_policies": {"response_size_read": "null", "response_size_save": "null"},
		},
	},
	// The migration fills the new columns of the rows above from findings.raw.
	// The step adds an occurrence written by a release that has the columns.
	"0003_finding_result_identity.sql": {
		checksum: "53b687474cce5a7d5754d0d68dac90f648ce14bf11362fc065ccbb63e7f9d8a0",
		seed: `
INSERT INTO findings (id, scan_id, template_id, name, severity, host, matched_at, type, raw, created_at,
                      cve, tags, target_id, dedup_key, finding_id, raw_line, result_discriminator,
                      matcher_name, extractor_name, extracted_results) VALUES
  (4, 'cfc3a63a-5eb6-4004-ada1-3d124a6c1781', 'http-missing-security-headers', 'HTTP Missing Security Headers',
   'info', 'app.example.com', 'https://app.example.com/', 'http',
   '{"host": "app.example.com", "type": "http", "matched-at": "https://app.example.com/", "template-id": "http-missing-security-headers", "matcher-name": "content-security-policy", "extracted-results": ["default-src ''self''"]}',
   '2026-10-02 01:05:00.000002+00', '{}', '{misconfig,headers,generic}', 'e5518069-8a40-480d-bb6b-d26895a3c142',
   'dk-synthetic-0001', 1, NULL,
   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
   'content-security-policy', '', '{"default-src ''self''"}');

UPDATE finding_lifecycle
   SET latest_occurrence_id = 4, matcher_name = 'content-security-policy',
       extracted_results = '{"default-src ''self''"}'
 WHERE id = 1;
SELECT setval('findings_id_seq', 4);
`,
	},
	"0004_schedule_timezone.sql": {
		checksum: "698ed0ab44f1e65fe725a61c7d39b218bac6b9a1f7bf53f32b6a3d9442bdfb04",
		seed: `
UPDATE schedules SET timezone = 'Europe/Berlin' WHERE id = '38affc28-4c01-4b31-a0b4-201867f8a20e';
`,
		added: map[string]map[string]string{
			"schedules": {"timezone": `"UTC"`},
		},
	},
	"0005_scan_notification_outbox.sql": {
		checksum: "6023690ceb7851c7095ba6531798407cbb8757becf70e39294a12041ebf4efb1",
		seed: `
UPDATE scan_policies
   SET notify_enabled = true,
       notify_recipients = '{secops@example.com,"Jürgen Weiß <jurgen@example.org>"}',
       notify_min_severity = 'medium'
 WHERE id = 'ff78a637-51a2-4f4c-84d7-efd8ca16ece9';

UPDATE scans
   SET notify_enabled = true,
       notify_recipients = '{secops@example.com,"Jürgen Weiß <jurgen@example.org>"}',
       notify_min_severity = 'medium'
 WHERE id = 'cfc3a63a-5eb6-4004-ada1-3d124a6c1781';
UPDATE scans SET notify_recipients = '{}' WHERE id = '8cf6a182-5e43-4d8e-b60a-494f19e7d9e1';

INSERT INTO scan_notification_outbox (scan_id, kind, payload, created_at, claimed_at) VALUES
  ('cfc3a63a-5eb6-4004-ada1-3d124a6c1781', 'digest',
   '{"new": 2, "fixed": 0, "counts": {"info": 2, "medium": 0}, "target": "Shop – Produktion", "recipients": ["secops@example.com"]}',
   '2026-10-02 01:17:45.678901+00', '2026-10-02 01:17:46.000002+00'),
  ('47df5ac5-9906-4999-b147-fd30f25a51f6', 'failed',
   '{"reason": "Scanner nicht erreichbar", "detail": null}',
   '2026-10-01 12:00:30+00', NULL);
`,
		added: map[string]map[string]string{
			"scan_policies": {"notify_enabled": "null", "notify_recipients": "null", "notify_min_severity": "null"},
			"scans":         {"notify_enabled": "false", "notify_recipients": "null", "notify_min_severity": "null"},
		},
	},
	// The template sync source is seeded from the environment at startup,
	// never by the migration, and NULL marks sync history from before it.
	"0006_template_sync_source.sql": {
		checksum: "283a040263cb77db30ce5dc9d0eb9725e5edae5043b30c21bb2d5f2b883055e2",
		seed: `
UPDATE app_settings
   SET template_sync_repo = 'https://git.example.com/mirror/nuclei-templates.git',
       template_sync_ref = 'latest',
       template_sync_source_updated_at = '2026-10-20 08:15:00.123456+00',
       template_sync_source_updated_by = 'kc|4f1d8a90-77e2-4c55-9a0e-1c2b3d4e5f60';

INSERT INTO template_sync_runs (id, started_at, finished_at, status, ref_before, ref_after,
                                added, removed, updated, skipped, error, templates_commit, template_count,
                                restored, source_repo, source_ref) VALUES
  ('5b0e3f6c-2d8a-4c1e-9f7b-6a5d4c3b2a19', '2026-10-21 04:00:00+00', '2026-10-21 04:01:05.5+00', 'success',
   'v10.2.7', 'v10.2.8', 3, 0, 5, 0, NULL, '6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7', 3,
   1, 'https://git.example.com/mirror/nuclei-templates.git', 'latest');
`,
		added: map[string]map[string]string{
			"app_settings": {
				"template_sync_repo":              "null",
				"template_sync_ref":               "null",
				"template_sync_source_updated_at": "null",
				"template_sync_source_updated_by": "null",
			},
			"template_sync_runs": {"restored": "null", "source_repo": "null", "source_ref": "null"},
		},
	},
}

// embeddedMigrationNames lists the embedded migration files in the order
// Migrate applies them.
func embeddedMigrationNames(t *testing.T) []string {
	t.Helper()
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatalf("list embedded migrations: %v", err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names
}

// TestEveryMigrationHasUpgradeSeedStep needs no database: it fails when a
// migration has no seed step, when a step names no embedded migration, or
// when a migration file no longer matches its recorded checksum.
func TestEveryMigrationHasUpgradeSeedStep(t *testing.T) {
	names := embeddedMigrationNames(t)
	if lastReleaseMigration < 1 || lastReleaseMigration > len(names) {
		t.Fatalf("lastReleaseMigration = %d, want 1 to %d (the embedded migrations)", lastReleaseMigration, len(names))
	}
	embedded := make(map[string]bool, len(names))
	for _, name := range names {
		embedded[name] = true
		step, ok := upgradeSeedSteps[name]
		if !ok {
			t.Errorf("migration %s has no step in upgradeSeedSteps; add its seed step, checksum and added columns", name)
			continue
		}
		if strings.TrimSpace(step.seed) == "" {
			t.Errorf("upgradeSeedSteps[%q] has no seed; write synthetic rows into what the migration adds", name)
		}
		sqlBytes, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		if sum := fmt.Sprintf("%x", sha256.Sum256(sqlBytes)); sum != step.checksum {
			t.Errorf("migration %s has checksum %s, want %s recorded in upgradeSeedSteps; applied migrations are immutable, add a new migration instead",
				name, sum, step.checksum)
		}
	}
	for name := range upgradeSeedSteps {
		if !embedded[name] {
			t.Errorf("upgradeSeedSteps has a step for %s, which is no embedded migration", name)
		}
	}
}

// TestUpgradeFromLastReleasePostgres builds the database of the last release
// (migrations 1 to lastReleaseMigration, each followed by its seed step),
// dumps and restores it, runs the current migrations on it, and checks that
// the schema equals a fresh install and that every seeded row reads back
// unchanged.
//
// The dump is generated here, not stored as a fixture: it is filled with the
// synthetic rows of upgradeSeedSteps, dumped with pg_dump and restored with
// psql.
func TestUpgradeFromLastReleasePostgres(t *testing.T) {
	dsn := os.Getenv("NSC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NSC_TEST_DATABASE_URL is not set")
	}
	pgDump := findPGDump(t)
	psql := findPSQL(t, pgDump)
	names := embeddedMigrationNames(t)
	if lastReleaseMigration < 1 || lastReleaseMigration > len(names) {
		t.Fatalf("lastReleaseMigration = %d, want 1 to %d (the embedded migrations)", lastReleaseMigration, len(names))
	}
	released, later := names[:lastReleaseMigration], names[lastReleaseMigration:]

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	release, schema := openEmptyIsolatedPostgres(t, ctx, dsn)
	applyReleaseMigrations(t, ctx, release.pool, released)
	tables := schemaTables(t, ctx, release.pool)
	seeded := snapshotSchema(t, ctx, release.pool, tables)
	for _, table := range tables {
		if len(seeded.rows[table]) == 0 {
			t.Fatalf("last-release table %s has no seed rows; seed every table so the upgrade test reads it back", table)
		}
	}
	release.pool.Close()

	dumpFile := filepath.Join(t.TempDir(), "last-release.sql")
	dumpSchemaWithData(t, ctx, pgDump, dsn, schema, dumpFile)
	admin, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open admin store: %v", err)
	}
	defer admin.Close()
	if _, err := admin.pool.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
		t.Fatalf("drop last-release schema before restore: %v", err)
	}
	restoreDump(t, ctx, psql, dsn, dumpFile)

	upgraded := openSchemaStore(t, ctx, dsn, schema)
	restored := snapshotSchema(t, ctx, upgraded.pool, tables)
	compareSnapshots(t, "restored dump", seeded, restored, nil)

	if err := upgraded.Migrate(ctx); err != nil {
		t.Fatalf("Migrate the restored last-release database: %v", err)
	}
	checkUpgradedMigrationHistory(t, ctx, upgraded.pool, released, len(names))

	fresh, freshSchema := openEmptyIsolatedPostgres(t, ctx, dsn)
	if err := fresh.Migrate(ctx); err != nil {
		t.Fatalf("Migrate a fresh install: %v", err)
	}
	upgradedDump := normalizedSchemaDump(t, ctx, pgDump, dsn, schema)
	freshDump := normalizedSchemaDump(t, ctx, pgDump, dsn, freshSchema)
	if upgradedDump != freshDump {
		t.Fatalf("schema upgraded from the last release differs from a fresh install: %s",
			firstSchemaDifference(upgradedDump, freshDump))
	}

	migrated := snapshotSchema(t, ctx, upgraded.pool, tables)
	compareSnapshots(t, "migrated database", seeded, migrated, columnsAddedAfter(t, later))
	checkReleaseDataThroughStore(t, ctx, upgraded)
}

// applyReleaseMigrations builds the last release's schema in one transaction:
// each released migration, its record in the history table the way Migrate
// writes it, then its seed step.
func applyReleaseMigrations(t *testing.T, ctx context.Context, pool *pgxpool.Pool, released []string) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin last-release migrations: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			checksum_sha256 TEXT,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		t.Fatalf("create last-release migration history: %v", err)
	}
	for _, name := range released {
		step, ok := upgradeSeedSteps[name]
		if !ok {
			t.Fatalf("migration %s has no step in upgradeSeedSteps", name)
		}
		sqlBytes, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		if sum := fmt.Sprintf("%x", sha256.Sum256(sqlBytes)); sum != step.checksum {
			t.Fatalf("migration %s changed since its release: checksum %s, want %s", name, sum, step.checksum)
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("apply released migration %s: %v", name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version, checksum_sha256) VALUES ($1, $2)`,
			name, step.checksum); err != nil {
			t.Fatalf("record released migration %s: %v", name, err)
		}
		if _, err := tx.Exec(ctx, step.seed); err != nil {
			t.Fatalf("seed step of migration %s: %v", name, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit last-release migrations: %v", err)
	}
}

// columnsAddedAfter merges the added columns of the migrations newer than the
// last release. Two of them adding the same column is a mistake in the steps.
func columnsAddedAfter(t *testing.T, later []string) map[string]map[string]string {
	t.Helper()
	merged := make(map[string]map[string]string)
	for _, name := range later {
		for table, columns := range upgradeSeedSteps[name].added {
			if merged[table] == nil {
				merged[table] = make(map[string]string)
			}
			for column, value := range columns {
				if _, dup := merged[table][column]; dup {
					t.Fatalf("upgradeSeedSteps lists %s.%s as added by more than one migration after the last release", table, column)
				}
				merged[table][column] = value
			}
		}
	}
	return merged
}

// schemaSnapshot holds every row of a schema's tables as to_jsonb column
// values keyed by primary key, plus the state of its sequences.
type schemaSnapshot struct {
	rows      map[string]map[string]map[string]json.RawMessage
	sequences map[string]string
}

func schemaTables(t *testing.T, ctx context.Context, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT tablename FROM pg_tables
		 WHERE schemaname = current_schema() AND tablename <> 'schema_migrations'
		 ORDER BY tablename`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	return tables
}

func snapshotSchema(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tables []string) schemaSnapshot {
	t.Helper()
	snap := schemaSnapshot{
		rows:      make(map[string]map[string]map[string]json.RawMessage, len(tables)),
		sequences: make(map[string]string),
	}
	for _, table := range tables {
		pkRows, err := pool.Query(ctx, `
			SELECT a.attname
			  FROM pg_index i
			  JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
			 WHERE i.indrelid = $1::regclass AND i.indisprimary
			 ORDER BY array_position(i.indkey::int2[], a.attnum)`, table)
		if err != nil {
			t.Fatalf("read primary key of %s: %v", table, err)
		}
		pk, err := pgx.CollectRows(pkRows, pgx.RowTo[string])
		if err != nil || len(pk) == 0 {
			t.Fatalf("read primary key of %s: %v (columns %v)", table, err, pk)
		}

		rows, err := pool.Query(ctx, "SELECT to_jsonb(t)::text FROM "+pgx.Identifier{table}.Sanitize()+" AS t")
		if err != nil {
			t.Fatalf("read rows of %s: %v", table, err)
		}
		texts, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatalf("read rows of %s: %v", table, err)
		}
		byKey := make(map[string]map[string]json.RawMessage, len(texts))
		for _, text := range texts {
			var row map[string]json.RawMessage
			if err := json.Unmarshal([]byte(text), &row); err != nil {
				t.Fatalf("decode row of %s: %v", table, err)
			}
			keyParts := make([]string, 0, len(pk))
			for _, column := range pk {
				keyParts = append(keyParts, string(row[column]))
			}
			byKey[strings.Join(keyParts, ",")] = row
		}
		snap.rows[table] = byKey
	}

	seqRows, err := pool.Query(ctx, `
		SELECT sequencename FROM pg_sequences
		 WHERE schemaname = current_schema() ORDER BY sequencename`)
	if err != nil {
		t.Fatalf("list sequences: %v", err)
	}
	sequences, err := pgx.CollectRows(seqRows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("list sequences: %v", err)
	}
	for _, sequence := range sequences {
		var state string
		if err := pool.QueryRow(ctx,
			"SELECT last_value || ' ' || is_called FROM "+pgx.Identifier{sequence}.Sanitize()).Scan(&state); err != nil {
			t.Fatalf("read sequence %s: %v", sequence, err)
		}
		snap.sequences[sequence] = state
	}
	return snap
}

// compareSnapshots checks that got holds exactly the rows of want, each with
// unchanged values. Columns absent from want must be listed in added with the
// value every row holds.
func compareSnapshots(t *testing.T, label string, want, got schemaSnapshot, added map[string]map[string]string) {
	t.Helper()
	for table, wantRows := range want.rows {
		gotRows := got.rows[table]
		if len(gotRows) != len(wantRows) {
			t.Errorf("%s: table %s has %d rows, want the %d seeded", label, table, len(gotRows), len(wantRows))
		}
		addedHere := make(map[string]bool)
		for key, wantRow := range wantRows {
			gotRow, ok := gotRows[key]
			if !ok {
				t.Errorf("%s: %s row %s is missing", label, table, key)
				continue
			}
			for column, wantValue := range wantRow {
				gotValue, ok := gotRow[column]
				if !ok {
					t.Errorf("%s: %s row %s lost column %s", label, table, key, column)
					continue
				}
				if !bytes.Equal(gotValue, wantValue) {
					t.Errorf("%s: %s row %s column %s = %s, want %s", label, table, key, column, gotValue, wantValue)
				}
			}
			for column, gotValue := range gotRow {
				if _, ok := wantRow[column]; ok {
					continue
				}
				expected, ok := added[table][column]
				if !ok {
					t.Errorf("%s: %s.%s was added after the last release; list the value upgraded rows hold in the added map of its migration in upgradeSeedSteps (row %s holds %s)",
						label, table, column, key, gotValue)
					continue
				}
				addedHere[column] = true
				if !jsonEqual(gotValue, json.RawMessage(expected)) {
					t.Errorf("%s: upgraded %s row %s column %s = %s, want %s", label, table, key, column, gotValue, expected)
				}
			}
		}
		for column := range added[table] {
			if !addedHere[column] {
				t.Errorf("%s: upgradeSeedSteps lists %s.%s as added after the last release, but the migrated rows have no such new column", label, table, column)
			}
		}
	}
	for table := range added {
		if _, ok := want.rows[table]; !ok {
			t.Errorf("%s: upgradeSeedSteps lists table %s as changed after the last release, but the last release has no seed rows for it", label, table)
		}
	}
	for sequence, wantState := range want.sequences {
		if gotState := got.sequences[sequence]; gotState != wantState {
			t.Errorf("%s: sequence %s = %q, want %q", label, sequence, gotState, wantState)
		}
	}
}

func jsonEqual(a, b json.RawMessage) bool {
	var left, right any
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return false
	}
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return bytes.Equal(leftJSON, rightJSON)
}

// checkUpgradedMigrationHistory checks that the last release's records
// survive unchanged and that Migrate recorded every later migration once.
func checkUpgradedMigrationHistory(t *testing.T, ctx context.Context, pool *pgxpool.Pool, released []string, total int) {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT version, checksum_sha256 FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatalf("read migration history: %v", err)
	}
	type record struct {
		Version  string
		Checksum string
	}
	history, err := pgx.CollectRows(rows, pgx.RowToStructByPos[record])
	if err != nil {
		t.Fatalf("read migration history: %v", err)
	}
	if len(history) != total {
		t.Fatalf("upgraded migration history has %d records, want %d: %v", len(history), total, history)
	}
	for i, name := range released {
		if want := upgradeSeedSteps[name].checksum; history[i].Version != name || history[i].Checksum != want {
			t.Fatalf("upgraded migration record %d = %v, want the released %s %s", i+1, history[i], name, want)
		}
	}
}

// checkReleaseDataThroughStore reads seeded rows through the store API, the
// way the upgraded release reads them.
func checkReleaseDataThroughStore(t *testing.T, ctx context.Context, st *Store) {
	t.Helper()
	settings, err := st.GetAppSettings(ctx)
	if err != nil {
		t.Fatalf("read upgraded app settings: %v", err)
	}
	if !settings.RetentionEnabled || settings.ScanRetentionDays == nil || *settings.ScanRetentionDays != 90 ||
		!settings.RetentionIncludeAdhoc || settings.UpdatedBy != "zoe.admin@example.com" {
		t.Errorf("upgraded app settings = %#v, want the seeded 90-day retention", settings)
	}
	source, err := st.GetTemplateSyncSource(ctx)
	if err != nil {
		t.Fatalf("read upgraded template sync source: %v", err)
	}
	if source.Repo != "https://git.example.com/mirror/nuclei-templates.git" || source.Ref != "latest" {
		t.Errorf("upgraded template sync source = %#v, want the seeded mirror at latest", source)
	}

	scan, err := st.GetScan(ctx, "cfc3a63a-5eb6-4004-ada1-3d124a6c1781")
	if err != nil {
		t.Fatalf("read upgraded scan: %v", err)
	}
	if scan.State != "complete" || scan.TargetName != "Shop – Produktion" || scan.NodeName != "dmz-frankfurt-1" ||
		!scan.NotifyEnabled || scan.NotifyMinSeverity != "medium" ||
		strings.Join(scan.NotifyRecipients, "|") != "secops@example.com|Jürgen Weiß <jurgen@example.org>" ||
		len(scan.CoveredEndpoints) != 2 || scan.CoveredEndpoints[1].TemplateID != "custom-login-panel-ümlaut" ||
		!scan.HasRaw || !scan.HasLog || scan.SkippedFindingCount != 1 {
		t.Errorf("upgraded scan = %#v, want the seeded scheduled scan", scan)
	}
	failed, err := st.GetScan(ctx, "47df5ac5-9906-4999-b147-fd30f25a51f6")
	if err != nil {
		t.Fatalf("read upgraded failed scan: %v", err)
	}
	if failed.State != "failed" || failed.Error != "Scanner nicht erreichbar: connection refused (Ü-Test)" ||
		failed.NodeID != "" || failed.CoveredEndpoints != nil || failed.DiscoveredTargets != nil || failed.NotifyRecipients != nil {
		t.Errorf("upgraded failed scan = %#v, want the seeded NULLs kept", failed)
	}

	schedule, err := st.GetSchedule(ctx, "38affc28-4c01-4b31-a0b4-201867f8a20e")
	if err != nil {
		t.Fatalf("read upgraded schedule: %v", err)
	}
	wantNext := time.Date(2026, 10, 5, 1, 0, 0, 0, time.UTC)
	if schedule.Cron != "0 3 * * 1-5" || schedule.Timezone != "Europe/Berlin" || !schedule.Enabled ||
		schedule.NextRunAt == nil || !schedule.NextRunAt.Equal(wantNext) ||
		schedule.LastScanID != "cfc3a63a-5eb6-4004-ada1-3d124a6c1781" {
		t.Errorf("upgraded schedule = %#v, want the seeded Europe/Berlin schedule", schedule)
	}

	target, err := st.GetTarget(ctx, "e5518069-8a40-480d-bb6b-d26895a3c142")
	if err != nil {
		t.Fatalf("read upgraded target: %v", err)
	}
	if target.Name != "Shop – Produktion" || strings.Join(target.Hosts, "|") != "app.example.com|198.51.100.0/28" ||
		strings.Join(target.Tags, "|") != "prod|Kunden-Portal|東京" {
		t.Errorf("upgraded target = %#v, want the seeded target", target)
	}
}

// findPSQL finds the psql that restores the dump: NSC_TEST_PSQL, the psql next
// to pg_dump, or psql on PATH.
func findPSQL(t *testing.T, pgDump string) string {
	t.Helper()
	if configured := os.Getenv("NSC_TEST_PSQL"); configured != "" {
		return configured
	}
	if sibling := filepath.Join(filepath.Dir(pgDump), "psql"); sibling != pgDump {
		if info, err := os.Stat(sibling); err == nil && !info.IsDir() {
			return sibling
		}
	}
	if path, err := exec.LookPath("psql"); err == nil {
		return path
	}
	t.Fatal("NSC_TEST_DATABASE_URL is set but psql was not found; install the PostgreSQL client or set NSC_TEST_PSQL")
	return ""
}

func dumpSchemaWithData(t *testing.T, ctx context.Context, pgDump, dsn, schema, file string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, pgDump,
		"--no-owner",
		"--no-privileges",
		"--schema="+schema,
		"--file="+file,
		"--dbname="+dsn,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pg_dump last-release schema %s: %v\n%s", schema, err, output)
	}

	// pg_dump 17 and newer always emit SET transaction_timeout, which a
	// PostgreSQL 16 server rejects. The setting only guards the restore
	// session, so drop it rather than relax ON_ERROR_STOP.
	dump, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read last-release dump: %v", err)
	}
	lines := strings.Split(string(dump), "\n")
	kept := lines[:0]
	for _, line := range lines {
		if !strings.HasPrefix(line, "SET transaction_timeout ") {
			kept = append(kept, line)
		}
	}
	if err := os.WriteFile(file, []byte(strings.Join(kept, "\n")), 0o600); err != nil {
		t.Fatalf("write last-release dump: %v", err)
	}
}

func restoreDump(t *testing.T, ctx context.Context, psql, dsn, file string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, psql,
		"--no-psqlrc",
		"--quiet",
		"--single-transaction",
		"--set=ON_ERROR_STOP=1",
		"--file="+file,
		"--dbname="+dsn,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("restore last-release dump: %v\n%s", err, output)
	}
}

// openSchemaStore opens a new pool on an existing schema, so no connection
// carries prepared statements from before the restore.
func openSchemaStore(t *testing.T, ctx context.Context, dsn, schema string) *Store {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = make(map[string]string)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open restored schema pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return &Store{pool: pool}
}
