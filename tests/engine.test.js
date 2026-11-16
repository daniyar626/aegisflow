/*
 * Automated checks for the triage engine and the two interface languages.
 * Run from the project folder:  node --test tests/
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const engine = require('../js/engine.js');
const intel = require('../js/intel.js');
const demo = require('../js/demo-data.js');
const i18n = require('../js/i18n.js');

const read = (name) => fs.readFileSync(path.join(__dirname, '..', 'sample-data', name), 'utf8');
const code = (fn) => { try { fn(); } catch (e) { return e.code; } return 'no error'; };
const labCases = (opts) => engine.buildCases(engine.fromRecords(demo.build()).alerts, opts);
const byPattern = (cases, pattern) => cases.filter((c) => c.pattern === pattern);

test('lab dataset: 211 alerts become 11 cases', () => {
  const parsed = engine.fromRecords(demo.build());
  assert.strictEqual(parsed.alerts.length, 211);
  assert.strictEqual(parsed.skipped, 0);
  assert.strictEqual(engine.buildCases(parsed.alerts).length, 11);
});

test('lab dataset: every alert belongs to exactly one case', () => {
  const total = labCases().reduce((n, c) => n + c.count, 0);
  assert.strictEqual(total, 211);
});

test('the successful password-guessing attack is the top case', () => {
  const top = labCases()[0];
  assert.strictEqual(top.pattern, 'bruteforce_success');
  assert.strictEqual(top.verdict, 'malicious');
  assert.strictEqual(top.severity, 'critical');
  assert.strictEqual(top.params.fails, 142);
  assert.strictEqual(top.params.user, 'deploy');
  assert.deepStrictEqual(top.recommendation.action, { type: 'block_ip', target: '203.0.113.45' });
});

test('changes on the same host after the intrusion are linked to it', () => {
  const cases = labCases();
  const changes = byPattern(cases, 'suspicious_changes')[0];
  assert.ok(changes.intrusion, 'expected an intrusion link');
  assert.strictEqual(changes.intrusion.caseId, cases[0].id);
  assert.strictEqual(changes.verdict, 'malicious');
  assert.ok(changes.related.includes(cases[0].id));
});

test('harmless activity is not flagged', () => {
  const cases = labCases();
  for (const pattern of ['admin_activity', 'login_typo', 'background_scan']) {
    const c = byPattern(cases, pattern)[0];
    assert.ok(c, pattern + ' case exists');
    assert.strictEqual(c.verdict, 'benign', pattern);
    assert.strictEqual(c.recommendation.decision, 'dismiss', pattern);
  }
});

test('nothing is recommended for approval without a containment action', () => {
  for (const c of labCases()) {
    if (c.recommendation.decision === 'approve') assert.ok(c.recommendation.action, c.pattern);
  }
});

test('an unexplained high-level alert is sent to a person with low confidence', () => {
  const c = byPattern(labCases(), 'unclassified').find((x) => x.maxLevel >= 7);
  assert.strictEqual(c.verdict, 'review');
  assert.strictEqual(c.confidence, 'low');
  assert.strictEqual(c.recommendation.decision, 'escalate');
});

test('score equals the sum of its factors, inside 0..100', () => {
  for (const c of labCases()) {
    const sum = c.factors.reduce((n, f) => n + f.points, 0);
    assert.strictEqual(c.score, Math.max(0, Math.min(100, sum)), c.pattern);
  }
});

test('reputation outage: verdicts are recomputed and confidence drops', () => {
  const normal = byPattern(labCases(), 'web_attack')[0];
  const outage = byPattern(labCases({ intelAvailable: false }), 'web_attack')[0];
  assert.strictEqual(normal.verdict, 'malicious');
  assert.strictEqual(outage.verdict, 'review');
  assert.strictEqual(outage.enrichment.available, false);
  assert.notStrictEqual(outage.confidence, 'high');
  assert.strictEqual(normal.id, outage.id, 'case ids must not depend on enrichment');
});

test('results are deterministic', () => {
  const a = labCases().map((c) => [c.id, c.score, c.hash]);
  const b = labCases().map((c) => [c.id, c.score, c.hash]);
  assert.deepStrictEqual(a, b);
});

test('import: clean file', () => {
  const r = engine.parseAlerts(read('1-valid-alerts.json'));
  assert.strictEqual(r.alerts.length, 30);
  assert.strictEqual(r.skipped, 0);
  const cases = engine.buildCases(r.alerts);
  assert.strictEqual(cases.length, 2);
  assert.strictEqual(cases[0].pattern, 'bruteforce_external');
});

test('import: damaged records are skipped and counted', () => {
  const r = engine.parseAlerts(read('2-partly-damaged-alerts.json'));
  assert.strictEqual(r.alerts.length, 12);
  assert.strictEqual(r.skipped, 3);
  assert.strictEqual(r.total, 15);
});

test('import: invalid, empty and unrelated input is refused with a reason', () => {
  const emptyList = JSON.stringify([]);
  assert.strictEqual(code(() => engine.parseAlerts(read('3-broken-file.json'))), 'invalid_json');
  assert.strictEqual(code(() => engine.parseAlerts(read('4-empty-file.json'))), 'empty');
  assert.strictEqual(code(() => engine.parseAlerts(read('5-not-wazuh-alerts.json'))), 'no_valid');
  assert.strictEqual(code(() => engine.parseAlerts('   ')), 'empty');
  assert.strictEqual(code(() => engine.parseAlerts(emptyList)), 'empty');
  assert.strictEqual(code(() => engine.parseAlerts(undefined)), 'empty');
});

test('import: more alerts than the limit are refused', () => {
  const one = demo.build()[0];
  const many = Array.from({ length: engine.LIMITS.maxAlerts + 1 }, () => one);
  assert.strictEqual(code(() => engine.fromRecords(many)), 'too_many');
});

test('import: indexer and API export shapes are understood', () => {
  const recs = demo.buildImportSample().slice(0, 5);
  assert.strictEqual(engine.parseAlerts(JSON.stringify({ hits: { hits: recs.map((r) => ({ _source: r })) } })).alerts.length, 5);
  assert.strictEqual(engine.parseAlerts(JSON.stringify({ data: { affected_items: recs } })).alerts.length, 5);
  assert.strictEqual(engine.parseAlerts(JSON.stringify(recs)).alerts.length, 5);
});

test('hostile field values cannot reach commands or grouping keys', () => {
  const evil = JSON.parse(JSON.stringify(demo.build()[0]));
  evil.data.srcip = '1.2.3.4; rm -rf /';
  const r = engine.fromRecords([evil]);
  assert.strictEqual(r.alerts[0].srcip, '');
});

test('SHA-256 matches the platform implementation', () => {
  for (const s of ['', 'abc', 'Қазақша мәтін '.repeat(50), 'x'.repeat(1000)]) {
    assert.strictEqual(engine.sha256(s), crypto.createHash('sha256').update(s).digest('hex'));
  }
});

test('address classification', () => {
  assert.strictEqual(intel.classifyIp('10.20.3.44'), 'private');
  assert.strictEqual(intel.classifyIp('172.31.255.1'), 'private');
  assert.strictEqual(intel.classifyIp('192.168.1.1'), 'private');
  assert.strictEqual(intel.classifyIp('203.0.113.45'), 'doc');
  assert.strictEqual(intel.classifyIp('8.8.8.8'), 'public');
  assert.strictEqual(intel.classifyIp('999.1.1.1'), 'invalid');
  assert.strictEqual(intel.classifyIp('2001:db8::1'), 'ipv6');
  assert.strictEqual(intel.lookup('203.0.113.45').length, 2);
  assert.strictEqual(intel.lookup('8.8.8.8').length, 0);
});

test('English and Kazakh have the same keys and the same placeholders', () => {
  const en = i18n.strings.en, kk = i18n.strings.kk;
  const names = (s) => (s.match(/\{(\w+)/g) || []).map((m) => m.slice(1)).sort().filter((v, i, a) => a.indexOf(v) === i);
  assert.deepStrictEqual(Object.keys(kk).sort(), Object.keys(en).sort());
  for (const key of Object.keys(en)) {
    assert.ok(kk[key].trim().length > 0, key);
    assert.deepStrictEqual(names(kk[key]), names(en[key]), 'placeholders differ in ' + key);
  }
});

test('every text key the interface asks for exists', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'js', 'app.js'), 'utf8');
  const en = i18n.strings.en;
  const literal = [...src.matchAll(/\bt\('([a-z0-9_.]+)'[,)]/gi)].map((m) => m[1]);
  assert.ok(literal.length > 150);
  for (const key of literal) assert.ok(key in en, 'missing text: ' + key);
  const dynamic = {
    'title.': engine.PATTERNS, 'f.pattern.': engine.PATTERNS,
    'sev.': ['critical', 'high', 'medium', 'low'], 'verdict.': ['malicious', 'review', 'benign'],
    'conf.': ['high', 'medium', 'low'], 'st.': ['new', 'approved', 'dismissed', 'escalated'],
    'out.': ['approved', 'dismissed', 'escalated'], 'ev.': ['approved', 'dismissed', 'escalated', 'reopened', 'loaded'],
    'ip.': ['public', 'private', 'doc', 'loopback', 'ipv6', 'invalid'], 'role.': ['admin', 'analyst', 'viewer'],
    'err.': ['empty', 'invalid_json', 'no_valid', 'too_many', 'too_large', 'read', 'paste_empty'],
    'nav.': ['connect', 'queue', 'audit', 'report', 'settings', 'admin'],
    'login.err.': ['bad', 'locked', 'disabled'],
    'acc.err.': ['username_format', 'username_taken', 'name_short', 'role', 'password_weak', 'password_same', 'current_wrong', 'forbidden', 'missing', 'self', 'last_admin'],
    'acc.ev.': ['login', 'login_failed', 'login_disabled', 'locked', 'created', 'deleted', 'disabled', 'enabled', 'unlocked', 'password_reset', 'password_changed', 'role_admin', 'role_analyst', 'role_viewer', 'restored'],
    'adm.status.': ['active', 'disabled', 'locked', 'mustchange'],
    'adm.m.': ['users', 'admins', 'disabled', 'locked'],
    'adm.col.': ['user', 'role', 'status', 'last', 'hash', 'actions', 'time', 'by', 'event', 'account'],
    'c.': ['clear', 'corroborated', 'no_rep', 'rep_unavailable', 'borderline', 'no_pattern', 'few', 'ambiguous'],
    'f.': ['level', 'volume', 'rep_listed', 'internal', 'ext_success', 'after_intrusion', 'high_level_unknown']
  };
  for (const prefix of Object.keys(dynamic)) for (const k of dynamic[prefix]) assert.ok(prefix + k in en, 'missing text: ' + prefix + k);
  for (const c of labCases()) for (const s of c.recommendation.steps) assert.ok('step.' + s.id in en, 'missing text: step.' + s.id);
});

test('plural forms', () => {
  i18n.set('en');
  assert.strictEqual(i18n.t('queue.summary', { alerts: 1, cases: 1 }), '1 alert grouped into 1 case');
  assert.strictEqual(i18n.t('queue.summary', { alerts: 211, cases: 11 }), '211 alerts grouped into 11 cases');
  i18n.set('kk');
  assert.strictEqual(i18n.t('queue.summary', { alerts: 211, cases: 11 }), '211 дабыл 11 іске топталды');
  i18n.set('en');
});
