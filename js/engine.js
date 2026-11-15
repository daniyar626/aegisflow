/*
 * AegisFlow triage engine.
 *
 * Turns raw Wazuh alerts into cases: parse and validate, group by source
 * address and host, match against known patterns, score, and recommend.
 * Pure logic: no DOM, no network, no randomness. The same alerts always
 * produce the same cases, and every point of the score is kept as a factor
 * with the ids of the alerts behind it.
 */
(function (root) {
  'use strict';
  var AF = root.AF = root.AF || {};
  var intel = AF.intel;
  if (!intel && typeof require === 'function') intel = require('./intel.js');

  var LIMITS = { maxAlerts: 2000, maxBytes: 2 * 1024 * 1024, maxField: 4000 };
  var MIN = 60 * 1000;
  var GAP_IP = 60 * MIN;      // alerts from one address to one host stay in a case while gaps are shorter
  var GAP_HOST = 15 * MIN;    // host-only alerts form a session while gaps are shorter
  var RELATED = 60 * MIN;     // window for linking cases on the same host
  var THRESHOLDS = { review: 25, malicious: 55, critical: 75 };
  var BORDERLINE = 4;

  var PATTERN_POINTS = {
    bruteforce_success: 35,
    bruteforce_external: 15,
    bruteforce_internal: 22,
    web_attack: 20,
    malware: 30,
    suspicious_changes: 20,
    admin_activity: -10,
    login_typo: -10,
    background_scan: 3,
    unclassified: 0
  };

  var CRITICAL_PATH = /^\/etc\/(passwd|shadow|sudoers|group|crontab|ssh\/sshd_config|pam\.d\/|sudoers\.d\/)|authorized_keys$|^\/root\/\.|\\windows\\system32\\(config\\|drivers\\etc\\hosts)/i;

  function AFError(code, params) {
    var e = new Error(code);
    e.code = code;
    e.params = params || {};
    return e;
  }

  /* ---------- parsing and validation ---------- */

  function str(v) {
    if (typeof v === 'string') return v.slice(0, LIMITS.maxField);
    if (typeof v === 'number' && isFinite(v)) return String(v);
    return '';
  }
  function obj(v) { return v && typeof v === 'object' && !Array.isArray(v) ? v : {}; }

  function parseTs(v) {
    if (typeof v === 'number' && isFinite(v)) return v < 1e12 ? v * 1000 : v;
    if (typeof v !== 'string' || !v) return null;
    // Wazuh writes offsets as +0500; Date.parse needs +05:00.
    var fixed = v.trim().replace(/([+-]\d{2})(\d{2})$/, '$1:$2');
    var ms = Date.parse(fixed);
    return isNaN(ms) ? null : ms;
  }

  function extractRecords(j) {
    if (Array.isArray(j)) return j;
    if (j && typeof j === 'object') {
      if (j.hits && Array.isArray(j.hits.hits)) return j.hits.hits;            // indexer export
      if (j.data && Array.isArray(j.data.affected_items)) return j.data.affected_items; // API reply
      if (Array.isArray(j.alerts)) return j.alerts;
    }
    return [j];
  }

  function normalise(rec, index) {
    if (!rec || typeof rec !== 'object' || Array.isArray(rec)) return null;
    if (rec._source && typeof rec._source === 'object') rec = rec._source;
    var rule = rec.rule;
    if (!rule || typeof rule !== 'object') return null;
    var level = Number(rule.level);
    if (rule.level === null || rule.level === '' || !isFinite(level)) return null;
    var desc = str(rule.description);
    if (!desc) return null;
    var ts = parseTs(rec.timestamp !== undefined ? rec.timestamp : rec['@timestamp']);
    if (ts === null) return null;

    var data = obj(rec.data);
    var win = obj(obj(data.win).eventdata);
    var srcip = str(data.srcip || data.src_ip || win.ipAddress).trim();
    if (!/^[0-9a-fA-F:.]{3,45}$/.test(srcip) || srcip === '::1' || srcip === '127.0.0.1') srcip = '';
    var agent = obj(rec.agent);
    var groups = [];
    if (Array.isArray(rule.groups)) {
      for (var i = 0; i < rule.groups.length && i < 30; i++) {
        var g = str(rule.groups[i]).toLowerCase();
        if (g) groups.push(g);
      }
    }
    return {
      id: str(rec.id) || 'row-' + (index + 1),
      ts: ts,
      level: Math.max(0, Math.min(16, Math.round(level))),
      ruleId: str(rule.id) || '?',
      desc: desc,
      groups: groups,
      host: str(agent.name) || str(obj(rec.manager).name) || 'unknown-host',
      hostIp: str(agent.ip),
      srcip: srcip,
      user: str(data.dstuser || data.srcuser || win.targetUserName || data.user),
      path: str(obj(rec.syscheck).path),
      url: str(data.url),
      fullLog: str(rec.full_log),
      location: str(rec.location),
      raw: rec
    };
  }

  /* records: array of already-parsed JSON values. */
  function fromRecords(records, extraSkipped) {
    var badLines = extraSkipped || 0;
    if (!records.length && !badLines) throw AFError('empty');
    if (records.length > LIMITS.maxAlerts) {
      throw AFError('too_many', { total: records.length, max: LIMITS.maxAlerts });
    }
    var alerts = [], kept = [], skipped = badLines, seen = {};
    for (var i = 0; i < records.length; i++) {
      var a = normalise(records[i], i);
      if (!a) { skipped++; continue; }
      if (seen[a.id]) a.id = a.id + '#' + (i + 1);
      seen[a.id] = true;
      alerts.push(a);
      kept.push(a.raw);
    }
    var total = records.length + badLines;
    if (!alerts.length) throw AFError('no_valid', { total: total });
    alerts.sort(function (x, y) { return x.ts - y.ts; });
    return { alerts: alerts, records: kept, skipped: skipped, total: total };
  }

  /* text: contents of alerts.json (one JSON object per line) or any JSON export. */
  function parseAlerts(text) {
    if (typeof text !== 'string') throw AFError('empty');
    var trimmed = text.replace(/^﻿/, '').trim();
    if (!trimmed) throw AFError('empty');
    var records, badLines = 0;
    try {
      records = extractRecords(JSON.parse(trimmed));
    } catch (e) {
      var detail = String((e && e.message) || e).slice(0, 140);
      var lines = trimmed.split(/\r?\n/), parsed = [];
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i].trim();
        if (!line) continue;
        try {
          var value = JSON.parse(line);
          // A stray string or number on its own line is debris from a broken file, not a record.
          if (value && typeof value === 'object') parsed.push(value); else badLines++;
        } catch (e2) { badLines++; }
      }
      if (!parsed.length) throw AFError('invalid_json', { detail: detail });
      records = [];
      for (var p = 0; p < parsed.length; p++) {
        var part = extractRecords(parsed[p]);
        for (var q = 0; q < part.length; q++) records.push(part[q]);
      }
    }
    return fromRecords(records, badLines);
  }

  /* ---------- classification ---------- */

  function has(groups, list) {
    for (var i = 0; i < list.length; i++) if (groups.indexOf(list[i]) !== -1) return true;
    return false;
  }

  function categorize(a) {
    var g = a.groups;
    if (has(g, ['virustotal', 'rootcheck', 'malware', 'yara', 'clamd'])) return 'malware';
    if (has(g, ['authentication_failed', 'authentication_failures', 'invalid_login', 'win_authentication_failed'])) return 'auth_fail';
    if (g.indexOf('web') !== -1 && has(g, ['attack', 'sqlinjection', 'sql_injection', 'xss', 'web_scan', 'recon'])) return 'web';
    if (has(g, ['syscheck'])) return 'fim';
    if (has(g, ['adduser', 'addgroup', 'account_changed'])) return 'account';
    if (has(g, ['sudo'])) return 'sudo';
    if (has(g, ['dpkg', 'yum', 'rpm'])) return 'pkg';
    if (has(g, ['authentication_success'])) return a.srcip ? 'auth_success' : 'session';
    if (has(g, ['pam', 'login_session'])) return 'session';
    return 'other';
  }

  function ids(list) { return list.map(function (a) { return a.id; }); }
  function byCat(c, cat) { return c.alerts.filter(function (a) { return a.cat === cat; }); }

  function topValues(list, getter, max) {
    var counts = {}, order = [];
    list.forEach(function (a) {
      var v = getter(a);
      if (!v) return;
      if (!counts[v]) { counts[v] = 0; order.push(v); }
      counts[v]++;
    });
    order.sort(function (x, y) { return counts[y] - counts[x]; });
    return { values: order.slice(0, max), total: order.length };
  }

  function factor(c, id, points, params, alertIds) {
    c.factors.push({ id: id, points: points, params: params || {}, alertIds: alertIds || [] });
  }

  /* ---------- pattern matching ---------- */

  function analyseIpCase(c) {
    var fails = byCat(c, 'auth_fail');
    var succ = byCat(c, 'auth_success');
    var web = byCat(c, 'web');
    var ipClass = intel.classifyIp(c.srcip);
    var external = intel.isExternal(ipClass);
    c.ipClass = ipClass;
    c.external = external;

    var successAfter = null, failsBefore = fails;
    if (fails.length) {
      for (var i = 0; i < succ.length; i++) {
        if (succ[i].ts >= fails[0].ts) { successAfter = succ[i]; break; }
      }
      if (successAfter) {
        failsBefore = fails.filter(function (f) { return f.ts <= successAfter.ts; });
      }
    }
    var users = topValues(fails, function (a) { return a.user; }, 3);
    var base = { ip: c.srcip, host: c.host, count: c.count, level: c.maxLevel };

    if (web.length && web.length >= fails.length) {
      var kinds = topValues(web, function (a) { return a.desc; }, 2);
      c.pattern = 'web_attack';
      c.params = merge(base, { hits: web.length, durationMs: span(web), kinds: kinds.values, kindsTotal: kinds.total });
      c.patternIds = ids(web);
    } else if (fails.length >= 5 && successAfter) {
      c.pattern = 'bruteforce_success';
      c.params = merge(base, {
        fails: failsBefore.length, durationMs: span(failsBefore),
        user: successAfter.user || '?', successTs: successAfter.ts
      });
      c.patternIds = ids(failsBefore).concat([successAfter.id]);
    } else if (fails.length >= 5) {
      c.pattern = external ? 'bruteforce_external' : 'bruteforce_internal';
      c.params = merge(base, { fails: fails.length, durationMs: span(fails), users: users.values, usersTotal: users.total });
      c.patternIds = ids(fails);
    } else if (fails.length && successAfter && !external) {
      c.pattern = 'login_typo';
      c.params = merge(base, {
        fails: failsBefore.length, user: successAfter.user || '?',
        gapMs: successAfter.ts - failsBefore[failsBefore.length - 1].ts
      });
      c.patternIds = ids(failsBefore).concat([successAfter.id]);
    } else if (fails.length && !succ.length && external) {
      c.pattern = 'background_scan';
      c.params = merge(base, { fails: fails.length, users: users.values, usersTotal: users.total });
      c.patternIds = ids(fails);
    } else if (!fails.length && succ.length === c.count && !external) {
      c.pattern = 'admin_activity';
      c.params = merge(base, kindsOf(c.alerts));
      c.patternIds = ids(c.alerts);
    } else {
      c.pattern = 'unclassified';
      c.params = base;
      c.patternIds = [];
      c.externalSuccess = external && succ.length > 0;
      c.externalSuccessIds = ids(succ);
    }
  }

  function analyseHostCase(c) {
    var malware = byCat(c, 'malware');
    var account = byCat(c, 'account');
    var fim = byCat(c, 'fim');
    var criticalFim = fim.filter(function (a) { return CRITICAL_PATH.test(a.path); });
    var base = { host: c.host, count: c.count, level: c.maxLevel };
    c.ipClass = null;
    c.external = false;

    if (malware.length) {
      var top = malware.slice().sort(function (x, y) { return y.level - x.level; })[0];
      c.pattern = 'malware';
      c.params = merge(base, { detail: top.desc });
      c.patternIds = ids(malware);
    } else if (account.length || criticalFim.length) {
      var names = topValues(account, function (a) {
        if (a.user) return a.user;
        var m = /name=([^,\s]+)/.exec(a.fullLog);
        return m ? m[1] : '';
      }, 3);
      var paths = topValues(criticalFim, function (a) { return a.path; }, 3);
      c.pattern = 'suspicious_changes';
      c.params = merge(base, { names: names.values, paths: paths.values, hasAccount: account.length > 0, hasFim: criticalFim.length > 0 });
      c.patternIds = ids(account).concat(ids(criticalFim));
    } else if (c.maxLevel <= 7 && c.alerts.every(function (a) { return a.cat === 'session' || a.cat === 'sudo' || a.cat === 'pkg'; })) {
      c.pattern = 'admin_activity';
      c.params = merge(base, kindsOf(c.alerts));
      c.patternIds = ids(c.alerts);
    } else {
      c.pattern = 'unclassified';
      c.params = base;
      c.patternIds = [];
    }
  }

  function kindsOf(list) {
    var k = topValues(list, function (a) { return a.desc; }, 3);
    return { kinds: k.values, kindsTotal: k.total };
  }
  function span(list) { return list.length ? list[list.length - 1].ts - list[0].ts : 0; }
  function merge(a, b) {
    var out = {}, k;
    for (k in a) out[k] = a[k];
    for (k in b) out[k] = b[k];
    return out;
  }

  /* ---------- scoring ---------- */

  function levelPoints(level) {
    if (level >= 12) return 30;
    if (level >= 10) return 22;
    if (level >= 7) return 14;
    if (level >= 4) return 6;
    return 2;
  }
  function volumePoints(n) {
    if (n >= 50) return 15;
    if (n >= 10) return 10;
    if (n >= 5) return 5;
    return 0;
  }

  function score(c, intelAvailable) {
    c.factors = [];
    var top = c.alerts.filter(function (a) { return a.level === c.maxLevel; });
    factor(c, 'level', levelPoints(c.maxLevel), { level: c.maxLevel }, ids(top));
    var vp = volumePoints(c.count);
    if (vp) factor(c, 'volume', vp, { count: c.count }, []);
    factor(c, 'pattern.' + c.pattern, PATTERN_POINTS[c.pattern], c.params, c.patternIds);

    c.enrichment = { checked: false, available: true, listed: [] };
    if (c.kind === 'ip' && c.external) {
      c.enrichment.checked = true;
      if (!intelAvailable) {
        c.enrichment.available = false;
      } else {
        c.enrichment.listed = intel.lookup(c.srcip);
        if (c.enrichment.listed.length) {
          factor(c, 'rep_listed', Math.min(20, 10 * c.enrichment.listed.length), { n: c.enrichment.listed.length }, []);
        }
      }
    }
    if (c.kind === 'ip' && !c.external && (c.pattern === 'login_typo' || c.pattern === 'admin_activity')) {
      factor(c, 'internal', -8, { ip: c.srcip }, []);
    }
    if (c.externalSuccess) factor(c, 'ext_success', 25, { ip: c.srcip }, c.externalSuccessIds);
    if (c.intrusion) {
      factor(c, 'after_intrusion', 25, { caseId: c.intrusion.caseId, gapMs: c.intrusion.gapMs }, []);
    }

    var sum = 0;
    c.factors.forEach(function (f) { sum += f.points; });
    if (c.pattern === 'unclassified' && c.maxLevel >= 7 && sum < 30) {
      factor(c, 'high_level_unknown', 30 - sum, { level: c.maxLevel }, ids(top));
      sum = 30;
    }
    c.score = Math.max(0, Math.min(100, sum));
    c.verdict = c.score >= THRESHOLDS.malicious ? 'malicious' : c.score >= THRESHOLDS.review ? 'review' : 'benign';
    c.severity = c.score >= THRESHOLDS.critical ? 'critical' : c.score >= THRESHOLDS.malicious ? 'high' : c.score >= THRESHOLDS.review ? 'medium' : 'low';
  }

  function confidence(c) {
    var level = 2, reasons = [];
    var ambiguous = c.pattern === 'bruteforce_internal' || (c.pattern === 'suspicious_changes' && !c.intrusion);
    if (c.pattern === 'unclassified') { level = 0; reasons.push({ id: 'no_pattern' }); }
    else if (ambiguous) { level = 1; reasons.push({ id: 'ambiguous' }); }
    else reasons.push({ id: 'clear' });

    if (c.enrichment.checked && c.pattern !== 'unclassified') {
      if (!c.enrichment.available) { level--; reasons.push({ id: 'rep_unavailable' }); }
      else if (c.enrichment.listed.length) reasons.push({ id: 'corroborated' });
      else { level--; reasons.push({ id: 'no_rep' }); }
    }
    var dist = Math.min(Math.abs(c.score - THRESHOLDS.review), Math.abs(c.score - THRESHOLDS.malicious));
    if (dist <= BORDERLINE) { level--; reasons.push({ id: 'borderline', params: { n: dist } }); }
    if (c.count === 1 && c.pattern !== 'malware') { level--; reasons.push({ id: 'few' }); }
    c.confidence = ['low', 'medium', 'high'][Math.max(0, Math.min(2, level))];
    c.confidenceReasons = reasons;
  }

  function recommend(c) {
    var p = c.params, steps = [], decision = 'escalate', action = null;
    if (c.kind === 'ip' && c.external) action = { type: 'block_ip', target: c.srcip };
    switch (c.pattern) {
      case 'bruteforce_success':
        decision = 'approve';
        steps = [['block_ip', { ip: c.srcip }], ['reset_password', { user: p.user }], ['review_host', { host: c.host }], ['check_related', {}]];
        break;
      case 'bruteforce_external':
        decision = 'approve';
        steps = [['block_ip', { ip: c.srcip }], ['rate_limit', { host: c.host }]];
        break;
      case 'web_attack':
        decision = 'approve';
        steps = [['block_ip', { ip: c.srcip }], ['check_web_responses', {}], ['patch_app', {}]];
        break;
      case 'malware':
        decision = 'approve';
        action = { type: 'isolate_host', target: c.host };
        steps = [['isolate_host', { host: c.host }], ['preserve', {}], ['scan', {}]];
        break;
      case 'suspicious_changes':
        if (c.intrusion) {
          decision = 'approve';
          action = { type: 'isolate_host', target: c.host };
          steps = [['isolate_host', { host: c.host }]];
        } else {
          steps = [['confirm_change', { host: c.host }]];
        }
        if (p.names && p.names.length) steps.push(['remove_account', { user: p.names[0] }]);
        if (c.intrusion) steps.push(['check_related', {}]);
        break;
      case 'bruteforce_internal':
        steps = [['find_internal_source', { ip: c.srcip }], ['check_service_password', {}]];
        break;
      case 'login_typo':
        decision = 'dismiss';
        steps = [['confirm_user', { user: p.user }]];
        break;
      case 'admin_activity':
      case 'background_scan':
        decision = 'dismiss';
        steps = [['no_action', {}]];
        break;
      default:
        decision = c.verdict === 'benign' ? 'dismiss' : 'escalate';
        steps = [['read_raw', {}]];
    }
    // A case that follows an intrusion is never routine, whatever it looks like on its own.
    if (c.intrusion && decision === 'dismiss') { decision = 'escalate'; steps = [['check_related', {}], ['read_raw', {}]]; }
    if (decision === 'approve' && !action) decision = 'escalate';
    c.recommendation = {
      decision: decision,
      action: action,
      steps: steps.map(function (s) { return { id: s[0], params: s[1] }; })
    };
  }

  /* ---------- correlation ---------- */

  function caseId(key, first) {
    return 'AF-' + sha256(key + '|' + first.id + '|' + first.ts).slice(0, 6).toUpperCase();
  }

  function buildCases(alerts, opts) {
    var intelAvailable = !(opts && opts.intelAvailable === false);
    var sorted = alerts.slice().sort(function (x, y) { return x.ts - y.ts; });
    var open = {}, cases = [];

    sorted.forEach(function (a) {
      a.cat = categorize(a);
      var key = a.srcip ? 'ip|' + a.srcip + '|' + a.host : 'host|' + a.host;
      var gap = a.srcip ? GAP_IP : GAP_HOST;
      var c = open[key];
      if (!c || a.ts - c.lastTs > gap) {
        c = {
          id: caseId(key, a), key: key, kind: a.srcip ? 'ip' : 'host',
          srcip: a.srcip, host: a.host, hostIp: a.hostIp,
          firstTs: a.ts, lastTs: a.ts, alerts: [], maxLevel: 0, intrusion: null
        };
        open[key] = c;
        cases.push(c);
      }
      c.alerts.push(a);
      c.lastTs = a.ts;
      if (a.level > c.maxLevel) c.maxLevel = a.level;
      if (!c.hostIp && a.hostIp) c.hostIp = a.hostIp;
    });

    cases.forEach(function (c) {
      c.count = c.alerts.length;
      if (c.kind === 'ip') analyseIpCase(c); else analyseHostCase(c);
    });

    // Host activity that starts within an hour of a successful password-guessing
    // attack on the same host is treated as part of the same incident.
    cases.forEach(function (c) {
      if (c.kind !== 'host') return;
      cases.forEach(function (o) {
        if (o.pattern !== 'bruteforce_success' || o.host !== c.host) return;
        var gapMs = c.firstTs - o.params.successTs;
        if (gapMs >= 0 && gapMs <= RELATED && (!c.intrusion || gapMs < c.intrusion.gapMs)) {
          c.intrusion = { caseId: o.id, gapMs: gapMs };
        }
      });
    });

    cases.forEach(function (c) {
      score(c, intelAvailable);
      confidence(c);
      recommend(c);
      c.related = cases.filter(function (o) {
        return o !== c && o.host === c.host && o.firstTs <= c.lastTs + RELATED && o.lastTs >= c.firstTs - RELATED;
      }).map(function (o) { return o.id; });
      c.hash = evidenceHash(c);
    });

    cases.sort(function (x, y) { return y.score - x.score || y.lastTs - x.lastTs; });
    return cases;
  }

  /* Rows for the evidence timeline: long runs of the same kind collapse into one burst. */
  function timeline(c) {
    var rows = [], run = [];
    function flush() {
      if (!run.length) return;
      if (run.length >= 4) rows.push({ type: 'burst', cat: run[0].cat, alerts: run });
      else run.forEach(function (a) { rows.push({ type: 'event', alert: a }); });
      run = [];
    }
    c.alerts.forEach(function (a) {
      var same = run.length && run[0].cat === a.cat && (a.cat === 'auth_fail' || a.cat === 'web' || run[0].ruleId === a.ruleId);
      if (!same) flush();
      run.push(a);
    });
    flush();
    return rows;
  }

  /* ---------- SHA-256 (evidence fingerprint) ---------- */

  var K = (function () {
    var k = [], n = 2;
    function prime(x) { for (var d = 2; d * d <= x; d++) if (x % d === 0) return false; return true; }
    while (k.length < 64) { if (prime(n)) k.push((Math.pow(n, 1 / 3) * 4294967296) | 0); n++; }
    return k;
  })();
  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256(text) {
    var bytes = new TextEncoder().encode(String(text));
    var l = bytes.length, padded = ((l + 9 + 63) >> 6) << 6;
    var buf = new Uint8Array(padded);
    buf.set(bytes);
    buf[l] = 0x80;
    var dv = new DataView(buf.buffer);
    dv.setUint32(padded - 8, Math.floor((l * 8) / 4294967296));
    dv.setUint32(padded - 4, (l * 8) >>> 0);
    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var w = new Int32Array(64);
    for (var off = 0; off < padded; off += 64) {
      var i;
      for (i = 0; i < 16; i++) w[i] = dv.getInt32(off + i * 4);
      for (i = 16; i < 64; i++) {
        var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (i = 0; i < 64; i++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[i] + w[i]) | 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    return H.map(function (x) { return ('00000000' + (x >>> 0).toString(16)).slice(-8); }).join('');
  }

  /* Fingerprint of exactly the alerts a reviewer saw when deciding. */
  function evidenceHash(c) {
    return sha256(c.alerts.map(function (a) { return a.id + '@' + a.ts + '#' + a.ruleId; }).join('\n'));
  }

  var api = {
    LIMITS: LIMITS,
    THRESHOLDS: THRESHOLDS,
    PATTERNS: Object.keys(PATTERN_POINTS),
    parseAlerts: parseAlerts,
    fromRecords: fromRecords,
    buildCases: buildCases,
    timeline: timeline,
    sha256: sha256,
    evidenceHash: evidenceHash
  };
  AF.engine = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
