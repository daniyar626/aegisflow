/*
 * AegisFlow interface.
 *
 * Renders the pages from the persisted state and the cases the engine builds.
 * Every page except sign-in needs a signed-in account (see accounts.js).
 * All text reaches the page through text nodes, never innerHTML, because alert
 * content comes from logs an attacker can influence.
 */
(function () {
  'use strict';
  var AF = window.AF, I = AF.i18n, t = I.t, store = AF.store, engine = AF.engine, intel = AF.intel, accounts = AF.accounts;
  var VERSION = '1.1';
  var DECISION_OF = { approved: 'approve', dismissed: 'dismiss', escalated: 'escalate' };

  var S;                                                       // persisted state
  var M = { alerts: [], cases: [], byId: {} };                 // derived from the loaded alerts
  var V = { status: 'open', verdict: 'any', q: '', paste: '', importError: null, importWarn: null, storageWarned: false };
  var A;                                                       // accounts, from accounts.js
  var ME = null;                                               // the signed-in account

  /* ---------- small helpers ---------- */

  function $(id) { return document.getElementById(id); }

  function append(el, child) {
    if (child === null || child === undefined || child === false) return;
    if (Array.isArray(child)) { child.forEach(function (c) { append(el, c); }); return; }
    el.appendChild(typeof child === 'object' ? child : document.createTextNode(String(child)));
  }

  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) {
      for (var k in attrs) {
        var v = attrs[k];
        if (v === null || v === undefined || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k.slice(0, 2) === 'on' && typeof v === 'function') el.addEventListener(k.slice(2), v);
        else if (v === true) el.setAttribute(k, '');
        else el.setAttribute(k, String(v));
      }
    }
    for (var i = 2; i < arguments.length; i++) append(el, arguments[i]);
    return el;
  }

  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function fmtClock(ts) {
    var d = new Date(ts);
    return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }
  function fmtTime(ts, seconds) {
    var d = new Date(ts);
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + (seconds ? ':' + pad(d.getSeconds()) : '');
  }
  function fmtDur(ms) {
    var s = Math.round((ms || 0) / 1000);
    if (s < 1) return t('dur.under');
    if (s < 60) return t('dur.s', { n: s });
    var m = Math.floor(s / 60), r = s % 60;
    if (m < 60) return t('dur.m', { n: m }) + (r ? ' ' + t('dur.s', { n: r }) : '');
    var hrs = Math.floor(m / 60);
    return t('dur.h', { n: hrs }) + (m % 60 ? ' ' + t('dur.m', { n: m % 60 }) : '');
  }
  function joinList(values, total) {
    // Wazuh rule descriptions end with a full stop; drop it inside a list.
    var s = (values || []).map(function (v) { return String(v).replace(/\.$/, ''); }).join(', ');
    if (total > (values || []).length) s += ' ' + t('list.more', { n: total - values.length });
    return s;
  }
  function points(n) { return (n > 0 ? '+' : n < 0 ? '−' : '') + Math.abs(n); }
  function localName(name) { return name[I.get()] || name.en; }
  function reducedMotion() {
    return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  function toast(message, kind) {
    var region = $(kind === 'error' ? 'alerts' : 'toasts');
    var el = h('div', { class: 'toast' + (kind === 'error' ? ' toast-error' : '') },
      h('span', { text: message }),
      h('button', { type: 'button', class: 'toast-x', 'aria-label': t('close'), onclick: function () { el.remove(); } }, '×'));
    region.appendChild(el);
    setTimeout(function () { el.remove(); }, kind === 'error' ? 12000 : 6000);
  }

  function persist() {
    store.save();
    if (store.persistFailed && !V.storageWarned) {
      V.storageWarned = true;
      toast(t('err.storage'), 'error');
    }
  }

  function go(hash) {
    if (location.hash === hash) render({ focus: true });
    else location.hash = hash;
  }

  /* ---------- accounts ---------- */

  /* Decisions and the audit log carry the signed-in account's name and role. */
  function syncProfile() {
    if (!ME) return;
    S.profile.name = ME.name;
    S.profile.role = ME.role;
  }

  function saveAccounts() {
    accounts.save();
    if (accounts.persistFailed && !V.storageWarned) {
      V.storageWarned = true;
      toast(t('err.storage'), 'error');
    }
  }

  function signOut() {
    accounts.endSession();
    ME = null;
    S.profile.name = '';
    persist();
    toast(t('login.out'));
    go('#/login');
  }

  function roleOptions(id, value) {
    var sel = h('select', { id: id });
    accounts.ROLES.forEach(function (r) { sel.appendChild(h('option', { value: r, text: t('role.' + r) })); });
    sel.value = value || 'analyst';
    return sel;
  }

  function passwordInput(id, autocomplete) {
    return h('input', { type: 'password', id: id, maxlength: 128, autocomplete: autocomplete, required: true });
  }

  /* ---------- data ---------- */

  function rebuild() {
    M = { alerts: [], cases: [], byId: {} };
    var records = null;
    if (S.source && S.source.type === 'demo') records = AF.demo.build();
    else if (S.source && S.records) records = S.records;
    if (!records) { S.source = null; return; }
    try {
      var parsed = engine.fromRecords(records);
      M.alerts = parsed.alerts;
      M.cases = engine.buildCases(parsed.alerts, { intelAvailable: !S.settings.intelOutage });
      M.cases.forEach(function (c) { M.byId[c.id] = c; });
    } catch (e) {
      S.source = null;
      S.records = null;
    }
  }

  function sourceLabel(source) {
    if (!source) return t('none');
    if (source.type === 'demo') return t('source.demo');
    if (source.type === 'file') return t('source.file', { name: source.name });
    return t('source.paste');
  }

  function afterLoad() {
    rebuild();
    S.audit.push({ at: Date.now(), by: '', role: '', event: 'loaded', alerts: M.alerts.length, cases: M.cases.length, source: S.source });
    persist();
    V.status = 'open'; V.verdict = 'any'; V.q = '';
    toast(t('queue.summary', { alerts: M.alerts.length, cases: M.cases.length }));
    go('#/queue');
  }

  function loadDemo() {
    V.importError = null; V.importWarn = null;
    S.source = { type: 'demo', name: '', at: Date.now() };
    S.records = null;
    afterLoad();
  }

  function importFailed(code, params) {
    V.importError = { code: code, params: params || {} };
    render();
    var box = $('import-error');
    if (box) box.focus();
  }

  function loadText(text, type, name) {
    V.importError = null; V.importWarn = null;
    var parsed;
    try { parsed = engine.parseAlerts(text); }
    catch (e) { importFailed(e.code || 'read', e.params); return; }
    S.source = { type: type, name: (name || '').slice(0, 80), at: Date.now() };
    S.records = parsed.records;
    if (parsed.skipped) V.importWarn = { skipped: parsed.skipped, total: parsed.total };
    V.paste = '';
    afterLoad();
  }

  function statusOf(c) { return S.decisions[c.id] ? S.decisions[c.id].type : 'new'; }

  /* ---------- case text ---------- */

  function caseTitle(c) { return t('title.' + c.pattern); }

  function summarySentences(c) {
    var p = c.params, out = [];
    var after = c.intrusion ? { gap: fmtDur(c.intrusion.gapMs), caseId: c.intrusion.caseId } : null;
    var dur = fmtDur(p.durationMs);
    function rep() {
      var e = c.enrichment;
      if (!e.checked) return;
      if (!e.available) out.push(t('rep.unavailable'));
      else if (e.listed.length) out.push(t('rep.listed', { n: e.listed.length, lists: e.listed.map(function (l) { return localName(l.name); }).join(', ') }));
      else out.push(t('rep.unknown'));
    }
    switch (c.pattern) {
      case 'bruteforce_success':
        out.push(t('sum.bruteforce_success', { ip: p.ip, host: p.host, fails: p.fails, duration: dur, user: p.user }));
        rep();
        out.push(t('sum.bruteforce_success.close', { user: p.user, host: p.host }));
        break;
      case 'bruteforce_external':
        out.push(t('sum.bruteforce_external', { ip: p.ip, host: p.host, fails: p.fails, duration: dur }));
        rep();
        out.push(t('sum.bruteforce_external.close', { users: joinList(p.users, p.usersTotal) }));
        break;
      case 'bruteforce_internal':
        out.push(t('sum.bruteforce_internal', { ip: p.ip, host: p.host, fails: p.fails, duration: dur, users: joinList(p.users, p.usersTotal) }));
        out.push(t('sum.bruteforce_internal.close'));
        break;
      case 'web_attack':
        out.push(t('sum.web_attack', { ip: p.ip, host: p.host, hits: p.hits, duration: dur, kinds: joinList(p.kinds, p.kindsTotal) }));
        rep();
        out.push(t('sum.web_attack.close'));
        break;
      case 'malware':
        out.push(t('sum.malware', { host: p.host, detail: p.detail.replace(/\.$/, '') }));
        if (after) out.push(t('sum.unclassified.after', after));
        out.push(t('sum.malware.close'));
        break;
      case 'suspicious_changes':
        if (p.hasAccount) out.push(t('sum.changes.account', { host: p.host, names: p.names.join(', ') || '?' }));
        if (p.hasFim) out.push(t('sum.changes.fim', { host: p.host, paths: p.paths.join(', ') }));
        out.push(after ? t('sum.changes.after', after) : t('sum.changes.close', { host: p.host }));
        break;
      case 'admin_activity':
        out.push(t('sum.admin_activity', { host: p.host, count: p.count, kinds: joinList(p.kinds, p.kindsTotal) }));
        out.push(after ? t('sum.admin_activity.after', after) : t('sum.admin_activity.close'));
        break;
      case 'login_typo':
        out.push(t('sum.login_typo', { ip: p.ip, host: p.host, fails: p.fails, user: p.user, gap: fmtDur(p.gapMs) }));
        out.push(t('sum.login_typo.close'));
        break;
      case 'background_scan':
        out.push(t('sum.background_scan', { ip: p.ip, host: p.host, fails: p.fails, users: joinList(p.users, p.usersTotal) }));
        rep();
        out.push(t('sum.background_scan.close'));
        break;
      default:
        out.push(t('sum.unclassified', { host: p.host, count: p.count, level: p.level }));
        if (after) out.push(t('sum.unclassified.after', after));
        rep();
        out.push(t(p.level >= 7 ? 'sum.unclassified.high' : 'sum.unclassified.low'));
    }
    return out;
  }

  function recText(rec) {
    if (rec.decision === 'approve' && rec.action) return t('rec.approve.' + rec.action.type, { target: rec.action.target });
    return t('rec.' + (rec.decision === 'approve' ? 'escalate' : rec.decision));
  }
  function actionText(action) { return t('act.' + action.type, { target: action.target }); }
  function stepText(step) { return t('step.' + step.id, step.params); }

  function ticketText(c, d) {
    var L = [t('ticket.header'), ''];
    L.push(t('ticket.case') + ': ' + c.id + ', ' + caseTitle(c));
    L.push(t('ticket.decision') + ': ' + t('out.' + d.type));
    L.push(t('ticket.by') + ': ' + d.by + ' (' + t('role.' + d.role) + ')');
    L.push(t('ticket.time') + ': ' + fmtTime(d.at, true));
    L.push(t('ticket.hash') + ': ' + d.hash);
    if (d.type === 'approved' && d.action) {
      L.push('');
      L.push(t('ticket.action') + ': ' + actionText(d.action));
      if (d.action.type === 'block_ip') {
        L.push(t('ticket.example') + ':');
        L.push('  iptables -I INPUT -s ' + d.action.target + ' -j DROP');
      }
    }
    if (d.reason) L.push(t('ticket.reason') + ': ' + t('reason.' + d.reason));
    if (d.note) L.push(t('ticket.note') + ': ' + d.note);
    L.push('', t('ticket.summary') + ':', summarySentences(c).join(' '));
    L.push('', t('ticket.steps') + ':');
    c.recommendation.steps.forEach(function (s, i) { L.push('  ' + (i + 1) + '. ' + stepText(s)); });
    L.push('', t('ticket.not_executed'));
    return L.join('\n');
  }

  /* ---------- shared pieces ---------- */

  function sevBadge(c) { return h('span', { class: 'sev sev-' + c.severity, text: t('sev.' + c.severity) }); }
  function verdictBadge(c) { return h('span', { class: 'verdict v-' + c.verdict, text: t('verdict.' + c.verdict) }); }
  function statusBadge(c) {
    var st = statusOf(c);
    return h('span', { class: 'st st-' + st, text: t('st.' + st) });
  }

  function emptyState(title, body, button) {
    return h('div', { class: 'empty' },
      title ? h('h2', { text: title }) : null,
      body ? h('p', { text: body }) : null,
      button || null);
  }

  function field(id, label, control, help) {
    return h('div', { class: 'field' },
      h('label', { for: id, text: label }),
      control,
      help ? h('p', { class: 'help', text: help }) : null);
  }

  /* ---------- dialogs ---------- */

  function openDialog(cfg) {
    var error = h('p', { class: 'form-error', role: 'alert', tabindex: '-1' });
    error.hidden = true;
    var dlg = h('dialog', { class: 'dlg', 'aria-labelledby': 'dlg-title' });
    function close() { if (dlg.close) dlg.close(); else dlg.remove(); }
    var form = h('form', {
      novalidate: true,
      onsubmit: function (e) {
        e.preventDefault();
        var message = cfg.onConfirm();
        if (message) { error.textContent = message; error.hidden = false; error.focus(); }
        else close();
      }
    },
      h('h2', { id: 'dlg-title', text: cfg.title }),
      cfg.body,
      error,
      h('div', { class: 'dlg-actions' },
        h('button', { type: 'button', class: 'btn', onclick: close, text: t('dlg.cancel') }),
        h('button', { type: 'submit', class: 'btn ' + (cfg.danger ? 'btn-danger' : 'btn-primary'), text: cfg.confirm })));
    dlg.appendChild(form);
    dlg.addEventListener('close', function () { dlg.remove(); if (cfg.after) cfg.after(); });
    document.body.appendChild(dlg);
    if (dlg.showModal) dlg.showModal(); else dlg.setAttribute('open', '');
  }

  /* A decision always carries a name. If the profile has none, the dialog asks for it. */
  function reviewerRow(labelKey) {
    if (S.profile.name) {
      return {
        node: h('div', { class: 'kv' }, h('dt', { text: t(labelKey) }), h('dd', { text: S.profile.name + ', ' + t('role.' + S.profile.role) })),
        read: function () { return S.profile.name; }
      };
    }
    var input = h('input', { type: 'text', id: 'dlg-name', maxlength: 60, autocomplete: 'name', required: true });
    return {
      node: h('div', { class: 'kv kv-field' }, h('dt', null, h('label', { for: 'dlg-name', text: t('field.name') })), h('dd', null, input)),
      read: function () { return input.value.trim(); }
    };
  }

  function canDecide() {
    if (S.profile.role === 'viewer') { toast(t('err.permission'), 'error'); return false; }
    return true;
  }

  function overrideNote(c, type) {
    if (DECISION_OF[type] === c.recommendation.decision) return null;
    return h('p', { class: 'notice notice-warn', text: t('dlg.override', { rec: recText(c.recommendation) }) });
  }

  function record(c, type, extra) {
    var now = Date.now();
    var d = {
      type: type, by: S.profile.name, role: S.profile.role, at: now,
      ttdMs: now - (S.opened[c.id] || now),
      reason: extra.reason || '', note: (extra.note || '').slice(0, 500),
      action: type === 'approved' ? c.recommendation.action : null,
      recommended: c.recommendation.decision,
      override: DECISION_OF[type] !== c.recommendation.decision,
      hash: c.hash, verdict: c.verdict, score: c.score
    };
    S.decisions[c.id] = d;
    S.audit.push({
      at: now, by: d.by, role: d.role, event: type, caseId: c.id, pattern: c.pattern, host: c.host, srcip: c.srcip,
      action: d.action, reason: d.reason, note: d.note, hash: d.hash, override: d.override
    });
    persist();
    toast(t('out.recorded'));
    render();
    // Runs after the dialog has closed, so focus lands on the recorded decision.
    setTimeout(function () { var slip = $('decision'); if (slip) slip.focus(); }, 0);
  }

  function takeName(reviewer) {
    var name = reviewer.read();
    if (name.length < 2) return false;
    S.profile.name = name.slice(0, 60);
    return true;
  }

  function askApprove(c) {
    if (!canDecide()) return;
    var reviewer = reviewerRow('dlg.field.approver');
    var check = h('input', { type: 'checkbox', id: 'dlg-check' });
    openDialog({
      title: t('dlg.approve.title'),
      confirm: t('dlg.approve.confirm'),
      body: [
        overrideNote(c, 'approved'),
        h('dl', { class: 'kvs' },
          h('div', { class: 'kv' }, h('dt', { text: t('dlg.field.action') }), h('dd', { class: 'strong', text: actionText(c.recommendation.action) })),
          h('div', { class: 'kv' }, h('dt', { text: t('dlg.field.case') }), h('dd', { text: c.id + ', ' + caseTitle(c) })),
          h('div', { class: 'kv' }, h('dt', { text: t('dlg.field.hash') }), h('dd', { class: 'mono', text: c.hash.slice(0, 16) })),
          reviewer.node),
        h('label', { class: 'check', for: 'dlg-check' }, check, h('span', { text: t('dlg.approve.check') })),
        h('p', { class: 'help', text: t('dec.nothing_auto') })
      ],
      onConfirm: function () {
        if (!takeName(reviewer)) return t('err.no_name');
        if (!check.checked) return t('err.confirm_review');
        record(c, 'approved', {});
        return '';
      }
    });
  }

  function askDismiss(c) {
    if (!canDecide()) return;
    var reviewer = reviewerRow('dlg.field.reviewer');
    var reason = h('select', { id: 'dlg-reason' }, h('option', { value: '', text: t('reason.choose') }));
    ['benign', 'maintenance', 'noise', 'test', 'other'].forEach(function (r) {
      reason.appendChild(h('option', { value: r, text: t('reason.' + r) }));
    });
    var note = h('textarea', { id: 'dlg-note', rows: 3, maxlength: 500 });
    openDialog({
      title: t('dlg.dismiss.title'),
      confirm: t('dlg.dismiss.confirm'),
      body: [
        overrideNote(c, 'dismissed'),
        h('dl', { class: 'kvs' },
          h('div', { class: 'kv' }, h('dt', { text: t('dlg.field.case') }), h('dd', { text: c.id + ', ' + caseTitle(c) })),
          reviewer.node),
        field('dlg-reason', t('dlg.dismiss.reason'), reason),
        field('dlg-note', t('dlg.note'), note)
      ],
      onConfirm: function () {
        if (!takeName(reviewer)) return t('err.no_name');
        if (!reason.value) return t('err.reason');
        record(c, 'dismissed', { reason: reason.value, note: note.value.trim() });
        return '';
      }
    });
  }

  function askEscalate(c) {
    if (!canDecide()) return;
    var reviewer = reviewerRow('dlg.field.reviewer');
    var note = h('textarea', { id: 'dlg-note', rows: 4, maxlength: 500 });
    openDialog({
      title: t('dlg.escalate.title'),
      confirm: t('dlg.escalate.confirm'),
      body: [
        overrideNote(c, 'escalated'),
        h('dl', { class: 'kvs' },
          h('div', { class: 'kv' }, h('dt', { text: t('dlg.field.case') }), h('dd', { text: c.id + ', ' + caseTitle(c) })),
          reviewer.node),
        field('dlg-note', t('dlg.escalate.note'), note)
      ],
      onConfirm: function () {
        if (!takeName(reviewer)) return t('err.no_name');
        if (note.value.trim().length < 3) return t('err.note');
        record(c, 'escalated', { note: note.value.trim() });
        return '';
      }
    });
  }

  function reopen(c) {
    if (!canDecide()) return;
    var d = S.decisions[c.id];
    delete S.decisions[c.id];
    S.opened[c.id] = Date.now();
    S.audit.push({ at: Date.now(), by: S.profile.name || d.by, role: S.profile.role, event: 'reopened', caseId: c.id, pattern: c.pattern, host: c.host, srcip: c.srcip, hash: c.hash });
    persist();
    toast(t('out.reopened'));
    render();
  }

  /* ---------- header and footer ---------- */

  function renderHeader(r) {
    var top = $('top');
    top.textContent = '';
    $('skip').textContent = t('app.skip');
    var active = r.name === 'case' ? 'queue' : r.name;
    var names = ['connect', 'queue', 'audit', 'report', 'settings'];
    if (ME && ME.role === 'admin') names.push('admin');
    var nav = ME && !ME.mustChange ? h('nav', { class: 'nav', 'aria-label': t('nav.label') }, h('ul', null,
      names.map(function (name) {
        return h('li', null, h('a', { href: '#/' + name, 'aria-current': active === name ? 'page' : null, text: t('nav.' + name) }));
      }))) : null;
    var langs = h('div', { class: 'langs', role: 'group', 'aria-label': t('lang.label') },
      I.languages.map(function (l) {
        return h('button', {
          type: 'button', class: 'lang', lang: l.code, title: l.label, 'aria-pressed': I.get() === l.code ? 'true' : 'false',
          onclick: function () {
            I.set(l.code); S.lang = l.code; persist(); render();
            var pressed = document.querySelector('.lang[aria-pressed="true"]');
            if (pressed) pressed.focus();
          }
        }, l.short);
      }));
    var who = ME ? h('a', { class: 'who', href: '#/settings', title: ME.name + ', ' + t('role.' + ME.role) }, ME.name) : null;
    var out = ME ? h('button', { type: 'button', class: 'signout', onclick: signOut, text: t('signout') }) : null;
    top.appendChild(h('div', { class: 'top-in' },
      h('a', { class: 'brand', href: '#/' + (!ME ? 'login' : M.cases.length ? 'queue' : 'connect') }, h('img', { src: 'favicon.svg', alt: '', width: 26, height: 26 }), 'AegisFlow'),
      nav,
      h('div', { class: 'top-side' }, langs, who, out)));
    $('foot').textContent = t('app.footer', { v: VERSION });
  }

  /* ---------- page: data source ---------- */

  function pageConnect() {
    var file = h('input', { type: 'file', id: 'imp-file', accept: '.json,.ndjson,.log,.txt,application/json' });
    file.addEventListener('change', function () {
      var f = file.files && file.files[0];
      if (!f) return;
      if (f.size > engine.LIMITS.maxBytes) {
        importFailed('too_large', { size: (f.size / 1048576).toFixed(1), max: engine.LIMITS.maxBytes / 1048576 });
        return;
      }
      var reader = new FileReader();
      reader.onload = function () { loadText(String(reader.result || ''), 'file', f.name); };
      reader.onerror = function () { importFailed('read'); };
      reader.readAsText(f);
    });
    var paste = h('textarea', { id: 'imp-paste', rows: 5, spellcheck: 'false', class: 'mono' });
    paste.value = V.paste;   // keep what was pasted when an error re-renders the page
    paste.addEventListener('input', function () { V.paste = paste.value; });
    function analysePaste() {
      var text = paste.value;
      if (!text.trim()) { importFailed('paste_empty'); return; }
      if (text.length > engine.LIMITS.maxBytes) {
        importFailed('too_large', { size: (text.length / 1048576).toFixed(1), max: engine.LIMITS.maxBytes / 1048576 });
        return;
      }
      loadText(text, 'paste', '');
    }

    var importError = V.importError
      ? h('p', { class: 'form-error', id: 'import-error', role: 'alert', tabindex: '-1', text: t('err.' + V.importError.code, V.importError.params) })
      : null;

    return h('div', { class: 'page page-connect' },
      h('div', { class: 'hero' },
        h('h1', { tabindex: '-1', text: t('connect.h1') }),
        h('p', { class: 'lead', text: t('connect.lead') })),
      M.cases.length ? h('p', { class: 'notice notice-ok' },
        t('connect.loaded', { alerts: M.alerts.length, cases: M.cases.length }) + ' ',
        h('a', { href: '#/queue', text: t('connect.open_queue') })) : null,
      h('ol', { class: 'steps' },
        h('li', null,
          h('h2', { text: t('connect.step1') }),
          h('p', { class: 'strong', text: t('connect.signedin', { name: ME.name, role: t('role.' + ME.role) }) }),
          h('p', { class: 'help', text: t('connect.signedin.help') })),
        h('li', null,
          h('h2', { text: t('connect.step2') }),
          M.cases.length ? h('p', { class: 'help', text: t('connect.replace_note') }) : null,
          h('div', { class: 'sources' },
            h('section', { class: 'source' },
              h('h3', { text: t('connect.demo.title') }),
              h('p', { text: t('connect.demo.body') }),
              h('button', { type: 'button', class: 'btn btn-primary', id: 'load-demo', onclick: loadDemo, text: t('connect.demo.btn') })),
            h('section', { class: 'source' },
              h('h3', { text: t('connect.import.title') }),
              h('p', { text: t('connect.import.body', { max: engine.LIMITS.maxAlerts, mb: engine.LIMITS.maxBytes / 1048576 }) }),
              importError,
              field('imp-file', t('connect.import.file'), file),
              field('imp-paste', t('connect.import.paste'), paste),
              h('button', { type: 'button', class: 'btn', onclick: analysePaste, text: t('connect.import.btn') }))))),
      h('div', { class: 'facts' },
        h('section', null, h('h2', { text: t('connect.privacy.title') }), h('p', { text: t('connect.privacy.body') })),
        h('section', null, h('h2', { text: t('connect.live.title') }), h('p', { text: t('connect.live.body') }))));
  }

  /* ---------- page: queue ---------- */

  function pageQueue() {
    var page = h('div', { class: 'page page-queue' });
    page.appendChild(h('h1', { tabindex: '-1', text: t('queue.h1') }));

    if (!M.cases.length) {
      page.appendChild(emptyState(t('queue.empty.nodata.title'), t('queue.empty.nodata.body'),
        h('a', { class: 'btn btn-primary', href: '#/connect', text: t('queue.empty.nodata.btn') })));
      return page;
    }

    var count = { malicious: 0, review: 0, benign: 0 };
    M.cases.forEach(function (c) { count[c.verdict]++; });
    page.appendChild(h('p', { class: 'lead' },
      t('queue.summary', { alerts: M.alerts.length, cases: M.cases.length }) + '. ' +
      t('queue.counts', { mal: count.malicious, rev: count.review, ben: count.benign }) + '.'));
    if (S.settings.intelOutage) page.appendChild(h('p', { class: 'notice notice-warn', text: t('queue.outage') }));
    if (V.importWarn) page.appendChild(h('p', { class: 'notice notice-warn', text: t('warn.skipped', V.importWarn) }));

    var statusBox = h('fieldset', { class: 'seg' }, h('legend', { text: t('queue.filter.status') }));
    ['open', 'decided', 'all'].forEach(function (s) {
      var input = h('input', { type: 'radio', name: 'q-status', id: 'q-status-' + s, value: s });
      input.checked = V.status === s;
      input.addEventListener('change', function () { V.status = s; draw(); });
      statusBox.appendChild(input);
      statusBox.appendChild(h('label', { for: 'q-status-' + s, text: t('status.' + s) }));
    });
    var verdict = h('select', { id: 'q-verdict' }, h('option', { value: 'any', text: t('queue.filter.any') }));
    ['malicious', 'review', 'benign'].forEach(function (v) { verdict.appendChild(h('option', { value: v, text: t('verdict.' + v) })); });
    verdict.value = V.verdict;
    verdict.addEventListener('change', function () { V.verdict = verdict.value; draw(); });
    var search = h('input', { type: 'search', id: 'q-search', value: V.q, autocomplete: 'off' });
    search.addEventListener('input', function () { V.q = search.value; draw(); });

    page.appendChild(h('div', { class: 'filters' },
      statusBox,
      field('q-verdict', t('queue.filter.verdict'), verdict),
      field('q-search', t('queue.search'), search)));

    var tbody = h('tbody');
    var table = h('table', { class: 'queue' },
      h('thead', null, h('tr', null,
        ['severity', 'case', 'source', 'host', 'alerts', 'last', 'verdict', 'confidence', 'status'].map(function (c) {
          return h('th', { scope: 'col', class: c === 'alerts' ? 'num' : null, text: t('col.' + c) });
        }))),
      tbody);
    var shown = h('p', { class: 'shown', role: 'status' });
    var hole = h('div');
    page.appendChild(h('div', { class: 'table-wrap' }, table));
    page.appendChild(shown);
    page.appendChild(hole);

    function cell(label, cls, content) { return h('td', { 'data-label': t('col.' + label), class: cls }, content); }

    function draw() {
      var q = V.q.trim().toLowerCase();
      var rows = M.cases.filter(function (c) {
        var decided = !!S.decisions[c.id];
        if (V.status === 'open' && decided) return false;
        if (V.status === 'decided' && !decided) return false;
        if (V.verdict !== 'any' && c.verdict !== V.verdict) return false;
        if (q && (c.id + ' ' + c.host + ' ' + c.srcip + ' ' + caseTitle(c)).toLowerCase().indexOf(q) === -1) return false;
        return true;
      });
      tbody.textContent = '';
      rows.forEach(function (c) {
        var tr = h('tr', { class: 'spine-' + c.severity },
          cell('severity', null, sevBadge(c)),
          cell('case', 'cell-case', [h('a', { href: '#/case/' + c.id, text: caseTitle(c) }), h('span', { class: 'case-id', text: c.id })]),
          cell('source', 'mono', c.srcip || h('span', { class: 'muted sans', text: t('src.host_only') })),
          cell('host', 'mono', c.host),
          cell('alerts', 'num', String(c.count)),
          cell('last', 'nowrap', fmtTime(c.lastTs)),
          cell('verdict', null, verdictBadge(c)),
          cell('confidence', null, t('conf.' + c.confidence)),
          cell('status', null, statusBadge(c)));
        tr.addEventListener('click', function (e) {
          if (e.target.closest('a')) return;
          location.hash = '#/case/' + c.id;
        });
        tbody.appendChild(tr);
      });
      table.hidden = !rows.length;
      shown.textContent = t('queue.shown', { n: rows.length });
      hole.textContent = '';
      if (!rows.length) {
        var allDecided = M.cases.every(function (c) { return S.decisions[c.id]; });
        if (V.status === 'open' && V.verdict === 'any' && !q && allDecided) {
          hole.appendChild(emptyState(t('queue.empty.done.title'), t('queue.empty.done.body'),
            h('button', { type: 'button', class: 'btn', text: t('queue.empty.done.btn'), onclick: function () { V.status = 'decided'; render(); } })));
        } else {
          hole.appendChild(emptyState(t('queue.empty.filter.title'), t('queue.empty.filter.body'),
            h('button', { type: 'button', class: 'btn', text: t('queue.empty.filter.btn'), onclick: function () { V.status = 'all'; V.verdict = 'any'; V.q = ''; render(); } })));
        }
      }
    }
    draw();
    return page;
  }

  /* ---------- page: case ---------- */

  function showEvidence(alertIds) {
    var wanted = {}, first = null;
    alertIds.forEach(function (id) { wanted[id] = true; });
    Array.prototype.forEach.call(document.querySelectorAll('.tl-row'), function (row) {
      var hit = (row._ids || []).some(function (id) { return wanted[id]; });
      row.classList.toggle('is-evidence', hit);
      if (hit && !first) first = row;
    });
    if (first) {
      first.scrollIntoView({ block: 'center', behavior: reducedMotion() ? 'auto' : 'smooth' });
      first.focus({ preventScroll: true });
    }
  }

  function rawRecord(a) {
    var text;
    try { text = JSON.stringify(a.raw, null, 2); } catch (e) { text = String(a.fullLog || a.desc); }
    if (text.length > 6000) text = text.slice(0, 6000) + '\n...';
    return h('details', { class: 'raw' }, h('summary', { text: t('case.raw') }), h('pre', { text: text }));
  }

  function timelineRow(row) {
    var li;
    if (row.type === 'event') {
      var a = row.alert;
      li = h('li', { class: 'tl-row', tabindex: '-1' },
        h('time', { class: 'tl-time', datetime: new Date(a.ts).toISOString(), title: fmtTime(a.ts, true), text: fmtClock(a.ts) }),
        h('div', { class: 'tl-body' },
          h('p', { class: 'tl-desc', text: a.desc }),
          h('p', { class: 'tl-meta', text: t('case.rule', { id: a.ruleId, level: a.level }) + (a.user ? ', ' + a.user : '') + (a.path ? ', ' + a.path : '') }),
          rawRecord(a)),
        h('span', { class: 'lvl lvl-' + (a.level >= 10 ? 'hi' : a.level >= 7 ? 'mid' : 'lo'), text: String(a.level) }));
      li._ids = [a.id];
      return li;
    }
    var list = row.alerts, first = list[0], last = list[list.length - 1];
    var rules = [], maxLevel = 0;
    list.forEach(function (x) {
      if (rules.indexOf(x.ruleId) === -1) rules.push(x.ruleId);
      if (x.level > maxLevel) maxLevel = x.level;
    });
    var kind = t('case.burst.' + (row.cat === 'auth_fail' || row.cat === 'web' ? row.cat : 'other'));
    var sub = h('ol', { class: 'tl-sub' });
    var more = h('button', { type: 'button', class: 'link', text: t('case.show_all', { count: list.length }) });
    var filled = 0;
    function fill(limit) {
      for (; filled < list.length && filled < limit; filled++) {
        var x = list[filled];
        sub.appendChild(h('li', null, h('span', { class: 'tl-sub-time', text: fmtClock(x.ts) }), h('span', { text: (x.fullLog || x.desc).slice(0, 220) })));
      }
      more.hidden = filled >= list.length;
    }
    more.addEventListener('click', function () { fill(list.length); });
    var details = h('details', { class: 'raw' }, h('summary', { text: t('case.burst.open') }), sub, more);
    details.addEventListener('toggle', function () { if (details.open && !filled) fill(12); });
    li = h('li', { class: 'tl-row tl-burst', tabindex: '-1' },
      h('time', { class: 'tl-time', datetime: new Date(first.ts).toISOString(), title: fmtTime(first.ts, true), text: fmtClock(first.ts) }),
      h('div', { class: 'tl-body' },
        h('p', { class: 'tl-desc', text: t('case.burst', { count: list.length, kind: kind }) }),
        h('p', { class: 'tl-meta', text: t('case.burst.range', { first: fmtClock(first.ts), last: fmtClock(last.ts), rules: rules.join(', ') }) }),
        details),
      h('span', { class: 'lvl lvl-' + (maxLevel >= 10 ? 'hi' : maxLevel >= 7 ? 'mid' : 'lo'), text: String(maxLevel) }));
    li._ids = list.map(function (x) { return x.id; });
    return li;
  }

  function scoreMeter(c) {
    var fill = h('div', { class: 'meter-fill v-' + c.verdict });
    fill.style.setProperty('width', c.score + '%');
    var t1 = h('span', { class: 'meter-tick' }), t2 = h('span', { class: 'meter-tick' });
    t1.style.setProperty('left', engine.THRESHOLDS.review + '%');
    t2.style.setProperty('left', engine.THRESHOLDS.malicious + '%');
    return h('div', { class: 'meter', role: 'img', 'aria-label': t('case.score', { score: c.score }) }, fill, t1, t2);
  }

  function decisionSlip(c) {
    var d = S.decisions[c.id], rec = c.recommendation;
    var slip = h('section', { class: 'slip', id: 'decision', tabindex: '-1', 'aria-labelledby': 'dec-h' });
    slip.appendChild(h('h2', { id: 'dec-h', text: t('dec.title') }));

    if (d) {
      var pre = h('pre', { class: 'ticket', tabindex: '0', text: ticketText(c, d) });
      var next = M.cases.filter(function (o) { return !S.decisions[o.id]; })[0];
      append(slip, [
        h('p', { class: 'stamp stamp-' + d.type, text: t('out.' + d.type) }),
        h('p', { class: 'slip-by', text: t('out.by', { name: d.by, time: fmtTime(d.at, true) }) }),
        h('p', { class: 'help', text: t('out.ttd', { duration: fmtDur(d.ttdMs) }) }),
        d.override ? h('p', { class: 'notice notice-warn', text: t('ev.override') + ': ' + recText(rec) }) : null,
        h('h3', { text: t('out.ticket') }),
        pre,
        h('div', { class: 'slip-actions' },
          h('button', {
            type: 'button', class: 'btn', text: t('out.copy'),
            onclick: function () {
              var text = pre.textContent;
              function fallback() {
                var range = document.createRange();
                range.selectNodeContents(pre);
                var sel = window.getSelection();
                sel.removeAllRanges();
                sel.addRange(range);
                var ok = false;
                try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
                toast(t(ok ? 'out.copied' : 'out.copy_fail'), ok ? null : 'error');
              }
              if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(function () { toast(t('out.copied')); }, fallback);
              } else fallback();
            }
          }),
          next ? h('a', { class: 'btn btn-primary', href: '#/case/' + next.id, text: t('out.next') }) : null,
          h('a', { class: 'btn', href: '#/audit', text: t('out.audit_link') }),
          h('button', { type: 'button', class: 'btn btn-quiet', text: t('out.reopen'), onclick: function () { reopen(c); } }))
      ]);
      return slip;
    }

    var viewer = S.profile.role === 'viewer';
    function action(type, label, handler, primary) {
      return h('button', {
        type: 'button', class: 'btn' + (primary ? ' btn-primary' : ''), id: 'btn-' + type,
        'aria-disabled': viewer ? 'true' : null, onclick: handler, text: label
      });
    }
    append(slip, [
      h('p', { class: 'rec-label', text: t('dec.recommended') }),
      h('p', { class: 'rec-text', text: recText(rec) }),
      h('h3', { text: t('dec.steps') }),
      h('ol', { class: 'steplist' }, rec.steps.map(function (s) { return h('li', { text: stepText(s) }); })),
      h('div', { class: 'slip-actions' },
        rec.action ? action('approve', t('btn.approve'), function () { askApprove(c); }, rec.decision === 'approve') : null,
        action('dismiss', t('btn.dismiss'), function () { askDismiss(c); }, rec.decision === 'dismiss'),
        action('escalate', t('btn.escalate'), function () { askEscalate(c); }, rec.decision === 'escalate' || (rec.decision === 'approve' && !rec.action))),
      rec.action ? null : h('p', { class: 'help', text: t('dec.no_action') }),
      viewer ? h('p', { class: 'notice notice-warn', text: t('dec.viewer_note') }) : null,
      h('p', { class: 'slip-by', text: S.profile.name ? t('dec.reviewer', { name: S.profile.name, role: t('role.' + S.profile.role) }) : t('profile.none') }),
      h('p', { class: 'help', text: t('dec.nothing_auto') })
    ]);
    return slip;
  }

  function enrichment(c) {
    var box = h('section', { class: 'side-box', 'aria-labelledby': 'enr-h' }, h('h2', { id: 'enr-h', text: t('case.enrich') }));
    if (c.kind !== 'ip') {
      append(box, [
        h('p', { text: t('enrich.no_ip') }),
        h('dl', { class: 'kvs' }, h('div', { class: 'kv' }, h('dt', { text: t('enrich.host') }), h('dd', { class: 'mono', text: c.host + (c.hostIp ? ' (' + c.hostIp + ')' : '') })))
      ]);
      return box;
    }
    var e = c.enrichment, rep;
    if (!e.checked) rep = h('p', { class: 'muted', text: t('enrich.rep.na') });
    else if (!e.available) rep = h('p', { class: 'notice notice-warn', text: t('enrich.rep.unavailable') });
    else if (!e.listed.length) rep = h('p', { class: 'muted', text: t('enrich.rep.none') });
    else rep = h('ul', { class: 'replist' }, e.listed.map(function (l) {
      return h('li', null, h('span', { class: 'strong', text: localName(l.name) }), h('span', { class: 'muted', text: ' ' + t('enrich.updated', { date: l.updated }) }));
    }));
    append(box, [
      h('p', { class: 'ip mono', text: c.srcip }),
      h('dl', { class: 'kvs' },
        h('div', { class: 'kv' }, h('dt', { text: t('enrich.type') }), h('dd', { text: t('ip.' + c.ipClass) })),
        h('div', { class: 'kv' }, h('dt', { text: t('enrich.host') }), h('dd', { class: 'mono', text: c.host + (c.hostIp ? ' (' + c.hostIp + ')' : '') }))),
      h('h3', { text: t('enrich.rep') }),
      rep,
      e.checked ? h('p', { class: 'help', text: t('enrich.source_note') }) : null
    ]);
    return box;
  }

  function feedbackForm(c) {
    var saved = S.feedback[c.id] || {};
    var useful = saved.useful === undefined ? null : saved.useful;
    var box = h('section', { class: 'side-box', 'aria-labelledby': 'fb-h' }, h('h2', { id: 'fb-h', text: t('fb.title') }));
    var yes = h('button', { type: 'button', class: 'btn tog', 'aria-pressed': useful === true ? 'true' : 'false', text: t('fb.useful') });
    var no = h('button', { type: 'button', class: 'btn tog', 'aria-pressed': useful === false ? 'true' : 'false', text: t('fb.not_useful') });
    yes.addEventListener('click', function () { useful = true; yes.setAttribute('aria-pressed', 'true'); no.setAttribute('aria-pressed', 'false'); });
    no.addEventListener('click', function () { useful = false; no.setAttribute('aria-pressed', 'true'); yes.setAttribute('aria-pressed', 'false'); });
    var trust = h('fieldset', { class: 'trust' }, h('legend', { text: t('fb.trust') }));
    for (var n = 1; n <= 5; n++) {
      var input = h('input', { type: 'radio', name: 'fb-trust', id: 'fb-trust-' + n, value: n });
      input.checked = saved.trust === n;
      trust.appendChild(input);
      trust.appendChild(h('label', { for: 'fb-trust-' + n, text: String(n) }));
    }
    var comment = h('textarea', { id: 'fb-comment', rows: 3, maxlength: 500 });
    comment.value = saved.comment || '';
    var error = h('p', { class: 'form-error', role: 'alert' });
    error.hidden = true;
    append(box, [
      h('div', { class: 'slip-actions' }, yes, no),
      trust,
      h('p', { class: 'help', text: t('fb.trust.scale') }),
      field('fb-comment', t('fb.comment'), comment),
      error,
      h('button', {
        type: 'button', class: 'btn', text: t('fb.save'),
        onclick: function () {
          if (useful === null) { error.textContent = t('fb.need_rating'); error.hidden = false; return; }
          var picked = box.querySelector('input[name="fb-trust"]:checked');
          S.feedback[c.id] = { useful: useful, trust: picked ? Number(picked.value) : null, comment: comment.value.trim().slice(0, 500), at: Date.now() };
          error.hidden = true;
          persist();
          toast(t('fb.saved'));
        }
      })
    ]);
    return box;
  }

  function pageCase(r) {
    var c = M.byId[r.id];
    if (!c) {
      return h('div', { class: 'page' },
        h('h1', { tabindex: '-1', text: t('err.case_missing.title') }),
        emptyState('', t('err.case_missing.body'), h('a', { class: 'btn btn-primary', href: '#/queue', text: t('case.back') })));
    }
    if (!S.decisions[c.id] && !S.opened[c.id]) { S.opened[c.id] = Date.now(); persist(); }

    var factors = h('ul', { class: 'factors' }, c.factors.map(function (f) {
      return h('li', null,
        h('span', { class: 'pts ' + (f.points > 0 ? 'pts-up' : f.points < 0 ? 'pts-down' : 'pts-zero'), 'aria-label': t('case.points', { points: points(f.points) }), text: points(f.points) }),
        h('span', { class: 'factor-text', text: t('f.' + f.id, f.params) }),
        f.alertIds.length ? h('button', { type: 'button', class: 'link', text: t('case.evidence_n', { n: f.alertIds.length }), onclick: function () { showEvidence(f.alertIds); } }) : null);
    }));

    var related = c.related.map(function (id) { return M.byId[id]; }).filter(Boolean);

    return h('div', { class: 'page page-case' },
      h('p', { class: 'back' }, h('a', { href: '#/queue', text: t('case.back') })),
      h('header', { class: 'case-head spine-' + c.severity },
        h('div', { class: 'chips' }, sevBadge(c), verdictBadge(c), h('span', { class: 'chip', text: t('case.confidence', { level: t('conf.' + c.confidence) }) }), statusBadge(c)),
        h('h1', { tabindex: '-1', text: caseTitle(c) }),
        h('p', { class: 'case-meta', text: t('case.meta', { id: c.id, count: c.count, first: fmtTime(c.firstTs, true), last: fmtClock(c.lastTs) }) }),
        h('p', { class: 'jump' }, h('button', {
          type: 'button', class: 'link', text: t('dec.title'),
          onclick: function () {
            var slip = $('decision');
            slip.scrollIntoView({ block: 'start', behavior: reducedMotion() ? 'auto' : 'smooth' });
            slip.focus({ preventScroll: true });
          }
        }))),
      h('div', { class: 'case-grid' },
        h('div', { class: 'case-main' },
          h('section', { 'aria-labelledby': 'sum-h' },
            h('h2', { id: 'sum-h', text: t('case.summary') }),
            h('p', { class: 'summary', text: summarySentences(c).join(' ') })),
          h('section', { 'aria-labelledby': 'why-h' },
            h('h2', { id: 'why-h', text: t('case.why') }),
            h('p', { class: 'score-line', text: t('case.score', { score: c.score }) }),
            scoreMeter(c),
            h('p', { class: 'help', text: t('case.score.scale') + ' ' + t('case.why.help') }),
            factors,
            h('h3', { text: t('case.confidence', { level: t('conf.' + c.confidence) }) }),
            h('ul', { class: 'reasons' }, c.confidenceReasons.map(function (reason) { return h('li', { text: t('c.' + reason.id, reason.params) }); }))),
          h('section', { 'aria-labelledby': 'tl-h' },
            h('h2', { id: 'tl-h', text: t('case.timeline') }),
            h('p', { class: 'help', text: t('case.timeline.help') }),
            h('ol', { class: 'timeline' }, engine.timeline(c).map(timelineRow))),
          related.length ? h('section', { 'aria-labelledby': 'rel-h' },
            h('h2', { id: 'rel-h', text: t('case.related') }),
            h('ul', { class: 'related' }, related.map(function (o) {
              return h('li', null, verdictBadge(o), ' ', h('a', { href: '#/case/' + o.id, text: caseTitle(o) }), h('span', { class: 'muted', text: ' ' + o.id + ', ' + fmtTime(o.firstTs) }));
            }))) : null),
        h('aside', { class: 'case-side' },
          decisionSlip(c),
          enrichment(c),
          S.decisions[c.id] ? feedbackForm(c) : null)));
  }

  /* ---------- exports ---------- */

  function csvCell(v) {
    var s = v === null || v === undefined ? '' : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;   // keep spreadsheets from running a cell as a formula
    return '"' + s.replace(/"/g, '""') + '"';
  }
  function download(name, rows) {
    var csv = '﻿' + rows.map(function (r) { return r.map(csvCell).join(','); }).join('\r\n');
    var url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
    var a = h('a', { href: url, download: name });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
    toast(t('audit.exported'));
  }

  /* ---------- page: audit ---------- */

  function auditDetail(e) {
    if (e.event === 'loaded') return t('audit.detail.loaded', { alerts: e.alerts, cases: e.cases, source: sourceLabel(e.source) });
    var parts = [t('title.' + e.pattern) + (e.host ? ', ' + e.host : '') + (e.srcip ? ', ' + e.srcip : '')];
    if (e.event === 'approved' && e.action) parts.push(actionText(e.action));
    if (e.reason) parts.push(t('reason.' + e.reason));
    if (e.note) parts.push(e.note);
    if (e.override) parts.push(t('ev.override'));
    return parts.join('. ');
  }

  function pageAudit() {
    var entries = S.audit.slice().reverse();
    var page = h('div', { class: 'page' },
      h('h1', { tabindex: '-1', text: t('audit.h1') }),
      h('p', { class: 'lead', text: t('audit.lead') }));
    if (!entries.length) {
      page.appendChild(emptyState(t('audit.empty.title'), t('audit.empty.body'),
        h('a', { class: 'btn btn-primary', href: '#/queue', text: t('audit.empty.btn') })));
      return page;
    }
    page.appendChild(h('p', null, h('button', {
      type: 'button', class: 'btn', text: t('audit.export'),
      onclick: function () {
        var rows = [[t('col.time'), t('col.reviewer'), t('field.role'), t('col.event'), t('col.case'), t('col.detail'), t('col.hash')]];
        S.audit.forEach(function (e) {
          rows.push([new Date(e.at).toISOString(), e.by || t('audit.system'), e.role ? t('role.' + e.role) : '', t('ev.' + e.event), e.caseId || '', auditDetail(e), e.hash || '']);
        });
        download('aegisflow-audit-log.csv', rows);
      }
    })));
    page.appendChild(h('div', { class: 'table-wrap' }, h('table', { class: 'plain' },
      h('thead', null, h('tr', null, ['time', 'reviewer', 'event', 'case', 'detail', 'hash'].map(function (c) { return h('th', { scope: 'col', text: t('col.' + c) }); }))),
      h('tbody', null, entries.map(function (e) {
        return h('tr', null,
          h('td', { 'data-label': t('col.time'), class: 'nowrap', text: fmtTime(e.at, true) }),
          h('td', { 'data-label': t('col.reviewer'), text: e.by ? e.by + ', ' + t('role.' + e.role) : t('audit.system') }),
          h('td', { 'data-label': t('col.event') }, h('span', { class: 'st st-' + e.event, text: t('ev.' + e.event) })),
          h('td', { 'data-label': t('col.case'), class: 'mono' }, e.caseId ? (M.byId[e.caseId] ? h('a', { href: '#/case/' + e.caseId, text: e.caseId }) : e.caseId) : ''),
          h('td', { 'data-label': t('col.detail'), text: auditDetail(e) }),
          h('td', { 'data-label': t('col.hash'), class: 'mono', title: e.hash || null, text: e.hash ? e.hash.slice(0, 16) : '' }));
      })))));
    return page;
  }

  /* ---------- page: session report ---------- */

  function median(list) {
    if (!list.length) return null;
    var s = list.slice().sort(function (a, b) { return a - b; }), m = Math.floor(s.length / 2);
    return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
  }

  function pageReport() {
    var page = h('div', { class: 'page' },
      h('h1', { tabindex: '-1', text: t('report.h1') }),
      h('p', { class: 'lead', text: t('report.lead') }));
    var decided = M.cases.filter(function (c) { return S.decisions[c.id]; });
    var times = [], followed = 0, rated = 0, useful = 0, trusts = [];
    decided.forEach(function (c) {
      var d = S.decisions[c.id], f = S.feedback[c.id];
      times.push(d.ttdMs);
      if (!d.override) followed++;
      if (f) {
        rated++;
        if (f.useful) useful++;
        if (f.trust) trusts.push(f.trust);
      }
    });
    var med = median(times);
    function pct(a, b) { return b ? Math.round((a / b) * 100) + '%' : t('none'); }
    var metrics = [
      ['alerts', String(M.alerts.length)],
      ['cases', String(M.cases.length)],
      ['reduction', M.alerts.length ? Math.round((1 - M.cases.length / M.alerts.length) * 100) + '%' : t('none')],
      ['decided', decided.length + ' / ' + M.cases.length],
      ['median', med === null ? t('none') : fmtDur(med)],
      ['followed', pct(followed, decided.length)],
      ['useful', pct(useful, rated)],
      ['trust', trusts.length ? (trusts.reduce(function (a, b) { return a + b; }, 0) / trusts.length).toFixed(1) : t('none')]
    ];
    page.appendChild(h('dl', { class: 'metrics' }, metrics.map(function (m) {
      return h('div', null, h('dt', { text: t('m.' + m[0]) }), h('dd', { text: m[1] }));
    })));
    if (!decided.length) {
      page.appendChild(emptyState(t('report.empty.title'), t('report.empty.body'),
        h('a', { class: 'btn btn-primary', href: '#/queue', text: t('audit.empty.btn') })));
      return page;
    }
    function rating(c) {
      var f = S.feedback[c.id];
      return f ? t(f.useful ? 'fb.useful' : 'fb.not_useful') : '';
    }
    page.appendChild(h('p', null, h('button', {
      type: 'button', class: 'btn', text: t('report.export'),
      onclick: function () {
        var rows = [[t('col.case'), 'ID', t('col.host'), t('col.source'), t('col.alerts'), 'Score', t('col.verdict'), t('col.confidence'), t('col.recommended'), t('col.decision'), t('ev.override'), t('col.reviewer'), t('col.ttd') + ' (s)', t('col.rating'), t('col.trust'), t('fb.comment')]];
        decided.forEach(function (c) {
          var d = S.decisions[c.id], f = S.feedback[c.id] || {};
          rows.push([caseTitle(c), c.id, c.host, c.srcip, c.count, c.score, t('verdict.' + c.verdict), t('conf.' + c.confidence), t('rec.short.' + c.recommendation.decision), t('out.' + d.type), d.override ? 1 : 0, d.by, Math.round(d.ttdMs / 1000), rating(c), f.trust || '', f.comment || '']);
        });
        download('aegisflow-session-report.csv', rows);
      }
    })));
    page.appendChild(h('div', { class: 'table-wrap' }, h('table', { class: 'plain' },
      h('thead', null, h('tr', null, ['case', 'verdict', 'recommended', 'decision', 'reviewer', 'ttd', 'rating', 'trust'].map(function (c) { return h('th', { scope: 'col', text: t('col.' + c) }); }))),
      h('tbody', null, decided.map(function (c) {
        var d = S.decisions[c.id], f = S.feedback[c.id] || {};
        return h('tr', null,
          h('td', { 'data-label': t('col.case') }, h('a', { href: '#/case/' + c.id, text: caseTitle(c) }), h('span', { class: 'case-id', text: c.id })),
          h('td', { 'data-label': t('col.verdict') }, verdictBadge(c)),
          h('td', { 'data-label': t('col.recommended'), text: t('rec.short.' + c.recommendation.decision) }),
          h('td', { 'data-label': t('col.decision') }, statusBadge(c)),
          h('td', { 'data-label': t('col.reviewer'), text: d.by }),
          h('td', { 'data-label': t('col.ttd'), class: 'nowrap', text: fmtDur(d.ttdMs) }),
          h('td', { 'data-label': t('col.rating'), text: rating(c) }),
          h('td', { 'data-label': t('col.trust'), text: f.trust ? String(f.trust) : '' }));
      })))));
    page.appendChild(h('p', { class: 'help', text: t('report.method') }));
    return page;
  }

  /* ---------- page: settings ---------- */

  /* A form to change a password. With temporary=true it is the step that follows an administrator's reset. */
  function passwordForm(temporary, done) {
    var cur = passwordInput('pw-current', 'current-password');
    var next = passwordInput('pw-new', 'new-password');
    var again = passwordInput('pw-repeat', 'new-password');
    var error = h('p', { class: 'form-error', role: 'alert', tabindex: '-1' });
    error.hidden = true;
    function fail(message) { error.textContent = message; error.hidden = false; error.focus(); }
    return h('form', {
      novalidate: true,
      onsubmit: function (e) {
        e.preventDefault();
        if (next.value !== again.value) { fail(t('pw.mismatch')); return; }
        var r = accounts.changePassword(A, ME, cur.value, next.value);
        if (r.error) { fail(t('acc.err.' + r.error)); return; }
        saveAccounts();
        toast(t('pw.changed'));
        done();
      }
    },
      field('pw-current', t(temporary ? 'pw.temp' : 'pw.current'), cur),
      field('pw-new', t('pw.new'), next, t('pw.rule')),
      field('pw-repeat', t('pw.repeat'), again),
      error,
      h('button', { type: 'submit', class: 'btn btn-primary', text: t('pw.btn') }));
  }

  function pageSettings() {
    var outage = h('input', { type: 'checkbox', id: 'set-outage' });
    outage.checked = S.settings.intelOutage;
    outage.addEventListener('change', function () {
      S.settings.intelOutage = outage.checked;
      rebuild();
      persist();
      toast(t(outage.checked ? 'set.outage.on' : 'set.outage.off'));
    });
    var decisions = Object.keys(S.decisions).length;
    return h('div', { class: 'page page-settings' },
      h('h1', { tabindex: '-1', text: t('set.h1') }),
      h('section', { class: 'panel' },
        h('h2', { text: t('set.profile') }),
        ME.weak ? h('p', { class: 'notice notice-warn', text: t('acc.weak.me') }) : null,
        h('dl', { class: 'kvs' },
          h('div', { class: 'kv' }, h('dt', { text: t('adm.f.name') }), h('dd', { text: ME.name })),
          h('div', { class: 'kv' }, h('dt', { text: t('adm.f.username') }), h('dd', { class: 'mono', text: ME.username })),
          h('div', { class: 'kv' }, h('dt', { text: t('field.role') }), h('dd', { text: t('role.' + ME.role) })),
          h('div', { class: 'kv' }, h('dt', { text: t('set.account.last') }), h('dd', { text: ME.lastLogin ? fmtTime(ME.lastLogin) : t('adm.never') }))),
        h('h3', { text: t('pw.btn') }),
        passwordForm(false, function () { render(); })),
      h('section', { class: 'panel' },
        h('h2', { text: t('set.demo') }),
        h('label', { class: 'check', for: 'set-outage' }, outage, h('span', { text: t('set.outage') })),
        h('p', { class: 'help', text: t('set.outage.help') })),
      h('section', { class: 'panel' },
        h('h2', { text: t('set.data') }),
        h('p', { text: M.alerts.length ? t('set.data.info', { alerts: M.alerts.length, source: sourceLabel(S.source), decisions: decisions, audit: S.audit.length }) : t('set.data.none') }),
        h('p', { class: 'help', text: t('connect.privacy.body') }),
        h('button', {
          type: 'button', class: 'btn btn-danger-quiet', text: t('set.clear'),
          onclick: function () {
            openDialog({
              title: t('set.clear.title'), confirm: t('set.clear.do'), danger: true,
              body: h('p', { text: t('set.clear.body') }),
              onConfirm: function () {
                S = store.reset();
                V.importError = null; V.importWarn = null;
                rebuild();
                toast(t('set.cleared'));
                go('#/connect');
                return '';
              }
            });
          }
        })),
      h('section', { class: 'panel' },
        h('h2', { text: t('set.about') }),
        h('p', { text: t('set.about.body', { n: engine.PATTERNS.length - 1 }) }),
        h('p', { class: 'help', text: t('case.score.scale') }),
        h('h3', { text: t('set.limits') }),
        h('ul', null, [1, 2, 3, 4, 5].map(function (n) { return h('li', { text: t('set.limit.' + n) }); }))));
  }

  /* ---------- page: sign in ---------- */

  function pageLogin() {
    var user = h('input', { type: 'text', id: 'login-user', maxlength: 32, autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', required: true });
    var pass = passwordInput('login-pass', 'current-password');
    var error = h('p', { class: 'form-error', id: 'login-error', role: 'alert', tabindex: '-1' });
    error.hidden = true;
    function fail(message) { error.textContent = message; error.hidden = false; pass.value = ''; error.focus(); }
    var form = h('form', {
      class: 'login-form', novalidate: true,
      onsubmit: function (e) {
        e.preventDefault();
        if (!user.value.trim() || !pass.value) { fail(t('login.err.empty')); return; }
        var r = accounts.login(A, user.value, pass.value);
        saveAccounts();
        if (r.error) { fail(t('login.err.' + r.error, { s: r.seconds })); return; }
        ME = r.user;
        accounts.startSession(ME);
        syncProfile();
        persist();
        toast(t('login.welcome', { name: ME.name }));
        go(ME.mustChange ? '#/login' : (M.cases.length ? '#/queue' : '#/connect'));
      }
    },
      field('login-user', t('login.user'), user),
      field('login-pass', t('login.pass'), pass),
      error,
      h('button', { type: 'submit', class: 'btn btn-primary', id: 'login-btn', text: t('login.btn') }));
    return h('div', { class: 'page page-login' },
      h('div', { class: 'login' },
        h('h1', { tabindex: '-1', text: t('login.h1') }),
        h('p', { class: 'lead', text: t('login.lead') }),
        h('section', { class: 'panel' }, form),
        h('p', { class: 'notice', text: t('login.demo') }),
        h('p', { class: 'help', text: t('login.note') })));
  }

  /* After an administrator sets a temporary password, the user chooses their own before anything else. */
  function pageMustChange() {
    return h('div', { class: 'page page-login' },
      h('div', { class: 'login' },
        h('h1', { tabindex: '-1', text: t('must.h1') }),
        h('p', { class: 'lead', text: t('must.lead') }),
        h('section', { class: 'panel' }, passwordForm(true, function () { go(M.cases.length ? '#/queue' : '#/connect'); })),
        h('p', null, h('button', { type: 'button', class: 'btn btn-quiet', onclick: signOut, text: t('signout') }))));
  }

  /* ---------- page: users and access (administrators) ---------- */

  function statusOfUser(u) {
    if (u.disabled) return 'disabled';
    if (accounts.isLocked(u)) return 'locked';
    if (u.mustChange) return 'mustchange';
    return 'active';
  }

  function adminResult(r, okKey, u, extra) {
    if (r.error) { toast(t('acc.err.' + r.error), 'error'); render(); return false; }
    saveAccounts();
    var p = { user: u.username };
    for (var k in extra || {}) p[k] = extra[k];
    toast(t(okKey, p));
    return true;
  }

  function askReset(u) {
    var pw = passwordInput('dlg-pw', 'new-password');
    openDialog({
      title: t('adm.reset.title', { user: u.username }),
      confirm: t('adm.reset.confirm'),
      body: [h('p', { text: t('adm.reset.body') }), field('dlg-pw', t('adm.f.password'), pw, t('pw.rule'))],
      onConfirm: function () {
        var r = accounts.resetPassword(A, ME, u.id, pw.value);
        if (r.error) return t('acc.err.' + r.error);
        adminResult(r, 'adm.reset.done', u);
        render();
        return '';
      }
    });
  }

  function askDelete(u) {
    openDialog({
      title: t('adm.delete.title', { user: u.username }),
      confirm: t('adm.delete.confirm'), danger: true,
      body: h('p', { text: t('adm.delete.body') }),
      onConfirm: function () {
        var r = accounts.deleteUser(A, ME, u.id);
        if (r.error) return t('acc.err.' + r.error);
        adminResult(r, 'adm.deleted', u);
        render();
        return '';
      }
    });
  }

  function addUserForm() {
    var uname = h('input', { type: 'text', id: 'adm-username', maxlength: 32, autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false' });
    var name = h('input', { type: 'text', id: 'adm-name', maxlength: 60, autocomplete: 'off' });
    var role = roleOptions('adm-role', 'analyst');
    var pw = passwordInput('adm-password', 'new-password');
    var error = h('p', { class: 'form-error', role: 'alert', tabindex: '-1' });
    error.hidden = true;
    return h('form', {
      novalidate: true,
      onsubmit: function (e) {
        e.preventDefault();
        var r = accounts.createUser(A, ME, { username: uname.value, name: name.value, role: role.value, password: pw.value });
        if (r.error) { error.textContent = t('acc.err.' + r.error); error.hidden = false; error.focus(); return; }
        saveAccounts();
        toast(t('adm.created', { user: r.user.username }));
        render();
      }
    },
      h('p', { class: 'help', text: t('adm.add.help') }),
      h('div', { class: 'grid-form' },
        field('adm-username', t('adm.f.username'), uname),
        field('adm-name', t('adm.f.name'), name),
        field('adm-role', t('adm.f.role'), role),
        field('adm-password', t('adm.f.password'), pw, t('pw.rule'))),
      error,
      h('button', { type: 'submit', class: 'btn btn-primary', text: t('adm.add.btn') }));
  }

  function userRow(u) {
    var self = u.id === ME.id;
    var st = statusOfUser(u);
    var role = roleOptions('role-' + u.id, u.role);
    role.setAttribute('aria-label', t('adm.col.role') + ': ' + u.username);
    role.addEventListener('change', function () {
      var r = accounts.setRole(A, ME, u.id, role.value);
      if (!adminResult(r, 'adm.role.done', u, { role: t('role.' + role.value) })) return;
      if (self) { syncProfile(); persist(); }
      if (self && ME.role !== 'admin') go('#/settings'); else render();
    });
    var parts = u.hash.split('$');
    var actions = h('div', { class: 'actions' },
      h('button', { type: 'button', class: 'btn btn-small', onclick: function () { askReset(u); }, text: t('adm.btn.reset') }),
      st === 'locked' ? h('button', {
        type: 'button', class: 'btn btn-small',
        onclick: function () { if (adminResult(accounts.unlock(A, ME, u.id), 'adm.unlocked.done', u)) render(); },
        text: t('adm.btn.unlock')
      }) : null,
      self ? null : h('button', {
        type: 'button', class: 'btn btn-small',
        onclick: function () {
          var r = accounts.setDisabled(A, ME, u.id, !u.disabled);
          if (adminResult(r, u.disabled ? 'adm.disabled.done' : 'adm.enabled.done', u)) render();
        },
        text: t(u.disabled ? 'adm.btn.enable' : 'adm.btn.disable')
      }),
      self ? null : h('button', { type: 'button', class: 'btn btn-small btn-danger-quiet', onclick: function () { askDelete(u); }, text: t('adm.btn.delete') }));
    return h('tr', null,
      h('td', { 'data-label': t('adm.col.user') },
        h('span', { class: 'user-name', text: u.name + (self ? ' ' + t('adm.you') : '') }),
        h('span', { class: 'user-login', text: u.username })),
      h('td', { 'data-label': t('adm.col.role') }, role),
      h('td', { 'data-label': t('adm.col.status') }, h('span', { class: 'st st-' + st, text: t('adm.status.' + st) }),
        u.weak ? h('span', { class: 'weak', text: t('adm.weak.one') }) : null),
      h('td', { 'data-label': t('adm.col.last'), class: 'nowrap', text: u.lastLogin ? fmtTime(u.lastLogin) : t('adm.never') }),
      h('td', { 'data-label': t('adm.col.hash'), class: 'hash', title: u.hash, text: parts.length === 4 ? parts[3].slice(0, 12) + '…' : '' }),
      h('td', { 'data-label': t('adm.col.actions') }, self ? h('p', { class: 'help', text: t('adm.self') }) : null, actions));
  }

  function pageAdmin() {
    if (ME.role !== 'admin') {
      return h('div', { class: 'page' },
        h('h1', { tabindex: '-1', text: t('adm.h1') }),
        emptyState('', t('adm.forbidden'), h('a', { class: 'btn btn-primary', href: '#/queue', text: t('nav.queue') })));
    }
    var users = A.users;
    var weak = users.filter(function (u) { return u.weak; }).length;
    var page = h('div', { class: 'page page-admin' },
      h('h1', { tabindex: '-1', text: t('adm.h1') }),
      h('p', { class: 'lead', text: t('adm.lead') }));
    if (weak) page.appendChild(h('p', { class: 'notice notice-warn', text: t('adm.weak', { n: weak }) }));
    page.appendChild(h('dl', { class: 'metrics' }, [
      ['users', users.length],
      ['admins', users.filter(function (u) { return u.role === 'admin' && !u.disabled; }).length],
      ['disabled', users.filter(function (u) { return u.disabled; }).length],
      ['locked', users.filter(function (u) { return accounts.isLocked(u); }).length]
    ].map(function (m) { return h('div', null, h('dt', { text: t('adm.m.' + m[0]) }), h('dd', { text: String(m[1]) })); })));
    page.appendChild(h('h2', { text: t('adm.list') }));
    page.appendChild(h('div', { class: 'table-wrap' }, h('table', { class: 'plain users' },
      h('thead', null, h('tr', null, ['user', 'role', 'status', 'last', 'hash', 'actions'].map(function (c) { return h('th', { scope: 'col', text: t('adm.col.' + c) }); }))),
      h('tbody', null, users.map(userRow)))));
    page.appendChild(h('p', { class: 'help', text: t('adm.hash.help') }));
    page.appendChild(h('section', { class: 'panel' }, h('h2', { text: t('adm.add') }), addUserForm()));

    var events = A.events.slice(-30).reverse();
    page.appendChild(h('h2', { text: t('adm.events') }));
    page.appendChild(events.length ? h('div', { class: 'table-wrap' }, h('table', { class: 'plain' },
      h('thead', null, h('tr', null, ['time', 'by', 'event', 'account'].map(function (c) { return h('th', { scope: 'col', text: t('adm.col.' + c) }); }))),
      h('tbody', null, events.map(function (e) {
        return h('tr', null,
          h('td', { 'data-label': t('adm.col.time'), class: 'nowrap', text: fmtTime(e.at, true) }),
          h('td', { 'data-label': t('adm.col.by'), class: 'mono', text: e.by || t('adm.system') }),
          h('td', { 'data-label': t('adm.col.event'), text: t('acc.ev.' + e.event) }),
          h('td', { 'data-label': t('adm.col.account'), class: 'mono', text: e.target || '' }));
      })))) : h('p', { class: 'help', text: t('adm.events.empty') }));

    page.appendChild(h('section', { class: 'panel' },
      h('h2', { text: t('adm.restore') }),
      h('p', { class: 'help', text: t('adm.restore.body') }),
      h('button', {
        type: 'button', class: 'btn btn-danger-quiet', text: t('adm.restore.btn'),
        onclick: function () {
          openDialog({
            title: t('adm.restore.title'), confirm: t('adm.restore.btn'), danger: true,
            body: h('p', { text: t('adm.restore.body') }),
            onConfirm: function () {
              A = accounts.reset();
              accounts.state.events.push({ at: Date.now(), by: '', event: 'restored', target: '' });
              saveAccounts();
              accounts.endSession();
              ME = null;
              toast(t('adm.restored'));
              go('#/login');
              return '';
            }
          });
        }
      })));
    return page;
  }

  /* ---------- router ---------- */

  function route() {
    var hash = location.hash || '', m;
    if (hash === '' || hash === '#' || hash === '#/') return { name: M.cases.length ? 'queue' : 'connect' };
    if ((m = /^#\/(connect|queue|audit|report|settings|admin|login)$/.exec(hash))) return { name: m[1] };
    if ((m = /^#\/case\/([A-Za-z0-9-]{1,40})$/.exec(hash))) return { name: 'case', id: m[1] };
    if (hash === '#main') return { name: M.cases.length ? 'queue' : 'connect' };
    return { name: 'notfound' };
  }

  var PAGES = {
    connect: pageConnect, queue: pageQueue, 'case': pageCase, audit: pageAudit, report: pageReport, settings: pageSettings,
    admin: pageAdmin, login: function () { return h('div'); },
    notfound: function () {
      return h('div', { class: 'page' },
        h('h1', { tabindex: '-1', text: t('err.page.title') }),
        emptyState('', t('err.page.body'), h('a', { class: 'btn btn-primary', href: '#/', text: t('nav.queue') })));
    }
  };

  /* Signed out: only the sign-in page. A temporary password: only the page that replaces it. */
  function pageFor(r) {
    if (!ME) return pageLogin();
    if (ME.mustChange) return pageMustChange();
    if (r.name === 'login') { setTimeout(function () { go(M.cases.length ? '#/queue' : '#/connect'); }, 0); return h('div'); }
    return PAGES[r.name](r);
  }

  function render(opts) {
    var r = route();
    document.documentElement.lang = I.get();
    if (ME && !accounts.find(A, ME.id)) { ME = null; accounts.endSession(); }
    renderHeader(r);
    var main = $('main');
    main.textContent = '';
    main.appendChild(pageFor(r));
    var h1 = main.querySelector('h1');
    document.title = (h1 ? h1.textContent + ' | ' : '') + 'AegisFlow';
    if (opts && opts.focus) {
      window.scrollTo(0, 0);
      if (h1) h1.focus({ preventScroll: true });
    }
  }

  function boot() {
    S = store.load();
    A = accounts.load();
    ME = accounts.session();
    syncProfile();
    if (!S.lang) S.lang = /^kk/i.test(navigator.language || '') ? 'kk' : 'en';
    I.set(S.lang);
    rebuild();
    window.addEventListener('hashchange', function () { render({ focus: true }); });
    render();
    if (store.wasCorrupt || accounts.wasCorrupt) toast(t('err.storage_corrupt'), 'error');
    if (store.persistFailed) { V.storageWarned = true; toast(t('err.storage'), 'error'); }
  }

  boot();
})();
