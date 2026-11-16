/*
 * AegisFlow state, kept in this browser's localStorage and nowhere else.
 * Every read and write is guarded: a full, blocked or damaged store must
 * never stop the app from working in the current tab.
 */
(function (root) {
  'use strict';
  var AF = root.AF = root.AF || {};
  var KEY = 'aegisflow.v1';

  function defaults() {
    return {
      v: 1,
      lang: null,
      profile: { name: '', role: 'analyst' },
      source: null,        // { type: demo|file|paste, name, at, skipped, total }
      records: null,       // imported raw alerts (the lab dataset is rebuilt, not stored)
      decisions: {},       // caseId -> decision
      audit: [],           // append-only list of events
      feedback: {},        // caseId -> { useful, trust, comment, at }
      opened: {},          // caseId -> first time the case was opened
      settings: { intelOutage: false }
    };
  }

  function isObj(v) { return v && typeof v === 'object' && !Array.isArray(v); }

  /* Accept only the shape this version writes; anything else is reset. */
  function sanitise(p) {
    var d = defaults();
    if (!isObj(p) || p.v !== 1) return null;
    if (p.lang === 'en' || p.lang === 'kk') d.lang = p.lang;
    if (isObj(p.profile)) {
      if (typeof p.profile.name === 'string') d.profile.name = p.profile.name.slice(0, 60);
      if (p.profile.role === 'viewer' || p.profile.role === 'admin') d.profile.role = p.profile.role;
    }
    if (isObj(p.source) && (p.source.type === 'demo' || p.source.type === 'file' || p.source.type === 'paste')) d.source = p.source;
    if (Array.isArray(p.records)) d.records = p.records;
    if (isObj(p.decisions)) d.decisions = p.decisions;
    if (Array.isArray(p.audit)) d.audit = p.audit;
    if (isObj(p.feedback)) d.feedback = p.feedback;
    if (isObj(p.opened)) d.opened = p.opened;
    if (isObj(p.settings)) d.settings.intelOutage = p.settings.intelOutage === true;
    return d;
  }

  var api = {
    state: defaults(),
    persistFailed: false,   // true when the last save did not reach storage
    wasCorrupt: false,      // true when stored data was unreadable and reset

    load: function () {
      var raw = null;
      try { raw = root.localStorage.getItem(KEY); }
      catch (e) { api.persistFailed = true; }
      if (raw) {
        var parsed = null;
        try { parsed = sanitise(JSON.parse(raw)); } catch (e2) { parsed = null; }
        if (parsed) api.state = parsed;
        else { api.state = defaults(); api.wasCorrupt = true; }
      }
      return api.state;
    },

    save: function () {
      try {
        root.localStorage.setItem(KEY, JSON.stringify(api.state));
        api.persistFailed = false;
      } catch (e) {
        api.persistFailed = true;
        // Imported alerts are the bulky part. Keep decisions and the audit log if they still fit.
        try {
          var slim = {};
          for (var k in api.state) slim[k] = k === 'records' ? null : api.state[k];
          if (slim.source && slim.source.type !== 'demo') slim.source = null;
          root.localStorage.setItem(KEY, JSON.stringify(slim));
        } catch (e2) { /* nothing can be stored; the tab keeps working from memory */ }
      }
      return !api.persistFailed;
    },

    reset: function () {
      var lang = api.state.lang;
      api.state = defaults();
      api.state.lang = lang;
      try { root.localStorage.removeItem(KEY); } catch (e) { /* ignore */ }
      api.save();
      return api.state;
    }
  };

  AF.store = api;
})(typeof window !== 'undefined' ? window : globalThis);
