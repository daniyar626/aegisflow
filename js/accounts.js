/*
 * AegisFlow accounts: sign-in, roles and account management.
 *
 * This MVP has no server, so accounts live in this browser's localStorage and
 * passwords are checked here. Passwords are never stored: each one is kept as
 * a salted, iterated SHA-256 hash. That protects the stored list from casual
 * reading, but it is not server-side security: a production version must check
 * passwords on a server. The interface says so.
 */
(function (root) {
  'use strict';
  var AF = root.AF = root.AF || {};
  var engine = AF.engine;
  if (!engine && typeof require === 'function') engine = require('./engine.js');

  var KEY = 'aegisflow.accounts.v1';
  var SESSION_KEY = 'aegisflow.session.v1';
  var ITERATIONS = 4000;
  var MAX_FAILS = 5;
  var LOCK_MS = 60 * 1000;
  var ROLES = ['admin', 'analyst', 'viewer'];
  var WEAK = ['password', 'password1', 'admin', 'admin123', '12345678', '123456789', 'qwerty123', 'aegisflow'];

  // The demonstration administrator (username admin). Only the hash is kept here.
  var SEED_SALT = '6f1d2c8b9a0e4f73b5c6d7e8f9a0b1c2';
  var SEED_HASH = 'd32309ae9ea5cfffc2d7e08906b2114994cfa88d78328423c8b725444ec5677a';

  /* ---------- hashing ---------- */

  function randomHex(bytes) {
    var out = '';
    var c = root.crypto;
    if (c && c.getRandomValues) {
      var a = new Uint8Array(bytes);
      c.getRandomValues(a);
      for (var i = 0; i < a.length; i++) out += (a[i] < 16 ? '0' : '') + a[i].toString(16);
      return out;
    }
    if (typeof require === 'function') return require('crypto').randomBytes(bytes).toString('hex');
    throw new Error('no random source');
  }

  function digest(password, salt, iterations) {
    var h = engine.sha256(salt + ':' + password);
    for (var i = 1; i < iterations; i++) h = engine.sha256(h + salt);
    return h;
  }

  /* Stored form: sha256i$<iterations>$<salt>$<hash> */
  function hashPassword(password, salt) {
    salt = salt || randomHex(16);
    return 'sha256i$' + ITERATIONS + '$' + salt + '$' + digest(password, salt, ITERATIONS);
  }

  function verify(password, stored) {
    var p = String(stored || '').split('$');
    if (p.length !== 4 || p[0] !== 'sha256i') return false;
    var n = parseInt(p[1], 10);
    if (!(n > 0 && n <= 100000)) return false;
    var expected = digest(String(password), p[2], n);
    // compare every character, so the time does not depend on where they differ
    var diff = expected.length ^ p[3].length;
    for (var i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ (p[3].charCodeAt(i) || 0);
    return diff === 0;
  }

  function isWeak(password, username) {
    var pw = String(password || '');
    var low = pw.toLowerCase();
    return pw.length < 8 || WEAK.indexOf(low) >= 0 || (username && low === String(username).toLowerCase());
  }

  /* ---------- state ---------- */

  function seedAdmin(now) {
    return {
      id: 'u-admin', username: 'admin', name: 'Demo Admin', role: 'admin',
      hash: 'sha256i$' + ITERATIONS + '$' + SEED_SALT + '$' + SEED_HASH,
      weak: true, mustChange: false, disabled: false,
      created: now, createdBy: 'system', lastLogin: null, failed: 0, lockedUntil: 0
    };
  }

  function defaults(now) {
    now = now || Date.now();
    return { v: 1, users: [seedAdmin(now)], events: [] };
  }

  function isObj(v) { return v && typeof v === 'object' && !Array.isArray(v); }

  /* Accept only well-formed accounts; a damaged list falls back to the demo administrator. */
  function sanitise(p) {
    if (!isObj(p) || p.v !== 1 || !Array.isArray(p.users)) return null;
    var seen = {};
    var users = p.users.filter(function (u) {
      if (!isObj(u) || typeof u.id !== 'string' || typeof u.username !== 'string' || typeof u.hash !== 'string') return false;
      if (ROLES.indexOf(u.role) < 0 || !/^[a-z0-9._-]{3,32}$/.test(u.username) || seen[u.username]) return false;
      seen[u.username] = true;
      return true;
    }).map(function (u) {
      return {
        id: u.id.slice(0, 40), username: u.username, name: String(u.name || u.username).slice(0, 60), role: u.role,
        hash: u.hash.slice(0, 200), weak: u.weak === true, mustChange: u.mustChange === true, disabled: u.disabled === true,
        created: Number(u.created) || 0, createdBy: String(u.createdBy || '').slice(0, 40),
        lastLogin: Number(u.lastLogin) || null, failed: Math.max(0, Number(u.failed) || 0), lockedUntil: Number(u.lockedUntil) || 0
      };
    });
    if (!activeAdmins({ users: users }).length) return null;
    var events = Array.isArray(p.events) ? p.events.filter(isObj).slice(-200) : [];
    return { v: 1, users: users, events: events };
  }

  function activeAdmins(state) {
    return state.users.filter(function (u) { return u.role === 'admin' && !u.disabled; });
  }

  function find(state, id) {
    for (var i = 0; i < state.users.length; i++) if (state.users[i].id === id) return state.users[i];
    return null;
  }

  function byName(state, username) {
    var key = String(username || '').trim().toLowerCase();
    for (var i = 0; i < state.users.length; i++) if (state.users[i].username === key) return state.users[i];
    return null;
  }

  function logEvent(state, by, event, target, now) {
    state.events.push({ at: now || Date.now(), by: by || '', event: event, target: target || '' });
    if (state.events.length > 200) state.events.splice(0, state.events.length - 200);
  }

  function isLocked(u, now) { return u.lockedUntil > (now || Date.now()); }

  /* ---------- sign-in ---------- */

  /* One message for an unknown name and a wrong password, so the form does not reveal which names exist. */
  function login(state, username, password, now) {
    now = now || Date.now();
    var u = byName(state, username);
    if (!u) { logEvent(state, '', 'login_failed', String(username || '').slice(0, 32), now); return { error: 'bad' }; }
    if (u.disabled) { logEvent(state, u.username, 'login_disabled', u.username, now); return { error: 'disabled' }; }
    if (isLocked(u, now)) return { error: 'locked', seconds: Math.ceil((u.lockedUntil - now) / 1000) };
    if (!verify(password, u.hash)) {
      u.failed += 1;
      logEvent(state, '', 'login_failed', u.username, now);
      if (u.failed >= MAX_FAILS) {
        u.failed = 0;
        u.lockedUntil = now + LOCK_MS;
        logEvent(state, '', 'locked', u.username, now);
        return { error: 'locked', seconds: Math.ceil(LOCK_MS / 1000) };
      }
      return { error: 'bad', left: MAX_FAILS - u.failed };
    }
    u.failed = 0;
    u.lockedUntil = 0;
    u.lastLogin = now;
    u.weak = isWeak(password, u.username);
    logEvent(state, u.username, 'login', u.username, now);
    return { ok: true, user: u };
  }

  /* ---------- account management (administrators only) ---------- */

  function requireAdmin(actor) { return actor && actor.role === 'admin' && !actor.disabled; }

  function validateNew(state, input) {
    var username = String(input.username || '').trim().toLowerCase();
    if (!/^[a-z0-9._-]{3,32}$/.test(username)) return 'username_format';
    if (byName(state, username)) return 'username_taken';
    if (String(input.name || '').trim().length < 2) return 'name_short';
    if (ROLES.indexOf(input.role) < 0) return 'role';
    if (isWeak(input.password, username)) return 'password_weak';
    return '';
  }

  function createUser(state, actor, input, now) {
    now = now || Date.now();
    if (!requireAdmin(actor)) return { error: 'forbidden' };
    var err = validateNew(state, input);
    if (err) return { error: err };
    var u = {
      id: 'u-' + randomHex(6), username: String(input.username).trim().toLowerCase(), name: String(input.name).trim().slice(0, 60),
      role: input.role, hash: hashPassword(String(input.password)), weak: false, mustChange: true, disabled: false,
      created: now, createdBy: actor.username, lastLogin: null, failed: 0, lockedUntil: 0
    };
    state.users.push(u);
    logEvent(state, actor.username, 'created', u.username, now);
    return { ok: true, user: u };
  }

  /* The last active administrator can never be removed, disabled or demoted. */
  function wouldRemoveLastAdmin(state, u) {
    return u.role === 'admin' && !u.disabled && activeAdmins(state).length <= 1;
  }

  function setRole(state, actor, id, role, now) {
    if (!requireAdmin(actor)) return { error: 'forbidden' };
    var u = find(state, id);
    if (!u) return { error: 'missing' };
    if (ROLES.indexOf(role) < 0) return { error: 'role' };
    if (u.role === role) return { ok: true, user: u };
    if (role !== 'admin' && wouldRemoveLastAdmin(state, u)) return { error: 'last_admin' };
    u.role = role;
    logEvent(state, actor.username, 'role_' + role, u.username, now);
    return { ok: true, user: u };
  }

  function setDisabled(state, actor, id, disabled, now) {
    if (!requireAdmin(actor)) return { error: 'forbidden' };
    var u = find(state, id);
    if (!u) return { error: 'missing' };
    if (disabled && u.id === actor.id) return { error: 'self' };
    if (disabled && wouldRemoveLastAdmin(state, u)) return { error: 'last_admin' };
    u.disabled = !!disabled;
    logEvent(state, actor.username, disabled ? 'disabled' : 'enabled', u.username, now);
    return { ok: true, user: u };
  }

  function unlock(state, actor, id, now) {
    if (!requireAdmin(actor)) return { error: 'forbidden' };
    var u = find(state, id);
    if (!u) return { error: 'missing' };
    u.failed = 0;
    u.lockedUntil = 0;
    logEvent(state, actor.username, 'unlocked', u.username, now);
    return { ok: true, user: u };
  }

  function resetPassword(state, actor, id, password, now) {
    if (!requireAdmin(actor)) return { error: 'forbidden' };
    var u = find(state, id);
    if (!u) return { error: 'missing' };
    if (isWeak(password, u.username)) return { error: 'password_weak' };
    u.hash = hashPassword(String(password));
    u.weak = false;
    u.mustChange = u.id !== actor.id;
    u.failed = 0;
    u.lockedUntil = 0;
    logEvent(state, actor.username, 'password_reset', u.username, now);
    return { ok: true, user: u };
  }

  function deleteUser(state, actor, id, now) {
    if (!requireAdmin(actor)) return { error: 'forbidden' };
    var u = find(state, id);
    if (!u) return { error: 'missing' };
    if (u.id === actor.id) return { error: 'self' };
    if (wouldRemoveLastAdmin(state, u)) return { error: 'last_admin' };
    state.users.splice(state.users.indexOf(u), 1);
    logEvent(state, actor.username, 'deleted', u.username, now);
    return { ok: true };
  }

  /* Any signed-in user may change their own password. */
  function changePassword(state, user, current, next, now) {
    var u = user && find(state, user.id);
    if (!u) return { error: 'missing' };
    if (!verify(current, u.hash)) return { error: 'current_wrong' };
    if (isWeak(next, u.username)) return { error: 'password_weak' };
    if (verify(next, u.hash)) return { error: 'password_same' };
    u.hash = hashPassword(String(next));
    u.weak = false;
    u.mustChange = false;
    logEvent(state, u.username, 'password_changed', u.username, now);
    return { ok: true, user: u };
  }

  /* ---------- storage ---------- */

  var api = {
    ROLES: ROLES, MAX_FAILS: MAX_FAILS, LOCK_MS: LOCK_MS,
    hashPassword: hashPassword, verify: verify, isWeak: isWeak, defaults: defaults, sanitise: sanitise,
    activeAdmins: activeAdmins, find: find, isLocked: isLocked,
    login: login, createUser: createUser, setRole: setRole, setDisabled: setDisabled, unlock: unlock,
    resetPassword: resetPassword, deleteUser: deleteUser, changePassword: changePassword,
    _digest: digest, _seedSalt: SEED_SALT,

    state: null,
    persistFailed: false,
    wasCorrupt: false,

    load: function () {
      var raw = null;
      try { raw = root.localStorage.getItem(KEY); } catch (e) { api.persistFailed = true; }
      var parsed = null;
      if (raw) {
        try { parsed = sanitise(JSON.parse(raw)); } catch (e2) { parsed = null; }
        if (!parsed) api.wasCorrupt = true;
      }
      api.state = parsed || defaults();
      return api.state;
    },
    save: function () {
      try { root.localStorage.setItem(KEY, JSON.stringify(api.state)); api.persistFailed = false; }
      catch (e) { api.persistFailed = true; }
      return !api.persistFailed;
    },
    reset: function () {
      api.state = defaults();
      api.save();
      return api.state;
    },

    /* The session lasts until the tab is closed or the user signs out. */
    session: function () {
      var raw = null;
      try { raw = root.sessionStorage.getItem(SESSION_KEY); } catch (e) { raw = null; }
      if (!raw) return null;
      try {
        var s = JSON.parse(raw);
        var u = s && find(api.state, s.id);
        return u && !u.disabled ? u : null;
      } catch (e2) { return null; }
    },
    startSession: function (u) {
      try { root.sessionStorage.setItem(SESSION_KEY, JSON.stringify({ id: u.id, at: Date.now() })); } catch (e) { /* memory only */ }
    },
    endSession: function () {
      try { root.sessionStorage.removeItem(SESSION_KEY); } catch (e) { /* ignore */ }
    }
  };

  AF.accounts = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
