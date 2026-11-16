/*
 * Automated checks for sign-in and account management.
 * Run from the project folder:  node --test tests/
 */
const test = require('node:test');
const assert = require('node:assert');

const acc = require('../js/accounts.js');

const T0 = Date.UTC(2026, 10, 16, 9, 0, 0);
const fresh = () => acc.defaults(T0);
const admin = (s) => s.users.find((u) => u.username === 'admin');

test('the demo administrator signs in with admin / password', () => {
  const s = fresh();
  const r = acc.login(s, 'admin', 'password', T0);
  assert.ok(r.ok);
  assert.strictEqual(r.user.role, 'admin');
  assert.strictEqual(r.user.weak, true, 'the default password is flagged as weak');
  assert.ok(acc.login(s, '  ADMIN ', 'password', T0).ok, 'user names ignore case and spaces');
});

test('passwords are stored only as salted hashes', () => {
  const s = fresh();
  for (const u of s.users) assert.ok(!u.hash.includes('password'));
  const a = acc.hashPassword('Correct-horse-9'), b = acc.hashPassword('Correct-horse-9');
  assert.notStrictEqual(a, b, 'the same password gets a different salt each time');
  assert.match(a, /^sha256i\$\d+\$[0-9a-f]{32}\$[0-9a-f]{64}$/);
  assert.ok(acc.verify('Correct-horse-9', a));
  assert.ok(!acc.verify('correct-horse-9', a));
  assert.ok(!acc.verify('anything', 'not a hash'));
});

test('a wrong password and an unknown name give the same answer', () => {
  const s = fresh();
  assert.strictEqual(acc.login(s, 'admin', 'nope', T0).error, 'bad');
  assert.strictEqual(acc.login(s, 'nobody', 'nope', T0).error, 'bad');
});

test('five wrong passwords lock the account for a minute', () => {
  const s = fresh();
  for (let i = 0; i < acc.MAX_FAILS - 1; i++) assert.strictEqual(acc.login(s, 'admin', 'wrong', T0 + i).error, 'bad');
  assert.strictEqual(acc.login(s, 'admin', 'wrong', T0 + 10).error, 'locked');
  assert.strictEqual(acc.login(s, 'admin', 'password', T0 + 20).error, 'locked', 'even the right password waits');
  assert.ok(acc.login(s, 'admin', 'password', T0 + 10 + acc.LOCK_MS + 1).ok);
});

test('an administrator creates accounts with checked input', () => {
  const s = fresh(), a = admin(s);
  assert.strictEqual(acc.createUser(s, a, { username: 'x', name: 'Xx', role: 'analyst', password: 'Strong-pass-1' }).error, 'username_format');
  assert.strictEqual(acc.createUser(s, a, { username: 'admin', name: 'Xx', role: 'analyst', password: 'Strong-pass-1' }).error, 'username_taken');
  assert.strictEqual(acc.createUser(s, a, { username: 'aruzhan', name: 'Aruzhan', role: 'analyst', password: 'password' }).error, 'password_weak');
  assert.strictEqual(acc.createUser(s, a, { username: 'aruzhan', name: 'Aruzhan', role: 'boss', password: 'Strong-pass-1' }).error, 'role');
  const r = acc.createUser(s, a, { username: 'Aruzhan', name: 'Aruzhan', role: 'analyst', password: 'Strong-pass-1' }, T0);
  assert.ok(r.ok);
  assert.strictEqual(r.user.username, 'aruzhan');
  assert.strictEqual(r.user.mustChange, true, 'a new account must set its own password');
  assert.ok(acc.login(s, 'aruzhan', 'Strong-pass-1', T0).ok);
});

test('only an administrator manages accounts', () => {
  const s = fresh(), a = admin(s);
  const analyst = acc.createUser(s, a, { username: 'analyst1', name: 'Analyst One', role: 'analyst', password: 'Strong-pass-1' }).user;
  assert.strictEqual(acc.createUser(s, analyst, { username: 'other', name: 'Other', role: 'admin', password: 'Strong-pass-1' }).error, 'forbidden');
  assert.strictEqual(acc.deleteUser(s, analyst, a.id).error, 'forbidden');
  assert.strictEqual(acc.setRole(s, analyst, analyst.id, 'admin').error, 'forbidden');
});

test('the last administrator cannot be deleted, disabled or demoted', () => {
  const s = fresh(), a = admin(s);
  assert.strictEqual(acc.deleteUser(s, a, a.id).error, 'self');
  assert.strictEqual(acc.setDisabled(s, a, a.id, true).error, 'self');
  assert.strictEqual(acc.setRole(s, a, a.id, 'analyst').error, 'last_admin');
  const second = acc.createUser(s, a, { username: 'second', name: 'Second Admin', role: 'admin', password: 'Strong-pass-1' }).user;
  assert.ok(acc.setRole(s, a, a.id, 'analyst').ok, 'possible once another administrator exists');
  assert.strictEqual(acc.deleteUser(s, second, second.id).error, 'self');
});

test('disable, unlock, reset and delete', () => {
  const s = fresh(), a = admin(s);
  const u = acc.createUser(s, a, { username: 'viewer1', name: 'Viewer One', role: 'viewer', password: 'Strong-pass-1' }).user;
  assert.ok(acc.setDisabled(s, a, u.id, true).ok);
  assert.strictEqual(acc.login(s, 'viewer1', 'Strong-pass-1', T0).error, 'disabled');
  assert.ok(acc.setDisabled(s, a, u.id, false).ok);
  for (let i = 0; i < acc.MAX_FAILS; i++) acc.login(s, 'viewer1', 'wrong', T0);
  assert.ok(acc.isLocked(u, T0 + 1));
  assert.ok(acc.unlock(s, a, u.id).ok);
  assert.ok(!acc.isLocked(u, T0 + 1));
  assert.strictEqual(acc.resetPassword(s, a, u.id, '123').error, 'password_weak');
  assert.ok(acc.resetPassword(s, a, u.id, 'New-strong-pass-2').ok);
  assert.ok(!acc.login(s, 'viewer1', 'Strong-pass-1', T0 + 2).ok, 'the old password no longer works');
  assert.ok(acc.login(s, 'viewer1', 'New-strong-pass-2', T0 + 3).ok);
  assert.ok(acc.deleteUser(s, a, u.id).ok);
  assert.strictEqual(acc.login(s, 'viewer1', 'New-strong-pass-2', T0 + 4).error, 'bad');
  const events = s.events.map((e) => e.event);
  for (const e of ['created', 'disabled', 'enabled', 'locked', 'unlocked', 'password_reset', 'deleted']) assert.ok(events.includes(e), e);
});

test('a user changes their own password', () => {
  const s = fresh(), a = admin(s);
  assert.strictEqual(acc.changePassword(s, a, 'wrong', 'New-strong-pass-2').error, 'current_wrong');
  assert.strictEqual(acc.changePassword(s, a, 'password', 'admin').error, 'password_weak');
  assert.ok(acc.changePassword(s, a, 'password', 'New-strong-pass-2').ok);
  assert.strictEqual(a.weak, false);
  assert.ok(acc.login(s, 'admin', 'New-strong-pass-2', T0).ok);
});

test('anyone can sign up, with checked input and never as an administrator', () => {
  const s = fresh();
  assert.strictEqual(acc.register(s, { username: 'a', name: 'Dana', password: 'Strong-pass-1' }).error, 'username_format');
  assert.strictEqual(acc.register(s, { username: 'admin', name: 'Dana', password: 'Strong-pass-1' }).error, 'username_taken');
  assert.strictEqual(acc.register(s, { username: 'dana', name: 'Dana', password: '12345678' }).error, 'password_weak');
  assert.strictEqual(acc.register(s, { username: 'dana', name: 'D', password: 'Strong-pass-1' }).error, 'name_short');
  const r = acc.register(s, { username: 'Dana', name: 'Dana Student', password: 'Strong-pass-1', role: 'admin' }, T0);
  assert.ok(r.ok);
  assert.strictEqual(r.user.role, 'analyst', 'the role comes from the settings, not from the form');
  assert.strictEqual(r.user.mustChange, false, 'a self-chosen password needs no change');
  assert.strictEqual(r.user.createdBy, 'self');
  assert.ok(acc.login(s, 'dana', 'Strong-pass-1', T0 + 1).ok);
  assert.ok(s.events.some((e) => e.event === 'signed_up' && e.target === 'dana'));
});

test('an administrator can turn sign-up off or make new accounts viewers', () => {
  const s = fresh(), a = admin(s);
  const analyst = acc.register(s, { username: 'erlan', name: 'Erlan', password: 'Strong-pass-1' }).user;
  assert.strictEqual(acc.setSignup(s, analyst, false, 'analyst').error, 'forbidden');
  assert.strictEqual(acc.setSignup(s, a, true, 'admin').error, 'role');
  assert.ok(acc.setSignup(s, a, true, 'viewer').ok);
  assert.strictEqual(acc.register(s, { username: 'gulnar', name: 'Gulnar', password: 'Strong-pass-1' }).user.role, 'viewer');
  assert.ok(acc.setSignup(s, a, false, 'viewer').ok);
  assert.strictEqual(acc.register(s, { username: 'nurlan', name: 'Nurlan', password: 'Strong-pass-1' }).error, 'signup_off');
  const back = acc.sanitise(JSON.parse(JSON.stringify(s)));
  assert.deepStrictEqual(back.settings, { signup: false, signupRole: 'viewer' }, 'the settings survive a reload');
});

test('stored accounts are checked when they are read back', () => {
  const s = fresh();
  assert.ok(acc.sanitise(JSON.parse(JSON.stringify(s))));
  assert.strictEqual(acc.sanitise({ v: 1, users: [] }), null, 'a list with no administrator is refused');
  assert.strictEqual(acc.sanitise({ v: 1, users: [{ id: 'x', username: '<script>', hash: 'h', role: 'admin' }] }), null);
  assert.strictEqual(acc.sanitise('nonsense'), null);
});
