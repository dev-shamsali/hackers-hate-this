'use strict';
// In-process harness: mocks mysql2 + mongoose (no network, no real DB), stubs global fetch,
// runs in a throwaway cwd so multer's relative upload dir never touches the repo.
const Module = require('node:module');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const jwt = require('jsonwebtoken');

const ROOT = path.resolve(__dirname, '..', '..');
const SRC = path.join(ROOT, 'src', 'app.js');
const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-'));
process.chdir(sandbox);
process.on('exit', () => { try { fs.rmSync(sandbox, { recursive: true, force: true }); } catch {} });

// Test-only configuration, set BEFORE the app (and its zod-validated config) is loaded.
// The app has no secret defaults; tokens are signed with this same test secret.
const JWT_SECRET = 'test-secret-at-least-32-chars-long....';
Object.assign(process.env, {
  NODE_ENV: 'test', JWT_SECRET, JWT_ISSUER: 'test-issuer', JWT_AUDIENCE: 'test-audience',
  DB_USER: 'app_user', DB_PASSWORD: 'test-db-password', BCRYPT_ROUNDS: '4', PASSWORD_MIN_LENGTH: '1',
});
const bcrypt = require('bcryptjs');
const hashPw = (p) => bcrypt.hashSync(p, 4);   // app stores bcrypt hashes only; seed users accordingly

// ---------- fake data ----------
const state = { users: [], orders: [], queries: [], poolConfig: null, fetchCalls: [] };
let seq = 0;
function reset() {
  if (app && app.locals.resetRateLimits) app.locals.resetRateLimits();   // fresh limiter state per test
  seq = 0; state.queries.length = 0; state.fetchCalls.length = 0;
  state.users = [
    { _id: 'uA', email: 'a@t1.test', password: hashPw('pwA'), role: 'user', tenantId: 't1' },
    { _id: 'uB', email: 'b@t1.test', password: hashPw('pwB'), role: 'user', tenantId: 't1' },
    { _id: 'uC', email: 'c@t2.test', password: hashPw('pwC'), role: 'user', tenantId: 't2' },
    { _id: 'uAdmin', email: 'admin@t1.test', password: hashPw('pwAdmin'), role: 'admin', tenantId: 't1' },
  ];
  state.orders = [{ id: 1, userId: 'uA', total: 100, secret: 'order-of-A' }, { id: 2, userId: 'uB', total: 5 }];
}
reset();

function matchVal(actual, cond) {
  if (cond && typeof cond === 'object' && !Array.isArray(cond)) {
    return Object.entries(cond).every(([op, v]) => {
      if (op === '$ne') return actual !== v;
      if (op === '$gt') return actual > v;
      if (op === '$regex') return new RegExp(v).test(String(actual));
      if (op === '$where') return true;
      return false;
    });
  }
  return actual === cond;   // arrays never equal a string (real Mongoose would cast-error)
}
const matches = (doc, q) => Object.entries(q).every(([k, c]) => matchVal(doc[k], c));
const SCHEMA_FIELDS = ['email', 'password', 'role', 'tenantId'];   // mirrors src schema (strict mode drops others)

const User = {
  async findOne(q) { return state.users.find((u) => matches(u, q)) || null; },
  async create(body) {
    const d = { _id: 'u' + (++seq) + '_new', role: 'user' };
    for (const f of SCHEMA_FIELDS) if (body[f] !== undefined) d[f] = body[f];
    state.users.push(d); return { ...d };
  },
  async findByIdAndUpdate(id, upd) { const u = state.users.find((x) => x._id === id); if (u) Object.assign(u, upd); return u; },
};
class Schema { constructor(d) { this.def = d; } }
const fakeMongoose = { Schema, model: () => User, connect: async () => {}, set: () => {} };

function sqlSyntaxBroken(sql) { return (sql.match(/'/g) || []).length % 2 === 1; }
const fakeMysql = {
  createPool(cfg) {
    state.poolConfig = cfg;
    return {
      query(sql, params, cb) {
        if (typeof params === 'function') { cb = params; params = []; }
        state.queries.push({ sql, params });
        setImmediate(() => {
          if (sqlSyntaxBroken(sql)) { const e = new Error(`You have an error in your SQL syntax near '${sql.slice(-20)}' at /app/src/app.js`); return cb(e); }
          if (/FROM orders/.test(sql)) return cb(null, state.orders.filter((o) => String(o.id) === String(params[0])));
          cb(null, [{ id: 1, name: 'widget' }, { id: 2, name: 'gadget' }, { id: 3, name: 'secret-hidden' }]);
        });
      },
    };
  },
};

const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'mysql2') return fakeMysql;
  if (request === 'mongoose') return fakeMongoose;
  return origLoad.apply(this, arguments);
};
globalThis.fetch = async (url) => { state.fetchCalls.push(String(url)); return { text: async () => 'SSRF-BODY' }; };

var app = require(SRC);

const sign = (payload, opts = { expiresIn: '1h' }, secret = JWT_SECRET) =>
  jwt.sign(payload, secret, { issuer: process.env.JWT_ISSUER, audience: process.env.JWT_AUDIENCE, ...opts });
const tokens = {
  userA: sign({ id: 'uA', role: 'user' }), userB: sign({ id: 'uB', role: 'user' }),
  userC: sign({ id: 'uC', role: 'user' }), admin: sign({ id: 'uAdmin', role: 'admin' }),
};
const bearer = (t) => 'Bearer ' + t;
module.exports = { app, state, tokens, bearer, sign, JWT_SECRET, reset, User, jwt };
