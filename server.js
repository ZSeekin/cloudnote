'use strict';
/**
 * 云笺 CloudNote · 服务端（分享 / 多人协作 / 划线评论）
 * Node + Express + sql.js（纯 WASM 的 SQLite，无需编译原生模块）
 * 数据库文件：./data/lite-doc.db（标准 SQLite 格式）
 * 媒体文件（图片/动图/视频）：./uploads，以 URL 形式在文档中引用。
 */
const path = require('path');
const fs = require('fs');
const express = require('express');
const multer = require('multer');
const initSqlJs = require('sql.js');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const UPLOAD_DIR = path.join(ROOT, 'uploads');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const DB_PATH = path.join(DATA_DIR, 'lite-doc.db');

/* ---------- 第三方登录配置（config.json，用户自行申请填入） ---------- */
const CONFIG_PATH = path.join(ROOT, 'config.json');
let config = {};
try { config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')); } catch (e) { config = {}; }
function providerConfigured(name) {
  const c = config[name];
  if (!c) return false;
  if (name === 'wecom') return !!(c.corpId && c.appSecret && c.agentId);
  return !!(c.appId && c.appSecret);
}

/* ---------- 数据库（sql.js / SQLite） ---------- */
let db = null;
let persistTimer = null;

function persistNow() {
  if (!db) return;
  fs.writeFileSync(DB_PATH + '.tmp', Buffer.from(db.export()));
  fs.renameSync(DB_PATH + '.tmp', DB_PATH);
}
function schedulePersist() {
  clearTimeout(persistTimer);
  persistTimer = setTimeout(persistNow, 300);
}
function all(sql, params) {
  const stmt = db.prepare(sql);
  if (params) stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}
function get(sql, params) { return all(sql, params)[0] || null; }
function run(sql, params) { db.run(sql, params || []); schedulePersist(); }

const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 7);

/* ---------- 账号 / 会话 ---------- */
const SESSION_TTL = 30 * 24 * 3600 * 1000;
function createSession(userId) {
  const token = uid() + uid();
  run('INSERT INTO sessions (token, user_id, created, expires) VALUES (?, ?, ?, ?)',
    [token, userId, Date.now(), Date.now() + SESSION_TTL]);
  return token;
}
function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie',
    'litedoc_sid=' + token + '; Path=/; HttpOnly; Max-Age=' + Math.floor(SESSION_TTL / 1000) + '; SameSite=Lax');
}
function readSid(req) {
  const m = (req.headers.cookie || '').match(/(?:^|;\s*)litedoc_sid=([^;]+)/);
  return m ? m[1] : null;
}
function getSessionUser(req) {
  const sid = readSid(req);
  if (!sid) return null;
  const row = get('SELECT user_id, expires FROM sessions WHERE token = ?', [sid]);
  if (!row || row.expires < Date.now()) return null;
  return get('SELECT * FROM users WHERE id = ?', [row.user_id]);
}
function publicUser(u) {
  const ids = all('SELECT provider FROM identities WHERE user_id = ?', [u.id]);
  return {
    id: u.id, nickname: u.nickname, avatar: u.avatar, phone: u.phone,
    providers: ids.map((i) => i.provider)
  };
}

/* ---------- 密码散列（scrypt，格式 salt:hash） ---------- */
const crypto = require('crypto');
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(pw), salt, 32).toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(pw, stored) {
  if (!stored || stored.indexOf(':') < 0) return false;
  const parts = stored.split(':');
  const hash = crypto.scryptSync(String(pw), parts[0], 32);
  const expect = Buffer.from(parts[1], 'hex');
  return hash.length === expect.length && crypto.timingSafeEqual(hash, expect);
}

/* ---------- 在线状态（内存，15 秒超时） ---------- */
const presence = new Map(); // docId -> Map(userId -> {name, color, ts})
const PRESENCE_TTL = 15000;
function touchPresence(docId, u) {
  if (!presence.has(docId)) presence.set(docId, new Map());
  const m = presence.get(docId);
  const now = Date.now();
  m.set(u.userId, { name: u.name, color: u.color, ts: now });
  const others = [];
  m.forEach((v, k) => {
    if (now - v.ts > PRESENCE_TTL) m.delete(k);
    else if (k !== u.userId) others.push({ userId: k, name: v.name, color: v.color });
  });
  return others;
}

/* ---------- 应用 ---------- */
const app = express();
app.use(express.json({ limit: '20mb' }));
app.use(express.static(path.join(ROOT, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '30d', immutable: true }));

/* 分享页路由 */
app.get('/share/:id', (req, res) => res.sendFile(path.join(ROOT, 'public', 'share.html')));

/* ---------- 媒体上传 ---------- */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    let ext = path.extname(file.originalname || '').slice(0, 10).toLowerCase().replace(/[^a-z0-9.]/g, '');
    cb(null, uid() + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 200 * 1024 * 1024 } });

app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'no file' });
  res.json({
    url: '/uploads/' + req.file.filename,
    name: req.file.originalname,
    size: req.file.size,
    type: req.file.mimetype
  });
});

/* ---------- 文档权限模型 ----------
 * 创建：必须登录；文档默认私有（share_mode='off'）只有作者可见。
 * 读：作者本人 或 已开启分享（view/edit）；owner_id 为空的为历史匿名文档，保持公开。
 * 写：作者本人；或 share_mode='edit' 且已登录的协作者；历史匿名文档不限制。
 * 删除/分享设置：仅作者（历史匿名文档保持原开放行为）。
 */
function isOwner(doc, u) { return !!(u && doc.owner_id && doc.owner_id === u.id); }
function canReadDoc(doc, u) {
  if (!doc) return false;
  if (isOwner(doc, u) || !doc.owner_id) return true;
  return doc.share_mode !== 'off';
}
function canWriteDoc(doc, u) {
  if (!doc) return false;
  if (isOwner(doc, u) || !doc.owner_id) return true;
  return doc.share_mode === 'edit' && !!u;
}
function canManageDoc(doc, u) {
  if (!doc) return false;
  if (!doc.owner_id) return true; // 历史匿名文档
  return isOwner(doc, u);
}

/* ---------- 文档 CRUD（带版本号 rev，支持协作冲突检测） ---------- */
app.get('/api/docs', (req, res) => {
  const u = getSessionUser(req);
  if (!u) return res.status(401).json({ error: 'login_required' });
  res.json(all('SELECT id, title, updated, owner_id FROM docs WHERE owner_id = ? ORDER BY updated DESC', [u.id]));
});

app.get('/api/docs/:id', (req, res) => {
  const u = getSessionUser(req);
  const row = get('SELECT * FROM docs WHERE id = ?', [req.params.id]);
  if (!row) return res.status(404).json({ error: 'not found' });
  if (!canReadDoc(row, u)) return res.status(403).json({ error: 'no_permission' });
  row.can_edit = canWriteDoc(row, u);
  row.is_owner = isOwner(row, u) || !row.owner_id;
  res.json(row);
});

/* 轻量轮询：只返回版本号等元数据 */
app.get('/api/docs/:id/meta', (req, res) => {
  const u = getSessionUser(req);
  const row = get('SELECT rev, updated, share_mode, owner_id FROM docs WHERE id = ?', [req.params.id]);
  if (!row) return res.status(404).json({ error: 'not found' });
  if (!canReadDoc(row, u)) return res.status(403).json({ error: 'no_permission' });
  res.json({ rev: row.rev, updated: row.updated, share_mode: row.share_mode, can_edit: canWriteDoc(row, u) });
});

app.post('/api/docs', (req, res) => {
  const u = getSessionUser(req);
  if (!u) return res.status(401).json({ error: 'login_required' });
  const b = req.body || {};
  const id = uid();
  run("INSERT INTO docs (id, title, html, updated, rev, share_mode, owner_id) VALUES (?, ?, ?, ?, 0, 'off', ?)",
    [id, String(b.title || ''), String(b.html || ''), Date.now(), u.id]);
  const row = get('SELECT * FROM docs WHERE id = ?', [id]);
  row.can_edit = true; row.is_owner = true;
  res.json(row);
});

/* 记录浏览（登录用户记到账号，匿名记到浏览器标识） */
app.post('/api/docs/:id/view', (req, res) => {
  const u = getSessionUser(req);
  const doc = get('SELECT owner_id, share_mode FROM docs WHERE id = ?', [req.params.id]);
  if (!doc || !canReadDoc(doc, u)) return res.status(403).json({ error: 'no_permission' });
  const anonKey = String((req.body || {}).anonKey || '').slice(0, 60);
  const key = u ? 'u:' + u.id : (anonKey ? 'a:' + anonKey : null);
  if (!key) return res.json({ ok: true });
  run('INSERT INTO views (userKey, docId, viewed_at) VALUES (?, ?, ?) ' +
      'ON CONFLICT(userKey, docId) DO UPDATE SET viewed_at = excluded.viewed_at',
    [key, req.params.id, Date.now()]);
  schedulePersist();
  res.json({ ok: true });
});

/* 保存：带 baseRev 时检测冲突（409），不带则强制覆盖（后保存者胜） */
app.put('/api/docs/:id', (req, res) => {
  const b = req.body || {};
  const u = getSessionUser(req);
  const row = get('SELECT rev, owner_id, share_mode FROM docs WHERE id = ?', [req.params.id]);
  if (!row) return res.status(404).json({ error: 'not found' });
  if (!canWriteDoc(row, u)) {
    if (!u && row.share_mode === 'edit') return res.status(401).json({ error: 'login_required' });
    return res.status(403).json({ error: 'no_permission' });
  }
  if (b.baseRev !== undefined && b.baseRev !== null && Number(b.baseRev) !== row.rev) {
    return res.status(409).json({ error: 'conflict', rev: row.rev });
  }
  const newRev = row.rev + 1;
  run('UPDATE docs SET title = COALESCE(?, title), html = COALESCE(?, html), updated = ?, rev = ? WHERE id = ?',
    [b.title === undefined ? null : String(b.title),
     b.html === undefined ? null : String(b.html),
     Date.now(), newRev, req.params.id]);
  persistNow();
  res.json({ ok: true, updated: Date.now(), rev: newRev });
});

/* 分享设置：off / view / edit（仅作者） */
app.put('/api/docs/:id/share', (req, res) => {
  const u = getSessionUser(req);
  const mode = (req.body && req.body.mode) || 'off';
  if (['off', 'view', 'edit'].indexOf(mode) < 0) return res.status(400).json({ error: 'bad mode' });
  const row = get('SELECT id, owner_id, share_mode FROM docs WHERE id = ?', [req.params.id]);
  if (!row) return res.status(404).json({ error: 'not found' });
  if (!canManageDoc(row, u)) return res.status(403).json({ error: 'no_permission' });
  run('UPDATE docs SET share_mode = ? WHERE id = ?', [mode, req.params.id]);
  persistNow();
  res.json({ ok: true, mode });
});

app.delete('/api/docs/:id', (req, res) => {
  const u = getSessionUser(req);
  const row = get('SELECT id, owner_id FROM docs WHERE id = ?', [req.params.id]);
  if (!row) return res.status(404).json({ error: 'not found' });
  if (!canManageDoc(row, u)) return res.status(403).json({ error: 'no_permission' });
  run('DELETE FROM docs WHERE id = ?', [req.params.id]);
  run('DELETE FROM comments WHERE docId = ?', [req.params.id]);
  persistNow();
  res.json({ ok: true });
});

/* ---------- 划线评论 ---------- */
app.get('/api/docs/:id/comments', (req, res) => {
  res.json(all('SELECT * FROM comments WHERE docId = ? ORDER BY created ASC', [req.params.id]));
});

app.post('/api/docs/:id/comments', (req, res) => {
  const b = req.body || {};
  if (!b.body || !b.cid) return res.status(400).json({ error: 'body & cid required' });
  const u = getSessionUser(req);
  const row = get('SELECT id, owner_id, share_mode FROM docs WHERE id = ?', [req.params.id]);
  if (!row) return res.status(404).json({ error: 'not found' });
  if (!canReadDoc(row, u)) return res.status(403).json({ error: 'no_permission' });
  const id = uid();
  run('INSERT INTO comments (id, docId, cid, quote, body, author, color, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [id, req.params.id, String(b.cid), String(b.quote || '').slice(0, 500),
     String(b.body).slice(0, 2000), String(b.author || '匿名'), String(b.color || '#8f959e'), Date.now()]);
  persistNow();
  res.json({ ok: true, id });
});

app.post('/api/comments/:id/resolve', (req, res) => {
  const b = req.body || {};
  const row = get('SELECT id FROM comments WHERE id = ?', [req.params.id]);
  if (!row) return res.status(404).json({ error: 'not found' });
  run('UPDATE comments SET resolved = 1, resolved_at = ?, resolved_by = ?, after_text = ? WHERE id = ?',
    [Date.now(), String(b.resolvedBy || '').slice(0, 60), String(b.after || '').slice(0, 500), req.params.id]);
  persistNow();
  res.json({ ok: true });
});

app.delete('/api/comments/:id', (req, res) => {
  run('DELETE FROM comments WHERE id = ?', [req.params.id]);
  persistNow();
  res.json({ ok: true });
});

/* ---------- 在线状态 ---------- */
app.post('/api/docs/:id/presence', (req, res) => {
  const b = req.body || {};
  if (!b.userId) return res.status(400).json({ error: 'userId required' });
  res.json({
    others: touchPresence(req.params.id, {
      userId: String(b.userId),
      name: String(b.name || '匿名'),
      color: String(b.color || '#8f959e')
    })
  });
});

/* ---------- 健康检查 ---------- */
app.get('/api/health', (req, res) =>
  res.json({ ok: true, docs: all('SELECT COUNT(*) c FROM docs')[0].c }));

/* ==================== 账号系统 ==================== */
app.get('/api/me', (req, res) => {
  const u = getSessionUser(req);
  res.json({ user: u ? publicUser(u) : null });
});

app.get('/api/auth/providers', (req, res) => {
  res.json({
    phone: true,
    wechat: providerConfigured('wechat'),
    feishu: providerConfigured('feishu'),
    wecom: providerConfigured('wecom')
  });
});

app.post('/api/auth/logout', (req, res) => {
  const sid = readSid(req);
  if (sid) run('DELETE FROM sessions WHERE token = ?', [sid]);
  res.setHeader('Set-Cookie', 'litedoc_sid=; Path=/; HttpOnly; Max-Age=0');
  persistNow();
  res.json({ ok: true });
});

/* ---------- 手机号验证码登录（开发模式直接返回验证码） ---------- */
app.post('/api/auth/phone/code', (req, res) => {
  const phone = String((req.body || {}).phone || '').trim();
  if (!/^1\d{10}$/.test(phone)) return res.status(400).json({ error: '手机号格式不正确' });
  const code = String(Math.floor(100000 + Math.random() * 900000));
  run('INSERT INTO phone_codes (phone, code, expires) VALUES (?, ?, ?) ' +
      'ON CONFLICT(phone) DO UPDATE SET code = excluded.code, expires = excluded.expires',
    [phone, code, Date.now() + 10 * 60 * 1000]);
  const sms = config.sms || {};
  if (sms.provider && sms.provider !== 'dev') {
    // TODO: 接入真实短信服务（阿里云/腾讯云），此处调用发送 API
    return res.json({ ok: true, sent: true });
  }
  console.log('[lite-doc] dev SMS code for ' + phone + ': ' + code);
  res.json({ ok: true, devCode: code }); // 开发模式：验证码直接返回给前端展示
});

app.post('/api/auth/phone/verify', (req, res) => {
  const b = req.body || {};
  const phone = String(b.phone || '').trim();
  const code = String(b.code || '').trim();
  const row = get('SELECT * FROM phone_codes WHERE phone = ?', [phone]);
  if (!row || row.code !== code || row.expires < Date.now()) {
    return res.status(400).json({ error: '验证码错误或已过期' });
  }
  run('DELETE FROM phone_codes WHERE phone = ?', [phone]);

  const me = getSessionUser(req);
  let user = get("SELECT u.* FROM users u JOIN identities i ON i.user_id = u.id " +
    "WHERE i.provider = 'phone' AND i.openid = ?", [phone]);

  if (me) {
    // 已登录：把手机号绑定到当前账号
    if (user && user.id !== me.id) return res.status(409).json({ error: '该手机号已绑定其他账号' });
    user = me;
    if (!get("SELECT 1 FROM identities WHERE user_id = ? AND provider = 'phone'", [me.id])) {
      run('INSERT INTO identities (user_id, provider, openid, unionid, name, avatar, created) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [me.id, 'phone', phone, '', phone, '', Date.now()]);
    }
    run('UPDATE users SET phone = ? WHERE id = ?', [phone, me.id]);
    persistNow();
  } else if (!user) {
    const id = uid();
    const nickname = String(b.nickname || '').trim() || ('用户' + phone.slice(-4));
    run('INSERT INTO users (id, nickname, avatar, phone, created) VALUES (?, ?, ?, ?, ?)',
      [id, nickname, '', phone, Date.now()]);
    run('INSERT INTO identities (user_id, provider, openid, unionid, name, avatar, created) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [id, 'phone', phone, '', nickname, '', Date.now()]);
    user = get('SELECT * FROM users WHERE id = ?', [id]);
    persistNow();
  }
  setSessionCookie(res, createSession(user.id));
  res.json({ ok: true, user: publicUser(user) });
});

/* ---------- 手机号 + 密码：注册 / 登录 ---------- */
function findUserByPhone(phone) {
  return get("SELECT u.* FROM users u JOIN identities i ON i.user_id = u.id " +
    "WHERE i.provider = 'phone' AND i.openid = ?", [phone]);
}

app.post('/api/auth/register', (req, res) => {
  const b = req.body || {};
  const phone = String(b.phone || '').trim();
  const password = String(b.password || '');
  const nickname = String(b.nickname || '').trim();
  if (!/^1\d{10}$/.test(phone)) return res.status(400).json({ error: '手机号格式不正确' });
  if (password.length < 6) return res.status(400).json({ error: '密码至少 6 位' });
  if (!nickname) return res.status(400).json({ error: '请填写用户名' });
  if (nickname.length > 20) return res.status(400).json({ error: '用户名最多 20 个字符' });

  const me = getSessionUser(req);
  const existing = findUserByPhone(phone);

  if (me) {
    // 已登录：把手机号+密码绑定到当前账号（多方式关联同一账号）
    if (existing && existing.id !== me.id) return res.status(409).json({ error: '该手机号已绑定其他账号' });
    if (!existing) {
      run('INSERT INTO identities (user_id, provider, openid, unionid, name, avatar, created) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [me.id, 'phone', phone, '', nickname, '', Date.now()]);
    }
    run('UPDATE users SET phone = ?, password_hash = ? WHERE id = ?',
      [phone, hashPassword(password), me.id]);
    persistNow();
    const u = get('SELECT * FROM users WHERE id = ?', [me.id]);
    return res.json({ ok: true, user: publicUser(u), bound: true });
  }

  if (existing) {
    if (existing.password_hash) return res.status(409).json({ error: '该手机号已注册，请直接登录' });
    // 历史验证码账号（无密码）：允许通过注册设置密码来认领
    run('UPDATE users SET password_hash = ?, nickname = ? WHERE id = ?',
      [hashPassword(password), nickname, existing.id]);
    persistNow();
    const u = get('SELECT * FROM users WHERE id = ?', [existing.id]);
    setSessionCookie(res, createSession(u.id));
    return res.json({ ok: true, user: publicUser(u) });
  }

  const id = uid();
  run('INSERT INTO users (id, nickname, avatar, phone, password_hash, created) VALUES (?, ?, ?, ?, ?, ?)',
    [id, nickname, '', phone, hashPassword(password), Date.now()]);
  run('INSERT INTO identities (user_id, provider, openid, unionid, name, avatar, created) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [id, 'phone', phone, '', nickname, '', Date.now()]);
  persistNow();
  const user = get('SELECT * FROM users WHERE id = ?', [id]);
  setSessionCookie(res, createSession(user.id));
  res.json({ ok: true, user: publicUser(user) });
});

app.post('/api/auth/login', (req, res) => {
  const b = req.body || {};
  const phone = String(b.phone || '').trim();
  const password = String(b.password || '');
  if (!phone || !password) return res.status(400).json({ error: '请输入手机号和密码' });
  const user = findUserByPhone(phone);
  if (!user || !verifyPassword(password, user.password_hash || '')) {
    return res.status(400).json({ error: '手机号或密码错误' });
  }
  setSessionCookie(res, createSession(user.id));
  res.json({ ok: true, user: publicUser(user) });
});

/* ---------- 第三方 OAuth（微信 / 飞书 / 企业微信） ---------- */
const oauthStates = new Map(); // state -> { ts, redirect, bindUserId }
function baseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || 'https';
  return proto + '://' + req.headers.host;
}

app.get('/api/auth/:provider/start', (req, res) => {
  const p = req.params.provider;
  if (['wechat', 'feishu', 'wecom'].indexOf(p) < 0) return res.status(404).end();
  if (!providerConfigured(p)) {
    return res.status(503).send(p + ' 登录暂未配置：请在对应开放平台注册应用，并把 AppID/Secret 填入 config.json');
  }
  const state = uid();
  const me = getSessionUser(req);
  oauthStates.set(state, {
    ts: Date.now(),
    redirect: String(req.query.redirect || '/'),
    bindUserId: me ? me.id : null
  });
  const cb = encodeURIComponent(baseUrl(req) + '/api/auth/' + p + '/callback');
  let url;
  if (p === 'wechat') {
    url = 'https://open.weixin.qq.com/connect/qrconnect?appid=' + config.wechat.appId +
      '&redirect_uri=' + cb + '&response_type=code&scope=snsapi_login&state=' + state + '#wechat_redirect';
  } else if (p === 'feishu') {
    url = 'https://open.feishu.cn/open-apis/authen/v1/authorize?app_id=' + config.feishu.appId +
      '&redirect_uri=' + cb + '&state=' + state;
  } else {
    url = 'https://open.work.weixin.qq.com/wwopen/sso/qrConnect?appid=' + config.wecom.corpId +
      '&agentid=' + config.wecom.agentId + '&redirect_uri=' + cb + '&state=' + state;
  }
  res.redirect(url);
});

async function fetchJson(url, opts) {
  const r = await fetch(url, opts);
  return r.json();
}
async function oauthUserInfo(p, code) {
  if (p === 'feishu') {
    const c = config.feishu;
    const t = await fetchJson('https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ app_id: c.appId, app_secret: c.appSecret })
    });
    const ut = await fetchJson('https://open.feishu.cn/open-apis/authen/v1/oidc/access_token', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + t.app_access_token },
      body: JSON.stringify({ grant_type: 'authorization_code', code })
    });
    const uat = ut.data && ut.data.access_token;
    const ui = await fetchJson('https://open.feishu.cn/open-apis/authen/v1/user_info', {
      headers: { Authorization: 'Bearer ' + uat }
    });
    const d = ui.data || {};
    return { openid: d.open_id, unionid: d.union_id || '', name: d.name || '', avatar: d.avatar_url || '' };
  }
  if (p === 'wechat') {
    const c = config.wechat;
    const t = await fetchJson('https://api.weixin.qq.com/sns/oauth2/access_token?appid=' + c.appId +
      '&secret=' + c.appSecret + '&code=' + code + '&grant_type=authorization_code');
    if (!t.access_token) throw new Error('wechat token: ' + JSON.stringify(t));
    const ui = await fetchJson('https://api.weixin.qq.com/sns/userinfo?access_token=' + t.access_token + '&openid=' + t.openid);
    return { openid: t.openid, unionid: t.unionid || ui.unionid || '', name: ui.nickname || '', avatar: ui.headimgurl || '' };
  }
  // wecom
  const c = config.wecom;
  const t = await fetchJson('https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=' + c.corpId + '&corpsecret=' + c.appSecret);
  const ui = await fetchJson('https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo?access_token=' + t.access_token + '&code=' + code);
  const userid = ui.userid || ui.openid;
  let name = '', avatar = '';
  if (ui.userid) {
    const ud = await fetchJson('https://qyapi.weixin.qq.com/cgi-bin/user/get?access_token=' + t.access_token + '&userid=' + ui.userid);
    name = ud.name || ''; avatar = ud.avatar || '';
  }
  return { openid: userid, unionid: '', name, avatar };
}

app.get('/api/auth/:provider/callback', async (req, res) => {
  const p = req.params.provider;
  const { code, state } = req.query;
  const st = oauthStates.get(state);
  oauthStates.delete(state);
  if (!st || Date.now() - st.ts > 10 * 60 * 1000 || !code) {
    return res.status(400).send('登录状态已过期，请回到应用重试');
  }
  try {
    const info = await oauthUserInfo(p, String(code));
    if (!info.openid) throw new Error('no openid');
    let user;
    if (st.bindUserId) {
      // 绑定到当前已登录账号
      const existing = get('SELECT user_id FROM identities WHERE provider = ? AND openid = ?', [p, info.openid]);
      if (existing && existing.user_id !== st.bindUserId) {
        return res.status(409).send('该第三方账号已绑定其他用户，请先用它登录后解绑');
      }
      user = get('SELECT * FROM users WHERE id = ?', [st.bindUserId]);
      if (!existing) {
        run('INSERT INTO identities (user_id, provider, openid, unionid, name, avatar, created) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [user.id, p, info.openid, info.unionid, info.name, info.avatar, Date.now()]);
        persistNow();
      }
    } else {
      const idn = get('SELECT user_id FROM identities WHERE provider = ? AND openid = ?', [p, info.openid]);
      if (idn) user = get('SELECT * FROM users WHERE id = ?', [idn.user_id]);
      if (!user) {
        const id = uid();
        run('INSERT INTO users (id, nickname, avatar, phone, created) VALUES (?, ?, ?, ?, ?)',
          [id, info.name || '用户', info.avatar || '', '', Date.now()]);
        run('INSERT INTO identities (user_id, provider, openid, unionid, name, avatar, created) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [id, p, info.openid, info.unionid, info.name, info.avatar, Date.now()]);
        user = get('SELECT * FROM users WHERE id = ?', [id]);
        persistNow();
      }
    }
    setSessionCookie(res, createSession(user.id));
    res.redirect(st.redirect || '/');
  } catch (e) {
    console.error('[lite-doc] oauth error (' + p + '):', e);
    res.status(500).send('第三方登录失败，请稍后重试');
  }
});

/* ---------- 我写的 / 浏览过的（分开） ---------- */
app.get('/api/my/docs', (req, res) => {
  const u = getSessionUser(req);
  const anonKey = String(req.query.anonKey || '').slice(0, 60);
  const owned = u ? all('SELECT id, title, updated FROM docs WHERE owner_id = ? ORDER BY updated DESC', [u.id]) : [];
  const key = u ? 'u:' + u.id : (anonKey ? 'a:' + anonKey : null);
  let viewed = [];
  if (key) {
    viewed = all('SELECT d.id, d.title, d.updated, v.viewed_at FROM views v ' +
      'JOIN docs d ON d.id = v.docId WHERE v.userKey = ? ORDER BY v.viewed_at DESC LIMIT 50', [key]);
  }
  const ownedIds = new Set(owned.map((o) => o.id));
  viewed = viewed.filter((v) => !ownedIds.has(v.id));
  res.json({ owned, viewed });
});

/* ---------- 启动（含旧库迁移） ---------- */
initSqlJs().then(function (SQL) {
  db = fs.existsSync(DB_PATH) ? new SQL.Database(fs.readFileSync(DB_PATH)) : new SQL.Database();
  db.run(`CREATE TABLE IF NOT EXISTS docs (
    id     TEXT PRIMARY KEY,
    title  TEXT NOT NULL DEFAULT '',
    html   TEXT NOT NULL DEFAULT '',
    updated INTEGER NOT NULL DEFAULT 0,
    rev    INTEGER NOT NULL DEFAULT 0,
    share_mode TEXT NOT NULL DEFAULT 'off'
  )`);
  // 旧库迁移：补齐新增列
  const cols = all('PRAGMA table_info(docs)').map((c) => c.name);
  if (cols.indexOf('rev') < 0) db.run('ALTER TABLE docs ADD COLUMN rev INTEGER NOT NULL DEFAULT 0');
  if (cols.indexOf('share_mode') < 0) db.run("ALTER TABLE docs ADD COLUMN share_mode TEXT NOT NULL DEFAULT 'off'");
  if (cols.indexOf('owner_id') < 0) db.run("ALTER TABLE docs ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''");
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id      TEXT PRIMARY KEY,
    docId   TEXT NOT NULL,
    cid     TEXT NOT NULL,
    quote   TEXT NOT NULL DEFAULT '',
    body    TEXT NOT NULL DEFAULT '',
    author  TEXT NOT NULL DEFAULT '',
    color   TEXT NOT NULL DEFAULT '',
    created INTEGER NOT NULL DEFAULT 0
  )`);
  // 旧库迁移：评论解决状态（归档而非删除）
  const ccols = all('PRAGMA table_info(comments)').map((c) => c.name);
  if (ccols.indexOf('resolved') < 0) {
    db.run('ALTER TABLE comments ADD COLUMN resolved INTEGER NOT NULL DEFAULT 0');
    db.run('ALTER TABLE comments ADD COLUMN resolved_at INTEGER NOT NULL DEFAULT 0');
    db.run("ALTER TABLE comments ADD COLUMN resolved_by TEXT NOT NULL DEFAULT ''");
    db.run("ALTER TABLE comments ADD COLUMN after_text TEXT NOT NULL DEFAULT ''");
  }
  // 账号系统表
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, nickname TEXT NOT NULL DEFAULT '', avatar TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL DEFAULT 0)`);
  // 旧库迁移：密码登录
  const ucols = all('PRAGMA table_info(users)').map((c) => c.name);
  if (ucols.indexOf('password_hash') < 0) {
    db.run("ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''");
  }
  db.run(`CREATE TABLE IF NOT EXISTS identities (
    user_id TEXT NOT NULL, provider TEXT NOT NULL, openid TEXT NOT NULL,
    unionid TEXT NOT NULL DEFAULT '', name TEXT NOT NULL DEFAULT '', avatar TEXT NOT NULL DEFAULT '',
    created INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (provider, openid))`);
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, user_id TEXT NOT NULL,
    created INTEGER NOT NULL DEFAULT 0, expires INTEGER NOT NULL DEFAULT 0)`);
  db.run(`CREATE TABLE IF NOT EXISTS phone_codes (
    phone TEXT PRIMARY KEY, code TEXT NOT NULL, expires INTEGER NOT NULL DEFAULT 0)`);
  db.run(`CREATE TABLE IF NOT EXISTS views (
    userKey TEXT NOT NULL, docId TEXT NOT NULL, viewed_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (userKey, docId))`);
  persistNow();
  app.listen(PORT, '0.0.0.0', function () {
    console.log('[lite-doc] listening on 0.0.0.0:' + PORT + ' (v2: share/collab/comments)');
  });
}).catch(function (err) {
  console.error('[lite-doc] failed to init database:', err);
  process.exit(1);
});
