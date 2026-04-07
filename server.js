require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.set('trust proxy', true);
const PORT = process.env.PORT || 4000;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const GITHUB_REPO = process.env.GITHUB_REPO;
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || 'main';
const GITHUB_API = 'https://api.github.com';
const SESSION_TIMEOUT_MS = 30 * 60 * 1000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('render.com') ? { rejectUnauthorized: false } : false
});

// ==================== DB INIT ====================
async function initDB() {
  await pool.query(`CREATE TABLE IF NOT EXISTS doc_users (id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT DEFAULT 'user', avatar_color TEXT DEFAULT '#6366f1', created_at TIMESTAMPTZ DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS login_logs (id SERIAL PRIMARY KEY, username TEXT NOT NULL, login_time TIMESTAMPTZ DEFAULT NOW(), logout_time TIMESTAMPTZ, ip_address TEXT DEFAULT '', browser_info TEXT DEFAULT '', device_name TEXT DEFAULT '')`);
  await pool.query(`CREATE TABLE IF NOT EXISTS view_logs (id SERIAL PRIMARY KEY, username TEXT NOT NULL, file_path TEXT NOT NULL, file_name TEXT DEFAULT '', view_start TIMESTAMPTZ DEFAULT NOW(), view_end TIMESTAMPTZ, view_duration_seconds INTEGER DEFAULT 0)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS favorites (id SERIAL PRIMARY KEY, username TEXT NOT NULL, file_path TEXT NOT NULL, file_name TEXT DEFAULT '', added_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE(username, file_path))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS notifications (id SERIAL PRIMARY KEY, target_role TEXT DEFAULT 'all', target_user TEXT DEFAULT '', title TEXT NOT NULL, message TEXT DEFAULT '', type TEXT DEFAULT 'info', created_at TIMESTAMPTZ DEFAULT NOW(), created_by TEXT DEFAULT '')`);
  await pool.query(`CREATE TABLE IF NOT EXISTS notification_reads (id SERIAL PRIMARY KEY, notification_id INTEGER REFERENCES notifications(id) ON DELETE CASCADE, username TEXT NOT NULL, read_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE(notification_id, username))`);
  await pool.query(`CREATE TABLE IF NOT EXISTS audit_log (id SERIAL PRIMARY KEY, username TEXT NOT NULL, action TEXT NOT NULL, details TEXT DEFAULT '', ip_address TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW())`);

  // Upgrade columns
  await pool.query(`ALTER TABLE login_logs ADD COLUMN IF NOT EXISTS browser_info TEXT DEFAULT ''`).catch(() => {});
  await pool.query(`ALTER TABLE login_logs ADD COLUMN IF NOT EXISTS device_name TEXT DEFAULT ''`).catch(() => {});
  await pool.query(`ALTER TABLE view_logs ADD COLUMN IF NOT EXISTS view_end TIMESTAMPTZ`).catch(() => {});

  const count = await pool.query('SELECT COUNT(*) as c FROM doc_users');
  if (parseInt(count.rows[0].c) === 0) {
    await pool.query('INSERT INTO doc_users (username, password, role, avatar_color) VALUES ($1, $2, $3, $4)', ['admin', bcrypt.hashSync('admin123', 10), 'admin', '#6366f1']);
  }
  console.log('Database ready');
}

// ==================== MIDDLEWARE ====================
app.use(express.json({ limit: '50mb' }));
app.use(express.text({ type: 'text/plain' }));
app.use(session({ secret: process.env.SESSION_SECRET || 'dv-secret-change-me', resave: false, saveUninitialized: false, cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } }));
app.use((req, res, next) => {
  if (req.session.user) {
    if (req.session.lastActivity && (Date.now() - req.session.lastActivity > SESSION_TIMEOUT_MS)) {
      if (req.session.loginLogId) pool.query('UPDATE login_logs SET logout_time = NOW() WHERE id = $1', [req.session.loginLogId]).catch(() => {});
      req.session.destroy();
      return res.status(440).json({ error: 'Session expired' });
    }
    req.session.lastActivity = Date.now();
  }
  next();
});

const auth = (r, s, n) => r.session.user ? n() : s.status(401).json({ error: 'Unauthorized' });
const adminOnly = (r, s, n) => r.session.user?.role === 'admin' ? n() : s.status(403).json({ error: 'Forbidden' });
const getIP = r => {
  let ip = r.headers['x-forwarded-for']?.split(',')[0]?.trim() || r.headers['x-real-ip'] || r.headers['cf-connecting-ip'] || r.ip || r.socket.remoteAddress || '';
  ip = ip.replace('::ffff:', '');
  if (ip === '::1' || ip === '127.0.0.1') ip = 'Localhost';
  return ip;
};
const getDevice = r => parseBrowser(r.headers['user-agent'] || '');
const logAudit = (u, a, d, device) => pool.query('INSERT INTO audit_log (username, action, details, ip_address) VALUES ($1,$2,$3,$4)', [u, a, d, device || '']).catch(() => {});

function parseBrowser(ua) {
  if (!ua) return 'Web Browser';
  let browser = 'Web Browser';
  if (ua.includes('Edg/')) browser = 'Edge';
  else if (ua.includes('OPR/') || ua.includes('Opera/')) browser = 'Opera';
  else if (ua.includes('Chrome/')) browser = 'Chrome';
  else if (ua.includes('Firefox/')) browser = 'Firefox';
  else if (ua.includes('Safari/')) browser = 'Safari';
  let os = '';
  if (ua.includes('iPhone')) os = 'iPhone';
  else if (ua.includes('iPad')) os = 'iPad';
  else if (ua.includes('Android')) { os = 'Android'; const m = ua.match(/;\s*([^;)]+)\s*Build/); if (m) os = m[1].trim(); }
  else if (ua.includes('Windows NT 10')) os = 'Windows';
  else if (ua.includes('Windows NT')) os = 'Windows';
  else if (ua.includes('Mac OS X')) os = 'Mac';
  else if (ua.includes('Linux')) os = 'Linux';
  return os ? `${browser} · ${os}` : browser;
}

// ==================== GITHUB HELPER ====================
async function ghAPI(urlPath, options = {}) {
  const url = urlPath.startsWith('http') ? urlPath : `${GITHUB_API}/repos/${GITHUB_REPO}${urlPath}`;
  console.log('[GitHub API]', url);
  const res = await fetch(url, {
    ...options,
    headers: { 'Authorization': `Bearer ${GITHUB_TOKEN}`, 'Accept': options.accept || 'application/vnd.github.v3+json', 'User-Agent': 'DocViewer', ...options.headers }
  });
  if (!res.ok) {
    const body = await res.text();
    console.error('[GitHub Error]', res.status, body);
    throw new Error(`GitHub ${res.status}: ${body}`);
  }
  if (options.raw) return res;
  return res.json();
}

// ==================== AUTH ====================
app.post('/api/login', async (req, res) => {
  try {
    const { username, password, browserInfo } = req.body;
    const r = await pool.query('SELECT * FROM doc_users WHERE username = $1', [username]);
    const user = r.rows[0];
    if (!user || !bcrypt.compareSync(password, user.password)) {
      logAudit(username || 'unknown', 'LOGIN_FAILED', 'Invalid credentials', getDevice(req));
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const browser = browserInfo || parseBrowser(req.headers['user-agent'] || '');
    req.session.user = { id: user.id, username: user.username, role: user.role, avatarColor: user.avatar_color };
    req.session.lastActivity = Date.now();
    const log = await pool.query('INSERT INTO login_logs (username, ip_address, browser_info) VALUES ($1, $2, $3) RETURNING id', [user.username, getDevice(req), browser]);
    req.session.loginLogId = log.rows[0].id;
    logAudit(user.username, 'LOGIN', `Via ${browser}`, getDevice(req));
    res.json({ username: user.username, role: user.role, avatarColor: user.avatar_color });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/logout', async (req, res) => {
  if (!req.session.user) return res.json({ ok: true });
  logAudit(req.session.user.username, 'LOGOUT', 'Logged out', getDevice(req));
  if (req.session.loginLogId) await pool.query('UPDATE login_logs SET logout_time = NOW() WHERE id = $1', [req.session.loginLogId]).catch(() => {});
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  res.json({ ...req.session.user, sessionTimeout: SESSION_TIMEOUT_MS });
});

// ==================== SESSIONS ====================
app.get('/api/active-sessions', adminOnly, async (req, res) => {
  try {
    const r = await pool.query(`SELECT username, login_time, logout_time, ip_address, COALESCE(NULLIF(browser_info,''), 'Web Browser') as browser_info FROM login_logs ORDER BY login_time DESC LIMIT 100`);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== USERS ====================
app.get('/api/users', adminOnly, async (req, res) => {
  const r = await pool.query('SELECT id, username, role, avatar_color, created_at FROM doc_users ORDER BY username');
  res.json(r.rows);
});
app.post('/api/users', adminOnly, async (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const exists = await pool.query('SELECT id FROM doc_users WHERE username = $1', [username]);
    if (exists.rows.length) return res.status(400).json({ error: 'Username exists' });
    const colors = ['#6366f1', '#8b5cf6', '#ec4899', '#f43f5e', '#f97316', '#eab308', '#22c55e', '#06b6d4', '#3b82f6'];
    await pool.query('INSERT INTO doc_users (username, password, role, avatar_color) VALUES ($1,$2,$3,$4)',
      [username, bcrypt.hashSync(password, 10), role || 'user', colors[Math.floor(Math.random() * colors.length)]]);
    logAudit(req.session.user.username, 'USER_CREATED', `Created: ${username}`, getDevice(req));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/users/:id', adminOnly, async (req, res) => {
  const r = await pool.query('SELECT username FROM doc_users WHERE id = $1', [req.params.id]);
  await pool.query('DELETE FROM doc_users WHERE id = $1 AND role != $2', [req.params.id, 'admin']);
  if (r.rows[0]) logAudit(req.session.user.username, 'USER_DELETED', `Deleted: ${r.rows[0].username}`, getDevice(req));
  res.json({ ok: true });
});
app.post('/api/users/change-password', auth, async (req, res) => {
  const { userId, newPassword } = req.body;
  if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: 'Min 4 chars' });
  const targetId = req.session.user.role === 'admin' && userId ? userId : req.session.user.id;
  await pool.query('UPDATE doc_users SET password = $1 WHERE id = $2', [bcrypt.hashSync(newPassword, 10), targetId]);
  logAudit(req.session.user.username, 'PASSWORD_CHANGED', `User ID: ${targetId}`, getDevice(req));
  res.json({ ok: true });
});

// ==================== GITHUB BROWSE ====================
app.get('/api/folders', auth, async (req, res) => {
  try {
    const data = await ghAPI(`/contents?ref=${GITHUB_BRANCH}`);
    const items = (Array.isArray(data) ? data : []).map(i => ({ name: i.name, path: i.path, type: i.type, size: i.size || 0 }));
    res.json(items);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/browse/*', auth, async (req, res) => {
  try {
    const folderPath = req.params[0];
    const data = await ghAPI(`/contents/${folderPath}?ref=${GITHUB_BRANCH}`);
    const items = (Array.isArray(data) ? data : [data]).map(i => ({ name: i.name, path: i.path, type: i.type, size: i.size || 0 }));
    res.json(items);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== DATE-BASED FILES ====================
app.get('/api/files-by-date', auth, async (req, res) => {
  try {
    const { date } = req.query;
    if (!date) return res.status(400).json({ error: 'Date required' });
    const since = `${date}T00:00:00Z`;
    const until = `${date}T23:59:59Z`;
    const commits = await ghAPI(`/commits?sha=${GITHUB_BRANCH}&since=${since}&until=${until}&per_page=100`);
    const filePaths = new Set();
    for (const c of commits) {
      try {
        const detail = await ghAPI(`/commits/${c.sha}`);
        (detail.files || []).forEach(f => {
          if (f.status !== 'removed' && f.filename !== '.gitkeep') filePaths.add(f.filename);
        });
      } catch (e) { /* skip */ }
    }
    const tree = await ghAPI(`/git/trees/${GITHUB_BRANCH}?recursive=1`);
    const treeMap = {};
    (tree.tree || []).forEach(t => { treeMap[t.path] = t; });
    const files = [...filePaths].filter(fp => treeMap[fp]).map(fp => ({
      name: fp.split('/').pop(), path: fp, size: treeMap[fp].size || 0, type: 'file'
    }));
    res.json(files);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== SEARCH ====================
app.get('/api/search', auth, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.length < 2) return res.json([]);
    const tree = await ghAPI(`/git/trees/${GITHUB_BRANCH}?recursive=1`);
    const query = q.toLowerCase();
    const results = (tree.tree || [])
      .filter(i => i.type === 'blob' && i.path.split('/').pop().toLowerCase().includes(query))
      .slice(0, 40)
      .map(i => ({ name: i.path.split('/').pop(), path: i.path, size: i.size || 0, type: 'file' }));
    res.json(results);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== PDF PROXY ====================
app.get('/api/pdf/*', auth, async (req, res) => {
  try {
    const filePath = req.params[0];
    const response = await fetch(`${GITHUB_API}/repos/${GITHUB_REPO}/contents/${filePath}?ref=${GITHUB_BRANCH}`, {
      headers: { 'Authorization': `Bearer ${GITHUB_TOKEN}`, 'Accept': 'application/vnd.github.v3.raw', 'User-Agent': 'DocViewer' }
    });
    if (!response.ok) throw new Error(`GitHub ${response.status}`);
    const buffer = await response.arrayBuffer();
    const fileName = filePath.split('/').pop();
    const vlog = await pool.query('INSERT INTO view_logs (username, file_path, file_name) VALUES ($1,$2,$3) RETURNING id', [req.session.user.username, filePath, fileName]);
    logAudit(req.session.user.username, 'VIEW_FILE', `Viewed: ${filePath}`, getDevice(req));
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'inline');
    res.setHeader('X-View-Log-Id', vlog.rows[0].id);
    res.send(Buffer.from(buffer));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Accurate view duration: client sends viewLogId + seconds on close
app.post('/api/view-log', auth, async (req, res) => {
  const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  const { viewLogId, filePath, durationSeconds } = body;
  const secs = Math.max(0, Math.min(durationSeconds || 0, 86400)); // cap at 24h
  if (viewLogId) {
    await pool.query(`UPDATE view_logs SET view_duration_seconds = $1, view_end = NOW() WHERE id = $2 AND username = $3`, [secs, viewLogId, req.session.user.username]);
  } else if (filePath) {
    await pool.query(`UPDATE view_logs SET view_duration_seconds = $1, view_end = NOW() WHERE id = (SELECT MAX(id) FROM view_logs WHERE username = $2 AND file_path = $3)`, [secs, req.session.user.username, filePath]);
  }
  res.json({ ok: true });
});

// ==================== PER-USER DOCUMENT TIME ====================
app.get('/api/user-doc-time', adminOnly, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT username, file_name, file_path,
             COUNT(*) as view_count,
             COALESCE(SUM(CASE WHEN view_duration_seconds > 0 THEN view_duration_seconds ELSE 0 END),0) as total_seconds,
             MAX(view_start) as last_viewed
      FROM view_logs
      GROUP BY username, file_name, file_path
      HAVING SUM(CASE WHEN view_duration_seconds > 0 THEN view_duration_seconds ELSE 0 END) > 0
      ORDER BY username, total_seconds DESC
    `);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== FAVORITES ====================
app.get('/api/favorites', auth, async (req, res) => {
  const r = await pool.query('SELECT file_path, file_name, added_at FROM favorites WHERE username = $1 ORDER BY added_at DESC', [req.session.user.username]);
  res.json(r.rows);
});
app.post('/api/favorites', auth, async (req, res) => {
  const { filePath, fileName } = req.body;
  await pool.query('INSERT INTO favorites (username, file_path, file_name) VALUES ($1,$2,$3) ON CONFLICT(username, file_path) DO NOTHING', [req.session.user.username, filePath, fileName]);
  res.json({ ok: true });
});
app.delete('/api/favorites/*', auth, async (req, res) => {
  await pool.query('DELETE FROM favorites WHERE username = $1 AND file_path = $2', [req.session.user.username, req.params[0]]);
  res.json({ ok: true });
});

// ==================== RECENT ====================
app.get('/api/recent', auth, async (req, res) => {
  const r = await pool.query(`SELECT DISTINCT ON (file_path) file_path, file_name, view_start, view_duration_seconds FROM view_logs WHERE username = $1 ORDER BY file_path, view_start DESC`, [req.session.user.username]);
  res.json(r.rows.sort((a, b) => new Date(b.view_start) - new Date(a.view_start)).slice(0, 20));
});

// ==================== DASHBOARD STATS ====================
app.get('/api/dashboard-stats', auth, async (req, res) => {
  const u = req.session.user.username, isAdmin = req.session.user.role === 'admin';
  const views = await pool.query(isAdmin ? 'SELECT COUNT(*) as c FROM view_logs' : 'SELECT COUNT(*) as c FROM view_logs WHERE username=$1', isAdmin ? [] : [u]);
  const favs = await pool.query('SELECT COUNT(*) as c FROM favorites WHERE username=$1', [u]);
  const time = await pool.query(isAdmin ? 'SELECT COALESCE(SUM(view_duration_seconds),0) as t FROM view_logs' : 'SELECT COALESCE(SUM(view_duration_seconds),0) as t FROM view_logs WHERE username=$1', isAdmin ? [] : [u]);
  const users = isAdmin ? (await pool.query("SELECT COUNT(*) as c FROM doc_users WHERE role='user'")).rows[0].c : '0';
  const today = isAdmin ? (await pool.query("SELECT COUNT(*) as c FROM login_logs WHERE login_time::date = CURRENT_DATE")).rows[0].c : '0';
  res.json({ totalViews: +views.rows[0].c, totalFavorites: +favs.rows[0].c, totalTimeMinutes: Math.round(+time.rows[0].t / 60), totalUsers: +users, todayLogins: +today });
});

// ==================== NOTIFICATIONS ====================
app.get('/api/notifications', auth, async (req, res) => {
  const r = await pool.query(`SELECT n.*, nr.read_at IS NOT NULL as is_read FROM notifications n LEFT JOIN notification_reads nr ON nr.notification_id=n.id AND nr.username=$1 WHERE n.target_role='all' OR n.target_role=$2 OR n.target_user=$1 ORDER BY n.created_at DESC LIMIT 50`, [req.session.user.username, req.session.user.role]);
  res.json(r.rows);
});
app.get('/api/notifications/unread-count', auth, async (req, res) => {
  const r = await pool.query(`SELECT COUNT(*) as c FROM notifications n WHERE (n.target_role='all' OR n.target_role=$2 OR n.target_user=$1) AND NOT EXISTS (SELECT 1 FROM notification_reads nr WHERE nr.notification_id=n.id AND nr.username=$1)`, [req.session.user.username, req.session.user.role]);
  res.json({ count: +r.rows[0].c });
});
app.post('/api/notifications/read/:id', auth, async (req, res) => {
  await pool.query('INSERT INTO notification_reads (notification_id, username) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.params.id, req.session.user.username]);
  res.json({ ok: true });
});
app.post('/api/notifications/read-all', auth, async (req, res) => {
  await pool.query(`INSERT INTO notification_reads (notification_id, username) SELECT n.id, $1 FROM notifications n WHERE (n.target_role='all' OR n.target_role=$2 OR n.target_user=$1) AND NOT EXISTS (SELECT 1 FROM notification_reads nr WHERE nr.notification_id=n.id AND nr.username=$1)`, [req.session.user.username, req.session.user.role]);
  res.json({ ok: true });
});
app.post('/api/notifications', adminOnly, async (req, res) => {
  const { title, message, type, targetRole } = req.body;
  await pool.query('INSERT INTO notifications (title, message, type, target_role, created_by) VALUES ($1,$2,$3,$4,$5)', [title, message || '', type || 'info', targetRole || 'all', req.session.user.username]);
  res.json({ ok: true });
});

// ==================== AUDIT LOG ====================
app.get('/api/audit-log', adminOnly, async (req, res) => {
  const pg = parseInt(req.query.page) || 1, lim = Math.min(parseInt(req.query.limit) || 50, 200), off = (pg - 1) * lim;
  const r = await pool.query('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT $1 OFFSET $2', [lim, off]);
  const total = await pool.query('SELECT COUNT(*) as c FROM audit_log');
  res.json({ logs: r.rows, total: +total.rows[0].c, page: pg, limit: lim });
});

// ==================== CLEANUP: DELETE LOGS OLDER THAN 3 MONTHS ====================
app.post('/api/admin/cleanup-logs', adminOnly, async (req, res) => {
  try {
    const { types = [], months = 3 } = req.body || {};
    const allowed = ['login_logs', 'view_logs', 'audit_log', 'notifications'];
    const selected = types.filter(t => allowed.includes(t));
    if (!selected.length) return res.status(400).json({ error: 'No valid data types selected' });
    const m = Math.max(0, Math.min(12, parseInt(months)));
    const deleted = {};
    let total = 0;
    const timeCol = { login_logs: 'login_time', view_logs: 'view_start', audit_log: 'created_at', notifications: 'created_at' };
    const labels = { login_logs: 'loginLogs', view_logs: 'viewLogs', audit_log: 'auditLogs', notifications: 'notifications' };
    for (const t of selected) {
      const r = m === 0
        ? await pool.query(`DELETE FROM ${t} RETURNING id`)
        : await pool.query(`DELETE FROM ${t} WHERE ${timeCol[t]} < NOW() - INTERVAL '${m} months' RETURNING id`);
      deleted[labels[t]] = r.rowCount;
      total += r.rowCount;
    }
    deleted.total = total;
    const parts = selected.map(t => `${labels[t]}:${deleted[labels[t]]}`).join(', ');
    logAudit(req.session.user.username, 'LOGS_CLEANUP', `Deleted ${total} records ${m===0?'(all data)':'older than '+m+'mo'} (${parts})`, getDevice(req));
    res.json({ ok: true, deleted });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== UPLOAD / MANAGE ====================
app.post('/api/upload', adminOnly, async (req, res) => {
  try {
    const { folderPath, fileName, fileContent } = req.body;
    const fullPath = folderPath ? `${folderPath}/${fileName}` : fileName;
    let sha = null;
    try { sha = (await ghAPI(`/contents/${fullPath}?ref=${GITHUB_BRANCH}`)).sha; } catch (e) {}
    const body = { message: `Upload ${fileName}`, content: fileContent, branch: GITHUB_BRANCH };
    if (sha) body.sha = sha;
    const r = await fetch(`${GITHUB_API}/repos/${GITHUB_REPO}/contents/${fullPath}`, {
      method: 'PUT', headers: { 'Authorization': `Bearer ${GITHUB_TOKEN}`, 'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'DocViewer', 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!r.ok) throw new Error(await r.text());
    logAudit(req.session.user.username, 'FILE_UPLOADED', `Uploaded: ${fullPath}`, getDevice(req));
    await pool.query('INSERT INTO notifications (title, message, type, target_role, created_by) VALUES ($1,$2,$3,$4,$5)',
      [`New document uploaded`, `"${fileName}" added to ${folderPath || 'root'}`, 'upload', 'user', req.session.user.username]);
    res.json({ ok: true, path: fullPath });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/create-folder', adminOnly, async (req, res) => {
  try {
    const { folderPath } = req.body;
    const r = await fetch(`${GITHUB_API}/repos/${GITHUB_REPO}/contents/${folderPath}/.gitkeep`, {
      method: 'PUT', headers: { 'Authorization': `Bearer ${GITHUB_TOKEN}`, 'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'DocViewer', 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: `Create ${folderPath}`, content: '', branch: GITHUB_BRANCH })
    });
    if (!r.ok) throw new Error(await r.text());
    logAudit(req.session.user.username, 'FOLDER_CREATED', `Created: ${folderPath}`, getDevice(req));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/files/*', adminOnly, async (req, res) => {
  try {
    const fp = req.params[0];
    const existing = await ghAPI(`/contents/${fp}?ref=${GITHUB_BRANCH}`);
    const r = await fetch(`${GITHUB_API}/repos/${GITHUB_REPO}/contents/${fp}`, {
      method: 'DELETE', headers: { 'Authorization': `Bearer ${GITHUB_TOKEN}`, 'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'DocViewer', 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: `Delete ${fp}`, sha: existing.sha, branch: GITHUB_BRANCH })
    });
    if (!r.ok) throw new Error(await r.text());
    logAudit(req.session.user.username, 'FILE_DELETED', `Deleted: ${fp}`, getDevice(req));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==================== ANALYTICS ====================
app.get('/api/analytics/logins', adminOnly, async (req, res) => {
  const d = parseInt(req.query.days) || 30;
  const perDay = await pool.query(`SELECT login_time::date as date, COUNT(*) as count FROM login_logs WHERE login_time >= NOW() - INTERVAL '${d} days' GROUP BY login_time::date ORDER BY date`);
  const perUser = await pool.query(`SELECT username, COUNT(*) as count FROM login_logs WHERE login_time >= NOW() - INTERVAL '${d} days' GROUP BY username ORDER BY count DESC`);
  const timeSpent = await pool.query(`SELECT username, COALESCE(SUM(EXTRACT(EPOCH FROM (COALESCE(logout_time, NOW()) - login_time))),0) as total_seconds FROM login_logs WHERE login_time >= NOW() - INTERVAL '${d} days' GROUP BY username ORDER BY total_seconds DESC`);
  res.json({ loginsPerDay: perDay.rows, loginsPerUser: perUser.rows, timeSpentPerUser: timeSpent.rows.map(r => ({ username: r.username, totalMinutes: Math.round(parseFloat(r.total_seconds) / 60) })) });
});
app.get('/api/analytics/views', adminOnly, async (req, res) => {
  const d = parseInt(req.query.days) || 30;
  const perDay = await pool.query(`SELECT view_start::date as date, COUNT(*) as count FROM view_logs WHERE view_start >= NOW() - INTERVAL '${d} days' GROUP BY view_start::date ORDER BY date`);
  const topFiles = await pool.query(`SELECT file_path, file_name, COUNT(*) as view_count, COALESCE(SUM(view_duration_seconds),0) as total_duration FROM view_logs WHERE view_start >= NOW() - INTERVAL '${d} days' GROUP BY file_path, file_name ORDER BY view_count DESC LIMIT 20`);
  const perUser = await pool.query(`SELECT username, COUNT(*) as view_count, COALESCE(SUM(view_duration_seconds),0) as total_duration FROM view_logs WHERE view_start >= NOW() - INTERVAL '${d} days' GROUP BY username ORDER BY view_count DESC`);
  res.json({ viewsPerDay: perDay.rows, topFiles: topFiles.rows, viewsPerUser: perUser.rows });
});
app.get('/api/analytics/export', adminOnly, async (req, res) => {
  const { type, days } = req.query; const d = parseInt(days) || 30;
  let rows, headers;
  if (type === 'logins') { const r = await pool.query(`SELECT username, login_time, logout_time, ip_address, COALESCE(NULLIF(browser_info,''),'Web Browser') as browser_info FROM login_logs WHERE login_time >= NOW() - INTERVAL '${d} days' ORDER BY login_time DESC`); headers = 'Username,Login Time,Logout Time,IP,Browser'; rows = r.rows.map(r => `${r.username},${r.login_time},${r.logout_time || ''},${r.ip_address},${r.browser_info}`); }
  else if (type === 'views') { const r = await pool.query(`SELECT username, file_path, file_name, view_start, view_duration_seconds FROM view_logs WHERE view_start >= NOW() - INTERVAL '${d} days' ORDER BY view_start DESC`); headers = 'Username,Path,Name,Start,Duration(s)'; rows = r.rows.map(r => `${r.username},${r.file_path},${r.file_name},${r.view_start},${r.view_duration_seconds}`); }
  else if (type === 'audit') { const r = await pool.query(`SELECT username, action, details, ip_address, created_at FROM audit_log WHERE created_at >= NOW() - INTERVAL '${d} days' ORDER BY created_at DESC`); headers = 'Username,Action,Details,IP,Time'; rows = r.rows.map(r => `${r.username},${r.action},"${(r.details || '').replace(/"/g, '""')}",${r.ip_address},${r.created_at}`); }
  else return res.status(400).json({ error: 'Invalid type' });
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename=${type}-export.csv`);
  res.send(headers + '\n' + rows.join('\n'));
});

// ==================== SERVE ====================
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Auto-cleanup logs older than 3 months (runs on startup + every 24 hours)
async function autoCleanup() {
  try {
    const r1 = await pool.query(`DELETE FROM login_logs WHERE login_time < NOW() - INTERVAL '3 months' RETURNING id`);
    const r2 = await pool.query(`DELETE FROM view_logs WHERE view_start < NOW() - INTERVAL '3 months' RETURNING id`);
    const r3 = await pool.query(`DELETE FROM notifications WHERE created_at < NOW() - INTERVAL '3 months' RETURNING id`);
    const total = r1.rowCount + r2.rowCount + r3.rowCount;
    if (total > 0) console.log(`Auto-cleanup: deleted ${total} records older than 3 months`);
  } catch (e) { console.error('Auto-cleanup error:', e.message); }
}

initDB().then(() => {
  app.listen(PORT, () => console.log(`DocViewer running on http://localhost:${PORT}`));
  autoCleanup(); // run on startup
  setInterval(autoCleanup, 24 * 60 * 60 * 1000); // run every 24 hours
}).catch(e => { console.error('DB failed:', e); process.exit(1); });
