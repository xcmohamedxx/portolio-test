const express = require('express');
const fetch = require('node-fetch'); // npm i node-fetch@2
const path = require('path');
const security = require('./security');

const app = express();
const PORT = process.env.PORT || 3000;
const BACKEND = process.env.BACKEND_URL || null; // e.g. https://your-api.example.com

const fs = require('fs');
const DATA_DIR = path.resolve(__dirname, 'data');
const PORTFOLIOS_FILE = path.join(DATA_DIR, 'portfolios.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Simple file-backed storage for portfolios
function loadPortfolios() {
  try {
    if (!fs.existsSync(PORTFOLIOS_FILE)) return [];
    const txt = fs.readFileSync(PORTFOLIOS_FILE, 'utf8');
    return JSON.parse(txt || '[]');
  } catch (e) {
    console.error('Failed to load portfolios:', e);
    return [];
  }
}

function savePortfolios(portfolios) {
  try {
    fs.writeFileSync(PORTFOLIOS_FILE, JSON.stringify(portfolios, null, 2), 'utf8');
    return true;
  } catch (e) {
    console.error('Failed to save portfolios:', e);
    return false;
  }
}

let portfolios = loadPortfolios();

app.use(express.json());

/* ============ Security Middleware ============ */
// IP blocking and rate limiting middleware
app.use((req, res, next) => {
  const ip = security.getClientIP(req);
  const fingerprint = security.generateFingerprint(req);

  // Track request
  security.trackRequest(ip);

  // Check if IP is blocked
  if (security.isIPBlocked(ip)) {
    console.warn(`🚨 BLOCKED REQUEST from ${ip}`);
    return res.status(403).json({ 
      error: 'Access denied', 
      message: 'Your IP has been temporarily blocked due to suspicious activity' 
    });
  }

  // Check rate limit
  if (!security.checkRateLimit(ip)) {
    console.warn(`⚠️ RATE LIMIT EXCEEDED for ${ip}`);
    return res.status(429).json({ 
      error: 'Too many requests',
      message: 'Please wait before making another request'
    });
  }

  // Check payload for injection attempts
  if (req.method !== 'GET' && req.body && !security.validatePayload(req.body)) {
    console.warn(`🚨 INJECTION ATTEMPT from ${ip}: ${JSON.stringify(req.body).substring(0, 100)}`);
    security.addSuspiciousPoints(ip, 5, 'Injection attempt detected');
    return res.status(400).json({ 
      error: 'Invalid request', 
      message: 'Request contains invalid data' 
    });
  }

  // Check fingerprint
  if (security.isFingerprintSuspicious(fingerprint)) {
    console.warn(`🚨 SUSPICIOUS FINGERPRINT from ${ip}`);
    security.addSuspiciousPoints(ip, 3, 'Suspicious fingerprint detected');
  }

  // Store IP and fingerprint in request for later use
  req.clientIP = ip;
  req.clientFingerprint = fingerprint;

  next();
});

// Log all requests for audit trail
app.use((req, res, next) => {
  const originalSend = res.send;
  res.send = function(data) {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - IP: ${req.clientIP}`);
    return originalSend.call(this, data);
  };
  next();
});

// proxy /api/* to BACKEND if configured
if (BACKEND) {
  app.use('/api', async (req, res) => {
    const url = BACKEND.replace(/\/$/, '') + req.originalUrl; // includes /api/...
    const opts = {
      method: req.method,
      headers: Object.assign({}, req.headers, { host: new URL(BACKEND).host }),
    };
    if (['POST','PUT','PATCH'].includes(req.method)) opts.body = JSON.stringify(req.body);
    try {
      const r = await fetch(url, opts);
      const text = await r.text();
      res.status(r.status).set(Object.fromEntries(r.headers.entries())).send(text);
    } catch (e) {
      res.status(502).json({ error: 'Bad gateway', details: String(e) });
    }
  });
}

/* ============ Portfolio API ============ */
// Optimize portfolio fetching
app.get('/api/portfolios', (req, res) => {
  res.json(portfolios.map((p) => ({
    id: p.id,
    name: p.name,
    email: p.email,
    bio: p.bio,
    skills: p.skills,
    profilePic: p.profilePic,
    verified: p.verified || false,
    created: p.created,
  })));
});

// Enhanced validation for portfolio creation
app.post('/api/portfolios', (req, res) => {
  const { name, email, bio, skills, profilePic, services, portfolio } = req.body || {};

  // Basic validation
  if (!name || typeof name !== 'string' || name.trim().length < 2) {
    return res.status(400).json({ error: 'Invalid name. Must be at least 2 characters.' });
  }

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }

  if (!bio || typeof bio !== 'string' || bio.trim().length < 10) {
    return res.status(400).json({ error: 'Bio must be at least 10 characters.' });
  }

  if (!skills || typeof skills !== 'string') {
    return res.status(400).json({ error: 'Skills must be a comma-separated string.' });
  }

  if (services && !Array.isArray(services)) {
    return res.status(400).json({ error: 'Services must be an array.' });
  }

  if (portfolio && !Array.isArray(portfolio)) {
    return res.status(400).json({ error: 'Portfolio items must be an array.' });
  }

  const id = Date.now().toString();
  const created = new Date().toISOString();
  const newPortfolio = {
    id,
    name,
    email,
    bio,
    skills,
    profilePic: profilePic || null,
    services: services || [],
    portfolio: portfolio || [],
    created,
    lastModified: created,
  };

  portfolios.push(newPortfolio);
  savePortfolios(portfolios);
  res.status(201).json(newPortfolio);
});

// Patch/update a portfolio
app.patch('/api/portfolios/:id', (req, res) => {
  const id = req.params.id;
  const body = req.body || {};
  const idx = portfolios.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'not found' });

  // If request attempts to set verified flag, you may want to protect this in production
  if (body.verified === true) {
    // optional: require admin key via query ?adminKey=...
    const adminKey = req.query.adminKey || process.env.ADMIN_KEY;
    // If ADMIN_KEY is set in env, require it, otherwise allow for local dev
    if (process.env.ADMIN_KEY && req.query.adminKey !== process.env.ADMIN_KEY) {
      return res.status(401).json({ error: 'admin key required to set verified' });
    }
  }

  portfolios[idx] = Object.assign({}, portfolios[idx], body, { lastModified: new Date().toISOString() });
  savePortfolios(portfolios);
  res.json(portfolios[idx]);
});

// serve static files (index.html, index.html, etc.)
app.use(express.static(path.resolve(__dirname)));

/* ============ Security API Endpoints (Admin) ============ */
// Get security report (admin endpoint - in production, add authentication)
app.get('/api/security/report', (req, res) => {
  // In production, add proper authentication here
  const adminKey = req.query.key;
  if (!adminKey || adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const report = security.getSecurityReport();
  res.json(report);
});

// Get IP info
app.get('/api/security/ip/:ip', (req, res) => {
  const adminKey = req.query.key;
  if (!adminKey || adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const ip = req.params.ip;
  const ipData = security.data.ipLog[ip];

  if (!ipData) {
    return res.json({ ip, tracked: false });
  }

  res.json({
    ip,
    tracked: true,
    blocked: ipData.blocked,
    failedLogins: ipData.failedLogins,
    suspiciousPoints: ipData.suspiciousPoints,
    recentRequests: ipData.requests.length,
    blockTime: ipData.blockTime ? new Date(ipData.blockTime).toISOString() : null
  });
});

// Manually block IP
app.post('/api/security/block-ip', (req, res) => {
  const adminKey = req.query.key;
  if (!adminKey || adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { ip, reason } = req.body;
  if (!ip) {
    return res.status(400).json({ error: 'IP required' });
  }

  security.blockIP(ip, reason || 'Manual admin block');
  res.json({ success: true, message: `IP ${ip} blocked` });
});

// Unblock IP
app.post('/api/security/unblock-ip', (req, res) => {
  const adminKey = req.query.key;
  if (!adminKey || adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { ip } = req.body;
  if (!ip) {
    return res.status(400).json({ error: 'IP required' });
  }

  if (security.data.ipLog[ip]) {
    security.data.ipLog[ip].blocked = false;
    security.data.ipLog[ip].blockTime = null;
    security.data.ipLog[ip].failedLogins = 0;
    security.saveSecurityData();
  }

  const idx = security.data.blockedIPs.indexOf(ip);
  if (idx !== -1) {
    security.data.blockedIPs.splice(idx, 1);
    security.saveSecurityData();
  }

  res.json({ success: true, message: `IP ${ip} unblocked` });
});

// Verify fingerprint
app.post('/api/security/verify-fingerprint', (req, res) => {
  const adminKey = req.query.key;
  if (!adminKey || adminKey !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { fingerprint, safe } = req.body;
  if (!fingerprint) {
    return res.status(400).json({ error: 'Fingerprint required' });
  }

  const idx = security.data.flaggedFingerprints.indexOf(fingerprint);
  
  if (safe && idx !== -1) {
    security.data.flaggedFingerprints.splice(idx, 1);
    security.saveSecurityData();
    res.json({ success: true, message: 'Fingerprint verified as safe' });
  } else if (!safe && idx === -1) {
    security.flagFingerprint(fingerprint, 'Admin flagged');
    res.json({ success: true, message: 'Fingerprint flagged as suspicious' });
  } else {
    res.json({ success: true, message: 'No change needed' });
  }
});

// In-memory user storage (for simplicity; replace with a database in production)
const users = {};

// Initialize admin account
const ADMIN_USERNAME = 'mohamed';
const ADMIN_PASSWORD = '@Simovites9';

users[ADMIN_USERNAME] = {
  username: ADMIN_USERNAME,
  password: ADMIN_PASSWORD,
  isAdmin: true,
};

// Middleware to check if the user is an admin
function requireAdmin(req, res, next) {
  const { username } = req.body || {};
  const user = users[username];

  if (!user || !user.isAdmin) {
    return res.status(403).json({ message: 'Admin access required.' });
  }

  next();
}

// Register a new user
app.post('/register', (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  if (users[username]) {
    return res.status(400).json({ message: 'Username already exists.' });
  }

  users[username] = { username, password }; // In production, hash the password
  res.status(201).json({ username });
});

// Login an existing user
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  const user = users[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ message: 'Invalid username or password.' });
  }

  res.status(200).json({ username });
});

// Admin endpoint to manage portfolios
app.delete('/api/portfolios/:id', requireAdmin, (req, res) => {
  const id = req.params.id;
  const index = portfolios.findIndex((p) => p.id === id);

  if (index === -1) {
    return res.status(404).json({ message: 'Portfolio not found.' });
  }

  portfolios.splice(index, 1);
  savePortfolios(portfolios);
  res.status(200).json({ message: 'Portfolio deleted successfully.' });
});

app.patch('/api/portfolios/:id/verify', requireAdmin, (req, res) => {
  const id = req.params.id;
  const portfolio = portfolios.find((p) => p.id === id);

  if (!portfolio) {
    return res.status(404).json({ message: 'Portfolio not found.' });
  }

  portfolio.verified = true;
  savePortfolios(portfolios);
  res.status(200).json({ message: 'Portfolio verified successfully.' });
});

app.patch('/api/portfolios/:id/unverify', requireAdmin, (req, res) => {
  const id = req.params.id;
  const portfolio = portfolios.find((p) => p.id === id);

  if (!portfolio) {
    return res.status(404).json({ message: 'Portfolio not found.' });
  }

  portfolio.verified = false;
  savePortfolios(portfolios);
  res.status(200).json({ message: 'Portfolio unverified successfully.' });
});

// Fallback - serve index.html for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.resolve(__dirname, 'index.html'));
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════╗
║     🚀 Portfolio Hub Server Started             ║
╚════════════════════════════════════════════════╝

  📍 URL: http://localhost:${PORT}
  🔐 Security: Active (IP tracking & rate limiting)
  📊 Backend: ${BACKEND ? BACKEND : 'None (local only)'}
  
  Admin Credentials:
  👤 Username: mohamed
  🔒 Password: @Simovites9
  
  Ready to accept connections!
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 Server shutting down gracefully...');
  server.close(() => {
    console.log('✓ Server closed');
    process.exit(0);
  });
});
