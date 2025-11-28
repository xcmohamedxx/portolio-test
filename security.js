/**
 * Security Module - Rate Limiting, IP Tracking, and Attack Prevention
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SECURITY_DB_PATH = path.join(__dirname, 'security-data.json');
const MAX_REQUESTS_PER_MINUTE = 30; // Requests per minute per IP
const MAX_FAILED_LOGINS = 5; // Failed login attempts before temporary block
const BLOCK_DURATION_MINUTES = 15; // How long to block suspicious IPs
const SUSPICIOUS_THRESHOLD = 10; // Suspicious activity points threshold

class SecurityManager {
  constructor() {
    this.data = this.loadSecurityData();
    this.startCleanupInterval();
  }

  loadSecurityData() {
    try {
      if (fs.existsSync(SECURITY_DB_PATH)) {
        return JSON.parse(fs.readFileSync(SECURITY_DB_PATH, 'utf8'));
      }
    } catch (e) {
      console.error('Error loading security data:', e.message);
    }
    return {
      ipLog: {}, // {ip: {requests: [], failedLogins: 0, suspiciousPoints: 0, blocked: false, blockTime: null}}
      blockedIPs: [],
      flaggedFingerprints: [],
      suspiciousPatterns: [],
      alertLog: []
    };
  }

  saveSecurityData() {
    try {
      fs.writeFileSync(SECURITY_DB_PATH, JSON.stringify(this.data, null, 2));
    } catch (e) {
      console.error('Error saving security data:', e.message);
    }
  }

  /**
   * Generate a fingerprint from request headers and user agent
   */
  generateFingerprint(req) {
    const components = [
      req.headers['user-agent'] || '',
      req.headers['accept-language'] || '',
      req.headers['accept-encoding'] || '',
      req.get('accept') || ''
    ].join('|');
    
    return crypto
      .createHash('sha256')
      .update(components)
      .digest('hex');
  }

  /**
   * Get client IP from request (handles proxies)
   */
  getClientIP(req) {
    return (
      req.headers['x-forwarded-for']?.split(',')[0].trim() ||
      req.headers['x-real-ip'] ||
      req.ip ||
      req.connection.remoteAddress ||
      'unknown'
    );
  }

  /**
   * Check if IP is currently blocked
   */
  isIPBlocked(ip) {
    const ipData = this.data.ipLog[ip];
    if (!ipData || !ipData.blocked) return false;

    // Check if block has expired
    const blockAge = Date.now() - ipData.blockTime;
    const blockDuration = BLOCK_DURATION_MINUTES * 60 * 1000;

    if (blockAge > blockDuration) {
      // Unblock after duration expires
      ipData.blocked = false;
      ipData.blockTime = null;
      ipData.failedLogins = 0;
      ipData.suspiciousPoints = 0;
      this.saveSecurityData();
      return false;
    }

    return true;
  }

  /**
   * Block an IP address
   */
  blockIP(ip, reason = 'Suspicious activity') {
    if (!this.data.ipLog[ip]) {
      this.data.ipLog[ip] = {
        requests: [],
        failedLogins: 0,
        suspiciousPoints: 0,
        blocked: false,
        blockTime: null
      };
    }

    this.data.ipLog[ip].blocked = true;
    this.data.ipLog[ip].blockTime = Date.now();

    if (!this.data.blockedIPs.includes(ip)) {
      this.data.blockedIPs.push(ip);
    }

    this.addAlert('IP_BLOCKED', ip, reason);
    this.saveSecurityData();

    console.warn(`🚨 SECURITY: IP blocked - ${ip} (Reason: ${reason})`);
  }

  /**
   * Add suspicious points to an IP
   */
  addSuspiciousPoints(ip, points = 1, reason = 'Unknown') {
    if (!this.data.ipLog[ip]) {
      this.data.ipLog[ip] = {
        requests: [],
        failedLogins: 0,
        suspiciousPoints: 0,
        blocked: false,
        blockTime: null
      };
    }

    this.data.ipLog[ip].suspiciousPoints += points;

    if (this.data.ipLog[ip].suspiciousPoints >= SUSPICIOUS_THRESHOLD) {
      this.blockIP(ip, `Suspicious activity threshold reached: ${reason}`);
      return true; // IP was blocked
    }

    return false;
  }

  /**
   * Track a request
   */
  trackRequest(ip) {
    if (!this.data.ipLog[ip]) {
      this.data.ipLog[ip] = {
        requests: [],
        failedLogins: 0,
        suspiciousPoints: 0,
        blocked: false,
        blockTime: null
      };
    }

    this.data.ipLog[ip].requests.push(Date.now());
  }

  /**
   * Check rate limit for an IP
   */
  checkRateLimit(ip) {
    if (!this.data.ipLog[ip]) return true; // Not rate limited

    const now = Date.now();
    const oneMinuteAgo = now - 60000;

    // Remove old requests outside the window
    this.data.ipLog[ip].requests = this.data.ipLog[ip].requests.filter(
      t => t > oneMinuteAgo
    );

    const requestCount = this.data.ipLog[ip].requests.length;

    if (requestCount >= MAX_REQUESTS_PER_MINUTE) {
      this.addSuspiciousPoints(ip, 2, 'Rate limit exceeded');
      return false; // Rate limited
    }

    return true; // Not rate limited
  }

  /**
   * Record failed login attempt
   */
  recordFailedLogin(ip) {
    if (!this.data.ipLog[ip]) {
      this.data.ipLog[ip] = {
        requests: [],
        failedLogins: 0,
        suspiciousPoints: 0,
        blocked: false,
        blockTime: null
      };
    }

    this.data.ipLog[ip].failedLogins += 1;

    if (this.data.ipLog[ip].failedLogins >= MAX_FAILED_LOGINS) {
      this.blockIP(ip, `Too many failed login attempts (${this.data.ipLog[ip].failedLogins})`);
      return true; // IP was blocked
    }

    this.addSuspiciousPoints(ip, 1, `Failed login attempt (${this.data.ipLog[ip].failedLogins}/${MAX_FAILED_LOGINS})`);
    this.saveSecurityData();
    return false;
  }

  /**
   * Reset failed login counter on successful login
   */
  resetFailedLogins(ip) {
    if (this.data.ipLog[ip]) {
      this.data.ipLog[ip].failedLogins = 0;
      this.data.ipLog[ip].suspiciousPoints = Math.max(0, this.data.ipLog[ip].suspiciousPoints - 2);
      this.saveSecurityData();
    }
  }

  /**
   * Flag a suspicious fingerprint
   */
  flagFingerprint(fingerprint, reason = 'Unknown') {
    if (!this.data.flaggedFingerprints.includes(fingerprint)) {
      this.data.flaggedFingerprints.push(fingerprint);
      this.addAlert('FINGERPRINT_FLAGGED', fingerprint, reason);
      this.saveSecurityData();
      console.warn(`🚨 SECURITY: Fingerprint flagged - ${fingerprint.substring(0, 16)}... (${reason})`);
    }
  }

  /**
   * Check if fingerprint is suspicious
   */
  isFingerprintSuspicious(fingerprint) {
    return this.data.flaggedFingerprints.includes(fingerprint);
  }

  /**
   * Add security alert to log
   */
  addAlert(type, target, reason = '') {
    const alert = {
      timestamp: new Date().toISOString(),
      type,
      target,
      reason
    };

    this.data.alertLog.push(alert);

    // Keep only last 1000 alerts
    if (this.data.alertLog.length > 1000) {
      this.data.alertLog = this.data.alertLog.slice(-1000);
    }

    this.saveSecurityData();
  }

  /**
   * Get security report
   */
  getSecurityReport() {
    const now = Date.now();
    const oneHourAgo = now - 3600000;

    const recentAlerts = this.data.alertLog.filter(
      a => new Date(a.timestamp).getTime() > oneHourAgo
    );

    const activeBlocks = Object.entries(this.data.ipLog)
      .filter(([ip, data]) => data.blocked)
      .map(([ip, data]) => ({
        ip,
        blockedAt: new Date(data.blockTime).toISOString(),
        failedLogins: data.failedLogins,
        suspiciousPoints: data.suspiciousPoints
      }));

    return {
      timestamp: new Date().toISOString(),
      totalBlockedIPs: this.data.blockedIPs.length,
      activeBlocks: activeBlocks.length,
      activeBlocksList: activeBlocks,
      recentAlertsCount: recentAlerts.length,
      recentAlerts: recentAlerts.slice(-20), // Last 20 alerts
      flaggedFingerprints: this.data.flaggedFingerprints.length
    };
  }

  /**
   * Clean up old data periodically
   */
  startCleanupInterval() {
    setInterval(() => {
      const now = Date.now();
      const oneDayAgo = now - 86400000; // 24 hours

      // Clean old requests from IP log
      for (const ip in this.data.ipLog) {
        this.data.ipLog[ip].requests = this.data.ipLog[ip].requests.filter(
          t => t > oneDayAgo
        );

        // Remove old IP logs with no activity
        if (
          this.data.ipLog[ip].requests.length === 0 &&
          !this.data.ipLog[ip].blocked &&
          this.data.ipLog[ip].failedLogins === 0
        ) {
          delete this.data.ipLog[ip];
        }
      }

      // Clean old alerts (keep last 7 days)
      const sevenDaysAgo = now - 7 * 86400000;
      this.data.alertLog = this.data.alertLog.filter(
        a => new Date(a.timestamp).getTime() > sevenDaysAgo
      );

      this.saveSecurityData();
    }, 3600000); // Run every hour
  }

  /**
   * Validate request payload for injection/XSS attempts
   */
  validatePayload(data) {
    const dangerousPatterns = [
      /<script/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /eval\(/i,
      /expression\(/i,
      /vbscript:/i,
      /<!--/,
      /-->/,
      /\x00/
    ];

    const payload = JSON.stringify(data);

    for (const pattern of dangerousPatterns) {
      if (pattern.test(payload)) {
        return false; // Dangerous payload detected
      }
    }

    return true;
  }
}

module.exports = new SecurityManager();
