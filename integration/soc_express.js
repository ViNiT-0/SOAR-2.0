// ============================================================
// SOC Alert Platform — Express.js Integration
// ------------------------------------------------------------
// Paste this file into your project and add ONE line to app.js
//
// In your app.js / server.js:
//   const socMonitor = require('./soc_express');
//   app.use(socMonitor);
// ============================================================

const SOC_API     = "https://crewless-lastly-homer.ngrok-free.dev/api/ingest";
const SOC_API_KEY = "soc-secret-key-2026";
const SITE_NAME   = "your-website.com";   // ← change this

function socMonitor(req, res, next) {
    res.on('finish', () => {
        // Skip health checks and static files
        if (req.path === '/health' || req.path.match(/\.(css|js|png|jpg|ico)$/)) {
            return;
        }

        const payload = {
            ip:          req.headers['x-forwarded-for'] || req.ip,
            url:         req.originalUrl,
            method:      req.method,
            status_code: res.statusCode,
            site:        SITE_NAME,
            user_agent:  req.headers['user-agent'] || '',
            body:        req.method === 'POST' ? JSON.stringify(req.body || {}) : ''
        };

        fetch(SOC_API, {
            method:  'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-Key':    SOC_API_KEY
            },
            body: JSON.stringify(payload)
        }).catch(() => {});  // Silent fail — never breaks your site
    });
    next();
}

module.exports = socMonitor;
