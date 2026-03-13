# SOC Alert Platform — Integration Guide

Your website will be monitored for:
- SQL Injection attacks
- XSS attempts  
- Path traversal attacks
- Admin panel probing
- Login brute force
- Directory scanning

You will receive instant Slack alerts when attacks are detected.

---

## Express.js / Node.js

**Step 1** — Copy `soc_express.js` into your project root

**Step 2** — Edit line 10 in `soc_express.js`:
```
const SITE_NAME = "your-actual-domain.com";
```

**Step 3** — Add these 2 lines to your `app.js` or `server.js`:
```javascript
const socMonitor = require('./soc_express');
app.use(socMonitor);
```

**Done.** Restart your server. You're protected.

---

## Django

**Step 1** — Copy `soc_django.py` into your Django project root

**Step 2** — Edit line 14 in `soc_django.py`:
```
SITE_NAME = "your-actual-domain.com"
```

**Step 3** — Add to `settings.py` MIDDLEWARE list:
```python
MIDDLEWARE = [
    ...
    'soc_django.SOCMiddleware',  # ← add this line
]
```

**Done.** Restart your server. You're protected.

---

## Flask

**Step 1** — Copy `soc_flask.py` into your Flask project root

**Step 2** — Edit line 15 in `soc_flask.py`:
```
SITE_NAME = "your-actual-domain.com"
```

**Step 3** — Add these 2 lines to your `app.py`:
```python
from soc_flask import init_soc_monitor
init_soc_monitor(app)
```

**Done.** Restart your server. You're protected.

---

## Test Your Integration

After adding the middleware, test it works:
```bash
curl -X GET "https://your-site.com/login?id=1 UNION SELECT * FROM users"
```

You should receive a Slack alert within 5 seconds.

---

Built by: SOC Alert Platform
Contact: ViNiT-0
