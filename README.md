# 🛡️ PHP PrivacyShield

**A production-grade, DPDP Act 2023 compliance SaaS tool built with PHP & MySQL.**

[![PHP](https://img.shields.io/badge/PHP-8.1+-blue?logo=php)](https://php.net)
[![MySQL](https://img.shields.io/badge/MySQL-8.0+-orange?logo=mysql)](https://mysql.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%20Protected-red)](https://owasp.org/www-project-top-ten/)

PHP PrivacyShield helps Indian businesses meet their obligations under the [Digital Personal Data Protection (DPDP) Act 2023](https://www.meity.gov.in/dpdp-act) by providing:

- **A JavaScript consent banner widget** — injectable on any webpage
- **A secure REST API** — to log consent decisions
- **An admin dashboard** — analytics, audit log, CSV export
- **A data rights portal** — manage Erasure/Access/Grievance requests

---

## 📋 Table of Contents

- [Requirements](#requirements)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Embedding the Widget](#embedding-the-widget)
- [Security Architecture](#security-architecture)
- [DPDP Act 2023 Compliance Map](#dpdp-act-2023-compliance-map)
- [Environment Variables](#environment-variables)
- [API Reference](#api-reference)

---

## Requirements

| Requirement | Version |
|---|---|
| PHP | 8.1+ |
| MySQL | 8.0+ |
| PDO MySQL extension | Required |
| OpenSSL extension | Required (for `random_bytes`) |
| Web server | Apache / Nginx |

---

## Project Structure

```
PHP-PrivacyShield/
├── config/
│   └── db.php                  # Secure PDO singleton connection
├── core/
│   ├── Auth.php                # Session management, CSRF, role gates
│   ├── Validator.php           # Input validation & XSS encoding
│   └── Response.php            # JSON API response helpers + CORS
├── api/
│   └── consent.php             # POST /api/consent.php — logs consent
├── admin/
│   ├── dashboard.php           # Consent analytics + audit log
│   └── requests.php            # Data rights request management
├── public/
│   ├── shield.js               # Vanilla JS consent banner widget
│   └── shield.css              # Banner styles (glassmorphic dark theme)
├── templates/
│   ├── admin_header.php        # Shared admin header + nav + design system
│   └── admin_footer.php        # Shared admin footer
├── register.php                # First-run superadmin registration
├── login.php                   # Admin login (rate-limited)
├── logout.php                  # Session destroy + audit log
├── init.sql                    # Database schema (run once)
└── README.md
```

---

## Quick Start

### 1. Create the Database

```bash
mysql -u root -p < init.sql
```

### 2. Configure Environment Variables

Set these on your server (via `.env`, Apache `SetEnv`, or Docker environment):

```bash
DB_HOST=localhost
DB_PORT=3306
DB_NAME=privacyshield
DB_USER=ps_user
DB_PASSWORD=your-strong-password
HASH_SALT=your-random-64-char-string-here
ALLOWED_ORIGINS=https://yourwebsite.com,https://www.yourwebsite.com
```

> **Security Note:** The `HASH_SALT` is used to anonymize IP addresses before storage. Generate a long random string and keep it secret.

### 3. Create a MySQL User

```sql
CREATE USER 'ps_user'@'localhost' IDENTIFIED BY 'your-strong-password';
GRANT SELECT, INSERT, UPDATE ON privacyshield.* TO 'ps_user'@'localhost';
FLUSH PRIVILEGES;
```

### 4. Configure Your Web Server

**Apache** (`mod_rewrite` recommended):

```apache
<Directory /var/www/privacyshield>
    AllowOverride All
    Options -Indexes -ExecCGI
</Directory>
```

**Nginx**:

```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;
    root /var/www/privacyshield;
    index login.php;

    location ~* \.php$ {
        fastcgi_pass unix:/run/php/php8.1-fpm.sock;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }

    # Block direct access to sensitive directories
    location ~* ^/(config|core|templates)/ { deny all; }
}
```

### 5. Register the First Admin

Visit `https://your-domain.com/register.php` to create the superadmin account. **This page locks itself** after the first user is created.

### 6. Log In

Visit `https://your-domain.com/login.php` and sign in with your superadmin credentials.

---

## Embedding the Widget

Add this snippet **before `</body>`** on any webpage you want to track consent for:

```html
<!-- PHP PrivacyShield Consent Widget -->
<script>
  window.PrivacyShieldConfig = {
    apiUrl:      'https://your-privacyshield-domain.com/api/consent.php',
    companyName: 'Acme Corp',
    policyUrl:   'https://your-domain.com/privacy-policy',
    version:     '1.0',  // Increment this when your privacy policy changes
  };
</script>
<script src="https://your-privacyshield-domain.com/public/shield.js" defer></script>
```

### Listening to Consent Events

```javascript
window.addEventListener('ps:consent', function(event) {
  if (event.detail.accepted) {
    // User accepted — load analytics, marketing pixels, etc.
    console.log('Consent granted ✓');
  } else {
    // User rejected — do NOT load non-essential third-party scripts.
    console.log('Consent rejected — no tracking.');
  }
});
```

### Re-Consent on Policy Update

When you update your Privacy Policy, increment `version` in the config. The widget checks localStorage for the version and will automatically re-display the banner to all visitors who have not consented to the new version.

---

## Security Architecture

| OWASP Threat | Implementation |
|---|---|
| **A01 — Broken Access Control** | `requireLogin()` + `requireRole()` on all admin routes |
| **A02 — Cryptographic Failures** | Bcrypt (cost 12) for passwords; SHA-256+salt for IP hashing |
| **A03 — Injection (SQLi)** | PDO prepared statements everywhere; `ATTR_EMULATE_PREPARES = false` |
| **A03 — Injection (XSS)** | `e()` / `htmlspecialchars()` on all template output |
| **A04 — Insecure Design** | First-run registration lock; role-based access; audit logging |
| **A05 — Security Misconfiguration** | No raw DB errors exposed; `X-Content-Type-Options: nosniff` |
| **A07 — Auth Failures** | Session rotation on login; rate limiting; timing-safe `password_verify()` |
| **A08 — CSRF** | Synchronized Token Pattern (STP); `hash_equals()` comparison |
| **A09 — Logging Failures** | `admin_audit_log` table; `error_log()` for internal errors |

---

## DPDP Act 2023 Compliance Map

| DPDP Act Section | Feature |
|---|---|
| **Section 6** — Consent requirements | Consent banner with clear Accept/Reject (no dark patterns) |
| **Section 7** — Consent records | `consent_logs` table with timestamp, version, and anonymized metadata |
| **Section 11** — Right of Access | Admin portal allows processing "access" requests |
| **Section 12** — Right of Erasure/Correction | "erasure" and "correction" request types supported |
| **Section 13** — Grievance Redressal | "grievance" request type with 30-day SLA tracking |
| **Section 6(4)** — Re-consent on change | Policy version tracking in localStorage; banner re-shown on version bump |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DB_HOST` | `localhost` | MySQL server hostname |
| `DB_PORT` | `3306` | MySQL server port |
| `DB_NAME` | `privacyshield` | Database name |
| `DB_USER` | `ps_user` | MySQL username |
| `DB_PASSWORD` | *(empty)* | MySQL password |
| `HASH_SALT` | *(built-in)* | Salt for IP/UA hashing — **must be set in production** |
| `ALLOWED_ORIGINS` | `http://localhost` | Comma-separated list of allowed CORS origins |

---

## API Reference

### `POST /api/consent.php`

Logs a visitor consent decision.

**Request Headers:**
```
Content-Type: application/json
Origin: https://your-client-site.com
```

**Request Body:**
```json
{
  "visitor_id":      "550e8400-e29b-41d4-a716-446655440000",
  "page_url":        "https://client-site.com/home",
  "consent":         true,
  "consent_version": "1.0"
}
```

**Success Response (200):**
```json
{
  "success": true,
  "data": {
    "logged": true,
    "message": "Consent recorded successfully under DPDP Act 2023 Section 6."
  }
}
```

**Error Response (422):**
```json
{
  "success": false,
  "message": "'visitor_id' must be a valid UUID v4."
}
```

---

## License

MIT License — see `LICENSE` for details.

---

> Built with 🛡️ for Indian compliance. This tool does not constitute legal advice. Always consult a qualified legal professional for DPDP Act compliance obligations specific to your organization.
