<?php
/**
 * PHP PrivacyShield — Admin Login
 * =====================================================================
 * File: login.php
 *
 * Secure admin authentication with:
 *   - password_verify() (timing-safe bcrypt comparison).
 *   - Session ID rotation on successful login (prevents fixation).
 *   - Login attempt throttling (max 5 attempts before lockout).
 *   - CSRF token validation on POST.
 *   - HttpOnly + Secure + SameSite=Strict cookie flags.
 * =====================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/config/db.php';
require_once __DIR__ . '/core/Auth.php';
require_once __DIR__ . '/core/Validator.php';

// If already logged in, redirect to dashboard.
if (!empty($_SESSION['admin_id'])) {
    header('Location: /admin/dashboard.php');
    exit;
}

// ── Rate Limiting (Session-Based) ─────────────────────────────────────────────
// Tracks failed attempts per-session. In production, replace with a
// Redis/APCu-based IP-level limiter for stronger protection.
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_SECONDS    = 300; // 5-minute lockout

$now            = time();
$attemptCount   = $_SESSION['login_attempts'] ?? 0;
$lockedUntil    = $_SESSION['login_locked_until'] ?? 0;
$isLocked       = $lockedUntil > $now;

// ── Handle POST ───────────────────────────────────────────────────────────────
$errors      = [];
$formEmail   = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate CSRF first before doing any work.
    validateCSRFToken();

    if ($isLocked) {
        $remaining = ceil(($lockedUntil - $now) / 60);
        $errors[]  = "Too many failed attempts. Please wait {$remaining} minute(s).";

    } else {
        try {
            $formEmail = validateEmail($_POST['email'] ?? '');
            $password  = validateString($_POST['password'] ?? '', 'password', 255);

        } catch (InvalidArgumentException $e) {
            $errors[] = $e->getMessage();
        }

        if (empty($errors)) {
            $pdo  = getDBConnection();
            $stmt = $pdo->prepare("SELECT id, name, email, password_hash, role, is_active FROM users WHERE email = :email LIMIT 1");
            $stmt->execute([':email' => $formEmail]);
            $admin = $stmt->fetch();

            // Use password_verify() which is inherently timing-safe.
            // We always call it even if the user doesn't exist to prevent
            // timing-based user enumeration (OWASP A02).
            $hashToCheck = $admin['password_hash'] ?? '$2y$12$invalidhashpaddingtomatchlength....';
            $valid       = password_verify($password, $hashToCheck);

            if ($valid && $admin && $admin['is_active']) {
                // ── Successful Login ──────────────────────────────────────
                // Reset attempt counter.
                unset($_SESSION['login_attempts'], $_SESSION['login_locked_until']);

                // Store identity in session (rotates session ID internally).
                loginAdmin($admin);

                // Update last_login timestamp.
                $pdo->prepare("UPDATE users SET last_login = NOW() WHERE id = :id")
                    ->execute([':id' => $admin['id']]);

                // Log the login event to audit trail.
                logAuditEvent(
                    (int)$admin['id'],
                    $admin['email'],
                    'LOGIN',
                    'users',
                    (int)$admin['id']
                );

                // Redirect to originally requested page (or dashboard).
                $redirect = $_SESSION['redirect_after_login'] ?? '/admin/dashboard.php';
                unset($_SESSION['redirect_after_login']);
                header('Location: ' . $redirect);
                exit;

            } else {
                // ── Failed Login ──────────────────────────────────────────
                $attemptCount++;
                $_SESSION['login_attempts'] = $attemptCount;

                if ($attemptCount >= MAX_LOGIN_ATTEMPTS) {
                    $_SESSION['login_locked_until'] = $now + LOCKOUT_SECONDS;
                    $errors[] = 'Too many failed attempts. Your session is locked for 5 minutes.';
                } else {
                    $remaining = MAX_LOGIN_ATTEMPTS - $attemptCount;
                    $errors[]  = "Invalid email or password. {$remaining} attempt(s) remaining.";
                }
            }
        }
    }
}

$csrfToken = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login — PHP PrivacyShield</title>
    <meta name="description" content="Secure admin login for PHP PrivacyShield DPDP Act compliance dashboard.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-deep:      #0a0e1a;
            --bg-card:      rgba(255,255,255,0.04);
            --border:       rgba(255,255,255,0.10);
            --accent:       #6366f1;
            --accent-glow:  rgba(99,102,241,0.35);
            --accent-hover: #818cf8;
            --text-primary: #f0f4ff;
            --text-muted:   #8892a4;
            --danger:       #ef4444;
            --success:      #22c55e;
            --radius:       14px;
        }
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg-deep);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
            background-image:
                radial-gradient(ellipse 60% 50% at 20% 20%, rgba(99,102,241,0.12) 0%, transparent 70%),
                radial-gradient(ellipse 50% 60% at 80% 80%, rgba(139,92,246,0.10) 0%, transparent 70%);
        }
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 2.5rem;
            width: 100%;
            max-width: 420px;
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            box-shadow: 0 0 60px rgba(99,102,241,0.08), 0 20px 40px rgba(0,0,0,0.4);
            animation: fadeUp 0.4s ease-out;
        }
        @keyframes fadeUp {
            from { opacity: 0; transform: translateY(16px); }
            to   { opacity: 1; transform: translateY(0); }
        }
        .logo {
            display: flex; align-items: center; gap: 0.6rem;
            margin-bottom: 2rem;
        }
        .logo-icon {
            width: 40px; height: 40px;
            background: linear-gradient(135deg, var(--accent), #7c3aed);
            border-radius: 10px;
            display: flex; align-items: center; justify-content: center;
            font-size: 20px;
        }
        .logo-text { font-size: 1.1rem; font-weight: 700; color: var(--text-primary); }
        .logo-text span { color: var(--accent); }

        h1 { font-size: 1.5rem; font-weight: 600; color: var(--text-primary); margin-bottom: 0.35rem; }
        .subtitle { font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1.8rem; }

        .alert {
            padding: 0.85rem 1rem; border-radius: 8px;
            font-size: 0.84rem; margin-bottom: 1.2rem;
        }
        .alert-error { background: rgba(239,68,68,0.10); border: 1px solid rgba(239,68,68,0.3); color: #fca5a5; }

        .form-group { margin-bottom: 1.2rem; }
        label {
            display: block; font-size: 0.80rem; font-weight: 500;
            color: var(--text-muted); margin-bottom: 0.4rem;
            letter-spacing: 0.04em; text-transform: uppercase;
        }
        input[type="email"], input[type="password"] {
            width: 100%; padding: 0.78rem 1rem;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 0.95rem; font-family: inherit;
            transition: border-color 0.2s, box-shadow 0.2s;
            outline: none;
        }
        input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
        input::placeholder { color: var(--text-muted); }
        input:disabled { opacity: 0.5; cursor: not-allowed; }

        .btn {
            width: 100%; padding: 0.88rem;
            background: linear-gradient(135deg, var(--accent), #7c3aed);
            color: white; border: none; border-radius: 8px;
            font-size: 0.95rem; font-weight: 600;
            cursor: pointer; font-family: inherit;
            transition: opacity 0.2s, transform 0.1s;
            margin-top: 0.5rem;
            position: relative;
        }
        .btn:hover:not(:disabled) { opacity: 0.9; transform: translateY(-1px); }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }

        .footer-note {
            text-align: center; margin-top: 1.5rem;
            font-size: 0.78rem; color: var(--text-muted);
        }
        .footer-note a { color: var(--accent-hover); text-decoration: none; }

        .lock-badge {
            display: inline-flex; align-items: center; gap: 0.4rem;
            font-size: 0.75rem; color: var(--text-muted);
            margin-top: 1rem; justify-content: center; width: 100%;
        }
    </style>
</head>
<body>
<div class="card">
    <div class="logo">
        <div class="logo-icon">🛡️</div>
        <div class="logo-text">Privacy<span>Shield</span></div>
    </div>

    <h1>Welcome back</h1>
    <p class="subtitle">Sign in to your compliance dashboard</p>

    <?php if (!empty($errors)): ?>
        <div class="alert alert-error">
            <?php foreach ($errors as $err): ?>
                <div>⚠ <?= e($err) ?></div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <form method="POST" action="/login.php" id="login-form">
        <input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>">

        <div class="form-group">
            <label for="email">Email Address</label>
            <input
                type="email" id="email" name="email"
                value="<?= e($formEmail) ?>"
                placeholder="admin@company.in"
                autocomplete="username"
                <?= $isLocked ? 'disabled' : '' ?>
                required autofocus>
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input
                type="password" id="password" name="password"
                placeholder="••••••••••••"
                autocomplete="current-password"
                <?= $isLocked ? 'disabled' : '' ?>
                required>
        </div>

        <button type="submit" class="btn" id="btn-login" <?= $isLocked ? 'disabled' : '' ?>>
            <?= $isLocked ? '🔒 Account Temporarily Locked' : 'Sign In →' ?>
        </button>
    </form>

    <div class="lock-badge">
        🔒 Protected by CSRF & session security
    </div>

    <div class="footer-note">
        DPDP Act 2023 Compliance Platform<br>
        <a href="https://digitalindia.gov.in" target="_blank" rel="noopener noreferrer">Learn about the Act</a>
    </div>
</div>
</body>
</html>
