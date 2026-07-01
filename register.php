<?php
/**
 * PHP PrivacyShield — Admin Registration (First-Run Only)
 * =====================================================================
 * File: register.php
 *
 * This page allows the FIRST admin account to be created.
 * Once one user exists in the database, this page is permanently locked
 * and returns a 403. This prevents unauthorized account creation.
 *
 * Security:
 *   - CSRF token validated on POST.
 *   - Password hashed with PASSWORD_BCRYPT (cost factor 12).
 *   - Input validation on all fields.
 *   - Registration locked after first user is created.
 * =====================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/config/db.php';
require_once __DIR__ . '/core/Auth.php';
require_once __DIR__ . '/core/Validator.php';

// ── First-Run Guard ───────────────────────────────────────────────────────────
// Check if any user already exists. If yes, lock this page permanently.
$pdo      = getDBConnection();
$countStmt = $pdo->query("SELECT COUNT(*) FROM users");
$userCount = (int)$countStmt->fetchColumn();

if ($userCount > 0) {
    http_response_code(403);
    // Show a user-friendly locked message.
    $locked = true;
}

// ── Handle POST ───────────────────────────────────────────────────────────────
$errors    = [];
$success   = false;
$formName  = '';
$formEmail = '';

if (!($locked ?? false) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCSRFToken();

    try {
        $formName     = validateString($_POST['name']     ?? '', 'name',     120);
        $formEmail    = validateEmail($_POST['email']     ?? '');
        $password     = validateString($_POST['password'] ?? '', 'password', 255);
        $passwordConf = validateString($_POST['password_confirm'] ?? '', 'password_confirm', 255);

        if (mb_strlen($password) < 12) {
            throw new InvalidArgumentException('Password must be at least 12 characters long.');
        }

        if ($password !== $passwordConf) {
            throw new InvalidArgumentException('Passwords do not match.');
        }

        // Hash the password with bcrypt, cost factor 12 (OWASP recommendation).
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

        $stmt = $pdo->prepare("
            INSERT INTO users (name, email, password_hash, role)
            VALUES (:name, :email, :hash, 'superadmin')
        ");
        $stmt->execute([':name' => $formName, ':email' => $formEmail, ':hash' => $hash]);

        $success = true;

    } catch (InvalidArgumentException $e) {
        $errors[] = $e->getMessage();
    } catch (PDOException $e) {
        if ($e->getCode() === '23000') {
            $errors[] = 'An account with this email already exists.';
        } else {
            error_log('[PrivacyShield][Register] ' . $e->getMessage());
            $errors[] = 'A database error occurred. Please try again.';
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
    <title>Create Admin Account — PHP PrivacyShield</title>
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
            --success:      #22c55e;
            --danger:       #ef4444;
            --warning:      #f59e0b;
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
            max-width: 460px;
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            box-shadow: 0 0 60px rgba(99,102,241,0.08), 0 20px 40px rgba(0,0,0,0.4);
        }
        .logo {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            margin-bottom: 2rem;
        }
        .logo-icon {
            width: 36px; height: 36px;
            background: linear-gradient(135deg, var(--accent), #7c3aed);
            border-radius: 8px;
            display: flex; align-items: center; justify-content: center;
            font-size: 18px;
        }
        .logo-text { font-size: 1.1rem; font-weight: 600; color: var(--text-primary); }
        .logo-text span { color: var(--accent); }

        h1 { font-size: 1.4rem; font-weight: 600; color: var(--text-primary); margin-bottom: 0.4rem; }
        .subtitle { font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1.8rem; }

        .alert {
            padding: 0.85rem 1rem; border-radius: 8px;
            font-size: 0.85rem; margin-bottom: 1.2rem;
        }
        .alert-error  { background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.3); color: #fca5a5; }
        .alert-success{ background: rgba(34,197,94,0.12); border: 1px solid rgba(34,197,94,0.3); color: #86efac; }
        .alert-locked { background: rgba(245,158,11,0.12); border: 1px solid rgba(245,158,11,0.3); color: #fcd34d; }

        .form-group { margin-bottom: 1.2rem; }
        label { display: block; font-size: 0.82rem; font-weight: 500; color: var(--text-muted); margin-bottom: 0.4rem; letter-spacing: 0.02em; text-transform: uppercase; }
        input[type="text"], input[type="email"], input[type="password"] {
            width: 100%; padding: 0.75rem 1rem;
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 0.95rem;
            font-family: inherit;
            transition: border-color 0.2s, box-shadow 0.2s;
            outline: none;
        }
        input:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }
        input::placeholder { color: var(--text-muted); }

        .btn {
            width: 100%; padding: 0.85rem;
            background: linear-gradient(135deg, var(--accent), #7c3aed);
            color: white; border: none; border-radius: 8px;
            font-size: 0.95rem; font-weight: 600;
            cursor: pointer; font-family: inherit;
            transition: opacity 0.2s, transform 0.1s;
            margin-top: 0.5rem;
        }
        .btn:hover { opacity: 0.9; transform: translateY(-1px); }
        .btn:active { transform: translateY(0); }

        .login-link { text-align: center; margin-top: 1.2rem; font-size: 0.85rem; color: var(--text-muted); }
        .login-link a { color: var(--accent-hover); text-decoration: none; font-weight: 500; }
        .login-link a:hover { text-decoration: underline; }

        .badge-first-run {
            display: inline-block;
            background: rgba(99,102,241,0.15); border: 1px solid rgba(99,102,241,0.3);
            color: var(--accent-hover); border-radius: 20px;
            padding: 0.2rem 0.7rem; font-size: 0.72rem; font-weight: 500;
            margin-bottom: 0.8rem;
        }
    </style>
</head>
<body>
<div class="card">
    <div class="logo">
        <div class="logo-icon">🛡️</div>
        <div class="logo-text">Privacy<span>Shield</span></div>
    </div>

    <?php if ($locked ?? false): ?>
        <h1>Registration Locked</h1>
        <p class="subtitle">An admin account already exists.</p>
        <div class="alert alert-locked">
            ⚠️ For security, registration is disabled once an admin account is active. Contact your superadmin to create additional accounts.
        </div>
        <div class="login-link"><a href="/login.php">← Back to Login</a></div>

    <?php elseif ($success): ?>
        <h1>Account Created!</h1>
        <div class="alert alert-success">
            ✅ Your superadmin account has been created successfully.
        </div>
        <div class="login-link"><a href="/login.php">Proceed to Login →</a></div>

    <?php else: ?>
        <div class="badge-first-run">⚡ First-Run Setup</div>
        <h1>Create Admin Account</h1>
        <p class="subtitle">Set up the first superadmin account for PrivacyShield.</p>

        <?php if (!empty($errors)): ?>
            <div class="alert alert-error">
                <?php foreach ($errors as $err): ?>
                    <div>⚠ <?= e($err) ?></div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="/register.php" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>">

            <div class="form-group">
                <label for="name">Full Name</label>
                <input type="text" id="name" name="name" value="<?= e($formName) ?>" placeholder="Arjun Sharma" required autofocus>
            </div>
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" value="<?= e($formEmail) ?>" placeholder="admin@company.in" required>
            </div>
            <div class="form-group">
                <label for="password">Password <span style="color:var(--text-muted);text-transform:none;font-weight:400">(min 12 chars)</span></label>
                <input type="password" id="password" name="password" placeholder="••••••••••••" required minlength="12">
            </div>
            <div class="form-group">
                <label for="password_confirm">Confirm Password</label>
                <input type="password" id="password_confirm" name="password_confirm" placeholder="••••••••••••" required>
            </div>

            <button type="submit" class="btn" id="btn-register">Create Superadmin Account</button>
        </form>
    <?php endif; ?>
</div>
</body>
</html>
