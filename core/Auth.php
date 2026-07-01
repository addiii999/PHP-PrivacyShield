<?php
/**
 * PHP PrivacyShield — Authentication & Session Security Helper
 * =====================================================================
 * File: core/Auth.php
 *
 * Centralises all session management, CSRF protection, and authentication
 * gate-keeping. Every admin page MUST begin with:
 *
 *   require_once __DIR__ . '/../core/Auth.php';
 *   requireLogin();
 *
 * Security measures implemented here:
 *   - OWASP A07: Session tokens rotated on login (prevents fixation).
 *   - OWASP A01: Role-based access checks via requireRole().
 *   - CSRF: Synchronized Token Pattern (STP) for all POST forms.
 *   - Cookie flags: HttpOnly, Secure (HTTPS), SameSite=Strict.
 * =====================================================================
 */

declare(strict_types=1);

// ── Session Configuration ─────────────────────────────────────────────────────
// These settings must be applied BEFORE session_start() is called.
// They are safe to call multiple times as long as no session is active.

if (session_status() === PHP_SESSION_NONE) {
    // Prevent JavaScript from reading the session cookie (mitigates XSS session theft).
    ini_set('session.cookie_httponly', '1');

    // Transmit session cookie over HTTPS only.
    // NOTE: Set to '0' in local HTTP development environments only.
    ini_set('session.cookie_secure', '1');

    // Prevent the cookie from being sent with cross-site requests.
    ini_set('session.cookie_samesite', 'Strict');

    // Use a cryptographically strong session ID.
    ini_set('session.entropy_length', '32');
    ini_set('session.hash_function', 'sha256');

    // Disable URL-based session IDs (prevents session fixation via URL manipulation).
    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_trans_sid', '0');

    session_start();
}

// ─────────────────────────────────────────────────────────────────────────────
// Authentication Gates
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Ensures the current visitor is a logged-in admin.
 * Redirects to the login page if not authenticated.
 *
 * @param string $loginUrl Path to the login page for redirect.
 */
function requireLogin(string $loginUrl = '/login.php'): void
{
    if (empty($_SESSION['admin_id']) || empty($_SESSION['admin_email'])) {
        // Preserve the originally requested URL so we can redirect after login.
        $_SESSION['redirect_after_login'] = $_SERVER['REQUEST_URI'] ?? '';
        header('Location: ' . $loginUrl);
        exit;
    }
}

/**
 * Ensures the current admin has at least the required role.
 * Role hierarchy: superadmin > admin > viewer.
 *
 * @param string $requiredRole Minimum role required ('viewer', 'admin', 'superadmin').
 */
function requireRole(string $requiredRole): void
{
    requireLogin();

    $hierarchy = ['viewer' => 1, 'admin' => 2, 'superadmin' => 3];
    $userRole  = $_SESSION['admin_role'] ?? 'viewer';

    if (($hierarchy[$userRole] ?? 0) < ($hierarchy[$requiredRole] ?? 99)) {
        http_response_code(403);
        exit('Access Denied: Insufficient privileges.');
    }
}

/**
 * Returns the currently authenticated admin's ID, or null.
 */
function currentAdminId(): ?int
{
    return isset($_SESSION['admin_id']) ? (int)$_SESSION['admin_id'] : null;
}

/**
 * Returns the currently authenticated admin's email, or null.
 */
function currentAdminEmail(): ?string
{
    return $_SESSION['admin_email'] ?? null;
}

/**
 * Returns the currently authenticated admin's name, or 'Admin'.
 */
function currentAdminName(): string
{
    return htmlspecialchars($_SESSION['admin_name'] ?? 'Admin', ENT_QUOTES, 'UTF-8');
}

// ─────────────────────────────────────────────────────────────────────────────
// Session Management
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Rotates the session ID to prevent session fixation attacks.
 * Called on every successful login.
 *
 * OWASP A07: Identification and Authentication Failures.
 */
function regenerateSession(): void
{
    // Regenerate the session ID, deleting the old session file immediately.
    session_regenerate_id(true);
}

/**
 * Stores admin identity in the session after successful login.
 *
 * @param array $admin Row from the `users` table.
 */
function loginAdmin(array $admin): void
{
    regenerateSession();

    $_SESSION['admin_id']    = (int)$admin['id'];
    $_SESSION['admin_email'] = $admin['email'];
    $_SESSION['admin_name']  = $admin['name'];
    $_SESSION['admin_role']  = $admin['role'];
    $_SESSION['login_time']  = time();
}

/**
 * Destroys the session and redirects to the login page.
 */
function logoutAdmin(): void
{
    // Clear all session variables.
    $_SESSION = [];

    // Destroy the session cookie.
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }

    session_destroy();

    header('Location: /login.php');
    exit;
}

// ─────────────────────────────────────────────────────────────────────────────
// CSRF Protection — Synchronized Token Pattern (STP)
// ─────────────────────────────────────────────────────────────────────────────
// How it works:
//   1. Server generates a random token and stores it in the session.
//   2. The token is embedded as a hidden field in every HTML form.
//   3. On POST, the server compares the submitted token to the session token.
//   4. If they don't match, the request is rejected (OWASP A01).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generates (or retrieves) the CSRF token for the current session.
 *
 * @return string A 64-character hex CSRF token.
 */
function generateCSRFToken(): string
{
    if (empty($_SESSION['csrf_token'])) {
        // bin2hex(random_bytes(32)) produces a 64-char cryptographically secure hex string.
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Renders the CSRF hidden input field for use inside HTML forms.
 *
 * Usage in a template:
 *   <?= csrfField() ?>
 *
 * @return string HTML string of the hidden input.
 */
function csrfField(): string
{
    $token = htmlspecialchars(generateCSRFToken(), ENT_QUOTES, 'UTF-8');
    return '<input type="hidden" name="csrf_token" value="' . $token . '">';
}

/**
 * Validates the CSRF token submitted with a POST request.
 * Terminates execution with a 403 if the token is missing or invalid.
 *
 * Uses hash_equals() for timing-safe comparison (prevents timing attacks).
 */
function validateCSRFToken(): void
{
    $submitted = $_POST['csrf_token'] ?? '';
    $expected  = $_SESSION['csrf_token'] ?? '';

    if (
        empty($submitted) ||
        empty($expected) ||
        !hash_equals($expected, $submitted)
    ) {
        http_response_code(403);
        exit('Invalid or missing CSRF token. Please refresh and try again.');
    }
}
