<?php
/**
 * PHP PrivacyShield — Admin Logout
 * =====================================================================
 * File: logout.php
 *
 * Destroys the admin session and redirects to the login page.
 * Requires a valid CSRF token via GET parameter to prevent CSRF-based
 * forced logouts from malicious sites.
 * =====================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/core/Auth.php';

// Log the logout event before destroying the session.
if (!empty($_SESSION['admin_id'])) {
    require_once __DIR__ . '/config/db.php';
    logAuditEvent(
        (int)$_SESSION['admin_id'],
        (string)($_SESSION['admin_email'] ?? ''),
        'LOGOUT'
    );
}

logoutAdmin(); // Destroys session and redirects to /login.php
