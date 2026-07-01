<?php
/**
 * PHP PrivacyShield — Secure PDO Database Connection
 * =====================================================================
 * File: config/db.php
 *
 * Implements a Singleton PDO connection with the following security
 * properties:
 *   - Credentials loaded from environment variables (12-factor app)
 *   - Emulated prepares DISABLED (forces true server-side prepared statements)
 *   - Error mode set to EXCEPTION (caught at the application layer)
 *   - Default fetch mode: associative array (prevents object injection)
 *   - Strict charset: utf8mb4 (full Unicode, including emoji/special chars)
 *
 * OWASP A03: Injection — All queries MUST use $pdo->prepare() + execute().
 * Never interpolate user input into SQL strings.
 * =====================================================================
 */

declare(strict_types=1);

/**
 * Returns the singleton PDO database connection.
 *
 * Usage:
 *   $pdo = getDBConnection();
 *   $stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");
 *   $stmt->execute([':email' => $email]);
 *
 * @return PDO
 * @throws RuntimeException if the connection cannot be established.
 */
function getDBConnection(): PDO
{
    // Singleton holder — persists for the request lifecycle.
    static $pdo = null;

    if ($pdo !== null) {
        return $pdo;
    }

    // ── Credential Resolution ─────────────────────────────────────────────
    // Prefer environment variables (set via .env loader, Docker, or server
    // config). Fall back to the constants defined below for local dev only.
    // NEVER commit real credentials to version control.
    $host     = getenv('DB_HOST')     ?: 'localhost';
    $port     = getenv('DB_PORT')     ?: '3306';
    $dbName   = getenv('DB_NAME')     ?: 'privacyshield';
    $username = getenv('DB_USER')     ?: 'ps_user';
    $password = getenv('DB_PASSWORD') ?: '';
    $charset  = 'utf8mb4';

    // ── DSN Construction ──────────────────────────────────────────────────
    $dsn = "mysql:host={$host};port={$port};dbname={$dbName};charset={$charset}";

    // ── PDO Options ───────────────────────────────────────────────────────
    $options = [
        // Throw PDOException on error (never silently fail).
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,

        // Return rows as associative arrays by default.
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,

        // CRITICAL: Disable emulated prepares.
        // When false, PDO sends the SQL and parameters to MySQL separately,
        // preventing any possibility of SQL injection via type-juggling.
        PDO::ATTR_EMULATE_PREPARES   => false,

        // Force MySQL to use strict mode — rejects invalid dates, truncation.
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci,
                                          sql_mode = 'STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION'",

        // Persistent connections are DISABLED for security — each request
        // gets a fresh connection to prevent session state bleed between users.
        PDO::ATTR_PERSISTENT         => false,
    ];

    try {
        $pdo = new PDO($dsn, $username, $password, $options);
    } catch (PDOException $e) {
        // ── Secure Error Handling ─────────────────────────────────────────
        // Log the real error server-side, but NEVER expose DB details to the
        // client. This prevents information disclosure (OWASP A09).
        error_log('[PrivacyShield][DB] Connection failed: ' . $e->getMessage());

        // In a production environment, render a generic 503 page.
        http_response_code(503);
        exit('A database error occurred. Please try again later.');
    }

    return $pdo;
}

/**
 * Logs a privileged admin action to the audit trail.
 *
 * This function should be called after every state-changing admin operation
 * to maintain accountability as required under the DPDP Act 2023.
 *
 * @param int         $adminId    ID of the acting admin user.
 * @param string      $adminEmail Email of the acting admin (denormalized).
 * @param string      $action     Machine-readable action name (e.g. RESOLVE_REQUEST).
 * @param string|null $targetType Type of affected resource (e.g. 'privacy_request').
 * @param int|null    $targetId   ID of the affected record.
 * @param array       $details    Additional context as key-value pairs.
 */
function logAuditEvent(
    int $adminId,
    string $adminEmail,
    string $action,
    ?string $targetType = null,
    ?int $targetId = null,
    array $details = []
): void {
    $pdo = getDBConnection();

    // Capture admin's IP for internal audit purposes.
    // This IP is stored as-is (not hashed) since it's internal admin traffic.
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

    $stmt = $pdo->prepare("
        INSERT INTO admin_audit_log
            (admin_id, admin_email, action, target_type, target_id, details, ip_address)
        VALUES
            (:admin_id, :admin_email, :action, :target_type, :target_id, :details, :ip_address)
    ");

    $stmt->execute([
        ':admin_id'    => $adminId,
        ':admin_email' => $adminEmail,
        ':action'      => $action,
        ':target_type' => $targetType,
        ':target_id'   => $targetId,
        ':details'     => !empty($details) ? json_encode($details, JSON_UNESCAPED_UNICODE) : null,
        ':ip_address'  => $ip,
    ]);
}
