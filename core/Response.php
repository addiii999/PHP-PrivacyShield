<?php
/**
 * PHP PrivacyShield — JSON API Response Helper
 * =====================================================================
 * File: core/Response.php
 *
 * Standardises all JSON API responses with consistent structure,
 * appropriate HTTP status codes, and security headers.
 *
 * All API endpoints should use these helpers instead of raw echo/json_encode.
 * =====================================================================
 */

declare(strict_types=1);

/**
 * Sends a successful JSON response and terminates execution.
 *
 * @param mixed $data    Response payload (will be JSON-encoded).
 * @param int   $status  HTTP status code (default 200).
 */
function sendSuccess(mixed $data = [], int $status = 200): never
{
    sendJSON(['success' => true, 'data' => $data], $status);
}

/**
 * Sends an error JSON response and terminates execution.
 *
 * @param string $message Human-readable error message.
 * @param int    $status  HTTP status code (default 400).
 * @param array  $errors  Optional array of field-level validation errors.
 */
function sendError(string $message, int $status = 400, array $errors = []): never
{
    $payload = ['success' => false, 'message' => $message];
    if (!empty($errors)) {
        $payload['errors'] = $errors;
    }
    sendJSON($payload, $status);
}

/**
 * Core JSON response sender.
 * Sets appropriate headers and terminates execution.
 *
 * @param array $payload Data to JSON-encode.
 * @param int   $status  HTTP status code.
 */
function sendJSON(array $payload, int $status = 200): never
{
    // Clear any previously set headers (prevents header injection).
    if (!headers_sent()) {
        // Set the HTTP status code.
        http_response_code($status);

        // Content type must be application/json for API responses.
        header('Content-Type: application/json; charset=UTF-8');

        // ── Security Headers ──────────────────────────────────────────────
        // Prevent MIME-type sniffing (OWASP A05).
        header('X-Content-Type-Options: nosniff');

        // Prevent clickjacking (defence in depth).
        header('X-Frame-Options: DENY');

        // Remove server version information.
        header_remove('X-Powered-By');
        header_remove('Server');
    }

    // JSON_UNESCAPED_UNICODE: preserve multi-byte characters (Hindi text, etc.)
    // JSON_UNESCAPED_SLASHES: cleaner URLs in output.
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
}

/**
 * Sets CORS headers dynamically from an allowlist of origins.
 *
 * Rather than using wildcard (*), we validate the requesting origin against
 * an allowlist and only reflect it if it's permitted. This prevents
 * credential-leaking cross-origin requests.
 *
 * @param string[] $allowedOrigins List of permitted origin URLs.
 *                                 Pass ['*'] to allow all (not recommended for production).
 */
function setCORSHeaders(array $allowedOrigins): void
{
    $requestOrigin = $_SERVER['HTTP_ORIGIN'] ?? '';

    // Handle wildcard (development mode only — NEVER use in production with credentials).
    if (in_array('*', $allowedOrigins, true)) {
        header('Access-Control-Allow-Origin: *');
    } elseif (in_array($requestOrigin, $allowedOrigins, true)) {
        // Reflect the exact origin back (required for credentialed requests).
        header('Access-Control-Allow-Origin: ' . $requestOrigin);
        header('Vary: Origin'); // Ensures correct caching behaviour.
    }
    // If origin is not in the allowlist, no CORS header is set → browser blocks.

    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, X-Requested-With');
    header('Access-Control-Max-Age: 86400'); // Cache preflight for 24 hours.

    // Handle CORS preflight OPTIONS request.
    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(204);
        exit;
    }
}

/**
 * Parses and returns the raw JSON request body as an associative array.
 * Terminates with a 400 error if the body is missing or malformed.
 *
 * @return array Decoded JSON payload.
 */
function getJSONBody(): array
{
    $raw = file_get_contents('php://input');

    if (empty($raw)) {
        sendError('Request body is empty. Expected JSON payload.', 400);
    }

    try {
        $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
    } catch (JsonException $e) {
        sendError('Invalid JSON payload: ' . $e->getMessage(), 400);
    }

    if (!is_array($data)) {
        sendError('JSON payload must be a JSON object, not a scalar or array.', 400);
    }

    return $data;
}
