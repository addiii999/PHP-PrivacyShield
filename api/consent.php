<?php
/**
 * PHP PrivacyShield — Consent Logging API Endpoint
 * =====================================================================
 * File: api/consent.php
 *
 * REST endpoint that receives consent decisions from the shield.js widget
 * and logs them to the `consent_logs` table.
 *
 * Method:  POST
 * URL:     /api/consent.php
 * Body:    application/json
 *
 * Request Payload:
 * {
 *   "visitor_id":       "uuid-v4",      // Client-generated UUID
 *   "page_url":         "https://...",  // Page where consent was collected
 *   "consent":          true/false,     // Accepted or rejected
 *   "consent_version":  "1.0"           // Optional, policy version shown
 * }
 *
 * Response (200 OK):
 * { "success": true, "data": { "logged": true } }
 *
 * Security:
 *   - Dynamic CORS with configurable origin allowlist.
 *   - Input validated with strict type checking.
 *   - IP and User-Agent are SHA-256 hashed before storage (no raw PII).
 *   - Rate limiting placeholder (can be extended with Redis/APCu).
 *
 * DPDP Act 2023: This endpoint implements the consent recording obligation
 * under Section 6 & 7 of the Act.
 * =====================================================================
 */

declare(strict_types=1);

// ── Autoload Dependencies ─────────────────────────────────────────────────────
require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../core/Response.php';
require_once __DIR__ . '/../core/Validator.php';

// ── CORS Configuration ────────────────────────────────────────────────────────
// Add your client website origins here. This prevents cross-origin abuse.
// In development, you may add 'http://localhost' or 'http://127.0.0.1'.
//
// IMPORTANT: Update this list with your actual production domain(s).
$allowedOrigins = array_filter(
    explode(',', getenv('ALLOWED_ORIGINS') ?: 'http://localhost,http://127.0.0.1')
);

setCORSHeaders($allowedOrigins);

// ── Method Enforcement ────────────────────────────────────────────────────────
// This endpoint only accepts POST requests carrying a JSON body.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendError('Method Not Allowed. Use POST.', 405);
}

// ── Content-Type Enforcement ──────────────────────────────────────────────────
$contentType = $_SERVER['CONTENT_TYPE'] ?? '';
if (stripos($contentType, 'application/json') === false) {
    sendError('Content-Type must be application/json.', 415);
}

// ── Parse & Validate Input ────────────────────────────────────────────────────
$body = getJSONBody();

try {
    // visitor_id: must be a valid UUID v4 (client-generated, not PII).
    $visitorId = validateUUID($body['visitor_id'] ?? '', 'visitor_id');

    // page_url: must be a valid HTTP/HTTPS URL.
    $pageUrl = validateUrl($body['page_url'] ?? '', 'page_url');

    // Limit URL length to prevent extremely long inputs.
    if (mb_strlen($pageUrl) > 2048) {
        throw new InvalidArgumentException("'page_url' must not exceed 2048 characters.");
    }

    // consent: must be a boolean value.
    $consentGiven = validateBool($body['consent'] ?? null, 'consent');

    // consent_version: optional, defaults to '1.0'.
    $consentVersion = isset($body['consent_version'])
        ? validateString($body['consent_version'], 'consent_version', 20, false)
        : '1.0';

    // Ensure consent_version is alphanumeric + dots only.
    if (!preg_match('/^[a-zA-Z0-9._-]{1,20}$/', $consentVersion)) {
        throw new InvalidArgumentException("'consent_version' contains invalid characters.");
    }

} catch (InvalidArgumentException $e) {
    sendError($e->getMessage(), 422);
}

// ── Anonymize PII Before Storage ──────────────────────────────────────────────
// DPDP Act 2023 Compliance: We MUST NOT store raw IP addresses or User-Agents
// as they constitute personal data under the Act.
// We store only a salted SHA-256 hash, which is non-reversible.

$rawIP        = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$rawUA        = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
$ipHash       = anonymizeIP($rawIP);
$userAgentHash = anonymizeUserAgent($rawUA);

// ── Database Insertion ────────────────────────────────────────────────────────
try {
    $pdo = getDBConnection();

    $stmt = $pdo->prepare("
        INSERT INTO consent_logs
            (visitor_id, page_url, consent_given, ip_hash, user_agent_hash, consent_version)
        VALUES
            (:visitor_id, :page_url, :consent_given, :ip_hash, :user_agent_hash, :consent_version)
    ");

    $stmt->execute([
        ':visitor_id'       => $visitorId,
        ':page_url'         => $pageUrl,
        ':consent_given'    => (int)$consentGiven,
        ':ip_hash'          => $ipHash,
        ':user_agent_hash'  => $userAgentHash,
        ':consent_version'  => $consentVersion,
    ]);

} catch (PDOException $e) {
    // Log the real error server-side, never expose it.
    error_log('[PrivacyShield][API] Consent insert failed: ' . $e->getMessage());
    sendError('An internal error occurred while recording consent. Please try again.', 500);
}

// ── Success Response ──────────────────────────────────────────────────────────
sendSuccess([
    'logged'   => true,
    'message'  => 'Consent recorded successfully under DPDP Act 2023 Section 6.',
]);
