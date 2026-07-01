<?php
/**
 * PHP PrivacyShield — Input Validation & Output Sanitization Utilities
 * =====================================================================
 * File: core/Validator.php
 *
 * All user-supplied input MUST pass through these functions before being
 * used in SQL queries, HTML output, or business logic.
 *
 * Prevents:
 *   - OWASP A03: Injection (validate before PDO parameter binding)
 *   - OWASP A03: XSS (encode before HTML output)
 *   - Business logic errors (type coercion, length violations)
 * =====================================================================
 */

declare(strict_types=1);

// ─────────────────────────────────────────────────────────────────────────────
// Output Encoding (XSS Prevention)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Encodes a string for safe output inside HTML content or attributes.
 * This is the primary XSS defence — use it on ALL dynamic values in templates.
 *
 * Encodes: &, ", ', <, >
 *
 * @param mixed  $value   The value to encode.
 * @param string $charset Character encoding (default UTF-8).
 * @return string HTML-safe encoded string.
 */
function e(mixed $value, string $charset = 'UTF-8'): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, $charset);
}

/**
 * Encodes a value for safe output inside a JavaScript string literal.
 * Use this when injecting PHP values into inline <script> blocks.
 *
 * @param mixed $value
 * @return string JSON-encoded value (safe for JS context).
 */
function ejs(mixed $value): string
{
    return json_encode($value, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE);
}

// ─────────────────────────────────────────────────────────────────────────────
// Input Validation
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Validates and returns a sanitized string, or throws InvalidArgumentException.
 *
 * @param mixed  $value   Raw input value.
 * @param string $field   Field name (used in error messages).
 * @param int    $maxLen  Maximum allowed length.
 * @param bool   $required Whether the field is required (non-empty).
 * @return string Trimmed string.
 * @throws InvalidArgumentException
 */
function validateString(mixed $value, string $field, int $maxLen = 500, bool $required = true): string
{
    if (!is_string($value) && !is_numeric($value)) {
        throw new InvalidArgumentException("'{$field}' must be a string.");
    }

    $trimmed = trim((string)$value);

    if ($required && $trimmed === '') {
        throw new InvalidArgumentException("'{$field}' is required and cannot be empty.");
    }

    if (mb_strlen($trimmed, 'UTF-8') > $maxLen) {
        throw new InvalidArgumentException("'{$field}' exceeds maximum length of {$maxLen} characters.");
    }

    return $trimmed;
}

/**
 * Validates an email address using PHP's built-in filter.
 *
 * @param mixed  $value
 * @param string $field
 * @return string Validated, lowercase email address.
 * @throws InvalidArgumentException
 */
function validateEmail(mixed $value, string $field = 'email'): string
{
    $trimmed = trim((string)$value);

    if (filter_var($trimmed, FILTER_VALIDATE_EMAIL) === false) {
        throw new InvalidArgumentException("'{$field}' must be a valid email address.");
    }

    return strtolower($trimmed);
}

/**
 * Validates a URL using PHP's filter.
 *
 * @param mixed  $value
 * @param string $field
 * @return string Validated URL.
 * @throws InvalidArgumentException
 */
function validateUrl(mixed $value, string $field = 'url'): string
{
    $trimmed = trim((string)$value);

    if (filter_var($trimmed, FILTER_VALIDATE_URL) === false) {
        throw new InvalidArgumentException("'{$field}' must be a valid URL.");
    }

    // Limit to http/https schemes only.
    if (!preg_match('#^https?://#i', $trimmed)) {
        throw new InvalidArgumentException("'{$field}' must use http or https scheme.");
    }

    return $trimmed;
}

/**
 * Validates a UUID v4 string.
 *
 * @param mixed  $value
 * @param string $field
 * @return string Validated UUID string.
 * @throws InvalidArgumentException
 */
function validateUUID(mixed $value, string $field = 'uuid'): string
{
    $pattern = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';

    if (!is_string($value) || !preg_match($pattern, $value)) {
        throw new InvalidArgumentException("'{$field}' must be a valid UUID v4.");
    }

    return strtolower($value);
}

/**
 * Validates a boolean-like value (true/false, 1/0, "true"/"false").
 *
 * @param mixed  $value
 * @param string $field
 * @return bool
 * @throws InvalidArgumentException
 */
function validateBool(mixed $value, string $field = 'value'): bool
{
    if (is_bool($value)) {
        return $value;
    }

    if (in_array($value, [1, 0, '1', '0', 'true', 'false'], true)) {
        return filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }

    throw new InvalidArgumentException("'{$field}' must be a boolean value (true/false).");
}

/**
 * Validates an integer within an optional range.
 *
 * @param mixed  $value
 * @param string $field
 * @param int    $min
 * @param int    $max
 * @return int
 * @throws InvalidArgumentException
 */
function validateInt(mixed $value, string $field, int $min = PHP_INT_MIN, int $max = PHP_INT_MAX): int
{
    $filtered = filter_var($value, FILTER_VALIDATE_INT);

    if ($filtered === false) {
        throw new InvalidArgumentException("'{$field}' must be an integer.");
    }

    $int = (int)$filtered;

    if ($int < $min || $int > $max) {
        throw new InvalidArgumentException("'{$field}' must be between {$min} and {$max}.");
    }

    return $int;
}

/**
 * Validates that a value is one of an allowed set of options.
 *
 * @param mixed  $value
 * @param array  $allowedValues
 * @param string $field
 * @return mixed The validated value.
 * @throws InvalidArgumentException
 */
function validateEnum(mixed $value, array $allowedValues, string $field = 'value'): mixed
{
    if (!in_array($value, $allowedValues, true)) {
        $allowed = implode(', ', array_map('strval', $allowedValues));
        throw new InvalidArgumentException("'{$field}' must be one of: {$allowed}.");
    }

    return $value;
}

// ─────────────────────────────────────────────────────────────────────────────
// Privacy / PII Utilities
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Anonymizes an IP address by hashing it with a server-side salt.
 *
 * DPDP Act 2023 Compliance: Raw IP addresses constitute personal data.
 * By storing only the salted hash, we avoid storing identifiable PII
 * while still retaining the ability to detect duplicate submissions.
 *
 * The salt should be stored in an environment variable (HASH_SALT).
 *
 * @param string $ip Raw IP address.
 * @return string 64-character SHA-256 hex hash.
 */
function anonymizeIP(string $ip): string
{
    $salt = getenv('HASH_SALT') ?: 'privacyshield-default-salt-change-me';
    return hash('sha256', $ip . $salt);
}

/**
 * Hashes a User-Agent string for storage.
 * Same principle as IP anonymization — we store a fingerprint, not raw data.
 *
 * @param string $userAgent Raw User-Agent header value.
 * @return string 64-character SHA-256 hex hash.
 */
function anonymizeUserAgent(string $userAgent): string
{
    $salt = getenv('HASH_SALT') ?: 'privacyshield-default-salt-change-me';
    return hash('sha256', $userAgent . $salt);
}

/**
 * Masks the middle portion of an email for safe display in the UI.
 * Example: john.doe@example.com → j*****e@example.com
 *
 * @param string $email
 * @return string Masked email.
 */
function maskEmail(string $email): string
{
    [$local, $domain] = explode('@', $email, 2) + ['', ''];

    if (strlen($local) <= 2) {
        return str_repeat('*', strlen($local)) . '@' . $domain;
    }

    return $local[0] . str_repeat('*', strlen($local) - 2) . $local[-1] . '@' . $domain;
}
