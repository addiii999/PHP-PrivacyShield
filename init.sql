-- =============================================================================
-- PHP PrivacyShield — Database Schema
-- DPDP Act 2023 Compliance Platform
-- =============================================================================
-- Run this file once to set up the database:
--   mysql -u root -p < init.sql
-- =============================================================================

CREATE DATABASE IF NOT EXISTS `privacyshield`
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE `privacyshield`;

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: users
-- Stores admin/staff accounts for the PrivacyShield dashboard.
-- Passwords are stored as bcrypt hashes (never plaintext).
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `users` (
    `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `name`          VARCHAR(120) NOT NULL,
    `email`         VARCHAR(255) NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL COMMENT 'bcrypt hash via password_hash()',
    `role`          ENUM('superadmin', 'admin', 'viewer') NOT NULL DEFAULT 'admin',
    `is_active`     TINYINT(1) NOT NULL DEFAULT 1,
    `created_at`    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `last_login`    DATETIME NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_users_email` (`email`),
    KEY `idx_users_role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Admin/staff accounts for the PrivacyShield platform';


-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: consent_logs
-- Immutable audit trail of every visitor consent decision.
--
-- DPDP Act 2023 Compliance Notes:
--   - Section 6: Consent must be free, specific, informed, and unambiguous.
--   - Section 7: Records of consent must be maintained.
--   - IPs are stored as SHA-256 hashes (salted) — no raw PII is stored.
--   - visitor_id is a client-generated UUID (not linked to personal identity).
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `consent_logs` (
    `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `visitor_id`        CHAR(36)        NOT NULL COMMENT 'Client-generated UUID (RFC 4122)',
    `page_url`          VARCHAR(2048)   NOT NULL COMMENT 'URL where consent was captured',
    `consent_given`     TINYINT(1)      NOT NULL COMMENT '1 = accepted, 0 = rejected',
    `ip_hash`           CHAR(64)        NOT NULL COMMENT 'SHA-256 hash of IP + server salt',
    `user_agent_hash`   CHAR(64)        NOT NULL COMMENT 'SHA-256 hash of User-Agent',
    `consent_version`   VARCHAR(20)     NOT NULL DEFAULT '1.0' COMMENT 'Version of the consent policy shown',
    `timestamp`         DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_consent_visitor` (`visitor_id`),
    KEY `idx_consent_timestamp` (`timestamp`),
    KEY `idx_consent_given` (`consent_given`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Immutable audit log of visitor consent decisions (DPDP Act S.6, S.7)';


-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: privacy_requests
-- Tracks Data Principal rights requests under the DPDP Act 2023.
--
-- DPDP Act 2023 Compliance Notes:
--   - Section 11: Right of Access to personal data.
--   - Section 12: Right of Correction and Erasure.
--   - Section 13: Right of Grievance Redressal.
--   - Section 14: Right to Nominate.
--   - Fiduciaries must respond within a "reasonable timeframe" (expected 30 days).
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `privacy_requests` (
    `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `requester_name`    VARCHAR(200)    NOT NULL,
    `requester_email`   VARCHAR(255)    NOT NULL,
    `request_type`      ENUM(
                            'access',       -- S.11: Right to access data summary
                            'erasure',      -- S.12: Right to erasure / be forgotten
                            'correction',   -- S.12: Right to correct inaccurate data
                            'portability',  -- Data portability (best practice)
                            'grievance'     -- S.13: Grievance redressal
                        ) NOT NULL,
    `status`            ENUM(
                            'pending',      -- Newly submitted, awaiting triage
                            'in_review',    -- Assigned and being processed
                            'resolved',     -- Fulfilled successfully
                            'rejected'      -- Rejected with documented reason
                        ) NOT NULL DEFAULT 'pending',
    `description`       TEXT            NOT NULL COMMENT 'Free-text details from the requester',
    `admin_notes`       TEXT            NULL COMMENT 'Internal notes by the admin (not shared with requester)',
    `submitted_at`      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `resolved_at`       DATETIME        NULL DEFAULT NULL,
    `resolved_by`       INT UNSIGNED    NULL DEFAULT NULL COMMENT 'FK to users.id',
    PRIMARY KEY (`id`),
    KEY `idx_pr_status` (`status`),
    KEY `idx_pr_type` (`request_type`),
    KEY `idx_pr_email` (`requester_email`),
    KEY `idx_pr_submitted` (`submitted_at`),
    CONSTRAINT `fk_pr_resolved_by` FOREIGN KEY (`resolved_by`)
        REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Data Principal rights requests (DPDP Act S.11, S.12, S.13)';


-- ─────────────────────────────────────────────────────────────────────────────
-- TABLE: admin_audit_log
-- Tracks every privileged action performed by admin users.
-- This is critical for accountability under the DPDP Act.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS `admin_audit_log` (
    `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `admin_id`      INT UNSIGNED    NOT NULL,
    `admin_email`   VARCHAR(255)    NOT NULL COMMENT 'Denormalized for log integrity',
    `action`        VARCHAR(100)    NOT NULL COMMENT 'e.g. RESOLVE_REQUEST, EXPORT_CSV, LOGIN',
    `target_type`   VARCHAR(50)     NULL COMMENT 'e.g. privacy_request, consent_log',
    `target_id`     BIGINT UNSIGNED NULL COMMENT 'ID of the affected record',
    `details`       TEXT            NULL COMMENT 'JSON-encoded contextual details',
    `ip_address`    VARCHAR(45)     NULL COMMENT 'IPv4 or IPv6 of admin (internal use)',
    `performed_at`  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_aal_admin` (`admin_id`),
    KEY `idx_aal_action` (`action`),
    KEY `idx_aal_performed` (`performed_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Privileged action audit trail for accountability';

-- =============================================================================
-- End of Schema
-- =============================================================================
