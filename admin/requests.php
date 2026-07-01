<?php
/**
 * PHP PrivacyShield — Data Rights Requests Portal
 * =====================================================================
 * File: admin/requests.php
 *
 * Manages "Right to Erasure", "Right to Access", and other DPDP Act
 * data principal rights requests.
 *
 * Features:
 *   - Lists all requests with status badges and filters.
 *   - Admin can update request status (with optional notes).
 *   - Every status change is logged to admin_audit_log.
 *   - CSRF-protected POST actions.
 *   - All outputs encoded with e() / htmlspecialchars().
 *
 * DPDP Act 2023 References:
 *   - Section 11: Right of Access to personal data summary.
 *   - Section 12: Right of Correction and Erasure.
 *   - Section 13: Right of Grievance Redressal.
 * =====================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../core/Auth.php';
require_once __DIR__ . '/../core/Validator.php';

requireLogin();

$pdo        = getDBConnection();
$adminId    = currentAdminId();
$adminEmail = currentAdminEmail();

// ── Allowed Status Transitions ────────────────────────────────────────────────
const ALLOWED_STATUSES = ['pending', 'in_review', 'resolved', 'rejected'];
const ALLOWED_TYPES    = ['access', 'erasure', 'correction', 'portability', 'grievance'];

$actionMessage = null;
$actionError   = null;

// ── Handle Status Update POST ─────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    validateCSRFToken();

    $postAction = $_POST['action'] ?? '';

    if ($postAction === 'update_status') {
        try {
            $requestId  = validateInt($_POST['request_id'] ?? '', 'request_id', 1);
            $newStatus  = validateEnum($_POST['new_status'] ?? '', ALLOWED_STATUSES, 'new_status');
            $adminNotes = validateString($_POST['admin_notes'] ?? '', 'admin_notes', 2000, false);

            // Fetch the existing request to validate it exists.
            $fetchStmt = $pdo->prepare("SELECT id, status, requester_email FROM privacy_requests WHERE id = :id LIMIT 1");
            $fetchStmt->execute([':id' => $requestId]);
            $request = $fetchStmt->fetch();

            if (!$request) {
                throw new InvalidArgumentException("Request #{$requestId} not found.");
            }

            // Update status and notes.
            $resolvedAt = in_array($newStatus, ['resolved', 'rejected']) ? date('Y-m-d H:i:s') : null;

            $updateStmt = $pdo->prepare("
                UPDATE privacy_requests
                SET status       = :status,
                    admin_notes  = :notes,
                    resolved_at  = :resolved_at,
                    resolved_by  = :resolved_by
                WHERE id = :id
            ");
            $updateStmt->execute([
                ':status'      => $newStatus,
                ':notes'       => $adminNotes !== '' ? $adminNotes : null,
                ':resolved_at' => $resolvedAt,
                ':resolved_by' => in_array($newStatus, ['resolved', 'rejected']) ? $adminId : null,
                ':id'          => $requestId,
            ]);

            // Audit log the status change.
            logAuditEvent(
                $adminId,
                $adminEmail,
                'UPDATE_REQUEST_STATUS',
                'privacy_request',
                $requestId,
                [
                    'old_status'      => $request['status'],
                    'new_status'      => $newStatus,
                    'requester_email' => $request['requester_email'],
                ]
            );

            $actionMessage = "Request #{$requestId} status updated to " . strtoupper($newStatus) . ".";

        } catch (InvalidArgumentException $e) {
            $actionError = $e->getMessage();
        } catch (PDOException $e) {
            error_log('[PrivacyShield][Requests] ' . $e->getMessage());
            $actionError = 'A database error occurred. Please try again.';
        }
    }
}

// ── Filter Parameters ─────────────────────────────────────────────────────────
$filterStatus = $_GET['status'] ?? '';
$filterType   = $_GET['type']   ?? '';
$search       = trim($_GET['search'] ?? '');

$whereClauses = [];
$queryParams  = [];

if (in_array($filterStatus, ALLOWED_STATUSES, true)) {
    $whereClauses[] = 'status = :status';
    $queryParams[':status'] = $filterStatus;
}

if (in_array($filterType, ALLOWED_TYPES, true)) {
    $whereClauses[] = 'request_type = :request_type';
    $queryParams[':request_type'] = $filterType;
}

if ($search !== '') {
    $whereClauses[] = '(requester_name LIKE :search OR requester_email LIKE :search2)';
    $queryParams[':search']  = '%' . $search . '%';
    $queryParams[':search2'] = '%' . $search . '%';
}

$whereSQL = !empty($whereClauses) ? 'WHERE ' . implode(' AND ', $whereClauses) : '';

// ── Fetch Requests ────────────────────────────────────────────────────────────
$stmt = $pdo->prepare("
    SELECT
        pr.*,
        u.name AS resolved_by_name
    FROM privacy_requests pr
    LEFT JOIN users u ON u.id = pr.resolved_by
    {$whereSQL}
    ORDER BY
        FIELD(pr.status, 'pending', 'in_review', 'resolved', 'rejected'),
        pr.submitted_at DESC
");
$stmt->execute($queryParams);
$requests = $stmt->fetchAll();

// ── Status Counts for Tabs ────────────────────────────────────────────────────
$countStmt = $pdo->query("
    SELECT status, COUNT(*) as cnt FROM privacy_requests GROUP BY status
");
$statusCounts = [];
foreach ($countStmt->fetchAll() as $row) {
    $statusCounts[$row['status']] = (int)$row['cnt'];
}

// ── Render ────────────────────────────────────────────────────────────────────
$pageTitle = 'Data Rights Requests';
$csrfToken = generateCSRFToken();

// Helper: status badge HTML.
function statusBadge(string $status): string {
    $map = [
        'pending'   => ['badge-warning', '⏳ Pending'],
        'in_review' => ['badge-info',    '🔄 In Review'],
        'resolved'  => ['badge-success', '✅ Resolved'],
        'rejected'  => ['badge-danger',  '✕ Rejected'],
    ];
    [$cls, $label] = $map[$status] ?? ['badge-muted', $status];
    return '<span class="badge ' . $cls . '">' . e($label) . '</span>';
}

// Helper: request type label.
function requestTypeLabel(string $type): string {
    $labels = [
        'access'      => ['🔍', 'Access',      'S.11'],
        'erasure'     => ['🗑️',  'Erasure',     'S.12'],
        'correction'  => ['✏️',  'Correction',  'S.12'],
        'portability' => ['📦', 'Portability', 'Best Practice'],
        'grievance'   => ['📣', 'Grievance',   'S.13'],
    ];
    [$icon, $label, $ref] = $labels[$type] ?? ['📄', $type, ''];
    return "<span title='DPDP Act {$ref}'>{$icon} " . e($label) . "</span>";
}

require_once __DIR__ . '/../templates/admin_header.php';
?>

<style>
    .request-grid { display: grid; gap: 1rem; }
    .request-card {
        background: var(--bg-card); border: 1px solid var(--border);
        border-radius: var(--radius); padding: 1.2rem 1.4rem;
        transition: border-color var(--transition);
    }
    .request-card:hover { border-color: rgba(255,255,255,0.15); }
    .request-card.pending   { border-left: 3px solid var(--warning); }
    .request-card.in_review { border-left: 3px solid var(--info); }
    .request-card.resolved  { border-left: 3px solid var(--success); }
    .request-card.rejected  { border-left: 3px solid var(--danger); }

    .request-header {
        display: flex; align-items: flex-start; justify-content: space-between;
        gap: 1rem; margin-bottom: 0.75rem;
    }
    .request-meta { font-size: 0.80rem; color: var(--text-muted); margin-top: 0.2rem; }

    .request-body {
        font-size: 0.85rem; color: var(--text-secondary);
        background: rgba(0,0,0,0.2); border-radius: var(--radius-sm);
        padding: 0.7rem 0.9rem; margin: 0.75rem 0;
        border: 1px solid var(--border);
        max-height: 120px; overflow-y: auto;
        line-height: 1.6; white-space: pre-wrap; word-break: break-word;
    }

    .request-actions {
        display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap;
        padding-top: 0.75rem; border-top: 1px solid var(--border);
    }

    .status-form { display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; }

    .filter-tabs {
        display: flex; gap: 0.3rem; margin-bottom: 1rem; flex-wrap: wrap;
    }
    .filter-tab {
        padding: 0.4rem 0.8rem; border-radius: 20px;
        font-size: 0.78rem; font-weight: 500; text-decoration: none;
        border: 1px solid var(--border); color: var(--text-secondary);
        transition: all var(--transition);
    }
    .filter-tab:hover { background: var(--bg-card-hover); color: var(--text-primary); }
    .filter-tab.active {
        background: var(--accent-dim); color: var(--accent-light);
        border-color: var(--border-accent);
    }
    .count-chip {
        display: inline-block; background: rgba(255,255,255,0.1);
        border-radius: 10px; padding: 0 0.45rem;
        font-size: 0.68rem; font-weight: 700; margin-left: 0.25rem;
    }
    details > summary { cursor: pointer; list-style: none; }
    details > summary::marker { display: none; }
</style>

<?php if ($actionMessage): ?>
    <div class="alert-box alert-box-success">✅ <?= e($actionMessage) ?></div>
<?php endif; ?>
<?php if ($actionError): ?>
    <div class="alert-box alert-box-error">⚠️ <?= e($actionError) ?></div>
<?php endif; ?>

<!-- ── Filter Bar ────────────────────────────────────────────────────────── -->
<div class="card" style="margin-bottom:1rem;">
    <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:0.75rem;">

        <!-- Status Tabs -->
        <div class="filter-tabs" id="status-tabs">
            <?php
            $allStatuses = ['' => 'All', 'pending' => 'Pending', 'in_review' => 'In Review', 'resolved' => 'Resolved', 'rejected' => 'Rejected'];
            $totalAll    = array_sum($statusCounts);
            foreach ($allStatuses as $val => $label):
                $isActive = $filterStatus === $val;
                $count    = $val === '' ? $totalAll : ($statusCounts[$val] ?? 0);
                $href     = '?' . http_build_query(array_filter(['status' => $val, 'type' => $filterType, 'search' => $search]));
            ?>
                <a href="<?= e($href) ?>" class="filter-tab <?= $isActive ? 'active' : '' ?>">
                    <?= e($label) ?>
                    <?php if ($count > 0): ?>
                        <span class="count-chip"><?= $count ?></span>
                    <?php endif; ?>
                </a>
            <?php endforeach; ?>
        </div>

        <!-- Search -->
        <form method="GET" style="display:flex; gap:0.4rem;">
            <?php if ($filterStatus): ?><input type="hidden" name="status" value="<?= e($filterStatus) ?>"><?php endif; ?>
            <?php if ($filterType):   ?><input type="hidden" name="type"   value="<?= e($filterType)   ?>"><?php endif; ?>
            <input type="text" name="search" class="form-control" placeholder="Search name or email…" value="<?= e($search) ?>" id="request-search">
            <button type="submit" class="btn btn-primary btn-sm">Search</button>
            <?php if ($search): ?>
                <a href="?status=<?= e($filterStatus) ?>&type=<?= e($filterType) ?>" class="btn btn-outline btn-sm">✕</a>
            <?php endif; ?>
        </form>
    </div>

    <!-- Type Filter -->
    <div class="filter-tabs" style="margin-top:0.75rem;" id="type-tabs">
        <?php
        $allTypes  = ['' => 'All Types', 'access' => '🔍 Access (S.11)', 'erasure' => '🗑️ Erasure (S.12)', 'correction' => '✏️ Correction (S.12)', 'portability' => '📦 Portability', 'grievance' => '📣 Grievance (S.13)'];
        foreach ($allTypes as $val => $label):
            $isActive = $filterType === $val;
            $href     = '?' . http_build_query(array_filter(['status' => $filterStatus, 'type' => $val, 'search' => $search]));
        ?>
            <a href="<?= e($href) ?>" class="filter-tab <?= $isActive ? 'active' : '' ?>">
                <?= e($label) ?>
            </a>
        <?php endforeach; ?>
    </div>
</div>

<!-- ── Requests List ─────────────────────────────────────────────────────── -->
<?php if (empty($requests)): ?>
    <div class="card">
        <div class="empty-state">
            <div class="empty-icon">📭</div>
            <p>No data rights requests match your current filter.</p>
        </div>
    </div>
<?php else: ?>
<div class="request-grid" id="requests-list">
    <?php foreach ($requests as $req): ?>
    <div class="request-card <?= e($req['status']) ?>" id="request-<?= (int)$req['id'] ?>">
        <div class="request-header">
            <div>
                <div style="display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap;">
                    <span style="font-weight:600; color:var(--text-primary);">
                        <?= e($req['requester_name']) ?>
                    </span>
                    <?= statusBadge($req['status']) ?>
                    <span class="badge badge-muted" style="font-size:0.70rem;">
                        <?= requestTypeLabel($req['request_type']) ?>
                    </span>
                </div>
                <div class="request-meta">
                    <a href="mailto:<?= e($req['requester_email']) ?>"
                       style="color:var(--accent-light); text-decoration:none;">
                        <?= e($req['requester_email']) ?>
                    </a>
                    &nbsp;·&nbsp;
                    Submitted <?= e(date('d M Y, H:i', strtotime($req['submitted_at']))) ?>
                    <?php if ($req['resolved_at']): ?>
                        &nbsp;·&nbsp; Resolved <?= e(date('d M Y', strtotime($req['resolved_at']))) ?>
                        <?php if ($req['resolved_by_name']): ?>
                            by <?= e($req['resolved_by_name']) ?>
                        <?php endif; ?>
                    <?php endif; ?>
                    &nbsp;·&nbsp; <span style="color:var(--text-muted);">ID #<?= (int)$req['id'] ?></span>
                </div>
            </div>
        </div>

        <!-- Description -->
        <div class="request-body"><?= e($req['description']) ?></div>

        <!-- Admin Notes (if any) -->
        <?php if (!empty($req['admin_notes'])): ?>
        <details style="margin-bottom:0.5rem;">
            <summary class="btn btn-outline btn-sm" style="display:inline-flex;">
                📝 View Admin Notes
            </summary>
            <div class="request-body" style="margin-top:0.5rem; border-color:rgba(99,102,241,0.25);">
                <?= e($req['admin_notes']) ?>
            </div>
        </details>
        <?php endif; ?>

        <!-- Status Update Form -->
        <?php if (!in_array($req['status'], ['resolved', 'rejected'])): ?>
        <form method="POST" class="request-actions" id="form-request-<?= (int)$req['id'] ?>">
            <input type="hidden" name="csrf_token"  value="<?= e($csrfToken) ?>">
            <input type="hidden" name="action"      value="update_status">
            <input type="hidden" name="request_id"  value="<?= (int)$req['id'] ?>">

            <div class="status-form">
                <select name="new_status" class="form-control" style="min-width:130px;"
                        id="status-select-<?= (int)$req['id'] ?>">
                    <?php foreach (['pending', 'in_review', 'resolved', 'rejected'] as $s): ?>
                        <option value="<?= e($s) ?>" <?= $req['status'] === $s ? 'selected' : '' ?>>
                            <?= e(ucwords(str_replace('_', ' ', $s))) ?>
                        </option>
                    <?php endforeach; ?>
                </select>

                <input type="text" name="admin_notes" class="form-control"
                       placeholder="Internal note (optional)…"
                       style="min-width:200px; flex:1;"
                       value="<?= e($req['admin_notes'] ?? '') ?>"
                       id="notes-<?= (int)$req['id'] ?>"
                       maxlength="2000">

                <button type="submit" class="btn btn-primary btn-sm"
                        id="btn-update-<?= (int)$req['id'] ?>">
                    Update
                </button>
            </div>
        </form>
        <?php else: ?>
        <div class="request-actions" style="color:var(--text-muted); font-size:0.78rem;">
            ✓ This request has been <?= e($req['status']) ?> and is now closed.
        </div>
        <?php endif; ?>
    </div>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<?php require_once __DIR__ . '/../templates/admin_footer.php'; ?>
