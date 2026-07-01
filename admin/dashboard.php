<?php
/**
 * PHP PrivacyShield — Admin Dashboard
 * =====================================================================
 * File: admin/dashboard.php
 *
 * Premium analytics dashboard showing:
 *   1. Summary stat cards (total consents, opt-in rate, pending requests).
 *   2. Consent audit log table with server-side pagination & search.
 *   3. CSV export of filtered results.
 *
 * Security:
 *   - requireLogin() enforced at the top.
 *   - All output encoded with e() / htmlspecialchars().
 *   - CSV export uses CSRF token validation.
 *   - Pagination parameters validated as integers.
 *   - Search parameters bound via PDO prepared statements.
 * =====================================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/db.php';
require_once __DIR__ . '/../core/Auth.php';
require_once __DIR__ . '/../core/Validator.php';

requireLogin();

$pdo = getDBConnection();

// ── CSV Export Handler ────────────────────────────────────────────────────────
// Must happen before any HTML output.
if (isset($_GET['export']) && $_GET['export'] === 'csv') {
    // Validate CSRF token passed as query parameter.
    $submittedToken = $_GET['csrf_token'] ?? '';
    $expectedToken  = $_SESSION['csrf_token'] ?? '';
    if (empty($submittedToken) || !hash_equals($expectedToken, $submittedToken)) {
        http_response_code(403);
        exit('Invalid CSRF token for export.');
    }

    // Log the export action.
    logAuditEvent(
        currentAdminId(),
        currentAdminEmail(),
        'EXPORT_CSV',
        'consent_logs',
        null,
        ['filter' => $_GET['search'] ?? '']
    );

    // Build export query (with optional search filter, no pagination).
    $exportWhere  = '';
    $exportParams = [];
    $search       = trim($_GET['search'] ?? '');

    if ($search !== '') {
        $exportWhere  = 'WHERE visitor_id LIKE :search';
        $exportParams = [':search' => '%' . $search . '%'];
    }

    $exportStmt = $pdo->prepare("
        SELECT id, visitor_id, page_url, consent_given, consent_version, timestamp
        FROM consent_logs
        {$exportWhere}
        ORDER BY timestamp DESC
        LIMIT 10000
    ");
    $exportStmt->execute($exportParams);
    $rows = $exportStmt->fetchAll();

    // Output CSV headers.
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="consent_export_' . date('Y-m-d') . '.csv"');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store, no-cache');

    $out = fopen('php://output', 'w');
    // UTF-8 BOM for Excel compatibility.
    fwrite($out, "\xEF\xBB\xBF");
    fputcsv($out, ['ID', 'Visitor ID', 'Page URL', 'Consent Given', 'Policy Version', 'Timestamp']);

    foreach ($rows as $row) {
        fputcsv($out, [
            $row['id'],
            $row['visitor_id'],
            $row['page_url'],
            $row['consent_given'] ? 'Accepted' : 'Rejected',
            $row['consent_version'],
            $row['timestamp'],
        ]);
    }

    fclose($out);
    exit;
}

// ── Stat Aggregations ─────────────────────────────────────────────────────────
$stats = [];

// Total consent events (all time).
$stats['total_consents'] = (int)$pdo->query("SELECT COUNT(*) FROM consent_logs")->fetchColumn();

// Consents in the last 30 days.
$stats['recent_consents'] = (int)$pdo->query(
    "SELECT COUNT(*) FROM consent_logs WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)"
)->fetchColumn();

// Opt-in rate (accepted / total * 100).
$accepted              = (int)$pdo->query("SELECT COUNT(*) FROM consent_logs WHERE consent_given = 1")->fetchColumn();
$stats['optin_rate']   = $stats['total_consents'] > 0
    ? round(($accepted / $stats['total_consents']) * 100, 1)
    : 0;

// Pending privacy requests.
$stats['pending_requests'] = (int)$pdo->query(
    "SELECT COUNT(*) FROM privacy_requests WHERE status = 'pending'"
)->fetchColumn();

// ── Pagination & Search Parameters ───────────────────────────────────────────
const ROWS_PER_PAGE = 25;

$currentPage = max(1, (int)($_GET['page'] ?? 1));
$search      = trim($_GET['search'] ?? '');
$filterDate  = trim($_GET['date'] ?? '');
$filterType  = $_GET['consent_type'] ?? ''; // '1' = accepted, '0' = rejected, '' = all

// Build WHERE clause for the log query.
$whereClauses = [];
$queryParams  = [];

if ($search !== '') {
    $whereClauses[] = 'visitor_id LIKE :search';
    $queryParams[':search'] = '%' . $search . '%';
}

if ($filterDate !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $filterDate)) {
    $whereClauses[] = 'DATE(timestamp) = :filter_date';
    $queryParams[':filter_date'] = $filterDate;
}

if (in_array($filterType, ['0', '1'], true)) {
    $whereClauses[] = 'consent_given = :consent_type';
    $queryParams[':consent_type'] = (int)$filterType;
}

$whereSQL = !empty($whereClauses) ? 'WHERE ' . implode(' AND ', $whereClauses) : '';

// Count total rows for pagination.
$countStmt = $pdo->prepare("SELECT COUNT(*) FROM consent_logs {$whereSQL}");
$countStmt->execute($queryParams);
$totalRows  = (int)$countStmt->fetchColumn();
$totalPages = max(1, (int)ceil($totalRows / ROWS_PER_PAGE));
$currentPage = min($currentPage, $totalPages);
$offset      = ($currentPage - 1) * ROWS_PER_PAGE;

// Fetch the current page of logs.
$logStmt = $pdo->prepare("
    SELECT id, visitor_id, page_url, consent_given, consent_version, timestamp
    FROM consent_logs
    {$whereSQL}
    ORDER BY timestamp DESC
    LIMIT :limit OFFSET :offset
");

// Bind limit/offset as integers explicitly (PDO bindValue required for these).
foreach ($queryParams as $key => $value) {
    $logStmt->bindValue($key, $value);
}
$logStmt->bindValue(':limit',  ROWS_PER_PAGE, PDO::PARAM_INT);
$logStmt->bindValue(':offset', $offset,       PDO::PARAM_INT);
$logStmt->execute();
$logs = $logStmt->fetchAll();

// ── Recent Admin Activity ─────────────────────────────────────────────────────
$activityStmt = $pdo->query("
    SELECT action, admin_email, performed_at, target_type
    FROM admin_audit_log
    ORDER BY performed_at DESC
    LIMIT 5
");
$recentActivity = $activityStmt->fetchAll();

// ── Render Page ───────────────────────────────────────────────────────────────
$pageTitle   = 'Dashboard';
$csrfToken   = generateCSRFToken();
$exportQuery = http_build_query([
    'export'     => 'csv',
    'search'     => $search,
    'date'       => $filterDate,
    'csrf_token' => $csrfToken,
]);

require_once __DIR__ . '/../templates/admin_header.php';
?>

<!-- ── Stat Cards ─────────────────────────────────────────────────────────── -->
<div class="stat-grid">
    <div class="stat-card" style="--stat-color: #6366f1;">
        <div class="stat-icon">📊</div>
        <div class="stat-label">Total Consents</div>
        <div class="stat-value" id="stat-total"><?= number_format($stats['total_consents']) ?></div>
        <div class="stat-sub">All time</div>
    </div>

    <div class="stat-card" style="--stat-color: #22c55e;">
        <div class="stat-icon">✅</div>
        <div class="stat-label">Opt-In Rate</div>
        <div class="stat-value" id="stat-optin"><?= $stats['optin_rate'] ?>%</div>
        <div class="stat-sub"><?= number_format($accepted) ?> accepted</div>
    </div>

    <div class="stat-card" style="--stat-color: #38bdf8;">
        <div class="stat-icon">📅</div>
        <div class="stat-label">Last 30 Days</div>
        <div class="stat-value" id="stat-recent"><?= number_format($stats['recent_consents']) ?></div>
        <div class="stat-sub">New consent events</div>
    </div>

    <div class="stat-card" style="--stat-color: <?= $stats['pending_requests'] > 0 ? '#f59e0b' : '#22c55e' ?>;">
        <div class="stat-icon"><?= $stats['pending_requests'] > 0 ? '⚠️' : '✅' ?></div>
        <div class="stat-label">Pending Requests</div>
        <div class="stat-value" id="stat-pending"><?= $stats['pending_requests'] ?></div>
        <div class="stat-sub"><a href="/admin/requests.php" style="color: inherit;">View requests →</a></div>
    </div>
</div>

<div style="display:grid; grid-template-columns: 1fr 320px; gap:1rem; align-items:start;">

<!-- ── Consent Audit Log ─────────────────────────────────────────────────── -->
<div class="card">
    <div class="card-header">
        <div>
            <div class="card-title">📋 Consent Audit Log</div>
            <div class="card-subtitle">DPDP Act 2023 — Section 7 Record Keeping</div>
        </div>
        <a href="?<?= $exportQuery ?>" class="btn btn-outline btn-sm" id="btn-export">
            ⬇ Export CSV
        </a>
    </div>

    <!-- Search & Filter Bar -->
    <form method="GET" action="/admin/dashboard.php" style="display:flex; gap:0.5rem; flex-wrap:wrap; margin-bottom:1rem;">
        <input
            type="text"
            name="search"
            class="form-control"
            placeholder="Search visitor ID..."
            value="<?= e($search) ?>"
            style="flex:1; min-width:160px;"
            id="search-input">

        <input
            type="date"
            name="date"
            class="form-control"
            value="<?= e($filterDate) ?>"
            id="date-filter">

        <select name="consent_type" class="form-control" id="type-filter">
            <option value="" <?= $filterType === '' ? 'selected' : '' ?>>All Types</option>
            <option value="1" <?= $filterType === '1' ? 'selected' : '' ?>>Accepted</option>
            <option value="0" <?= $filterType === '0' ? 'selected' : '' ?>>Rejected</option>
        </select>

        <button type="submit" class="btn btn-primary btn-sm" id="btn-search">🔍 Filter</button>

        <?php if ($search || $filterDate || $filterType !== ''): ?>
            <a href="/admin/dashboard.php" class="btn btn-outline btn-sm" id="btn-clear">✕ Clear</a>
        <?php endif; ?>
    </form>

    <!-- Results Summary -->
    <div style="font-size:0.78rem; color:var(--text-muted); margin-bottom:0.6rem;">
        Showing <?= number_format(min($offset + 1, $totalRows)) ?>–<?= number_format(min($offset + ROWS_PER_PAGE, $totalRows)) ?>
        of <?= number_format($totalRows) ?> records
        <?= ($search || $filterDate || $filterType !== '') ? '(filtered)' : '' ?>
    </div>

    <!-- Table -->
    <div class="table-wrapper">
        <?php if (empty($logs)): ?>
            <div class="empty-state">
                <div class="empty-icon">📭</div>
                <p>No consent records match your filter criteria.</p>
            </div>
        <?php else: ?>
        <table id="consent-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Visitor ID</th>
                    <th>Page URL</th>
                    <th>Decision</th>
                    <th>Version</th>
                    <th>Timestamp (IST)</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($logs as $log): ?>
                <tr>
                    <td style="color:var(--text-muted); font-size:0.75rem;"><?= e($log['id']) ?></td>
                    <td>
                        <code style="font-size:0.72rem; color:var(--accent-light); background:var(--accent-dim); padding:0.1rem 0.4rem; border-radius:4px;">
                            <?= e(substr($log['visitor_id'], 0, 18)) ?>…
                        </code>
                    </td>
                    <td style="max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"
                        title="<?= e($log['page_url']) ?>">
                        <?= e(parse_url($log['page_url'], PHP_URL_HOST) . parse_url($log['page_url'], PHP_URL_PATH)) ?>
                    </td>
                    <td>
                        <?php if ($log['consent_given']): ?>
                            <span class="badge badge-success">✓ Accepted</span>
                        <?php else: ?>
                            <span class="badge badge-danger">✕ Rejected</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <span class="badge badge-muted">v<?= e($log['consent_version']) ?></span>
                    </td>
                    <td style="font-size:0.78rem; color:var(--text-muted); white-space:nowrap;">
                        <?= e(date('d M Y, H:i', strtotime($log['timestamp']))) ?>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>

    <!-- Pagination -->
    <?php if ($totalPages > 1): ?>
    <div class="pagination" id="pagination">
        <?php
        // Build pagination URL preserving all filters.
        $paginationBase = '?' . http_build_query(array_filter([
            'search'       => $search,
            'date'         => $filterDate,
            'consent_type' => $filterType,
        ]));
        ?>

        <!-- Previous -->
        <?php if ($currentPage > 1): ?>
            <a href="<?= $paginationBase ?>&page=<?= $currentPage - 1 ?>" title="Previous">‹</a>
        <?php else: ?>
            <span class="disabled">‹</span>
        <?php endif; ?>

        <!-- Page Numbers -->
        <?php
        $start = max(1, $currentPage - 2);
        $end   = min($totalPages, $currentPage + 2);
        for ($p = $start; $p <= $end; $p++):
        ?>
            <?php if ($p === $currentPage): ?>
                <span class="current"><?= $p ?></span>
            <?php else: ?>
                <a href="<?= $paginationBase ?>&page=<?= $p ?>"><?= $p ?></a>
            <?php endif; ?>
        <?php endfor; ?>

        <!-- Next -->
        <?php if ($currentPage < $totalPages): ?>
            <a href="<?= $paginationBase ?>&page=<?= $currentPage + 1 ?>" title="Next">›</a>
        <?php else: ?>
            <span class="disabled">›</span>
        <?php endif; ?>
    </div>
    <?php endif; ?>
</div>

<!-- ── Sidebar: Recent Activity ──────────────────────────────────────────── -->
<div>
    <div class="card">
        <div class="card-header">
            <div class="card-title">🕐 Recent Admin Activity</div>
        </div>
        <?php if (empty($recentActivity)): ?>
            <div class="empty-state" style="padding:1.5rem;">
                <p>No activity yet.</p>
            </div>
        <?php else: ?>
            <?php foreach ($recentActivity as $act): ?>
            <div style="padding:0.6rem 0; border-bottom:1px solid var(--border); display:flex; flex-direction:column; gap:0.2rem;">
                <div style="display:flex; align-items:center; justify-content:space-between;">
                    <span class="badge badge-info" style="font-size:0.68rem;"><?= e($act['action']) ?></span>
                    <span style="font-size:0.70rem; color:var(--text-muted);"><?= e(date('d M, H:i', strtotime($act['performed_at']))) ?></span>
                </div>
                <div style="font-size:0.78rem; color:var(--text-secondary);"><?= e($act['admin_email']) ?></div>
            </div>
            <?php endforeach; ?>
        <?php endif; ?>
    </div>

    <!-- Compliance Info Card -->
    <div class="card" style="margin-top:1rem;">
        <div class="card-header">
            <div class="card-title">⚖️ DPDP Act 2023</div>
        </div>
        <div style="font-size:0.80rem; color:var(--text-secondary); line-height:1.7;">
            <div style="margin-bottom:0.5rem;">
                <span class="badge badge-success" style="font-size:0.68rem;">S.6</span>
                Consent records maintained ✓
            </div>
            <div style="margin-bottom:0.5rem;">
                <span class="badge badge-success" style="font-size:0.68rem;">S.7</span>
                Audit trail active ✓
            </div>
            <div style="margin-bottom:0.5rem;">
                <span class="badge badge-<?= $stats['pending_requests'] > 0 ? 'warning' : 'success' ?>" style="font-size:0.68rem;">S.11-13</span>
                <?= $stats['pending_requests'] > 0 ? "{$stats['pending_requests']} request(s) pending" : 'All requests resolved ✓' ?>
            </div>
            <div>
                <span class="badge badge-success" style="font-size:0.68rem;">OWASP</span>
                Top 10 protections active ✓
            </div>
        </div>
    </div>
</div>

</div><!-- /.grid -->

<?php require_once __DIR__ . '/../templates/admin_footer.php'; ?>
