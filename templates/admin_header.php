<?php
/**
 * PHP PrivacyShield — Shared Admin Header & Navigation
 * =====================================================================
 * File: templates/admin_header.php
 *
 * Include at the top of every admin page AFTER calling requireLogin().
 *
 * Usage:
 *   $pageTitle = 'Dashboard';
 *   require_once __DIR__ . '/../templates/admin_header.php';
 * =====================================================================
 */
// $pageTitle should be set by the including page.
$pageTitle = $pageTitle ?? 'Admin';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= e($pageTitle) ?> — PHP PrivacyShield</title>
    <meta name="robots" content="noindex, nofollow">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        /* ─── Design System Tokens ─────────────────────────────────────────── */
        :root {
            --bg-deep:        #070b17;
            --bg-surface:     #0d1224;
            --bg-card:        rgba(255,255,255,0.035);
            --bg-card-hover:  rgba(255,255,255,0.06);
            --border:         rgba(255,255,255,0.08);
            --border-accent:  rgba(99,102,241,0.4);
            --accent:         #6366f1;
            --accent-light:   #818cf8;
            --accent-glow:    rgba(99,102,241,0.25);
            --accent-dim:     rgba(99,102,241,0.12);
            --purple:         #7c3aed;
            --text-primary:   #e8eeff;
            --text-secondary: #a8b3cf;
            --text-muted:     #5c687d;
            --success:        #22c55e;
            --success-dim:    rgba(34,197,94,0.12);
            --danger:         #ef4444;
            --danger-dim:     rgba(239,68,68,0.12);
            --warning:        #f59e0b;
            --warning-dim:    rgba(245,158,11,0.12);
            --info:           #38bdf8;
            --info-dim:       rgba(56,189,248,0.12);
            --radius-sm:      6px;
            --radius:         12px;
            --radius-lg:      18px;
            --sidebar-w:      240px;
            --header-h:       60px;
            --transition:     0.2s ease;
        }

        /* ─── Base Reset ────────────────────────────────────────────────────── */
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        html { scroll-behavior: smooth; }
        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg-deep);
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            font-size: 14px;
            line-height: 1.6;
        }

        /* ─── Sidebar Navigation ────────────────────────────────────────────── */
        .sidebar {
            width: var(--sidebar-w);
            min-height: 100vh;
            background: var(--bg-surface);
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            position: fixed;
            top: 0; left: 0; bottom: 0;
            z-index: 100;
            padding: 0;
            overflow-y: auto;
        }
        .sidebar-logo {
            display: flex; align-items: center; gap: 0.6rem;
            padding: 1.2rem 1.4rem;
            border-bottom: 1px solid var(--border);
            text-decoration: none;
        }
        .sidebar-logo-icon {
            width: 34px; height: 34px;
            background: linear-gradient(135deg, var(--accent), var(--purple));
            border-radius: 8px;
            display: flex; align-items: center; justify-content: center;
            font-size: 17px; flex-shrink: 0;
        }
        .sidebar-logo-text { font-size: 0.95rem; font-weight: 700; color: var(--text-primary); }
        .sidebar-logo-text span { color: var(--accent-light); }

        .sidebar-nav { flex: 1; padding: 1rem 0.7rem; }
        .nav-section-label {
            font-size: 0.68rem; font-weight: 600; letter-spacing: 0.08em;
            text-transform: uppercase; color: var(--text-muted);
            padding: 0.5rem 0.7rem; margin-top: 0.5rem;
        }
        .nav-link {
            display: flex; align-items: center; gap: 0.65rem;
            padding: 0.6rem 0.75rem; border-radius: var(--radius-sm);
            color: var(--text-secondary); text-decoration: none;
            font-size: 0.875rem; font-weight: 500;
            transition: background var(--transition), color var(--transition);
            margin-bottom: 1px;
        }
        .nav-link:hover { background: var(--bg-card-hover); color: var(--text-primary); }
        .nav-link.active {
            background: var(--accent-dim); color: var(--accent-light);
            border: 1px solid var(--border-accent);
        }
        .nav-link .nav-icon { font-size: 1rem; width: 20px; text-align: center; }

        .sidebar-footer {
            padding: 1rem 0.7rem;
            border-top: 1px solid var(--border);
        }
        .user-card {
            display: flex; align-items: center; gap: 0.6rem;
            padding: 0.6rem 0.7rem; border-radius: var(--radius-sm);
            background: var(--bg-card);
        }
        .user-avatar {
            width: 30px; height: 30px; border-radius: 50%;
            background: linear-gradient(135deg, var(--accent), var(--purple));
            display: flex; align-items: center; justify-content: center;
            font-size: 12px; font-weight: 700; color: white;
            flex-shrink: 0;
        }
        .user-info { flex: 1; min-width: 0; }
        .user-name { font-size: 0.82rem; font-weight: 600; color: var(--text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .user-role { font-size: 0.70rem; color: var(--text-muted); }
        .logout-btn {
            color: var(--text-muted); text-decoration: none;
            font-size: 1rem; padding: 0.2rem;
            transition: color var(--transition);
        }
        .logout-btn:hover { color: var(--danger); }

        /* ─── Main Content Area ─────────────────────────────────────────────── */
        .main {
            margin-left: var(--sidebar-w);
            flex: 1;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        .topbar {
            height: var(--header-h);
            border-bottom: 1px solid var(--border);
            display: flex; align-items: center;
            padding: 0 1.8rem;
            gap: 1rem;
            background: rgba(7,11,23,0.8);
            backdrop-filter: blur(10px);
            position: sticky; top: 0; z-index: 50;
        }
        .topbar-title { font-size: 1rem; font-weight: 600; color: var(--text-primary); }
        .topbar-breadcrumb { font-size: 0.8rem; color: var(--text-muted); }
        .topbar-breadcrumb span { color: var(--text-secondary); }
        .topbar-actions { margin-left: auto; display: flex; align-items: center; gap: 0.75rem; }

        .compliance-badge {
            display: inline-flex; align-items: center; gap: 0.3rem;
            background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.25);
            color: #4ade80; border-radius: 20px;
            padding: 0.2rem 0.65rem; font-size: 0.72rem; font-weight: 500;
        }

        .page-content { padding: 1.8rem; flex: 1; }

        /* ─── Reusable Components ───────────────────────────────────────────── */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1.4rem;
            backdrop-filter: blur(8px);
        }
        .card-header {
            display: flex; align-items: center; justify-content: space-between;
            margin-bottom: 1rem; padding-bottom: 0.8rem;
            border-bottom: 1px solid var(--border);
        }
        .card-title { font-size: 0.9rem; font-weight: 600; color: var(--text-primary); }
        .card-subtitle { font-size: 0.78rem; color: var(--text-muted); margin-top: 0.15rem; }

        /* Stat Card */
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 1.2rem 1.4rem;
            position: relative;
            overflow: hidden;
            transition: border-color var(--transition), transform var(--transition);
        }
        .stat-card:hover { border-color: var(--border-accent); transform: translateY(-2px); }
        .stat-card::before {
            content: '';
            position: absolute; top: 0; left: 0; right: 0; height: 2px;
            background: var(--stat-color, var(--accent));
            border-radius: var(--radius) var(--radius) 0 0;
        }
        .stat-icon { font-size: 1.5rem; margin-bottom: 0.6rem; }
        .stat-label { font-size: 0.75rem; color: var(--text-muted); font-weight: 500; letter-spacing: 0.04em; text-transform: uppercase; margin-bottom: 0.3rem; }
        .stat-value { font-size: 1.9rem; font-weight: 800; color: var(--text-primary); line-height: 1; }
        .stat-sub { font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.3rem; }

        /* Table */
        .table-wrapper { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
        thead th {
            padding: 0.7rem 0.9rem; text-align: left;
            font-size: 0.72rem; font-weight: 600; letter-spacing: 0.05em;
            text-transform: uppercase; color: var(--text-muted);
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }
        tbody td {
            padding: 0.75rem 0.9rem;
            border-bottom: 1px solid rgba(255,255,255,0.04);
            color: var(--text-secondary);
            vertical-align: middle;
        }
        tbody tr:hover td { background: rgba(255,255,255,0.02); color: var(--text-primary); }
        tbody tr:last-child td { border-bottom: none; }

        /* Badges */
        .badge {
            display: inline-block; padding: 0.2rem 0.6rem;
            border-radius: 20px; font-size: 0.72rem; font-weight: 600;
        }
        .badge-success { background: var(--success-dim); color: #4ade80; border: 1px solid rgba(34,197,94,0.2); }
        .badge-danger  { background: var(--danger-dim);  color: #f87171; border: 1px solid rgba(239,68,68,0.2); }
        .badge-warning { background: var(--warning-dim); color: #fbbf24; border: 1px solid rgba(245,158,11,0.2); }
        .badge-info    { background: var(--info-dim);    color: #7dd3fc; border: 1px solid rgba(56,189,248,0.2); }
        .badge-muted   { background: rgba(255,255,255,0.06); color: var(--text-secondary); border: 1px solid var(--border); }

        /* Buttons */
        .btn {
            display: inline-flex; align-items: center; gap: 0.4rem;
            padding: 0.5rem 1rem; border-radius: var(--radius-sm);
            font-size: 0.82rem; font-weight: 500; font-family: inherit;
            cursor: pointer; border: 1px solid transparent;
            transition: all var(--transition); text-decoration: none;
            white-space: nowrap;
        }
        .btn-primary {
            background: linear-gradient(135deg, var(--accent), var(--purple));
            color: white; border-color: transparent;
        }
        .btn-primary:hover { opacity: 0.88; transform: translateY(-1px); }
        .btn-outline {
            background: transparent; color: var(--text-secondary);
            border-color: var(--border);
        }
        .btn-outline:hover { background: var(--bg-card-hover); color: var(--text-primary); }
        .btn-danger { background: var(--danger-dim); color: #f87171; border-color: rgba(239,68,68,0.2); }
        .btn-danger:hover { background: rgba(239,68,68,0.2); }
        .btn-sm { padding: 0.35rem 0.7rem; font-size: 0.78rem; }

        /* Form Controls */
        .form-control {
            padding: 0.55rem 0.9rem;
            background: rgba(255,255,255,0.04);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            color: var(--text-primary); font-size: 0.85rem; font-family: inherit;
            outline: none; transition: border-color var(--transition), box-shadow var(--transition);
        }
        .form-control:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
        .form-control::placeholder { color: var(--text-muted); }
        select.form-control option { background: var(--bg-surface); }

        /* Pagination */
        .pagination {
            display: flex; align-items: center; gap: 0.35rem;
            justify-content: flex-end; margin-top: 1rem;
        }
        .pagination a, .pagination span {
            display: inline-flex; align-items: center; justify-content: center;
            width: 30px; height: 30px; border-radius: var(--radius-sm);
            font-size: 0.8rem; text-decoration: none;
            border: 1px solid var(--border);
            color: var(--text-secondary);
            transition: all var(--transition);
        }
        .pagination a:hover { background: var(--bg-card-hover); color: var(--text-primary); }
        .pagination .current {
            background: var(--accent-dim); color: var(--accent-light);
            border-color: var(--border-accent); font-weight: 600;
        }
        .pagination .disabled { opacity: 0.3; pointer-events: none; }

        /* Alerts */
        .alert-box {
            padding: 0.85rem 1rem; border-radius: var(--radius-sm);
            font-size: 0.85rem; margin-bottom: 1rem;
        }
        .alert-box-success { background: var(--success-dim); border: 1px solid rgba(34,197,94,0.25); color: #86efac; }
        .alert-box-error   { background: var(--danger-dim);  border: 1px solid rgba(239,68,68,0.25);  color: #fca5a5; }
        .alert-box-info    { background: var(--info-dim);    border: 1px solid rgba(56,189,248,0.25);  color: #7dd3fc; }

        /* Empty State */
        .empty-state {
            text-align: center; padding: 3rem 1rem;
            color: var(--text-muted);
        }
        .empty-state .empty-icon { font-size: 2.5rem; margin-bottom: 0.8rem; }
        .empty-state p { font-size: 0.9rem; }
    </style>
</head>
<body>

<!-- ── Sidebar ──────────────────────────────────────────────────────────────── -->
<nav class="sidebar" id="sidebar">
    <a href="/admin/dashboard.php" class="sidebar-logo">
        <div class="sidebar-logo-icon">🛡️</div>
        <div class="sidebar-logo-text">Privacy<span>Shield</span></div>
    </a>

    <div class="sidebar-nav">
        <div class="nav-section-label">Compliance</div>

        <a href="/admin/dashboard.php"
           class="nav-link <?= basename($_SERVER['PHP_SELF']) === 'dashboard.php' ? 'active' : '' ?>">
            <span class="nav-icon">📊</span> Dashboard
        </a>

        <a href="/admin/requests.php"
           class="nav-link <?= basename($_SERVER['PHP_SELF']) === 'requests.php' ? 'active' : '' ?>">
            <span class="nav-icon">📋</span> Data Requests
        </a>

        <div class="nav-section-label" style="margin-top:1rem;">Settings</div>

        <a href="/logout.php" class="nav-link" id="nav-logout">
            <span class="nav-icon">🚪</span> Logout
        </a>
    </div>

    <div class="sidebar-footer">
        <div class="user-card">
            <div class="user-avatar"><?= strtoupper(substr(currentAdminName(), 0, 1)) ?></div>
            <div class="user-info">
                <div class="user-name"><?= currentAdminName() ?></div>
                <div class="user-role"><?= e($_SESSION['admin_role'] ?? 'admin') ?></div>
            </div>
            <a href="/logout.php" class="logout-btn" title="Logout">↩</a>
        </div>
    </div>
</nav>

<!-- ── Main Content ─────────────────────────────────────────────────────────── -->
<div class="main">
    <div class="topbar">
        <div>
            <div class="topbar-title"><?= e($pageTitle) ?></div>
            <div class="topbar-breadcrumb">PrivacyShield › <span><?= e($pageTitle) ?></span></div>
        </div>
        <div class="topbar-actions">
            <div class="compliance-badge">
                <span>✓</span> DPDP Act 2023 Compliant
            </div>
        </div>
    </div>
    <div class="page-content">
