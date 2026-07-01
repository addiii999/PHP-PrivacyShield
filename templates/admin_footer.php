    </div><!-- /.page-content -->
</div><!-- /.main -->

<style>
    /* Footer bar styling */
    .admin-footer {
        grid-column: 1 / -1;
        border-top: 1px solid var(--border);
        padding: 0.8rem 1.8rem;
        display: flex; align-items: center; justify-content: space-between;
        font-size: 0.75rem; color: var(--text-muted);
        background: rgba(13,18,36,0.5);
        margin-left: var(--sidebar-w);
    }
    .admin-footer a { color: var(--text-muted); text-decoration: none; }
    .admin-footer a:hover { color: var(--accent-light); }
</style>

<div class="admin-footer">
    <span>PHP PrivacyShield &copy; <?= date('Y') ?> — DPDP Act 2023 Compliance Platform</span>
    <span>
        Built with 🛡️ |
        <a href="https://www.meity.gov.in/dpdp-act" target="_blank" rel="noopener noreferrer">DPDP Act Text</a> |
        <a href="https://owasp.org/www-project-top-ten/" target="_blank" rel="noopener noreferrer">OWASP Top 10</a>
    </span>
</div>

</body>
</html>
