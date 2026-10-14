<?php
/* =========================================================
   Shared layout helpers for the MVNBC Dashboard.
   Provides the sidebar, top header and SVG icon set so every
   page shares one consistent, professional shell.
   ========================================================= */

if (!function_exists('mvnbc_icon')) {

    /* Inline stroke icons (Lucide-style). Keeps the UI dependency-free. */
    function mvnbc_icon($name) {
        $p = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">';
        $icons = [
            'grid'      => '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/>',
            'compare'   => '<path d="M12 3v18"/><path d="M5 8l-3 3 3 3"/><path d="M19 8l3 3-3 3"/><path d="M2 11h6"/><path d="M16 11h6"/>',
            'logs'      => '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8"/><path d="M8 17h8"/><path d="M8 9h2"/>',
            'terminal'  => '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="M7 9l3 3-3 3"/><path d="M13 15h4"/>',
            'devices'   => '<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/>',
            'key'       => '<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3 21 2"/><path d="m16.5 6.5 2 2"/><path d="m19 4 2 2"/>',
            'logout'    => '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/>',
            'server'    => '<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01"/><path d="M7 16.5h.01"/>',
            'check'     => '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><path d="m9 11 3 3L22 4"/>',
            'x-circle'  => '<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>',
            'files'     => '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7z"/><path d="M15 2v5h5"/>',
            'search'    => '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
            'eye'       => '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
            'download'  => '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/>',
            'trash'     => '<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
            'back'      => '<path d="M19 12H5"/><path d="m12 19-7-7 7-7"/>',
            'menu'      => '<path d="M4 6h16"/><path d="M4 12h16"/><path d="M4 18h16"/>',
            'alert'     => '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
            'inbox'     => '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>',
            'shield'    => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/>',
            'lock'      => '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
            'refresh'   => '<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M3 21v-5h5"/>',
            'save'      => '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><path d="M17 21v-8H7v8"/><path d="M7 3v5h8"/>',
            'chevron'   => '<path d="m9 18 6-6-6-6"/>',
            'bell'      => '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>',
            'archive'   => '<rect x="2" y="3" width="20" height="5" rx="1"/><path d="M4 8v11a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1V8"/><path d="M10 12h4"/>',
        ];
        $body = $icons[$name] ?? '';
        return $p . $body . '</svg>';
    }

    /* Sidebar + top header. $active marks the current nav entry. */
    function mvnbc_shell_open($active, $title, $subtitle = '', $base = '') {
        $username = htmlspecialchars($_SESSION['username'] ?? 'admin');
        $items = [
            ['key' => 'dashboard', 'href' => $base . 'index.php',                'icon' => 'grid',     'label' => 'Dashboard'],
            ['key' => 'compare',   'href' => $base . 'app/modules/compare.php',  'icon' => 'compare',  'label' => 'Compare'],
            ['key' => 'logs',      'href' => $base . 'logs.php',                 'icon' => 'logs',     'label' => 'Logs'],
            ['key' => 'devices',   'href' => $base . 'app/modules/config.php',   'icon' => 'devices',  'label' => 'Devices'],
            ['key' => 'alerts',    'href' => $base . 'app/modules/alerts.php',   'icon' => 'bell',     'label' => 'Alerts'],
            ['key' => 'settings',  'href' => $base . 'app/modules/settings.php', 'icon' => 'key',      'label' => 'Security'],
        ];
        ?>
        <div class="scrim" id="scrim" onclick="mvnbcToggleNav()"></div>
        <div class="app">
            <aside class="sidebar" id="sidebar">
                <div class="brand">
                    <img src="<?= $base ?>img/mvnbc.png" alt="MVNBC">
                    <div>
                        <div class="brand-name">MVNBC</div>
                    </div>
                </div>
                <div class="nav-label">Operations</div>
                <?php foreach ($items as $it): ?>
                    <a class="nav-item <?= $active === $it['key'] ? 'active' : '' ?>" href="<?= $it['href'] ?>">
                        <?= mvnbc_icon($it['icon']) ?><span><?= $it['label'] ?></span>
                    </a>
                <?php endforeach; ?>
                <div class="nav-spacer"></div>
                <a class="nav-item danger" href="<?= $base ?>logout.php">
                    <?= mvnbc_icon('logout') ?><span>Sign out</span>
                </a>
                <div class="sidebar-foot">
                    <span class="dot">●</span> Signed in as <strong><?= $username ?></strong>
                </div>
            </aside>

            <main class="main">
                <div class="topbar">
                    <button class="mobile-nav-toggle" onclick="mvnbcToggleNav()" aria-label="Menu"><?= mvnbc_icon('menu') ?></button>
                    <div>
                        <h1><?= htmlspecialchars($title) ?></h1>
                        <?php if ($subtitle): ?><div class="page-sub"><?= htmlspecialchars($subtitle) ?></div><?php endif; ?>
                    </div>
                    <div class="spacer"></div>
                    <?php if ($active === 'dashboard'): ?>
                        <span class="live-pill"><span class="live-dot"></span> Live · auto-refresh</span>
                    <?php endif; ?>
                </div>
        <?php
    }

    function mvnbc_shell_close() {
        ?>
            </main>
        </div>
        <script>
        function mvnbcToggleNav() {
            document.getElementById('sidebar').classList.toggle('open');
            document.getElementById('scrim').classList.toggle('show');
        }
        </script>
        <?php
    }
}
