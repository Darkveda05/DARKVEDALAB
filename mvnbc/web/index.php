<?php
session_start();

if (!isset($_SESSION['logged_in'])) {
    header("Location: login.php");
    exit;
}

/* SESSION TIMEOUT */
if (!isset($_SESSION['last_activity'])) {
    $_SESSION['last_activity'] = time();
}

if (time() - $_SESSION['last_activity'] > 900) {
    session_destroy();
    header("Location: login.php?error=session");
    exit;
}

$_SESSION['last_activity'] = time();
clearstatcache(true);

/* DIRECTORIES */
$backupDir = realpath(__DIR__ . "/../backups");
$logDir    = realpath(__DIR__ . "/../logs");
$search = strtolower(trim($_GET['search'] ?? ''));


function validateBackupFile($vendor, $file)
{
    if (!file_exists($file) || filesize($file) == 0) {
        return false;
    }

    $content = @file_get_contents($file);


    switch (strtolower($vendor)) {

        case 'cisco':
            return preg_match(
                '/Current configuration|Building configuration|hostname/i',
                $content
            );

        case 'ciscoasa':
            return preg_match(
                '/ASA Version|hostname/i',
                $content
            );

        case 'mikrotik':
            return (
                stripos($content, 'RouterOS') !== false &&
                (
                    stripos($content, '/interface') !== false ||
                    stripos($content, '/ip ') !== false ||
                    stripos($content, '/system ') !== false
                )
            );

        case 'h3c':
            return preg_match('/sysname/i', $content);

        case 'h3c_1920':
            return preg_match('/sysname/i', $content);

        case 'arista':
            return preg_match('/hostname/i', $content);

        case 'aruba':
            return preg_match('/hostname|Current configuration/i',$content);

        case 'fortigate':
            if (preg_match('/No route to host|Connection refused|Connection timed out|LOGIN FAILED|ssh:/i',$content))
            {
            return false;
            }
            return preg_match(
            '/#config-version=|config system|config firewall/i',
                $content
            );

        case 'juniper':
            if (preg_match('/LOGIN FAILED|Connection refused|No route to host|timed out|ssh:/i',$content))
            {
            return false;
            }
        return preg_match('/^set system|^set interfaces|^set routing-options/m',$content);

        default:
            return filesize($file) > 0;
    }
}


/* BACKUP SCANNER */
function getBackupFilesGrouped($baseDir, $search = '')
{
    $vendors = glob($baseDir . '/*', GLOB_ONLYDIR) ?: [];
    $grouped = [];

    foreach ($vendors as $vendorPath) {

        $vendor = basename($vendorPath);
        $files = glob($vendorPath . '/*') ?: [];
        rsort($files);

        foreach ($files as $file) {

            if (!is_file($file)) continue;

            $filename = basename($file);

            preg_match('/([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/', $filename, $ipMatch);
            $ip = $ipMatch[1] ?? 'Unknown';

            $date = date("Y-m-d H:i:s", filemtime($file));

            $hay = strtolower("$vendor $ip $filename $date");

            if ($search && strpos($hay, $search) === false) continue;

            $status = validateBackupFile($vendor, $file);

            $grouped[$vendor][] = [
            "path" => $file,
            "name" => $filename,
            "ip"   => $ip,
            "size" => round(filesize($file)/1024,2),
            "date" => $date,
            "status" => $status
            ];
        }
    }

    return $grouped;
}

/* LOG SCANNER */
function getLogs($dir) {
    $files = glob($dir."/*") ?: [];
    rsort($files);
    return $files;
}

$backupGroups = getBackupFilesGrouped($backupDir, $search);
$logFiles = getLogs($logDir);

/* Quick totals for the file panel header */
$totalBackupFiles = 0;
foreach ($backupGroups as $vf) { $totalBackupFiles += count($vf); }

require_once __DIR__ . '/app/includes/layout.php';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dashboard · MVNBC</title>
<link rel="stylesheet" href="assets/style.css?v=6">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
</head>
<body>

<?php mvnbc_shell_open('dashboard', 'Operations Dashboard', 'Multivendor network configuration backups'); ?>

<?php if (isset($_GET['deleted']) || isset($_GET['failed'])): ?>
    <?php $del = (int)($_GET['deleted'] ?? 0); $fl = (int)($_GET['failed'] ?? 0); ?>
    <div class="flash <?= $fl > 0 ? 'error' : 'success' ?>" id="flash">
        <?= mvnbc_icon($fl > 0 ? 'alert' : 'check') ?>
        <span><strong><?= $del ?></strong> file(s) deleted<?= $fl > 0 ? " · <strong>$fl</strong> failed" : "" ?>.</span>
        <span class="x" onclick="document.getElementById('flash').remove()">✕</span>
    </div>
<?php endif; ?>

<!-- ===== KPI TILES ===== -->
<div class="kpi-grid" id="kpiGrid">
    <div class="kpi accent">
        <div class="kpi-top"><span class="kpi-label">Total Devices</span><span class="kpi-ico"><?= mvnbc_icon('server') ?></span></div>
        <div class="kpi-value skeleton" id="kpiTotal">000</div>
        <div class="kpi-foot">Monitored in devices.conf</div>
    </div>
    <div class="kpi ok">
        <div class="kpi-top"><span class="kpi-label">Reachable</span><span class="kpi-ico"><?= mvnbc_icon('check') ?></span></div>
        <div class="kpi-value skeleton" id="kpiOk">000</div>
        <div class="kpi-foot">Latest backup validated</div>
    </div>
    <div class="kpi fail">
        <div class="kpi-top"><span class="kpi-label">Failing</span><span class="kpi-ico"><?= mvnbc_icon('x-circle') ?></span></div>
        <div class="kpi-value skeleton" id="kpiFail">000</div>
        <div class="kpi-foot">Need attention</div>
    </div>
    <div class="kpi info">
        <div class="kpi-top"><span class="kpi-label">Backup Files</span><span class="kpi-ico"><?= mvnbc_icon('files') ?></span></div>
        <div class="kpi-value skeleton" id="kpiFiles">000</div>
        <div class="kpi-foot"><span id="kpiFilesOk">0</span> valid · <span id="kpiFilesFail">0</span> invalid</div>
    </div>
</div>

<!-- ===== OVERVIEW: chart + vendor health ===== -->
<div class="overview-grid">
    <div class="panel" style="margin-bottom:0;">
        <div class="panel-head"><h2>Device Health</h2></div>
        <div class="chart-wrap">
            <canvas id="healthChart"></canvas>
            <div class="chart-center">
                <div class="big" id="healthPct">—</div>
                <div class="lbl">Reachable</div>
            </div>
        </div>
        <div class="chart-legend">
            <span><i style="background:#34d399"></i> Reachable</span>
            <span><i style="background:#f87171"></i> Failing</span>
        </div>
    </div>

    <div class="panel" style="margin-bottom:0;">
        <div class="panel-head">
            <h2>Vendor Status</h2>
            <span class="spacer"></span>
            <div class="seg" id="vendorFilter">
                <button class="active" data-f="all">All</button>
                <button data-f="good">Healthy</button>
                <button data-f="warn">Degraded</button>
                <button data-f="bad">Critical</button>
            </div>
        </div>
        <div class="vendor-list" id="vendorWrap">
            <div class="empty"><div class="skeleton" style="height:48px;width:100%;border-radius:9px;"></div></div>
        </div>
    </div>
</div>

<!-- ===== SEARCH ===== -->
<form method="GET" class="toolbar">
    <div class="search-field">
        <?= mvnbc_icon('search') ?>
        <input name="search" placeholder="Search by vendor, IP, filename or date…" value="<?= htmlspecialchars($search) ?>" autocomplete="off">
    </div>
    <button class="btn btn-primary" type="submit"><?= mvnbc_icon('search') ?> Search</button>
    <?php if ($search): ?><a class="btn btn-ghost" href="index.php">Clear</a><?php endif; ?>
</form>

<!-- ===== BACKUP FILES ===== -->
<div class="panel">
    <div class="panel-head">
        <h2>Backup Files</h2>
        <span class="count-chip"><?= $totalBackupFiles ?> file<?= $totalBackupFiles === 1 ? '' : 's' ?></span>
        <span class="spacer"></span>
        <?php if (!empty($backupGroups)): ?>
        <a class="btn btn-sm" href="download_zip.php?vendor=__all__"><?= mvnbc_icon('archive') ?> Download all (.zip)</a>
        <?php endif; ?>
    </div>

    <?php if (empty($backupGroups)): ?>
        <div class="empty">
            <?= mvnbc_icon('inbox') ?>
            <h3><?= $search ? 'No matching backups' : 'No backups yet' ?></h3>
            <p><?= $search ? 'Try a different vendor, IP or date.' : 'Backups will appear here once the scheduled job runs.' ?></p>
        </div>
    <?php else: ?>

    <?php foreach ($backupGroups as $vendor => $files): ?>
        <?php
            $okCount = 0;
            foreach ($files as $f) { if ($f['status']) $okCount++; }
            $vid = preg_replace('/[^a-z0-9_]/i', '', $vendor);
        ?>
        <form method="POST" action="bulk_delete.php" class="vendor-block" id="block-<?= $vid ?>">
            <input type="hidden" name="type" value="backup">

            <div class="vendor-block-head" onclick="toggleBlock('<?= $vid ?>', event)">
                <span class="chevron"><?= mvnbc_icon('chevron') ?></span>
                <span class="vtitle"><?= strtoupper($vendor) ?></span>
                <span class="vtag"><?= count($files) ?> · <?= $okCount ?> ok</span>
                <span class="spacer"></span>
                <span class="pill <?= $okCount === count($files) ? 'ok' : 'fail' ?>">
                    <?= $okCount ?>/<?= count($files) ?> valid
                </span>
            </div>

            <div class="vendor-block-body">
                <div class="table-wrap">
                <table class="data">
                    <thead>
                    <tr>
                        <th style="width:34px;"><input type="checkbox" onclick="toggleVendorAll(this, '<?= $vid ?>')"></th>
                        <th>File</th>
                        <th>IP Address</th>
                        <th>Size</th>
                        <th>Captured</th>
                        <th>Status</th>
                        <th>Action</th>
                    </tr>
                    </thead>
                    <tbody>
                    <?php foreach ($files as $f): ?>
                    <tr class="row-<?= $vid ?>">
                        <td><input type="checkbox" name="files[]" value="<?= htmlspecialchars($f['path']) ?>"></td>
                        <td class="file-name"><?= htmlspecialchars($f['name']) ?></td>
                        <td class="mono"><?= htmlspecialchars($f['ip']) ?></td>
                        <td><?= $f['size'] ?> KB</td>
                        <td class="mono"><?= $f['date'] ?></td>
                        <td>
                            <?php if ($f['status']): ?>
                                <span class="pill ok">OK</span>
                            <?php else: ?>
                                <span class="pill fail">Failed</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <div class="row-actions">
                                <a href="view2.php?file=<?= urlencode($f['path']) ?>"><?= mvnbc_icon('eye') ?> View</a>
                                <a href="download.php?file=<?= urlencode($f['path']) ?>"><?= mvnbc_icon('download') ?> Get</a>
                            </div>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                </div>

                <div class="btn-row" style="padding:14px 16px 16px;">
                    <a class="btn btn-sm" href="download_zip.php?vendor=<?= urlencode($vendor) ?>"><?= mvnbc_icon('archive') ?> Download <?= htmlspecialchars(strtoupper($vendor)) ?> (.zip)</a>
                    <span class="spacer"></span>
                    <button type="button" class="btn btn-sm" onclick="selectVendorAll('<?= $vid ?>')">Select all</button>
                    <button type="button" class="btn btn-sm" onclick="unselectVendorAll('<?= $vid ?>')">Clear</button>
                    <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Delete the selected backup files?')">
                        <?= mvnbc_icon('trash') ?> Delete selected
                    </button>
                </div>
            </div>
        </form>
    <?php endforeach; ?>

    <?php endif; ?>
</div>

<!-- ================= DASHBOARD JS ================= -->
<script>
let healthChart = null;
let vendorData  = [];
let activeFilter = "all";

function classify(rate) {
    if (rate >= 80) return "good";
    if (rate >= 50) return "warn";
    return "bad";
}

async function loadStats() {
    try {
        const r = await fetch("api_stats.php?v=" + Date.now());
        const d = await r.json();

        setVal("kpiTotal", d.total);
        setVal("kpiOk", d.ok);
        setVal("kpiFail", d.fail);
        setVal("kpiFiles", d.file_total);
        document.getElementById("kpiFilesOk").textContent = d.file_ok;
        document.getElementById("kpiFilesFail").textContent = d.file_fail;

        const pct = d.total ? Math.round((d.ok / d.total) * 100) : 0;
        document.getElementById("healthPct").textContent = pct + "%";

        // Chart is non-critical: never let a chart/CDN failure break the rest of the dashboard
        try { drawChart(d.ok, d.fail); } catch (chartErr) { console.warn("Chart render skipped:", chartErr); }

        vendorData = d.vendors || [];
        renderVendors(activeFilter);
    } catch (e) {
        document.getElementById("vendorWrap").innerHTML =
            '<div class="empty">Unable to load live stats. Check api_stats.php.</div>';
    }
}

function setVal(id, v) {
    const el = document.getElementById(id);
    el.classList.remove("skeleton");
    el.textContent = v;
}

function drawChart(ok, fail) {
    const ctx = document.getElementById("healthChart");
    if (typeof Chart === "undefined" || !ctx) return; // graceful degrade if CDN unavailable
    const data = (ok + fail) === 0 ? [1] : [ok, fail];
    const colors = (ok + fail) === 0 ? ["#1c2437"] : ["#34d399", "#f87171"];

    if (healthChart) {
        healthChart.data.datasets[0].data = data;
        healthChart.data.datasets[0].backgroundColor = colors;
        healthChart.update();
        return;
    }
    healthChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels: ["Reachable", "Failing"],
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderColor: "#111726",
                borderWidth: 3,
                hoverOffset: 6
            }]
        },
        options: {
            cutout: "72%",
            plugins: { legend: { display: false }, tooltip: { enabled: ok + fail > 0 } },
            animation: { duration: 600 }
        }
    });
}

function renderVendors(filter) {
    activeFilter = filter;
    let html = "";

    const list = vendorData.filter(v => {
        const rate = v.count ? (v.ok / v.count) * 100 : 0;
        return filter === "all" || classify(rate) === filter;
    });

    if (list.length === 0) {
        document.getElementById("vendorWrap").innerHTML =
            '<div class="empty" style="padding:28px;"><h3>Nothing here</h3><p>No vendors in this state.</p></div>';
        return;
    }

    list.forEach(v => {
        const rate = v.count ? (v.ok / v.count) * 100 : 0;
        const state = classify(rate);
        const barColor = state === "good" ? "#34d399" : state === "warn" ? "#fbbf24" : "#f87171";

        html += `
        <div class="vendor-row ${state}" id="vr-${v.vendor}">
            <div class="vendor-row-head" onclick="toggleVendorRow('${v.vendor}')">
                <span class="chevron">${chevronSvg()}</span>
                <span class="vname">${escapeHtml(v.vendor.toUpperCase())}</span>
                <span class="health-bar"><i style="width:${rate}%;background:${barColor}"></i></span>
                <span class="rate-badge">${rate.toFixed(0)}%</span>
            </div>
            <div class="vendor-row-body">
                <div class="mini-stat"><div class="ms-label">Total</div><div class="ms-value">${v.count}</div></div>
                <div class="mini-stat"><div class="ms-label">Reachable</div><div class="ms-value" style="color:#34d399">${v.ok}</div></div>
                <div class="mini-stat"><div class="ms-label">Failing</div><div class="ms-value" style="color:#f87171">${v.fail}</div></div>
                <div class="mini-stat span1"><div class="ms-label">Last OK</div><div class="ms-value mono">${escapeHtml(v.last)}</div></div>
            </div>
        </div>`;
    });

    document.getElementById("vendorWrap").innerHTML = html;
}

function toggleVendorRow(vendor) {
    document.getElementById("vr-" + vendor).classList.toggle("open");
}

function chevronSvg() {
    return '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 18 6-6-6-6"/></svg>';
}

function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

/* vendor filter segmented control */
document.querySelectorAll("#vendorFilter button").forEach(b => {
    b.addEventListener("click", () => {
        document.querySelectorAll("#vendorFilter button").forEach(x => x.classList.remove("active"));
        b.classList.add("active");
        renderVendors(b.dataset.f);
    });
});

/* ===== BACKUP TABLE TOOLS ===== */
function toggleBlock(vid, event) {
    if (event && event.target.closest('input')) return;
    document.getElementById("block-" + vid).classList.toggle("collapsed");
}
function toggleVendorAll(master, vid) {
    document.querySelectorAll(".row-" + vid + " input[type=checkbox]").forEach(cb => cb.checked = master.checked);
}
function selectVendorAll(vid) {
    document.querySelectorAll(".row-" + vid + " input[type=checkbox]").forEach(cb => cb.checked = true);
}
function unselectVendorAll(vid) {
    document.querySelectorAll(".row-" + vid + " input[type=checkbox]").forEach(cb => cb.checked = false);
}

loadStats();
setInterval(loadStats, 10000);
</script>

<?php mvnbc_shell_close(); ?>
</body>
</html>
