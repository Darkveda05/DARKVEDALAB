<?php
use DarkVeda\{Auth, Database, Zabbix, Settings};
use function DarkVeda\e;

$cfg = Zabbix::config();
$autoMin = Settings::int('monitoring_auto_sync_minutes', 0);
$configured = Zabbix::configured();
$canManageZabbix = Auth::can('snmp.manage');
$srcBadge = fn(string $src): string => match ($src) {
    'database'    => '<span class="badge text-bg-primary ms-1" title="Saved from this page — stored in the database">database</span>',
    'environment' => '<span class="badge text-bg-secondary ms-1" title="From environment variable (Docker / .env)">env</span>',
    'config file' => '<span class="badge text-bg-secondary ms-1" title="From config/config.php">config.php</span>',
    default       => '<span class="badge text-bg-secondary ms-1">' . e($src) . '</span>',
};

$rows = Database::q(
    'SELECT m.*, i.id AS ip_id, i.hostname, i.subnet_id, s.cidr
     FROM monitoring_status m
     LEFT JOIN ip_addresses i ON i.address = m.address
     LEFT JOIN subnets s ON s.id = i.subnet_id
     ORDER BY FIELD(m.state, "offline", "unknown", "online"), m.address'
);

$counts = ['online' => 0, 'offline' => 0, 'unknown' => 0];
foreach ($rows as $r) {
    $counts[$r['state']] = ($counts[$r['state']] ?? 0) + 1;
}
$stale = Database::one(
    'SELECT COUNT(*) c FROM monitoring_status WHERE checked_at < NOW() - INTERVAL 1 HOUR'
)['c'] ?? 0;

$bar = function (?string $pct): string {
    if ($pct === null || $pct === '') {
        return '<span class="text-secondary small">—</span>';
    }
    $v = (float)$pct;
    $cls = $v > 90 ? 'bg-danger' : ($v > 70 ? 'bg-warning' : 'bg-success');
    return '<div class="d-flex align-items-center gap-2">'
         . '<div class="progress flex-grow-1" style="min-width:70px"><div class="progress-bar ' . $cls . '" style="width:' . min($v, 100) . '%"></div></div>'
         . '<small>' . number_format($v, 1) . '%</small></div>';
};
?>
<div class="row g-3 mb-3">
  <?php foreach ([
      ['Online', $counts['online'] ?? 0, 'bi-check-circle', 'text-success'],
      ['Offline', $counts['offline'] ?? 0, 'bi-x-circle', 'text-danger'],
      ['Unknown', $counts['unknown'] ?? 0, 'bi-question-circle', 'text-secondary'],
      ['Stale (>1h)', $stale, 'bi-clock-history', 'text-warning'],
  ] as [$label, $value, $icon, $cls]): ?>
  <div class="col-6 col-lg-3">
    <div class="card"><div class="dv-stat">
      <i class="bi <?= e($icon) ?> <?= e($cls) ?>"></i>
      <div><div class="dv-stat-value"><?= (int)$value ?></div><div class="dv-stat-label"><?= e($label) ?></div></div>
    </div></div>
  </div>
  <?php endforeach; ?>
</div>

<div class="card mb-3">
  <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
    <span><i class="bi bi-plug"></i> Zabbix connection</span>
    <?php if ($configured): ?>
      <span class="badge text-bg-success"><i class="bi bi-check-circle"></i> Configured</span>
    <?php else: ?>
      <span class="badge text-bg-warning"><i class="bi bi-exclamation-triangle"></i> Not configured</span>
    <?php endif; ?>
  </div>
  <div class="card-body">
    <?php if ($configured): ?>
      <div class="row g-3 mb-3">
        <div class="col-md-8">
          <div class="text-secondary small">Endpoint <?= $srcBadge($cfg['url_source']) ?></div>
          <code><?= e($cfg['url']) ?></code>
        </div>
        <div class="col-md-4">
          <div class="text-secondary small">Token <?= $srcBadge($cfg['token_source']) ?></div>
          <code><?= e(substr($cfg['token'], 0, 6)) ?>…<?= e(substr($cfg['token'], -4)) ?></code>
          <?= $cfg['verify_tls'] ? '' : '<span class="badge text-bg-warning ms-2">TLS verify off</span>' ?>
          <div class="text-secondary small mt-1">
            Timeout <?= (int)$cfg['timeout'] ?>s <?= $srcBadge($cfg['timeout_source']) ?>
          </div>
        </div>
      </div>
    <?php elseif (!$canManageZabbix): ?>
      <div class="alert alert-warning mb-3">
        <strong>Not configured.</strong> Ask an administrator to set the Zabbix endpoint and API token below
        (or via <code>ZABBIX_URL</code> / <code>ZABBIX_TOKEN</code> environment variables).
      </div>
    <?php endif; ?>

    <?php if ($canManageZabbix): ?>
    <form method="post" class="row g-3 mb-3" id="zabbixForm">
      <?= Auth::csrfField() ?>
      <input type="hidden" name="action" value="zabbix_save">
      <div class="col-12 col-md-6">
        <label class="form-label" for="zabbixUrl">Zabbix URL *</label>
        <input id="zabbixUrl" name="zabbix_url" type="url" class="form-control"
               placeholder="https://zabbix.example.com/api_jsonrpc.php"
               value="<?= e($cfg['url']) ?>" maxlength="500" autocomplete="url">
        <div class="form-text">Zabbix 6.0+ / 7.x JSON-RPC endpoint, usually ending in <code>/api_jsonrpc.php</code>.</div>
      </div>
      <div class="col-12 col-md-6">
        <label class="form-label" for="zabbixToken">API token *</label>
        <div class="input-group">
          <input id="zabbixToken" name="zabbix_token" type="password" class="form-control"
                 placeholder="Token from Zabbix → Users → API tokens"
                 value="<?= e($cfg['token']) ?>" maxlength="1000" autocomplete="off">
          <button class="btn btn-outline-secondary" type="button" id="zabbixTokenToggle" title="Show / hide token">
            <i class="bi bi-eye"></i>
          </button>
        </div>
        <div class="form-text">Use a <strong>read-only</strong> API user — IPAM only ever reads.</div>
      </div>
      <div class="col-6 col-md-3">
        <label class="form-label" for="zabbixTimeout">Timeout (s)</label>
        <input id="zabbixTimeout" name="zabbix_timeout" type="number" class="form-control"
               min="3" max="60" step="1" value="<?= (int)$cfg['timeout'] ?>">
      </div>
      <div class="col-6 col-md-3 d-flex align-items-end pb-1">
        <div class="form-check form-switch">
          <input class="form-check-input" type="checkbox" role="switch"
                 id="zabbixVerify" name="zabbix_verify_tls" value="1" <?= $cfg['verify_tls'] ? 'checked' : '' ?>>
          <label class="form-check-label" for="zabbixVerify">Verify TLS</label>
        </div>
      </div>
      <div class="col-12 col-md-6 d-flex align-items-end gap-2 flex-wrap">
        <button class="btn btn-primary flex-grow-1" name="save" value="1">
          <i class="bi bi-check-lg"></i> Save
        </button>
        <button class="btn btn-outline-primary flex-grow-1" name="save_and_test" value="1">
          <i class="bi bi-broadcast"></i> Save &amp; test
        </button>
      </div>
      <?php if ($cfg['has_db']): ?>
      <div class="col-12">
        <div class="small text-secondary">
          Settings saved in the database take precedence over environment / <code>config.php</code>
          and survive container rebuilds.
        </div>
      </div>
      <?php elseif ($cfg['env_url'] !== '' || $cfg['env_token'] !== ''): ?>
      <div class="col-12">
        <div class="small text-secondary">
          <i class="bi bi-info-circle"></i> Environment variables are currently providing the connection.
          Saving here stores the values in the database, which then takes precedence.
        </div>
      </div>
      <?php endif; ?>
    </form>
    <script>
    (function () {
      var t = document.getElementById('zabbixToken');
      var b = document.getElementById('zabbixTokenToggle');
      if (t && b) b.addEventListener('click', function () {
        var show = t.type === 'password';
        t.type = show ? 'text' : 'password';
        b.innerHTML = show ? '<i class="bi bi-eye-slash"></i>' : '<i class="bi bi-eye"></i>';
      });
    })();
    </script>
    <?php endif; ?>

    <div class="d-flex gap-2 flex-wrap align-items-center">
      <form method="post" class="m-0">
        <?= Auth::csrfField() ?>
        <input type="hidden" name="action" value="zabbix_test">
        <button class="btn btn-outline-secondary" <?= $configured ? '' : 'disabled' ?>>
          <i class="bi bi-broadcast"></i> Test connection
        </button>
      </form>
      <form method="post" class="m-0" id="syncForm">
        <?= Auth::csrfField() ?>
        <input type="hidden" name="action" value="zabbix_sync">
        <button class="btn btn-primary" <?= $configured ? '' : 'disabled' ?>>
          <i class="bi bi-arrow-repeat"></i> Sync now
        </button>
      </form>
      <form method="post" class="m-0" data-confirm="Refresh the monitoring database? This deletes all stored Zabbix rows (API-pushed data is kept) and re-syncs everything from Zabbix from scratch.">
        <?= Auth::csrfField() ?>
        <input type="hidden" name="action" value="zabbix_refresh">
        <button class="btn btn-outline-primary" <?= $configured ? '' : 'disabled' ?>>
          <i class="bi bi-database"></i> Refresh database
        </button>
      </form>
      <?php if ($canManageZabbix && $cfg['has_db']): ?>
      <form method="post" class="m-0" data-confirm="Clear the saved Zabbix settings and fall back to environment / config file?">
        <?= Auth::csrfField() ?>
        <input type="hidden" name="action" value="zabbix_clear">
        <button class="btn btn-outline-danger">
          <i class="bi bi-trash"></i> Clear saved
        </button>
      </form>
      <?php endif; ?>

      <form method="post" class="m-0 d-flex gap-2 align-items-center ms-auto">
        <?= Auth::csrfField() ?>
        <input type="hidden" name="action" value="monitoring_interval">
        <label class="small text-secondary mb-0"><i class="bi bi-clock-history"></i> Auto-sync</label>
        <select name="minutes" class="form-select form-select-sm" style="width:auto"
                onchange="this.form.submit()" <?= $configured ? '' : 'disabled' ?>>
          <?php foreach ([0 => 'Off', 5 => 'Every 5 minutes', 10 => 'Every 10 minutes',
                          15 => 'Every 15 minutes', 30 => 'Every 30 minutes', 60 => 'Every hour'] as $m => $lbl): ?>
            <option value="<?= $m ?>" <?= $autoMin === $m ? 'selected' : '' ?>><?= e($lbl) ?></option>
          <?php endforeach; ?>
        </select>
        <noscript><button class="btn btn-sm btn-outline-secondary">Set</button></noscript>
      </form>
    </div>
    <?php if ($autoMin > 0 && $configured): ?>
      <div class="small text-secondary mt-2" id="autoStatus">
        <i class="bi bi-arrow-repeat"></i> Auto-sync active — next run in
        <span id="autoCountdown"><?= $autoMin ?>:00</span>. Keep this page open; for
        continuous background syncing use <code>bin/zabbix-sync.php</code> from cron.
      </div>
    <?php endif; ?>
    <div class="form-text mt-2">
      For continuous updates, run <code>php bin/zabbix-sync.php</code> from cron (every 5 minutes is typical),
      or have Zabbix push straight into the REST API — see <code>POST /api/v1/monitoring</code>.
    </div>
  </div>
</div>

<div class="card">
  <div class="card-header"><i class="bi bi-activity"></i> Monitoring status</div>
  <div class="table-responsive">
    <table class="table table-hover mb-0">
      <thead><tr>
        <th>State</th><th>IP</th><th>Zabbix host</th><th>Subnet</th>
        <th style="min-width:140px">CPU</th><th style="min-width:140px">Memory</th>
        <th>Problems</th><th>Source</th><th>Checked</th>
      </tr></thead>
      <tbody>
      <?php foreach ($rows as $r): ?>
        <tr>
          <td><span class="badge text-bg-<?= $r['state'] === 'online' ? 'success' : ($r['state'] === 'offline' ? 'danger' : 'secondary') ?>"><?= e($r['state']) ?></span></td>
          <td>
            <?php if ($r['subnet_id']): ?>
              <a href="/?page=subnet_view&id=<?= (int)$r['subnet_id'] ?>"><code><?= e($r['address']) ?></code></a>
            <?php else: ?>
              <code><?= e($r['address']) ?></code>
              <span class="badge text-bg-secondary ms-1" title="Not present in IPAM">unmanaged</span>
            <?php endif; ?>
          </td>
          <td><?= e($r['host_name'] ?: '—') ?></td>
          <td><code class="small"><?= e($r['cidr'] ?: '—') ?></code></td>
          <td><?= $bar($r['cpu_pct']) ?></td>
          <td><?= $bar($r['memory_pct']) ?></td>
          <td><?= (int)$r['problem_count'] > 0
                ? '<span class="badge text-bg-warning">' . (int)$r['problem_count'] . '</span>'
                : '<span class="text-secondary small">0</span>' ?></td>
          <td class="small text-secondary"><?= e($r['source']) ?></td>
          <td class="small text-secondary"><?= e($r['checked_at']) ?></td>
        </tr>
      <?php endforeach; ?>
      <?php if (!$rows): ?>
        <tr><td colspan="9" class="text-center text-secondary py-4">
          No monitoring data yet — configure Zabbix above and run a sync, or push status via the REST API.
        </td></tr>
      <?php endif; ?>
      </tbody>
    </table>
  </div>
</div>

<?php if ($autoMin > 0 && $configured): ?>
<script>
(function () {
  var minutes = <?= (int)$autoMin ?>;
  var remaining = minutes * 60;
  var out = document.getElementById('autoCountdown');
  var form = document.getElementById('syncForm');
  if (!form) return;

  function tick() {
    remaining--;
    if (out) {
      var m = Math.floor(remaining / 60), s = remaining % 60;
      out.textContent = m + ':' + (s < 10 ? '0' : '') + s;
    }
    if (remaining <= 0) {
      // submitting reloads the page with fresh data and a flash message
      form.submit();
      return;
    }
    setTimeout(tick, 1000);
  }
  setTimeout(tick, 1000);
})();
</script>
<?php endif; ?>
