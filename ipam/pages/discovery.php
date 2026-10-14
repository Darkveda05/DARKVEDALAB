<?php
use DarkVeda\{Auth, Database, Discovery};
use function DarkVeda\e;

$canRun    = Auth::can('discovery.run');
$canManage = Auth::can('ipam.manage');

$scannable = Database::q(
    "SELECT s.id, s.cidr, s.name, s.prefix_len,
            (SELECT MAX(finished_at) FROM discovery_runs r WHERE r.subnet_id = s.id) AS last_scan
     FROM subnets s
     WHERE s.ip_version = 4 AND s.status = 'active'
     ORDER BY s.network_bin"
);

$hosts = Database::q(
    'SELECT h.*, s.cidr FROM discovered_hosts h
     JOIN subnets s ON s.id = h.subnet_id
     WHERE h.adopted = 0
     ORDER BY FIELD(h.status, "new", "changed", "known"), h.last_seen DESC
     LIMIT 200'
);

// Unused candidates: active, in a subnet that has been scanned, never/last seen > 7 days
$unused = Database::q(
    "SELECT i.address, i.hostname, i.last_seen, s.cidr
     FROM ip_addresses i
     JOIN subnets s ON s.id = i.subnet_id
     WHERE i.status = 'active'
       AND EXISTS (SELECT 1 FROM discovery_runs r WHERE r.subnet_id = i.subnet_id AND r.finished_at IS NOT NULL)
       AND (i.last_seen IS NULL OR i.last_seen < NOW() - INTERVAL 7 DAY)
     ORDER BY i.last_seen IS NOT NULL, i.last_seen
     LIMIT 100"
);

$runs = Database::q(
    'SELECT r.*, s.cidr, u.username FROM discovery_runs r
     JOIN subnets s ON s.id = r.subnet_id
     LEFT JOIN users u ON u.id = r.triggered_by
     ORDER BY r.id DESC LIMIT 10'
);

$badge = fn(string $st): string => match ($st) {
    'new'     => 'danger',
    'changed' => 'warning',
    default   => 'secondary',
};
?>
<div class="row g-3 mb-3">
  <div class="col-12">
    <div class="card h-100">
      <div class="card-header"><i class="bi bi-radar"></i> Scan a subnet</div>
      <div class="table-responsive">
        <table class="table table-hover mb-0">
          <thead><tr><th>Subnet</th><th>Name</th><th>Last scan</th><th class="text-end"></th></tr></thead>
          <tbody>
          <?php foreach ($scannable as $s): $tooBig = (int)$s['prefix_len'] < 22; ?>
            <tr>
              <td><code><?= e($s['cidr']) ?></code></td>
              <td><?= e($s['name'] ?? '—') ?></td>
              <td class="small text-secondary"><?= e($s['last_scan'] ?? 'never') ?></td>
              <td class="text-end">
                <?php if ($canRun): ?>
                <form method="post" class="m-0 d-inline">
                  <?= Auth::csrfField() ?>
                  <input type="hidden" name="action" value="discovery_run">
                  <input type="hidden" name="subnet_id" value="<?= (int)$s['id'] ?>">
                  <button class="btn btn-sm btn-primary" <?= $tooBig ? 'disabled title="Larger than /22 — use bin/discover.php"' : '' ?>>
                    <i class="bi bi-play-fill"></i> Scan now
                  </button>
                </form>
                <?php endif; ?>
              </td>
            </tr>
          <?php endforeach; ?>
          <?php if (!$scannable): ?>
            <tr><td colspan="4" class="text-center text-secondary py-4">No active IPv4 subnets to scan.</td></tr>
          <?php endif; ?>
          </tbody>
        </table>
      </div>
      <div class="card-footer small text-secondary">
        Web scans are limited to /22 (1022 hosts). For scheduled scans use cron:
        <code>php bin/discover.php --all</code>
      </div>
    </div>
  </div>

</div>

<div class="card mb-3">
  <div class="card-header"><i class="bi bi-search"></i> Discovered hosts</div>
  <div class="table-responsive">
    <table class="table table-hover mb-0">
      <thead><tr>
        <th>Status</th><th>IP</th><th>Subnet</th><th>MAC</th><th>Hostname</th><th>First seen</th><th>Last seen</th><th class="text-end"></th>
      </tr></thead>
      <tbody>
      <?php foreach ($hosts as $h): ?>
        <tr>
          <td><span class="badge text-bg-<?= $badge($h['status']) ?>"><?= e($h['status']) ?></span></td>
          <td><code><?= e($h['address']) ?></code></td>
          <td><code class="small"><?= e($h['cidr']) ?></code></td>
          <td><code class="small"><?= e($h['mac_address'] ?? '—') ?></code></td>
          <td><?= e($h['hostname'] ?? '—') ?></td>
          <td class="small text-secondary"><?= e($h['first_seen']) ?></td>
          <td class="small text-secondary"><?= e($h['last_seen']) ?></td>
          <td class="text-end text-nowrap">
            <?php if ($h['status'] !== 'known' && $canManage): ?>
            <form method="post" class="d-inline m-0">
              <?= Auth::csrfField() ?>
              <input type="hidden" name="action" value="discovered_adopt">
              <input type="hidden" name="id" value="<?= (int)$h['id'] ?>">
              <button class="btn btn-sm btn-outline-primary" title="Adopt into inventory"><i class="bi bi-box-arrow-in-down"></i> Adopt</button>
            </form>
            <?php endif; ?>
            <?php if ($canRun): ?>
            <form method="post" class="d-inline m-0" data-confirm="Remove discovered entry <?= e($h['address']) ?>?">
              <?= Auth::csrfField() ?>
              <input type="hidden" name="action" value="discovered_delete">
              <input type="hidden" name="id" value="<?= (int)$h['id'] ?>">
              <button class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button>
            </form>
            <?php endif; ?>
          </td>
        </tr>
      <?php endforeach; ?>
      <?php if (!$hosts): ?>
        <tr><td colspan="8" class="text-center text-secondary py-4">Nothing discovered yet — run a scan above.</td></tr>
      <?php endif; ?>
      </tbody>
    </table>
  </div>
</div>

<div class="row g-3">
  <div class="col-lg-6">
    <div class="card">
      <div class="card-header"><i class="bi bi-moon"></i> Unused IP candidates <span class="small text-secondary">(active but silent &gt; 7 days)</span></div>
      <div class="table-responsive">
        <table class="table table-sm table-hover mb-0">
          <thead><tr><th>IP</th><th>Subnet</th><th>Hostname</th><th>Last seen</th></tr></thead>
          <tbody>
          <?php foreach ($unused as $u): ?>
            <tr>
              <td><code><?= e($u['address']) ?></code></td>
              <td><code class="small"><?= e($u['cidr']) ?></code></td>
              <td><?= e($u['hostname'] ?? '—') ?></td>
              <td class="small text-secondary"><?= e($u['last_seen'] ?? 'never') ?></td>
            </tr>
          <?php endforeach; ?>
          <?php if (!$unused): ?>
            <tr><td colspan="4" class="text-center text-secondary py-4">No candidates — scan subnets to build liveness data.</td></tr>
          <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="col-lg-6">
    <div class="card">
      <div class="card-header"><i class="bi bi-clock-history"></i> Recent scans</div>
      <div class="table-responsive">
        <table class="table table-sm table-hover mb-0">
          <thead><tr><th>Subnet</th><th>Finished</th><th>Alive</th><th>New</th><th>Changed</th><th>By</th></tr></thead>
          <tbody>
          <?php foreach ($runs as $r): ?>
            <tr>
              <td><code class="small"><?= e($r['cidr']) ?></code></td>
              <td class="small text-secondary"><?= e($r['finished_at'] ?? 'running…') ?></td>
              <td><?= (int)$r['hosts_alive'] ?>/<?= (int)$r['hosts_scanned'] ?></td>
              <td><?= (int)$r['new_hosts'] ?></td>
              <td><?= (int)$r['changed_hosts'] ?></td>
              <td class="small"><?= e($r['username'] ?? 'cron') ?></td>
            </tr>
          <?php endforeach; ?>
          <?php if (!$runs): ?>
            <tr><td colspan="6" class="text-center text-secondary py-4">No scans yet.</td></tr>
          <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>
