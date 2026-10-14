<?php
use DarkVeda\{Auth, Database, IpTools};
use function DarkVeda\e;

$stats = [
    'subnets' => Database::one('SELECT COUNT(*) c FROM subnets')['c'],
    'ips'     => Database::one('SELECT COUNT(*) c FROM ip_addresses')['c'],
    'vlans'   => Database::one('SELECT COUNT(*) c FROM vlans')['c'],
    'devices' => Database::one('SELECT COUNT(*) c FROM device_types')['c'],
];

$topSubnets = Database::q(
    'SELECT s.id, s.cidr, s.name, s.ip_version, s.prefix_len,
            (SELECT COUNT(*) FROM ip_addresses i WHERE i.subnet_id = s.id) AS assigned
     FROM subnets s
     ORDER BY assigned DESC
     LIMIT 8'
);

// IPs inside each top subnet (for the expandable rows)
$subnetIps = [];
foreach ($topSubnets as $s) {
    $subnetIps[(int)$s['id']] = Database::q(
        'SELECT i.address, i.status, i.hostname, i.mac_address, i.serial_number, i.last_seen,
                TRIM(CONCAT(COALESCE(v.name, ""), " ", dt.model)) AS device
         FROM ip_addresses i
         LEFT JOIN device_types dt ON dt.id = i.device_type_id
         LEFT JOIN vendors v ON v.id = dt.vendor_id
         WHERE i.subnet_id = ?
         ORDER BY i.address_bin
         LIMIT 50',
        [(int)$s['id']]
    );
}

// Conflicts (stored + live duplicate MAC / duplicate IP)
$q = trim((string)($_GET['q'] ?? ''));
$searchResults = null;
if ($q !== '') {
    $like = '%' . $q . '%';
    $searchResults = Database::q(
        'SELECT i.id, i.address, i.status, i.hostname, i.mac_address, i.serial_number,
                i.os, i.software_version, i.subnet_id, s.cidr,
                TRIM(CONCAT(COALESCE(v3.name, ""), " ", dt3.model)) AS device_type
         FROM ip_addresses i
         JOIN subnets s ON s.id = i.subnet_id
         LEFT JOIN device_types dt3 ON dt3.id = i.device_type_id
         LEFT JOIN vendors v3 ON v3.id = dt3.vendor_id
         WHERE i.address LIKE ? OR i.hostname LIKE ? OR i.serial_number LIKE ?
         ORDER BY i.address_bin LIMIT 50',
        [$like, $like, $like]
    );
}

$statusBadge = fn(string $st): string => match ($st) {
    'active'   => 'success',
    'reserved' => 'info',
    'dhcp'     => 'primary',
    default    => 'secondary',
};
?>
<div class="row g-3 mb-4">
  <?php
  $cards = [
      ['Subnets', $stats['subnets'], 'bi-diagram-3'],
      ['IP addresses', $stats['ips'], 'bi-geo'],
      ['VLANs', $stats['vlans'], 'bi-layers'],
      ['Device types', $stats['devices'], 'bi-hdd-rack'],
  ];
  foreach ($cards as [$label, $value, $icon]): ?>
  <div class="col-6 col-lg-3">
    <div class="card">
      <div class="dv-stat">
        <i class="bi <?= e($icon) ?>"></i>
        <div>
          <div class="dv-stat-value"><?= (int)$value ?></div>
          <div class="dv-stat-label"><?= e($label) ?></div>
        </div>
      </div>
    </div>
  </div>
  <?php endforeach; ?>
</div>

<div class="row g-3">
  <div class="col-12">
    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span><i class="bi bi-bar-chart"></i> Subnet utilization</span>
        <a class="btn btn-sm btn-outline-secondary" href="/?page=subnets">All subnets</a>
      </div>
      <div class="table-responsive">
        <table class="table table-hover mb-0">
          <thead><tr><th style="width:32px"></th><th>Subnet</th><th>Name</th><th>Assigned</th><th class="dv-util">Utilization</th></tr></thead>
          <tbody>
          <?php foreach ($topSubnets as $s):
              $sid  = (int)$s['id'];
              $util = IpTools::utilization((int)$s['ip_version'], (int)$s['prefix_len'], (int)$s['assigned']);
              $ips  = $subnetIps[$sid] ?? [];
          ?>
            <tr data-bs-toggle="collapse" data-bs-target="#subips-<?= $sid ?>" role="button">
              <td class="text-secondary"><i class="bi bi-chevron-right dv-chevron"></i></td>
              <td><a href="/?page=subnet_view&id=<?= $sid ?>" onclick="event.stopPropagation()"><code><?= e($s['cidr']) ?></code></a></td>
              <td><?= e($s['name'] ?? '—') ?></td>
              <td><?= (int)$s['assigned'] ?></td>
              <td class="dv-util">
                <?php if ($util === null): ?>
                  <span class="text-secondary small">n/a</span>
                <?php else: ?>
                  <div class="d-flex align-items-center gap-2">
                    <div class="progress flex-grow-1">
                      <div class="progress-bar <?= $util > 85 ? 'bg-danger' : ($util > 60 ? 'bg-warning' : 'bg-success') ?>"
                           style="width: <?= min($util, 100) ?>%"></div>
                    </div>
                    <small><?= $util ?>%</small>
                  </div>
                <?php endif; ?>
              </td>
            </tr>
            <tr class="dv-expand-row">
              <td colspan="5" class="p-0 border-0">
                <div class="collapse" id="subips-<?= $sid ?>">
                  <div class="p-2 dv-nested">
                    <?php if ($ips): ?>
                      <table class="table table-sm mb-1">
                        <thead><tr><th>IP</th><th>Status</th><th>Hostname</th><th>Device</th><th>MAC</th><th>Last seen</th></tr></thead>
                        <tbody>
                        <?php foreach ($ips as $ip): ?>
                          <tr>
                            <td><code><?= e($ip['address']) ?></code></td>
                            <td><span class="badge text-bg-<?= $statusBadge($ip['status']) ?>"><?= e($ip['status']) ?></span></td>
                            <td><?= e($ip['hostname'] ?? '—') ?></td>
                            <td><?= e($ip['device'] ?: '—') ?></td>
                            <td><code class="small"><?= e($ip['mac_address'] ?? '—') ?></code></td>
                            <td class="small text-secondary"><?= e($ip['last_seen'] ?? 'never') ?></td>
                          </tr>
                        <?php endforeach; ?>
                        </tbody>
                      </table>
                      <div class="small text-secondary px-1 pb-1">
                        Showing up to 50 —
                        <a href="/?page=subnet_view&id=<?= $sid ?>">open full subnet view</a>
                      </div>
                    <?php else: ?>
                      <div class="small text-secondary p-2">No IPs assigned in this subnet yet.</div>
                    <?php endif; ?>
                  </div>
                </div>
              </td>
            </tr>
          <?php endforeach; ?>
          <?php if (!$topSubnets): ?>
            <tr><td colspan="5" class="text-center text-secondary py-4">No subnets yet — create one under Subnets & IPs.</td></tr>
          <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<?php // ---- Device search (v1.5) ---- ?>
<div class="row g-3 mt-0">
  <div class="col-12">
    <div class="card">
      <div class="card-header"><i class="bi bi-search"></i> Device search</div>
      <div class="card-body pb-2">
        <form method="get" class="row g-2">
          <input type="hidden" name="page" value="dashboard">
          <div class="col-md-10">
            <input name="q" class="form-control" value="<?= e($q) ?>"
                   placeholder="Search by IP address, name or serial number…">
          </div>
          <div class="col-md-2 d-grid">
            <button class="btn btn-primary"><i class="bi bi-search"></i> Search</button>
          </div>
        </form>
      </div>
      <?php if ($searchResults !== null): ?>
      <div class="table-responsive">
        <table class="table table-hover mb-0">
          <thead><tr>
            <th>IP</th><th>Subnet</th><th>Status</th><th>Hostname</th><th>Device</th>
            <th>MAC</th><th>Serial</th><th>OS</th><th>Sw. version</th>
          </tr></thead>
          <tbody>
          <?php foreach ($searchResults as $r): ?>
            <tr>
              <td><a href="/?page=subnet_view&id=<?= (int)$r['subnet_id'] ?>"><code><?= e($r['address']) ?></code></a></td>
              <td><code class="small"><?= e($r['cidr']) ?></code></td>
              <td><span class="badge text-bg-<?= $statusBadge($r['status']) ?>"><?= e($r['status']) ?></span></td>
              <td><?= e($r['hostname'] ?? '—') ?></td>
              <td><?= e($r['device_type'] ?: '—') ?></td>
              <td><code class="small"><?= e($r['mac_address'] ?? '—') ?></code></td>
              <td><code class="small"><?= e($r['serial_number'] ?? '—') ?></code></td>
              <td><?= e($r['os'] ?? '—') ?></td>
              <td><?= e($r['software_version'] ?? '—') ?></td>
            </tr>
          <?php endforeach; ?>
          <?php if (!$searchResults): ?>
            <tr><td colspan="9" class="text-center text-secondary py-4">No matches for "<?= e($q) ?>".</td></tr>
          <?php endif; ?>
          </tbody>
        </table>
      </div>
      <?php endif; ?>
    </div>
  </div>
</div>
