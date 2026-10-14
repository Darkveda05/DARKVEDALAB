<?php
use DarkVeda\{App, Auth, Database, IpTools, Zabbix};
use function DarkVeda\e;

$id = (int)($_GET['id'] ?? 0);
$subnet = Database::one(
    'SELECT s.*, v.vid AS vlan_vid, v.name AS vlan_name, st.name AS site_name
     FROM subnets s
     LEFT JOIN vlans v ON v.id = s.vlan_id
     LEFT JOIN sites st ON st.id = s.site_id
     WHERE s.id = ?', [$id]
);
if (!$subnet) {
    App::flash('danger', 'Subnet not found.');
    App::redirect('/?page=subnets');
}

$ips = Database::q(
    'SELECT i.*, TRIM(CONCAT(COALESCE(ven.name, ""), " ", dt.model)) AS device_name FROM ip_addresses i
     LEFT JOIN device_types dt ON dt.id = i.device_type_id
     LEFT JOIN vendors ven ON ven.id = dt.vendor_id
     WHERE i.subnet_id = ? ORDER BY i.address_bin', [$id]
);
$monitor = Zabbix::statusMap(array_column($ips, 'address'));
$snmpProfiles = Database::q('SELECT id, name FROM snmp_credentials ORDER BY name');
$deviceTypes = Database::q(
    'SELECT dt.id, TRIM(CONCAT(COALESCE(v.name, ""), " ", dt.model)) AS label
     FROM device_types dt LEFT JOIN vendors v ON v.id = dt.vendor_id
     ORDER BY label'
);

$util = IpTools::utilization((int)$subnet['ip_version'], (int)$subnet['prefix_len'], count($ips));
$nextFree = (int)$subnet['ip_version'] === 4
    ? IpTools::firstFreeV4($subnet['network_bin'], (int)$subnet['prefix_len'], array_column($ips, 'address_bin'))
    : null;
$canManage = Auth::can('ipam.manage');
?>
<div class="card mb-3">
  <div class="card-body d-flex flex-wrap gap-4 align-items-center">
    <div>
      <div class="text-secondary small">Subnet</div>
      <h5 class="mb-0"><code><?= e($subnet['cidr']) ?></code>
        <span class="badge text-bg-secondary">IPv<?= (int)$subnet['ip_version'] ?></span></h5>
    </div>
    <div><div class="text-secondary small">Name</div><?= e($subnet['name'] ?? '—') ?></div>
    <div><div class="text-secondary small">VLAN</div><?= $subnet['vlan_vid'] ? (int)$subnet['vlan_vid'] . ' · ' . e($subnet['vlan_name']) : '—' ?></div>
    <div><div class="text-secondary small">Site</div><?= e($subnet['site_name'] ?? '—') ?></div>
    <div><div class="text-secondary small">Gateway</div><?= e($subnet['gateway'] ?? '—') ?></div>
    <div>
      <div class="text-secondary small">Utilization</div>
      <?= $util === null ? 'n/a' : $util . '%' ?>
      (<?= count($ips) ?> / <?= e(IpTools::usableHosts((int)$subnet['ip_version'], (int)$subnet['prefix_len'])) ?>)
    </div>
    <?php if ($nextFree): ?>
    <div><div class="text-secondary small">Next free</div><code><?= e($nextFree) ?></code></div>
    <?php endif; ?>
    <div class="ms-auto">
      <a class="btn btn-sm btn-outline-secondary" href="/?page=subnets"><i class="bi bi-arrow-left"></i> Back</a>
    </div>
  </div>
</div>

<?php if ($canManage): ?>
<div class="card mb-3"><div class="card-body">
  <form method="post" class="row g-3">
    <?= Auth::csrfField() ?>
    <input type="hidden" name="action" value="ip_create">
    <input type="hidden" name="subnet_id" value="<?= $id ?>">
    <div class="col-md-2">
      <label class="form-label">IP address *</label>
      <input name="address" class="form-control" value="<?= e($nextFree ?? '') ?>" required>
    </div>
    <div class="col-md-2">
      <label class="form-label">Status</label>
      <select name="status" class="form-select">
        <option>active</option><option>reserved</option><option>dhcp</option>
        <option>gateway</option><option>deprecated</option>
      </select>
    </div>
    <div class="col-md-2">
      <label class="form-label">Hostname</label>
      <input name="hostname" class="form-control">
    </div>
    <div class="col-md-2">
      <label class="form-label">Device</label>
      <select name="device_type_id" class="form-select">
        <option value="">—</option>
        <?php foreach ($deviceTypes as $d): ?>
          <option value="<?= (int)$d['id'] ?>"><?= e($d['label']) ?></option>
        <?php endforeach; ?>
      </select>
    </div>
    <div class="col-md-2">
      <label class="form-label">MAC</label>
      <input name="mac_address" class="form-control" placeholder="aa:bb:cc:dd:ee:ff">
    </div>
    <div class="col-md-2">
      <label class="form-label">Serial number</label>
      <input name="serial_number" class="form-control" placeholder="SN-...">
    </div>
    <div class="col-md-2">
      <label class="form-label">OS</label>
      <input name="os" class="form-control" placeholder="RouterOS">
    </div>
    <div class="col-md-2">
      <label class="form-label">Software version</label>
      <input name="software_version" class="form-control" placeholder="7.15.3">
    </div>
    <div class="col-md-2 d-flex align-items-end">
      <button class="btn btn-primary w-100"><i class="bi bi-plus-lg"></i> Assign</button>
    </div>
  </form>
</div></div>
<?php endif; ?>


<?php if (Auth::can('ipam.manage') && $snmpProfiles): ?>
<div class="card mb-3"><div class="card-body py-2">
  <form method="post" class="row g-2 align-items-center">
    <?= Auth::csrfField() ?>
    <input type="hidden" name="action" value="subnet_snmp_bind">
    <input type="hidden" name="subnet_id" value="<?= $id ?>">
    <div class="col-auto"><label class="col-form-label small text-secondary"><i class="bi bi-key"></i> SNMP profile for discovery</label></div>
    <div class="col-md-3">
      <select name="snmp_credential_id" class="form-select form-select-sm">
        <option value="">Use default profile</option>
        <?php foreach ($snmpProfiles as $p): ?>
          <option value="<?= (int)$p['id'] ?>" <?= (int)($subnet['snmp_credential_id'] ?? 0) === (int)$p['id'] ? 'selected' : '' ?>><?= e($p['name']) ?></option>
        <?php endforeach; ?>
      </select>
    </div>
    <div class="col-auto"><button class="btn btn-sm btn-outline-secondary">Apply</button></div>
  </form>
</div></div>
<?php endif; ?>

<div class="card">
  <div class="table-responsive">
    <table class="table table-hover">
      <thead>
        <tr><th>Monitor</th><th>Address</th><th>Status</th><th>Hostname</th><th>Device</th><th>MAC</th><th>Serial</th><th>OS</th><th>Sw. version</th><th>Description</th><th>Updated</th>
        <?php if ($canManage): ?><th></th><?php endif; ?></tr>
      </thead>
      <tbody>
      <?php foreach ($ips as $ip): ?>
        <tr>
          <?php $ms = $monitor[$ip['address']] ?? null; ?>
          <td>
            <?php if ($ms): ?>
              <span class="dv-dot dv-dot-<?= e($ms['state']) ?>"></span>
              <span class="small text-secondary" title="<?php
                echo e('CPU ' . ($ms['cpu_pct'] ?? '—') . '% · MEM ' . ($ms['memory_pct'] ?? '—') . '% · checked ' . $ms['checked_at']);
              ?>">
                <?= $ms['cpu_pct'] !== null ? 'CPU ' . number_format((float)$ms['cpu_pct'], 0) . '%' : e($ms['state']) ?>
                <?= $ms['memory_pct'] !== null ? ' · MEM ' . number_format((float)$ms['memory_pct'], 0) . '%' : '' ?>
              </span>
            <?php else: ?>
              <span class="dv-dot dv-dot-unknown" title="No monitoring data"></span>
            <?php endif; ?>
          </td>
          <td><code><?= e($ip['address']) ?></code></td>
          <td><span class="badge dv-status dv-badge-<?= e($ip['status']) ?>"><?= e($ip['status']) ?></span></td>
          <td><?= e($ip['hostname'] ?? '—') ?></td>
          <td><?= e($ip['device_name'] ?: '—') ?></td>
          <td><?= e($ip['mac_address'] ?? '—') ?></td>
          <td><code class="small"><?= e($ip['serial_number'] ?? '—') ?></code></td>
          <td><?= e($ip['os'] ?? '—') ?></td>
          <td><?= e($ip['software_version'] ?? '—') ?></td>
          <td><?= e($ip['description'] ?? '—') ?></td>
          <td class="text-secondary small"><?= e($ip['updated_at']) ?></td>
          <?php if ($canManage): ?>
          <td class="text-end text-nowrap">
            <button class="btn btn-sm btn-outline-secondary" data-bs-toggle="collapse"
                    data-bs-target="#editip-<?= (int)$ip['id'] ?>" title="Edit">
              <i class="bi bi-pencil"></i>
            </button>
            <form method="post" class="d-inline" data-confirm="Release <?= e($ip['address']) ?>?">
              <?= Auth::csrfField() ?>
              <input type="hidden" name="action" value="ip_delete">
              <input type="hidden" name="id" value="<?= (int)$ip['id'] ?>">
              <button class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button>
            </form>
          </td>
          <?php endif; ?>
        </tr>
        <?php if ($canManage): ?>
        <tr class="dv-expand-row">
          <td colspan="12" class="p-0 border-0">
            <div class="collapse" id="editip-<?= (int)$ip['id'] ?>">
              <div class="p-3 dv-nested">
                <form method="post" class="row g-3">
                  <?= Auth::csrfField() ?>
                  <input type="hidden" name="action" value="ip_update">
                  <input type="hidden" name="id" value="<?= (int)$ip['id'] ?>">
                  <input type="hidden" name="subnet_id" value="<?= $id ?>">
                  <div class="col-md-2">
                    <label class="form-label">Address</label>
                    <input class="form-control" value="<?= e($ip['address']) ?>" disabled
                           title="Address cannot be changed — release and re-assign instead">
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">Status</label>
                    <select name="status" class="form-select">
                      <?php foreach (['active','reserved','dhcp','gateway','deprecated'] as $opt): ?>
                        <option <?= $ip['status'] === $opt ? 'selected' : '' ?>><?= $opt ?></option>
                      <?php endforeach; ?>
                    </select>
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">Hostname</label>
                    <input name="hostname" class="form-control" value="<?= e($ip['hostname'] ?? '') ?>">
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">Device</label>
                    <select name="device_type_id" class="form-select">
                      <option value="">—</option>
                      <?php foreach ($deviceTypes as $d): ?>
                        <option value="<?= (int)$d['id'] ?>" <?= (int)$ip['device_type_id'] === (int)$d['id'] ? 'selected' : '' ?>><?= e($d['label']) ?></option>
                      <?php endforeach; ?>
                    </select>
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">MAC</label>
                    <input name="mac_address" class="form-control" value="<?= e($ip['mac_address'] ?? '') ?>" placeholder="aa:bb:cc:dd:ee:ff">
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">Serial number</label>
                    <input name="serial_number" class="form-control" value="<?= e($ip['serial_number'] ?? '') ?>">
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">OS</label>
                    <input name="os" class="form-control" value="<?= e($ip['os'] ?? '') ?>">
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">Software version</label>
                    <input name="software_version" class="form-control" value="<?= e($ip['software_version'] ?? '') ?>">
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">Description</label>
                    <input name="description" class="form-control" value="<?= e($ip['description'] ?? '') ?>">
                  </div>
                  <div class="col-md-2 offset-md-10 d-flex align-items-end">
                    <button class="btn btn-primary w-100"><i class="bi bi-check-lg"></i> Save</button>
                  </div>
                </form>
              </div>
            </div>
          </td>
        </tr>
        <?php endif; ?>
      <?php endforeach; ?>
      <?php if (!$ips): ?>
        <tr><td colspan="8" class="text-center text-secondary py-4">No IPs assigned in this subnet.</td></tr>
      <?php endif; ?>
      </tbody>
    </table>
  </div>
</div>
