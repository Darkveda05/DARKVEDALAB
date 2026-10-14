<?php
use DarkVeda\{Auth, Database, IpTools};
use function DarkVeda\e;

$subnets = Database::q(
    'SELECT s.*, v.vid AS vlan_vid, v.name AS vlan_name, st.name AS site_name,
            (SELECT COUNT(*) FROM ip_addresses i WHERE i.subnet_id = s.id) AS assigned
     FROM subnets s
     LEFT JOIN vlans v ON v.id = s.vlan_id
     LEFT JOIN sites st ON st.id = s.site_id
     ORDER BY s.ip_version, s.network_bin'
);
$vlans = Database::q('SELECT id, vid, name FROM vlans ORDER BY vid');
$sites = Database::q('SELECT id, name FROM sites ORDER BY name');
$canManage = Auth::can('ipam.manage');
?>
<div class="d-flex justify-content-between align-items-center mb-3">
  <div class="text-secondary small"><?= count($subnets) ?> subnet(s)</div>
  <div class="d-flex gap-2">
    <a class="btn btn-sm btn-outline-secondary" href="/?page=export&what=subnets">
      <i class="bi bi-filetype-csv"></i> Export CSV
    </a>
    <?php if ($canManage): ?>
    <button class="btn btn-sm btn-primary" data-bs-toggle="collapse" data-bs-target="#createForm">
      <i class="bi bi-plus-lg"></i> New subnet
    </button>
    <?php endif; ?>
  </div>
</div>

<?php if ($canManage): ?>
<div class="collapse mb-3" id="createForm">
  <div class="card"><div class="card-body">
    <form method="post" class="row g-3">
      <?= Auth::csrfField() ?>
      <input type="hidden" name="action" value="subnet_create">
      <div class="col-md-3">
        <label class="form-label">CIDR *</label>
        <input name="cidr" class="form-control" placeholder="10.0.0.0/24 or 2001:db8::/64" required>
      </div>
      <div class="col-md-3">
        <label class="form-label">Name</label>
        <input name="name" class="form-control" placeholder="Server LAN">
      </div>
      <div class="col-md-2">
        <label class="form-label">VLAN</label>
        <select name="vlan_id" class="form-select">
          <option value="">—</option>
          <?php foreach ($vlans as $v): ?>
            <option value="<?= (int)$v['id'] ?>"><?= (int)$v['vid'] ?> · <?= e($v['name']) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-md-2">
        <label class="form-label">Site</label>
        <select name="site_id" class="form-select">
          <option value="">—</option>
          <?php foreach ($sites as $s): ?>
            <option value="<?= (int)$s['id'] ?>"><?= e($s['name']) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-md-3">
        <label class="form-label">Gateway</label>
        <input name="gateway" class="form-control" placeholder="10.0.0.1">
      </div>
      <div class="col-md-3">
        <label class="form-label">Status</label>
        <select name="status" class="form-select">
          <option>active</option><option>reserved</option><option>deprecated</option><option>container</option>
        </select>
      </div>
      <div class="col-md-4">
        <label class="form-label">Description</label>
        <input name="description" class="form-control">
      </div>
      <div class="col-md-2 d-flex align-items-end">
        <button class="btn btn-primary w-100">Create</button>
      </div>
    </form>
  </div></div>
</div>
<?php endif; ?>

<div class="card">
  <div class="table-responsive">
    <table class="table table-hover">
      <thead>
        <tr>
          <th>Subnet</th><th>Name</th><th>VLAN</th><th>Site</th>
          <th>Status</th><th>Assigned</th><th class="dv-util">Utilization</th>
          <?php if ($canManage): ?><th></th><?php endif; ?>
        </tr>
      </thead>
      <tbody>
      <?php foreach ($subnets as $s):
          $util = IpTools::utilization((int)$s['ip_version'], (int)$s['prefix_len'], (int)$s['assigned']);
      ?>
        <tr>
          <td>
            <a href="/?page=subnet_view&id=<?= (int)$s['id'] ?>"><code><?= e($s['cidr']) ?></code></a>
            <span class="badge text-bg-secondary ms-1">v<?= (int)$s['ip_version'] ?></span>
          </td>
          <td><?= e($s['name'] ?? '—') ?></td>
          <td><?= $s['vlan_vid'] ? (int)$s['vlan_vid'] . ' · ' . e($s['vlan_name']) : '—' ?></td>
          <td><?= e($s['site_name'] ?? '—') ?></td>
          <td><span class="badge dv-status dv-badge-<?= e($s['status']) ?>"><?= e($s['status']) ?></span></td>
          <td><?= (int)$s['assigned'] ?> / <?= e(IpTools::usableHosts((int)$s['ip_version'], (int)$s['prefix_len'])) ?></td>
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
          <?php if ($canManage): ?>
          <td class="text-end text-nowrap">
            <button class="btn btn-sm btn-outline-secondary" data-bs-toggle="collapse"
                    data-bs-target="#editsubnet-<?= (int)$s['id'] ?>" title="Edit">
              <i class="bi bi-pencil"></i>
            </button>
            <form method="post" class="d-inline" data-confirm="Delete <?= e($s['cidr']) ?> and all its IP records?">
              <?= Auth::csrfField() ?>
              <input type="hidden" name="action" value="subnet_delete">
              <input type="hidden" name="id" value="<?= (int)$s['id'] ?>">
              <button class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button>
            </form>
          </td>
          <?php endif; ?>
        </tr>
        <?php if ($canManage): ?>
        <tr class="dv-expand-row">
          <td colspan="8" class="p-0 border-0">
            <div class="collapse" id="editsubnet-<?= (int)$s['id'] ?>">
              <div class="p-3 dv-nested">
                <form method="post" class="row g-3">
                  <?= Auth::csrfField() ?>
                  <input type="hidden" name="action" value="subnet_update">
                  <input type="hidden" name="id" value="<?= (int)$s['id'] ?>">
                  <div class="col-md-2">
                    <label class="form-label">CIDR</label>
                    <input class="form-control" value="<?= e($s['cidr']) ?>" disabled title="CIDR cannot be changed — recreate the subnet instead">
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">Name</label>
                    <input name="name" class="form-control" value="<?= e($s['name'] ?? '') ?>">
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">VLAN</label>
                    <select name="vlan_id" class="form-select">
                      <option value="">—</option>
                      <?php foreach ($vlans as $v): ?>
                        <option value="<?= (int)$v['id'] ?>" <?= (int)$s['vlan_id'] === (int)$v['id'] ? 'selected' : '' ?>><?= (int)$v['vid'] ?> · <?= e($v['name']) ?></option>
                      <?php endforeach; ?>
                    </select>
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">Site</label>
                    <select name="site_id" class="form-select">
                      <option value="">—</option>
                      <?php foreach ($sites as $st): ?>
                        <option value="<?= (int)$st['id'] ?>" <?= (int)$s['site_id'] === (int)$st['id'] ? 'selected' : '' ?>><?= e($st['name']) ?></option>
                      <?php endforeach; ?>
                    </select>
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">Gateway</label>
                    <input name="gateway" class="form-control" value="<?= e($s['gateway'] ?? '') ?>">
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">Status</label>
                    <select name="status" class="form-select">
                      <?php foreach (['active','reserved','deprecated','container'] as $opt): ?>
                        <option <?= $s['status'] === $opt ? 'selected' : '' ?>><?= $opt ?></option>
                      <?php endforeach; ?>
                    </select>
                  </div>
                  <div class="col-md-9">
                    <label class="form-label">Description</label>
                    <input name="description" class="form-control" value="<?= e($s['description'] ?? '') ?>">
                  </div>
                  <div class="col-md-3 d-flex align-items-end">
                    <button class="btn btn-primary w-100"><i class="bi bi-check-lg"></i> Save</button>
                  </div>
                </form>
              </div>
            </div>
          </td>
        </tr>
        <?php endif; ?>
      <?php endforeach; ?>
      <?php if (!$subnets): ?>
        <tr><td colspan="8" class="text-center text-secondary py-4">No subnets defined yet.</td></tr>
      <?php endif; ?>
      </tbody>
    </table>
  </div>
</div>
