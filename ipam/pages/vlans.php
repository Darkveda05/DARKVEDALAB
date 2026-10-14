<?php
use DarkVeda\{Auth, Database};
use function DarkVeda\e;

$vlans = Database::q(
    'SELECT v.*, s.name AS site_name,
            (SELECT COUNT(*) FROM subnets sub WHERE sub.vlan_id = v.id) AS subnet_count
     FROM vlans v LEFT JOIN sites s ON s.id = v.site_id
     ORDER BY v.vid'
);
$sites = Database::q('SELECT id, name FROM sites ORDER BY name');
$canManage = Auth::can('ipam.manage');
?>
<?php if ($canManage): ?>
<div class="card mb-3"><div class="card-body">
  <form method="post" class="row g-3">
    <?= Auth::csrfField() ?>
    <input type="hidden" name="action" value="vlan_create">
    <div class="col-md-2">
      <label class="form-label">VLAN ID *</label>
      <input type="number" name="vid" class="form-control" min="1" max="4094" required>
    </div>
    <div class="col-md-3">
      <label class="form-label">Name *</label>
      <input name="name" class="form-control" required>
    </div>
    <div class="col-md-2">
      <label class="form-label">Site</label>
      <select name="site_id" class="form-select">
        <option value="">Global</option>
        <?php foreach ($sites as $s): ?>
          <option value="<?= (int)$s['id'] ?>"><?= e($s['name']) ?></option>
        <?php endforeach; ?>
      </select>
    </div>
    <div class="col-md-3">
      <label class="form-label">Description</label>
      <input name="description" class="form-control">
    </div>
    <div class="col-md-2 d-flex align-items-end">
      <button class="btn btn-primary w-100"><i class="bi bi-plus-lg"></i> Add VLAN</button>
    </div>
  </form>
</div></div>
<?php endif; ?>

<div class="card">
  <div class="table-responsive">
    <table class="table table-hover">
      <thead><tr><th>VID</th><th>Name</th><th>Site</th><th>Status</th><th>Subnets</th><th>Description</th>
        <?php if ($canManage): ?><th></th><?php endif; ?></tr></thead>
      <tbody>
      <?php foreach ($vlans as $v): ?>
        <tr>
          <td><strong><?= (int)$v['vid'] ?></strong></td>
          <td><?= e($v['name']) ?></td>
          <td><?= e($v['site_name'] ?? 'Global') ?></td>
          <td><span class="badge dv-status dv-badge-<?= e($v['status']) ?>"><?= e($v['status']) ?></span></td>
          <td><?= (int)$v['subnet_count'] ?></td>
          <td><?= e($v['description'] ?? '—') ?></td>
          <?php if ($canManage): ?>
          <td class="text-end text-nowrap">
            <button class="btn btn-sm btn-outline-secondary" data-bs-toggle="collapse"
                    data-bs-target="#editvlan-<?= (int)$v['id'] ?>" title="Edit">
              <i class="bi bi-pencil"></i>
            </button>
            <form method="post" class="d-inline" data-confirm="Delete VLAN <?= (int)$v['vid'] ?>?">
              <?= Auth::csrfField() ?>
              <input type="hidden" name="action" value="vlan_delete">
              <input type="hidden" name="id" value="<?= (int)$v['id'] ?>">
              <button class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button>
            </form>
          </td>
          <?php endif; ?>
        </tr>
        <?php if ($canManage): ?>
        <tr class="dv-expand-row">
          <td colspan="7" class="p-0 border-0">
            <div class="collapse" id="editvlan-<?= (int)$v['id'] ?>">
              <div class="p-3 dv-nested">
                <form method="post" class="row g-3">
                  <?= Auth::csrfField() ?>
                  <input type="hidden" name="action" value="vlan_update">
                  <input type="hidden" name="id" value="<?= (int)$v['id'] ?>">
                  <div class="col-md-2">
                    <label class="form-label">VLAN ID *</label>
                    <input type="number" name="vid" class="form-control" min="1" max="4094" required value="<?= (int)$v['vid'] ?>">
                  </div>
                  <div class="col-md-3">
                    <label class="form-label">Name *</label>
                    <input name="name" class="form-control" required value="<?= e($v['name']) ?>">
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">Site</label>
                    <select name="site_id" class="form-select">
                      <option value="">Global</option>
                      <?php foreach ($sites as $st): ?>
                        <option value="<?= (int)$st['id'] ?>" <?= (int)$v['site_id'] === (int)$st['id'] ? 'selected' : '' ?>><?= e($st['name']) ?></option>
                      <?php endforeach; ?>
                    </select>
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">Status</label>
                    <select name="status" class="form-select">
                      <?php foreach (['active','reserved','deprecated'] as $opt): ?>
                        <option <?= $v['status'] === $opt ? 'selected' : '' ?>><?= $opt ?></option>
                      <?php endforeach; ?>
                    </select>
                  </div>
                  <div class="col-md-3">
                    <label class="form-label">Description</label>
                    <input name="description" class="form-control" value="<?= e($v['description'] ?? '') ?>">
                  </div>
                  <div class="col-md-2 d-flex align-items-end">
                    <button class="btn btn-primary w-100"><i class="bi bi-check-lg"></i> Save</button>
                  </div>
                </form>
              </div>
            </div>
          </td>
        </tr>
        <?php endif; ?>
      <?php endforeach; ?>
      <?php if (!$vlans): ?>
        <tr><td colspan="7" class="text-center text-secondary py-4">No VLANs defined.</td></tr>
      <?php endif; ?>
      </tbody>
    </table>
  </div>
</div>
