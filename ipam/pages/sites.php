<?php
use DarkVeda\{Auth, Database};
use function DarkVeda\e;

$sites = Database::q(
    'SELECT s.*,
            (SELECT COUNT(*) FROM subnets  WHERE site_id = s.id) AS subnet_count,
            (SELECT COUNT(*) FROM vlans    WHERE site_id = s.id) AS vlan_count,
            (SELECT COUNT(*) FROM devices  WHERE site_id = s.id) AS device_count
     FROM sites s ORDER BY s.name'
);
$canManage = Auth::can('ipam.manage');
?>
<?php if ($canManage): ?>
<div class="card mb-3"><div class="card-body">
  <form method="post" class="row g-3">
    <?= Auth::csrfField() ?>
    <input type="hidden" name="action" value="site_create">
    <div class="col-md-3">
      <label class="form-label">Name *</label>
      <input name="name" class="form-control" required placeholder="KL Data Center">
    </div>
    <div class="col-md-2">
      <label class="form-label">Slug</label>
      <input name="slug" class="form-control" placeholder="auto from name">
    </div>
    <div class="col-md-3">
      <label class="form-label">Address</label>
      <input name="address" class="form-control" placeholder="Building A, Server Room">
    </div>
    <div class="col-md-3">
      <label class="form-label">Description</label>
      <input name="description" class="form-control">
    </div>
    <div class="col-md-1 d-flex align-items-end">
      <button class="btn btn-primary w-100"><i class="bi bi-plus-lg"></i></button>
    </div>
  </form>
</div></div>
<?php endif; ?>

<div class="card">
  <div class="card-header"><i class="bi bi-buildings"></i> Sites</div>
  <div class="table-responsive">
    <table class="table table-hover mb-0">
      <thead><tr>
        <th>Name</th><th>Slug</th><th>Address</th><th>Subnets</th><th>VLANs</th><th>Devices</th><th>Description</th><th></th>
      </tr></thead>
      <tbody>
      <?php foreach ($sites as $s): ?>
        <tr>
          <td><strong><?= e($s['name']) ?></strong></td>
          <td><code><?= e($s['slug']) ?></code></td>
          <td><?= e($s['address'] ?? '—') ?></td>
          <td><?= (int)$s['subnet_count'] ?></td>
          <td><?= (int)$s['vlan_count'] ?></td>
          <td><?= (int)$s['device_count'] ?></td>
          <td class="text-secondary"><?= e($s['description'] ?? '—') ?></td>
          <td class="text-end text-nowrap">
            <?php if ($canManage): ?>
            <button class="btn btn-sm btn-outline-secondary" data-bs-toggle="collapse"
                    data-bs-target="#editsite-<?= (int)$s['id'] ?>" title="Edit">
              <i class="bi bi-pencil"></i>
            </button>
            <form method="post" class="d-inline m-0" data-confirm="Delete site <?= e($s['name']) ?>?">
              <?= Auth::csrfField() ?>
              <input type="hidden" name="action" value="site_delete">
              <input type="hidden" name="id" value="<?= (int)$s['id'] ?>">
              <button class="btn btn-sm btn-outline-danger" <?= ($s['subnet_count'] + $s['vlan_count'] + $s['device_count']) > 0 ? 'disabled title="Still referenced"' : '' ?>>
                <i class="bi bi-trash"></i>
              </button>
            </form>
            <?php endif; ?>
          </td>
        </tr>
        <?php if ($canManage): ?>
        <tr class="dv-expand-row">
          <td colspan="8" class="p-0 border-0">
            <div class="collapse" id="editsite-<?= (int)$s['id'] ?>">
              <div class="p-3 dv-nested">
                <form method="post" class="row g-3">
                  <?= Auth::csrfField() ?>
                  <input type="hidden" name="action" value="site_update">
                  <input type="hidden" name="id" value="<?= (int)$s['id'] ?>">
                  <div class="col-md-3">
                    <label class="form-label">Name *</label>
                    <input name="name" class="form-control" required value="<?= e($s['name']) ?>">
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">Slug</label>
                    <input name="slug" class="form-control" value="<?= e($s['slug']) ?>">
                  </div>
                  <div class="col-md-3">
                    <label class="form-label">Address</label>
                    <input name="address" class="form-control" value="<?= e($s['address'] ?? '') ?>">
                  </div>
                  <div class="col-md-3">
                    <label class="form-label">Description</label>
                    <input name="description" class="form-control" value="<?= e($s['description'] ?? '') ?>">
                  </div>
                  <div class="col-md-1 d-flex align-items-end">
                    <button class="btn btn-primary w-100" title="Save"><i class="bi bi-check-lg"></i></button>
                  </div>
                </form>
              </div>
            </div>
          </td>
        </tr>
        <?php endif; ?>
      <?php endforeach; ?>
      <?php if (!$sites): ?>
        <tr><td colspan="8" class="text-center text-secondary py-4">No sites yet.</td></tr>
      <?php endif; ?>
      </tbody>
    </table>
  </div>
</div>
