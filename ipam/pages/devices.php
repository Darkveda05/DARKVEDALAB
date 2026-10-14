<?php
use DarkVeda\{Auth, Database};
use function DarkVeda\e;

$types = Database::q(
    'SELECT dt.id, dt.model, dt.u_height, dt.image_path, v.name AS vendor FROM device_types dt
     LEFT JOIN vendors v ON v.id = dt.vendor_id
     ORDER BY v.name, dt.model'
);
$vendors   = Database::q('SELECT id, name FROM vendors ORDER BY name');
$canManage = Auth::can('devices.manage');
?>
<p class="text-secondary">
  Device <strong>types</strong> defined here appear in the device dropdown when assigning or
  editing IP addresses under <a href="/?page=subnets">Subnets &amp; IPs</a>.
</p>
<?php // ---- Device types management (v1.1) ---- ?>
<div class="card" id="dtypes">
  <div class="card-header"><i class="bi bi-cpu"></i> Device types</div>
  <?php if ($canManage): ?>
  <div class="card-body border-bottom">
    <form method="post" class="row g-3">
      <?= Auth::csrfField() ?>
      <input type="hidden" name="action" value="dtype_create">
      <div class="col-md-3">
        <label class="form-label">Vendor</label>
        <select name="vendor_id" class="form-select">
          <option value="">—</option>
          <?php foreach ($vendors as $v): ?>
            <option value="<?= (int)$v['id'] ?>"><?= e($v['name']) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-md-3">
        <label class="form-label">…or new vendor</label>
        <input name="vendor_new" class="form-control" placeholder="MikroTik">
      </div>
      <div class="col-md-3">
        <label class="form-label">Model *</label>
        <input name="model" class="form-control" required placeholder="CRS326-24G-2S+">
      </div>
      <div class="col-md-2">
        <label class="form-label">U height</label>
        <input name="u_height" type="number" min="0" max="48" value="1" class="form-control">
      </div>
      <div class="col-md-1 d-flex align-items-end">
        <button class="btn btn-primary w-100"><i class="bi bi-plus-lg"></i></button>
      </div>
    </form>
  </div>
  <?php endif; ?>
  <div class="table-responsive">
    <table class="table table-sm table-hover mb-0">
      <thead><tr><th style="width:78px">Image</th><th>Vendor</th><th>Model</th><th>U</th><th class="text-end"></th></tr></thead>
      <tbody>
      <?php foreach ($types as $t):
          $used = Database::one('SELECT COUNT(*) c FROM devices WHERE device_type_id = ?', [(int)$t['id']])['c'];
      ?>
        <tr>
          <td>
            <?php if ($t['image_path']): ?>
              <img src="/<?= e($t['image_path']) ?>" alt=""
                   style="width:66px;height:26px;object-fit:contain;background:#08080e;border-radius:3px">
            <?php else: ?>
              <span class="text-secondary small">—</span>
            <?php endif; ?>
          </td>
          <td><?= e($t['vendor'] ?? '—') ?></td>
          <td><?= e($t['model']) ?></td>
          <td><?= (int)($t['u_height'] ?? 1) ?></td>
          <td class="text-end text-nowrap">
            <?php if ($canManage): ?>
            <button class="btn btn-sm btn-outline-secondary" data-bs-toggle="collapse"
                    data-bs-target="#edittype-<?= (int)$t['id'] ?>" title="Edit">
              <i class="bi bi-pencil"></i>
            </button>
            <form method="post" class="d-inline m-0" data-confirm="Delete type <?= e($t['model']) ?>?">
              <?= Auth::csrfField() ?>
              <input type="hidden" name="action" value="dtype_delete">
              <input type="hidden" name="id" value="<?= (int)$t['id'] ?>">
              <button class="btn btn-sm btn-outline-danger" <?= (int)$used > 0 ? 'disabled title="In use by ' . (int)$used . ' device(s)"' : '' ?>>
                <i class="bi bi-trash"></i>
              </button>
            </form>
            <?php endif; ?>
          </td>
        </tr>
        <?php if ($canManage): ?>
        <tr class="dv-expand-row">
          <td colspan="5" class="p-0 border-0">
            <div class="collapse" id="edittype-<?= (int)$t['id'] ?>">
              <div class="p-3 dv-nested">
                <form method="post" class="row g-3">
                  <?= Auth::csrfField() ?>
                  <input type="hidden" name="action" value="dtype_update">
                  <input type="hidden" name="id" value="<?= (int)$t['id'] ?>">
                  <div class="col-md-3">
                    <label class="form-label">Vendor</label>
                    <select name="vendor_id" class="form-select">
                      <option value="">—</option>
                      <?php foreach ($vendors as $v): ?>
                        <option value="<?= (int)$v['id'] ?>" <?= $t['vendor'] === $v['name'] ? 'selected' : '' ?>><?= e($v['name']) ?></option>
                      <?php endforeach; ?>
                    </select>
                  </div>
                  <div class="col-md-3">
                    <label class="form-label">…or new vendor</label>
                    <input name="vendor_new" class="form-control">
                  </div>
                  <div class="col-md-3">
                    <label class="form-label">Model *</label>
                    <input name="model" class="form-control" required value="<?= e($t['model']) ?>">
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">U height</label>
                    <input name="u_height" type="number" min="0" max="48" class="form-control" value="<?= (int)($t['u_height'] ?? 1) ?>">
                  </div>
                  <div class="col-md-1 d-flex align-items-end">
                    <button class="btn btn-primary w-100" title="Save"><i class="bi bi-check-lg"></i></button>
                  </div>
                </form>

                <hr class="my-3">
                <form method="post" enctype="multipart/form-data" class="row g-2 align-items-end">
                  <?= Auth::csrfField() ?>
                  <input type="hidden" name="action" value="model_image_upload">
                  <input type="hidden" name="id" value="<?= (int)$t['id'] ?>">
                  <input type="hidden" name="back" value="/?page=devices">
                  <div class="col-md-6">
                    <label class="form-label">
                      Device photo
                      <span class="text-secondary">— shown on rack elevations and in the 3D view</span>
                    </label>
                    <input type="file" name="image" class="form-control form-control-sm" required
                           accept=".png,.jpg,.jpeg,.svg,.webp,image/png,image/jpeg,image/svg+xml,image/webp">
                    <div class="form-text">A wide front-on shot works best (roughly 8:1 for a 1U device).</div>
                  </div>
                  <div class="col-md-3">
                    <button class="btn btn-sm btn-outline-primary w-100"><i class="bi bi-upload"></i> Upload photo</button>
                  </div>
                  <?php if ($t['image_path']): ?>
                  <div class="col-md-3">
                    <img src="/<?= e($t['image_path']) ?>" alt=""
                         style="width:100%;max-height:44px;object-fit:contain;background:#08080e;border-radius:4px">
                  </div>
                  <?php endif; ?>
                </form>
                <?php if ($t['image_path']): ?>
                <form method="post" class="mt-2" data-confirm="Remove the photo for <?= e($t['model']) ?>?">
                  <?= Auth::csrfField() ?>
                  <input type="hidden" name="action" value="model_image_delete">
                  <input type="hidden" name="id" value="<?= (int)$t['id'] ?>">
                  <input type="hidden" name="back" value="/?page=devices">
                  <button class="btn btn-sm btn-outline-danger"><i class="bi bi-image"></i> Remove photo</button>
                </form>
                <?php endif; ?>
              </div>
            </div>
          </td>
        </tr>
        <?php endif; ?>
      <?php endforeach; ?>
      <?php if (!$types): ?>
        <tr><td colspan="5" class="text-center text-secondary py-3">No device types yet.</td></tr>
      <?php endif; ?>
      </tbody>
    </table>
  </div>
</div>
