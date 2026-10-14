<?php
use DarkVeda\{Auth, Database, ImageSearch, Uploads};
use function DarkVeda\e;

$canManage = Auth::can('devices.manage') || Auth::can('racks.manage');
$q         = trim((string)($_GET['q'] ?? ''));
$typeId    = (int)($_GET['type'] ?? 0);
$itemId    = (int)($_GET['item'] ?? 0);
$back      = (string)($_GET['back'] ?? '/?page=devices');

$types = Database::q(
    'SELECT dt.id, dt.model, dt.image_path, dt.image_credit,
            TRIM(CONCAT(COALESCE(v.name, ""), " ", dt.model)) AS label,
            (SELECT COUNT(*) FROM ip_addresses i WHERE i.device_type_id = dt.id) AS in_use
     FROM device_types dt LEFT JOIN vendors v ON v.id = dt.vendor_id
     ORDER BY v.name, dt.model'
);

$targetType = $typeId ? Database::one(
    'SELECT dt.*, TRIM(CONCAT(COALESCE(v.name, ""), " ", dt.model)) AS label
     FROM device_types dt LEFT JOIN vendors v ON v.id = dt.vendor_id WHERE dt.id = ?', [$typeId]
) : null;
$targetItem = $itemId ? Database::one('SELECT * FROM rack_items WHERE id = ?', [$itemId]) : null;

// pre-fill the box from whatever we are attaching to
if ($q === '') {
    $q = $targetType['label'] ?? ($targetItem['name'] ?? '');
}

$results = [];
$error   = null;
$searched = isset($_GET['q']) && $q !== '';
if ($searched) {
    try {
        $results = ImageSearch::search($q, 12, !isset($_GET['fresh']));
    } catch (Throwable $ex) {
        $error = $ex->getMessage();
    }
}
$available = ImageSearch::enabled();
?>
<div class="row g-3">
  <div class="col-lg-8">
    <div class="card mb-3">
      <div class="card-header"><i class="bi bi-search"></i> Find a device image</div>
      <div class="card-body">
        <?php if (!$available): ?>
          <div class="alert alert-warning mb-3">
            Image search needs outbound HTTPS from the server (cURL or <code>allow_url_fopen</code>).
            You can still upload a photo manually below.
          </div>
        <?php endif; ?>

        <form method="get" class="row g-2 mb-2">
          <input type="hidden" name="page" value="model_images">
          <?php if ($typeId): ?><input type="hidden" name="type" value="<?= $typeId ?>"><?php endif; ?>
          <?php if ($itemId): ?><input type="hidden" name="item" value="<?= $itemId ?>"><?php endif; ?>
          <input type="hidden" name="back" value="<?= e($back) ?>">
          <div class="col-md-9">
            <input name="q" class="form-control" value="<?= e($q) ?>"
                   placeholder="Vendor and model, e.g. MikroTik RB5009 or Cisco Catalyst 9200" required>
          </div>
          <div class="col-md-3 d-grid">
            <button class="btn btn-primary" <?= $available ? '' : 'disabled' ?>>
              <i class="bi bi-search"></i> Search
            </button>
          </div>
        </form>
        <div class="form-text">
          Searches Wikimedia Commons, where everything is openly licensed and safe to copy onto your own
          server. Attribution is saved with each image. Nothing downloads until you pick one.
        </div>
      </div>
    </div>

    <?php if ($error): ?>
      <div class="alert alert-danger"><?= e($error) ?></div>
    <?php endif; ?>

    <?php if ($searched && !$error): ?>
    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span><i class="bi bi-images"></i> <?= count($results) ?> result(s) for "<?= e($q) ?>"</span>
        <a class="btn btn-sm btn-outline-secondary"
           href="/?page=model_images&q=<?= urlencode($q) ?>&fresh=1<?= $typeId ? '&type=' . $typeId : '' ?><?= $itemId ? '&item=' . $itemId : '' ?>&back=<?= urlencode($back) ?>">
          <i class="bi bi-arrow-clockwise"></i> Refresh
        </a>
      </div>
      <div class="card-body">
        <?php if (!$results): ?>
          <div class="text-center text-secondary py-4">
            Nothing found. Try a shorter query — the vendor plus the model family
            (for example "MikroTik RB5009" rather than "RB5009UPr+S+IN") usually works better.
          </div>
        <?php else: ?>
        <div class="row g-3">
          <?php foreach ($results as $r): ?>
            <div class="col-md-6 col-xl-4">
              <div class="card h-100" style="background:#0e0e18">
                <div style="height:120px;display:flex;align-items:center;justify-content:center;background:#08080e;border-radius:6px 6px 0 0;overflow:hidden">
                  <img src="<?= e($r['thumb']) ?>" alt="" loading="lazy"
                       style="max-width:100%;max-height:120px;object-fit:contain">
                </div>
                <div class="card-body p-2">
                  <div class="small text-truncate" title="<?= e($r['title']) ?>"><?= e(str_replace('File:', '', $r['title'])) ?></div>
                  <div class="text-secondary" style="font-size:.72rem">
                    <?= (int)$r['width'] ?>×<?= (int)$r['height'] ?> · <?= e($r['credit']) ?>
                  </div>
                  <?php if ($canManage && ($typeId || $itemId)): ?>
                  <form method="post" class="mt-2">
                    <?= Auth::csrfField() ?>
                    <input type="hidden" name="action" value="model_image_apply">
                    <input type="hidden" name="target" value="<?= $itemId ? 'rack_item' : 'device_type' ?>">
                    <input type="hidden" name="id" value="<?= $itemId ?: $typeId ?>">
                    <input type="hidden" name="url" value="<?= e($r['url']) ?>">
                    <input type="hidden" name="credit" value="<?= e($r['credit']) ?>">
                    <input type="hidden" name="source" value="<?= e($r['descriptionurl']) ?>">
                    <input type="hidden" name="back" value="<?= e($back) ?>">
                    <button class="btn btn-sm btn-primary w-100">
                      <i class="bi bi-download"></i> Use this image
                    </button>
                  </form>
                  <?php elseif ($canManage): ?>
                    <div class="form-text mt-2">Pick a device type on the right first.</div>
                  <?php endif; ?>
                </div>
              </div>
            </div>
          <?php endforeach; ?>
        </div>
        <?php endif; ?>
      </div>
    </div>
    <?php endif; ?>
  </div>

  <div class="col-lg-4">
    <div class="card mb-3">
      <div class="card-header"><i class="bi bi-cpu"></i> Device types</div>
      <div class="table-responsive" style="max-height:420px;overflow-y:auto">
        <table class="table table-sm table-hover mb-0">
          <thead><tr><th>Image</th><th>Model</th><th class="text-end"></th></tr></thead>
          <tbody>
          <?php foreach ($types as $t): ?>
            <tr <?= $typeId === (int)$t['id'] ? 'style="background:rgba(139,92,246,.15)"' : '' ?>>
              <td style="width:74px">
                <?php if ($t['image_path']): ?>
                  <img src="/<?= e($t['image_path']) ?>" alt=""
                       style="width:64px;height:24px;object-fit:contain;background:#08080e;border-radius:3px">
                <?php else: ?>
                  <span class="text-secondary small">—</span>
                <?php endif; ?>
              </td>
              <td>
                <?= e($t['label']) ?>
                <div class="small text-secondary"><?= (int)$t['in_use'] ?> device(s)</div>
              </td>
              <td class="text-end text-nowrap">
                <a class="btn btn-sm btn-outline-primary"
                   href="/?page=model_images&type=<?= (int)$t['id'] ?>&q=<?= urlencode($t['label']) ?>&back=<?= urlencode($back) ?>"
                   title="Find an image for this model">
                  <i class="bi bi-search"></i>
                </a>
                <?php if ($t['image_path'] && $canManage): ?>
                <form method="post" class="d-inline m-0" data-confirm="Remove the image for <?= e($t['label']) ?>?">
                  <?= Auth::csrfField() ?>
                  <input type="hidden" name="action" value="model_image_delete">
                  <input type="hidden" name="id" value="<?= (int)$t['id'] ?>">
                  <input type="hidden" name="back" value="/?page=model_images">
                  <button class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button>
                </form>
                <?php endif; ?>
              </td>
            </tr>
          <?php endforeach; ?>
          <?php if (!$types): ?>
            <tr><td colspan="3" class="text-center text-secondary py-3">
              No device types yet — add one under <a href="/?page=devices">Devices</a>.
            </td></tr>
          <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

    <?php if ($canManage && $targetType): ?>
    <div class="card">
      <div class="card-header"><i class="bi bi-upload"></i> Upload for <?= e($targetType['label']) ?></div>
      <div class="card-body">
        <?php if ($targetType['image_path']): ?>
          <img src="/<?= e($targetType['image_path']) ?>" alt=""
               style="width:100%;max-height:90px;object-fit:contain;background:#08080e;border-radius:6px;margin-bottom:.6rem">
          <?php if ($targetType['image_credit']): ?>
            <div class="small text-secondary mb-2"><?= e($targetType['image_credit']) ?></div>
          <?php endif; ?>
        <?php endif; ?>
        <form method="post" enctype="multipart/form-data" class="row g-2">
          <?= Auth::csrfField() ?>
          <input type="hidden" name="action" value="model_image_upload">
          <input type="hidden" name="id" value="<?= (int)$targetType['id'] ?>">
          <input type="hidden" name="back" value="/?page=model_images&type=<?= (int)$targetType['id'] ?>">
          <div class="col-12">
            <input type="file" name="image" class="form-control form-control-sm" required
                   accept=".png,.jpg,.jpeg,.svg,.webp,image/png,image/jpeg,image/svg+xml,image/webp">
            <div class="form-text">Have your own photo? A wide front-on shot works best.</div>
          </div>
          <div class="col-12 d-grid">
            <button class="btn btn-sm btn-primary"><i class="bi bi-upload"></i> Upload image</button>
          </div>
        </form>
      </div>
    </div>
    <?php endif; ?>
  </div>
</div>
