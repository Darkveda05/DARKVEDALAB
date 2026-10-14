<?php
use DarkVeda\{Auth, Database, Zabbix, Uploads};
use function DarkVeda\e;

$canManage = Auth::can('racks.manage');
$sites = Database::q('SELECT id, name FROM sites ORDER BY name');
$racks = Database::q(
    'SELECT r.*, s.name AS site_name,
            (SELECT COUNT(*) FROM rack_items ri WHERE ri.rack_id = r.id) AS mounted,
            (SELECT COALESCE(SUM(ri.u_size),0) FROM rack_items ri WHERE ri.rack_id = r.id) AS used_u
     FROM racks r LEFT JOIN sites s ON s.id = r.site_id
     ORDER BY s.name, r.name'
);

$selectedId = (int)($_GET['id'] ?? 0);
if (!$selectedId && $racks) {
    $selectedId = (int)$racks[0]['id'];
}
$rack = $selectedId
    ? Database::one('SELECT r.*, s.name AS site_name FROM racks r LEFT JOIN sites s ON s.id = r.site_id WHERE r.id = ?', [$selectedId])
    : null;

$face = ($_GET['face'] ?? 'front') === 'rear' ? 'rear' : 'front';

// Enriched items for the selected rack (both faces — the client filters).
$items = [];
if ($rack) {
    $items = Database::q(
        'SELECT ri.id, ri.name, ri.kind, ri.u_position, ri.u_size, ri.face,
                ri.color, ri.description, ri.ip_id, ri.device_type_id,
                i.address, i.subnet_id,
                TRIM(CONCAT(
                    COALESCE(v.name, vd.name, ""), " ",
                    COALESCE(dt.model, dtd.model, "")
                )) AS type_label,
                COALESCE(NULLIF(ri.photo_path, ""), dt.image_path, dtd.image_path) AS display_image,
                ri.photo_path
         FROM rack_items ri
         LEFT JOIN ip_addresses i ON i.id = ri.ip_id
         LEFT JOIN device_types dt ON dt.id = i.device_type_id
         LEFT JOIN vendors v ON v.id = dt.vendor_id
         LEFT JOIN device_types dtd ON dtd.id = ri.device_type_id
         LEFT JOIN vendors vd ON vd.id = dtd.vendor_id
         WHERE ri.rack_id = ?
         ORDER BY ri.u_position DESC',
        [$selectedId]
    );
}

// Unmounted IP records — draggable onto the rack, carry a faceplate + default height.
$availableIps = Database::q(
    'SELECT i.id, i.address, i.hostname, s.cidr,
            COALESCE((SELECT dt.u_height FROM device_types dt WHERE dt.id = i.device_type_id), 1) AS u_height,
            (SELECT dt.image_path FROM device_types dt WHERE dt.id = i.device_type_id) AS image_path
     FROM ip_addresses i JOIN subnets s ON s.id = i.subnet_id
     WHERE NOT EXISTS (SELECT 1 FROM rack_items ri WHERE ri.ip_id = i.id)
     ORDER BY i.address_bin LIMIT 500'
);

// Hardware library — every known device model, draggable straight onto the rack.
$deviceTypes = Database::q(
    'SELECT dt.id, dt.model, dt.u_height, dt.image_path, v.name AS vendor
     FROM device_types dt LEFT JOIN vendors v ON v.id = dt.vendor_id
     ORDER BY v.name IS NULL, v.name, dt.model'
);

$mon = Zabbix::statusMap();
foreach ($items as &$it) {
    $it['state'] = $it['address'] ? ($mon[$it['address']]['state'] ?? null) : null;
}
unset($it);

$kinds = [
    'device'      => 'Device',
    'server'      => 'Server',
    'switch'      => 'Switch',
    'router'      => 'Router',
    'patch_panel' => 'Patch panel',
    'screen'      => 'Screen / KVM',
    'power'       => 'Power / PDU / UPS',
    'shelf'       => 'Shelf',
    'blank'       => 'Blanking plate',
    'other'       => 'Other',
];

// Generic building blocks for the palette (kind, label, default U height, icon).
$blocks = [
    ['server',      'Server',       2, 'bi-hdd'],
    ['switch',      'Switch',       1, 'bi-diagram-3'],
    ['router',      'Router',       1, 'bi-router'],
    ['patch_panel', 'Patch panel',  1, 'bi-grid-3x2'],
    ['power',       'PDU / UPS',    1, 'bi-plug'],
    ['screen',      'Screen / KVM', 1, 'bi-display'],
    ['shelf',       'Shelf',        1, 'bi-layout-text-window'],
    ['blank',       'Blank',        1, 'bi-dash-square'],
];

$uploadsOk = Uploads::writable();

$state = [
    'rack'    => $rack ? ['id' => (int)$rack['id'], 'name' => $rack['name'],
                          'u_height' => (int)$rack['u_height'], 'site' => $rack['site_name']] : null,
    'face'    => $face,
    'items'   => array_map(static function ($it) {
        return [
            'id'         => (int)$it['id'],
            'name'       => $it['name'],
            'kind'       => $it['kind'],
            'u_position' => (int)$it['u_position'],
            'u_size'     => (int)$it['u_size'],
            'face'       => $it['face'],
            'color'      => $it['color'],
            'address'    => $it['address'],
            'subnet_id'  => $it['subnet_id'] !== null ? (int)$it['subnet_id'] : null,
            'ip_id'      => $it['ip_id'] !== null ? (int)$it['ip_id'] : null,
            'type_label' => trim((string)$it['type_label']) ?: null,
            'image'      => $it['display_image'] ?: null,
            'state'      => $it['state'],
            'notes'      => $it['description'],
        ];
    }, $items),
    'canManage' => $canManage,
    'csrf'      => Auth::csrfToken(),
    'kinds'     => $kinds,
];
$jsonFlags = JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP;
?>
<?php if (!$uploadsOk): ?>
<div class="alert alert-warning">
  <strong>Uploads directory is not writable.</strong> Faceplate photo overrides can't be saved until
  <code>public/uploads</code> exists and is writable by the web server
  (linuxserver images: <code>mkdir -p public/uploads &amp;&amp; chown -R abc:abc public/uploads</code>).
</div>
<?php endif; ?>

<div class="row g-3 rk-page">
  <!-- Rack list -->
  <div class="col-xl-3 col-lg-4">
    <div class="card mb-3">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span><i class="bi bi-grid-3x3"></i> Racks</span>
        <a class="btn btn-sm btn-outline-secondary" href="/?page=rack3d" title="3D server room"><i class="bi bi-box"></i> 3D</a>
      </div>
      <ul class="list-group list-group-flush">
        <?php foreach ($racks as $r): $pct = (int)$r['u_height'] ? round(100 * (int)$r['used_u'] / (int)$r['u_height']) : 0; ?>
          <li class="list-group-item d-flex justify-content-between align-items-center"
              style="<?= (int)$r['id'] === $selectedId ? 'background:rgba(139,92,246,.15)' : 'background:transparent' ?>">
            <a href="/?page=racks&id=<?= (int)$r['id'] ?>" class="text-decoration-none flex-grow-1">
              <strong><?= e($r['name']) ?></strong>
              <div class="small text-secondary">
                <?= e($r['site_name'] ?? '—') ?> · <?= (int)$r['u_height'] ?>U · <?= (int)$r['used_u'] ?>U used (<?= $pct ?>%)
              </div>
              <div class="progress mt-1" style="height:4px;background:var(--dv-surface-2)">
                <div class="progress-bar" style="width:<?= min(100,$pct) ?>%;background:var(--dv-accent)"></div>
              </div>
            </a>
            <?php if ($canManage): ?>
            <form method="post" class="m-0 ms-2" data-confirm="Delete rack <?= e($r['name']) ?>? Mounted items are removed (IP records are kept).">
              <?= Auth::csrfField() ?>
              <input type="hidden" name="action" value="rack_delete">
              <input type="hidden" name="id" value="<?= (int)$r['id'] ?>">
              <button class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button>
            </form>
            <?php endif; ?>
          </li>
        <?php endforeach; ?>
        <?php if (!$racks): ?>
          <li class="list-group-item text-secondary" style="background:transparent">No racks yet.</li>
        <?php endif; ?>
      </ul>
    </div>

    <?php if ($canManage): ?>
    <div class="card">
      <div class="card-header"><i class="bi bi-plus-square"></i> New rack</div>
      <div class="card-body">
        <form method="post" class="row g-2">
          <?= Auth::csrfField() ?>
          <input type="hidden" name="action" value="rack_create">
          <div class="col-12">
            <label class="form-label">Name</label>
            <input name="name" class="form-control" required placeholder="RACK-A1">
          </div>
          <div class="col-12">
            <label class="form-label">Site</label>
            <select name="site_id" class="form-select" required>
              <option value="">—</option>
              <?php foreach ($sites as $s): ?>
                <option value="<?= (int)$s['id'] ?>"><?= e($s['name']) ?></option>
              <?php endforeach; ?>
            </select>
          </div>
          <div class="col-6">
            <label class="form-label">Height (U)</label>
            <input name="u_height" type="number" min="1" max="60" value="42" class="form-control">
          </div>
          <div class="col-12">
            <label class="form-label">Description</label>
            <input name="description" class="form-control">
          </div>
          <div class="col-12 d-grid">
            <button class="btn btn-primary"><i class="bi bi-plus-lg"></i> Create rack</button>
          </div>
        </form>
      </div>
    </div>
    <?php endif; ?>
  </div>

  <!-- Elevation -->
  <div class="col-xl-5 col-lg-8">
    <?php if (!$rack): ?>
      <div class="card"><div class="card-body text-center text-secondary py-5">
        Create a rack to start designing your layout.
      </div></div>
    <?php else: ?>
    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
        <span>
          <i class="bi bi-hdd-stack"></i> <?= e($rack['name']) ?>
          <small class="text-secondary"><?= e($rack['site_name'] ?? '') ?> · <?= (int)$rack['u_height'] ?>U</small>
        </span>
        <div class="d-flex gap-2 align-items-center">
          <div class="btn-group btn-group-sm" role="group" aria-label="Rack face">
            <button type="button" class="btn btn-outline-secondary active" data-face="front">Front</button>
            <button type="button" class="btn btn-outline-secondary" data-face="rear">Rear</button>
          </div>
          <div class="btn-group btn-group-sm">
            <button type="button" class="btn btn-outline-secondary dropdown-toggle" data-bs-toggle="dropdown" title="Export">
              <i class="bi bi-download"></i>
            </button>
            <ul class="dropdown-menu dropdown-menu-end">
              <li><button class="dropdown-item" type="button" id="rkExportPng"><i class="bi bi-filetype-png me-2"></i>Download PNG</button></li>
              <li><button class="dropdown-item" type="button" id="rkExportSvg"><i class="bi bi-filetype-svg me-2"></i>Download SVG</button></li>
            </ul>
          </div>
          <?php if ($canManage): ?>
          <button class="btn btn-sm btn-outline-secondary" data-bs-toggle="collapse" data-bs-target="#editrack" title="Rack settings">
            <i class="bi bi-sliders"></i>
          </button>
          <?php endif; ?>
        </div>
      </div>

      <?php if ($canManage): ?>
      <div class="collapse" id="editrack">
        <div class="p-3 dv-nested border-bottom">
          <form method="post" class="row g-2">
            <?= Auth::csrfField() ?>
            <input type="hidden" name="action" value="rack_update">
            <input type="hidden" name="id" value="<?= $selectedId ?>">
            <div class="col-md-4">
              <label class="form-label">Name</label>
              <input name="name" class="form-control" required value="<?= e($rack['name']) ?>">
            </div>
            <div class="col-md-4">
              <label class="form-label">Site</label>
              <select name="site_id" class="form-select" required>
                <?php foreach ($sites as $s): ?>
                  <option value="<?= (int)$s['id'] ?>" <?= (int)$rack['site_id'] === (int)$s['id'] ? 'selected' : '' ?>><?= e($s['name']) ?></option>
                <?php endforeach; ?>
              </select>
            </div>
            <div class="col-md-4">
              <label class="form-label">Height (U)</label>
              <input name="u_height" type="number" min="1" max="60" class="form-control" required value="<?= (int)$rack['u_height'] ?>">
            </div>
            <div class="col-md-9">
              <label class="form-label">Description</label>
              <input name="description" class="form-control" value="<?= e($rack['description'] ?? '') ?>">
            </div>
            <div class="col-md-3 d-flex align-items-end">
              <button class="btn btn-primary w-100"><i class="bi bi-check-lg"></i> Save</button>
            </div>
          </form>
        </div>
      </div>
      <?php endif; ?>

      <div class="card-body">
        <div class="rk-stage">
          <div class="rk-rack" id="rkRack" style="--rk-row:30px" data-u="<?= (int)$rack['u_height'] ?>">
            <div class="rk-rail" aria-hidden="true">
              <?php for ($u = (int)$rack['u_height']; $u >= 1; $u--): ?>
                <div class="rk-rail-u"><?= $u ?></div>
              <?php endfor; ?>
            </div>
            <div class="rk-frame" id="rkFrame">
              <div class="rk-slots" aria-hidden="true">
                <?php for ($u = (int)$rack['u_height']; $u >= 1; $u--): ?>
                  <div class="rk-slot"></div>
                <?php endfor; ?>
              </div>
              <div class="rk-items" id="rkItems"></div>
              <div class="rk-preview" id="rkPreview" hidden></div>
            </div>
            <div class="rk-rail" aria-hidden="true">
              <?php for ($u = (int)$rack['u_height']; $u >= 1; $u--): ?>
                <div class="rk-rail-u"><?= $u ?></div>
              <?php endfor; ?>
            </div>
          </div>
          <?php if ($canManage): ?>
          <p class="rk-hint text-secondary small mt-2 mb-0">
            <i class="bi bi-arrows-move"></i> Drag from the library to mount · drag a unit to move · drag its edge to resize · click to edit
          </p>
          <?php endif; ?>
        </div>
      </div>
    </div>
    <?php endif; ?>
  </div>

  <!-- Library + inspector -->
  <?php if ($rack): ?>
  <div class="col-xl-4 col-lg-12">
    <?php if ($canManage): ?>
    <div class="card mb-3 rk-inspector" id="rkInspector" hidden>
      <div class="card-header d-flex justify-content-between align-items-center">
        <span><i class="bi bi-pencil-square"></i> <span id="rkInspTitle">Edit unit</span></span>
        <button type="button" class="btn-close" id="rkInspClose" aria-label="Close"></button>
      </div>
      <div class="card-body">
        <div class="row g-2">
          <div class="col-12">
            <label class="form-label">Label</label>
            <input class="form-control" id="rkiName" placeholder="24-port patch panel">
          </div>
          <div class="col-6">
            <label class="form-label">Type</label>
            <select class="form-select" id="rkiKind">
              <?php foreach ($kinds as $k => $label): ?>
                <option value="<?= e($k) ?>"><?= e($label) ?></option>
              <?php endforeach; ?>
            </select>
          </div>
          <div class="col-6">
            <label class="form-label">Accent</label>
            <input type="color" class="form-control form-control-color w-100" id="rkiColor" value="#8b5cf6" title="Accent colour">
          </div>
          <div class="col-12">
            <label class="form-label">Linked IP record <span class="text-secondary">(optional)</span></label>
            <select class="form-select" id="rkiIp">
              <option value="">— none —</option>
              <?php foreach ($availableIps as $a): ?>
                <option value="<?= (int)$a['id'] ?>">
                  <?= e($a['address']) ?><?= $a['hostname'] ? ' · ' . e($a['hostname']) : '' ?> (<?= e($a['cidr']) ?>)
                </option>
              <?php endforeach; ?>
            </select>
          </div>
          <div class="col-12">
            <label class="form-label">Notes</label>
            <input class="form-control" id="rkiNotes">
          </div>
          <div class="col-12 d-flex gap-2">
            <button class="btn btn-primary flex-grow-1" id="rkiSave"><i class="bi bi-check-lg"></i> Save</button>
            <button class="btn btn-outline-danger" id="rkiDelete" title="Remove from rack"><i class="bi bi-box-arrow-up"></i></button>
          </div>
        </div>

        <hr class="my-3">
        <form method="post" enctype="multipart/form-data" id="rkPhotoForm" class="row g-2">
          <?= Auth::csrfField() ?>
          <input type="hidden" name="action" value="rack_item_save">
          <input type="hidden" name="rack_id" value="<?= $selectedId ?>">
          <input type="hidden" name="item_id" id="rkpItemId">
          <input type="hidden" name="name" id="rkpName">
          <input type="hidden" name="kind" id="rkpKind">
          <input type="hidden" name="ip_id" id="rkpIp">
          <input type="hidden" name="u_position" id="rkpPos">
          <input type="hidden" name="u_size" id="rkpSize">
          <input type="hidden" name="face" id="rkpFace">
          <input type="hidden" name="color" id="rkpColor">
          <input type="hidden" name="description" id="rkpNotes">
          <div class="col-12">
            <label class="form-label small">Faceplate photo override</label>
            <input type="file" name="photo" class="form-control form-control-sm"
                   accept=".png,.jpg,.jpeg,.svg,.webp,image/png,image/jpeg,image/svg+xml,image/webp" <?= $uploadsOk ? '' : 'disabled' ?>>
            <div class="form-text">Overrides the model image for this one unit. Saving reloads the page.</div>
          </div>
          <div class="col-12 d-grid">
            <button class="btn btn-sm btn-outline-secondary"><i class="bi bi-image"></i> Upload photo</button>
          </div>
        </form>
      </div>
    </div>

    <div class="card mb-3">
      <div class="card-header"><i class="bi bi-collection"></i> Library <span class="text-secondary small">— drag onto the rack</span></div>
      <div class="card-body">
        <input class="form-control form-control-sm mb-2" id="rkSearch" placeholder="Filter devices, IPs…" autocomplete="off">

        <div class="rk-palette-group">
          <div class="rk-palette-head">Generic gear</div>
          <div class="rk-palette rk-palette-blocks">
            <?php foreach ($blocks as [$k, $label, $u, $icon]): ?>
              <div class="rk-chip"
                   data-src="block" data-kind="<?= e($k) ?>" data-size="<?= (int)$u ?>"
                   data-name="<?= e($label) ?>" data-search="<?= e(strtolower($label . ' ' . $k)) ?>">
                <i class="bi <?= e($icon) ?>"></i>
                <span class="rk-chip-name"><?= e($label) ?></span>
                <span class="rk-chip-u"><?= (int)$u ?>U</span>
              </div>
            <?php endforeach; ?>
          </div>
        </div>

        <?php if ($deviceTypes): ?>
        <div class="rk-palette-group">
          <div class="rk-palette-head">Device models <span class="text-secondary">(<?= count($deviceTypes) ?>)</span></div>
          <div class="rk-palette rk-palette-scroll">
            <?php foreach ($deviceTypes as $dt): $lbl = trim(($dt['vendor'] ?? '') . ' ' . $dt['model']); ?>
              <div class="rk-chip rk-chip-model"
                   data-src="model" data-dtid="<?= (int)$dt['id'] ?>" data-kind="device"
                   data-size="<?= (int)$dt['u_height'] ?>" data-name="<?= e($lbl) ?>"
                   data-image="<?= e($dt['image_path'] ?? '') ?>"
                   data-search="<?= e(strtolower($lbl)) ?>">
                <?php if ($dt['image_path']): ?>
                  <img src="/<?= e($dt['image_path']) ?>" alt="" class="rk-chip-thumb" loading="lazy">
                <?php else: ?>
                  <span class="rk-chip-thumb rk-chip-thumb-blank"><i class="bi bi-hdd"></i></span>
                <?php endif; ?>
                <span class="rk-chip-name" title="<?= e($lbl) ?>"><?= e($lbl) ?></span>
                <span class="rk-chip-u"><?= (int)$dt['u_height'] ?>U</span>
              </div>
            <?php endforeach; ?>
          </div>
        </div>
        <?php endif; ?>

        <?php if ($availableIps): ?>
        <div class="rk-palette-group">
          <div class="rk-palette-head">IP records <span class="text-secondary">(<?= count($availableIps) ?>)</span></div>
          <div class="rk-palette rk-palette-scroll">
            <?php foreach ($availableIps as $a): $lbl = $a['hostname'] ?: $a['address']; ?>
              <div class="rk-chip rk-chip-model"
                   data-src="ip" data-ipid="<?= (int)$a['id'] ?>" data-kind="device"
                   data-size="<?= (int)$a['u_height'] ?>" data-name="<?= e($lbl) ?>"
                   data-image="<?= e($a['image_path'] ?? '') ?>"
                   data-search="<?= e(strtolower($lbl . ' ' . $a['address'])) ?>">
                <?php if ($a['image_path']): ?>
                  <img src="/<?= e($a['image_path']) ?>" alt="" class="rk-chip-thumb" loading="lazy">
                <?php else: ?>
                  <span class="rk-chip-thumb rk-chip-thumb-blank"><i class="bi bi-ethernet"></i></span>
                <?php endif; ?>
                <span class="rk-chip-name" title="<?= e($lbl) ?>"><?= e($lbl) ?></span>
                <span class="rk-chip-u"><?= e($a['address']) ?></span>
              </div>
            <?php endforeach; ?>
          </div>
        </div>
        <?php endif; ?>
      </div>
    </div>
    <?php endif; ?>

    <div class="card">
      <div class="card-header d-flex justify-content-between">
        <span><i class="bi bi-list-ul"></i> Mounted</span>
        <span class="text-secondary small" id="rkCount"></span>
      </div>
      <div class="table-responsive">
        <table class="table table-sm table-hover mb-0">
          <thead><tr><th>U</th><th>Face</th><th>Item</th><th>Status</th></tr></thead>
          <tbody id="rkMounted"></tbody>
        </table>
      </div>
    </div>
  </div>
  <?php endif; ?>
</div>

<div class="rk-toast-wrap" id="rkToasts"></div>

<?php if ($rack): ?>
<script>
window.RK_STATE = <?= json_encode($state, $jsonFlags) ?>;
</script>
<script>
(function () {
  'use strict';
  var S = window.RK_STATE;
  if (!S || !S.rack) return;

  var H = S.rack.u_height;
  var ROW = 30;                         // px per U, matches --rk-row
  var face = S.face || 'front';
  var canManage = !!S.canManage;
  var items = S.items.slice();
  var selectedId = null;

  var frame   = document.getElementById('rkFrame');
  var itemsEl = document.getElementById('rkItems');
  var preview = document.getElementById('rkPreview');
  var mounted = document.getElementById('rkMounted');
  var countEl = document.getElementById('rkCount');
  var inspector = document.getElementById('rkInspector');

  var KINDS = S.kinds || {};
  var KIND_COLOR = {
    server: '#8b5cf6', switch: '#3b82f6', router: '#06b6d4',
    patch_panel: '#22c55e', power: '#f97316', screen: '#eab308',
    shelf: '#64748b', blank: '#3f3f52', device: '#8b5cf6', other: '#64748b'
  };

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function topOf(it) { return (H - (it.u_position + it.u_size - 1)) * ROW; }
  function kindColor(it) { return it.color || KIND_COLOR[it.kind] || KIND_COLOR.device; }

  function uAtY(y) {
    var row = Math.floor(y / ROW);
    if (row < 0) row = 0; if (row > H - 1) row = H - 1;
    return H - row;
  }

  function collides(pos, size, f, excludeId) {
    if (pos < 1 || (pos + size - 1) > H) return true;
    for (var i = 0; i < items.length; i++) {
      var it = items[i];
      if (it.id === excludeId || it.face !== f) continue;
      var a1 = pos, a2 = pos + size - 1, b1 = it.u_position, b2 = it.u_position + it.u_size - 1;
      if (a1 <= b2 && b1 <= a2) return true;
    }
    return false;
  }

  function toast(msg, type) {
    var wrap = document.getElementById('rkToasts');
    var t = document.createElement('div');
    t.className = 'rk-toast rk-toast-' + (type || 'info');
    t.textContent = msg;
    wrap.appendChild(t);
    requestAnimationFrame(function () { t.classList.add('show'); });
    setTimeout(function () { t.classList.remove('show'); setTimeout(function () { t.remove(); }, 250); }, 3200);
  }

  function render() {
    itemsEl.innerHTML = '';
    var shown = items.filter(function (it) { return it.face === face; });
    shown.forEach(function (it) {
      var el = document.createElement('div');
      el.className = 'rk-item kind-' + it.kind + (it.image ? ' has-photo' : '') + (it.id === selectedId ? ' selected' : '');
      el.style.top = topOf(it) + 'px';
      el.style.height = (it.u_size * ROW) + 'px';
      el.style.setProperty('--rk-accent', kindColor(it));
      el.dataset.id = it.id;

      var meta = [];
      if (it.type_label) meta.push(it.type_label);
      if (it.address) meta.push(it.address);
      var top = it.u_position + it.u_size - 1;
      var uRange = it.u_size > 1 ? ('U' + it.u_position + '–U' + top) : ('U' + it.u_position);

      var inner = '';
      if (it.image) inner += '<img class="rk-face" src="/' + esc(it.image) + '" alt="" crossorigin="anonymous">';
      else inner += '<span class="rk-face rk-face-blank"></span>';
      inner += '<span class="rk-item-label">'
             + (it.state ? '<span class="rk-dot rk-dot-' + esc(it.state) + '"></span>' : '')
             + '<span class="rk-item-text"><strong>' + esc(it.name) + '</strong>'
             + '<small>' + esc(meta.join(' · ') || (KINDS[it.kind] || it.kind)) + ' · ' + uRange + '</small></span>'
             + '</span>';
      if (canManage) {
        inner += '<span class="rk-grip rk-grip-top" data-grip="top"></span>'
               + '<span class="rk-grip rk-grip-bottom" data-grip="bottom"></span>'
               + '<button class="rk-eject" title="Remove">&times;</button>';
      }
      el.innerHTML = inner;
      itemsEl.appendChild(el);
    });
    renderMounted();
  }

  function renderMounted() {
    if (!mounted) return;
    var sorted = items.slice().sort(function (a, b) { return b.u_position - a.u_position; });
    mounted.innerHTML = sorted.map(function (it) {
      var top = it.u_position + it.u_size - 1;
      var u = it.u_size > 1 ? (it.u_position + '–' + top) : ('' + it.u_position);
      var st = it.state
        ? '<span class="badge text-bg-' + (it.state === 'online' ? 'success' : it.state === 'offline' ? 'danger' : 'secondary') + '">' + esc(it.state) + '</span>'
        : '<span class="text-secondary small">—</span>';
      var name = it.subnet_id
        ? '<a href="/?page=subnet_view&id=' + it.subnet_id + '">' + esc(it.name) + '</a>'
        : esc(it.name);
      return '<tr data-goto="' + it.id + '" data-face="' + esc(it.face) + '" style="cursor:pointer">'
        + '<td><code>' + u + '</code></td>'
        + '<td class="small text-secondary">' + esc(it.face) + '</td>'
        + '<td>' + name + '<div class="small text-secondary">' + esc(KINDS[it.kind] || it.kind) + (it.address ? ' · ' + esc(it.address) : '') + '</div></td>'
        + '<td>' + st + '</td></tr>';
    }).join('') || '<tr><td colspan="4" class="text-center text-secondary py-4">Nothing mounted.</td></tr>';
    if (countEl) countEl.textContent = items.length + ' item' + (items.length === 1 ? '' : 's');
  }

  function api(op, data) {
    var body = new URLSearchParams();
    body.set('action', 'rack_api');
    body.set('_csrf', S.csrf);
    body.set('op', op);
    body.set('rack_id', S.rack.id);
    Object.keys(data || {}).forEach(function (k) {
      if (data[k] !== null && data[k] !== undefined) body.set(k, data[k]);
    });
    return fetch('/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'fetch' },
      body: body.toString()
    }).then(function (r) { return r.json().catch(function () { return { ok: false, error: 'Bad server response.' }; }); });
  }
  function upsert(it) {
    var i = items.findIndex(function (x) { return x.id === it.id; });
    if (i >= 0) items[i] = it; else items.push(it);
  }

  function select(id) {
    selectedId = id;
    render();
    if (!canManage || !inspector) return;
    var it = items.find(function (x) { return x.id === id; });
    if (!it) { inspector.hidden = true; return; }
    inspector.hidden = false;
    document.getElementById('rkInspTitle').textContent = 'U' + it.u_position + ' · ' + (it.name || 'unit');
    document.getElementById('rkiName').value = it.name || '';
    document.getElementById('rkiKind').value = it.kind || 'device';
    document.getElementById('rkiColor').value = it.color || KIND_COLOR[it.kind] || '#8b5cf6';
    document.getElementById('rkiIp').value = it.ip_id || '';
    document.getElementById('rkiNotes').value = it.notes || '';
    inspector.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
  function deselect() { selectedId = null; if (inspector) inspector.hidden = true; render(); }

  if (canManage && inspector) {
    document.getElementById('rkInspClose').addEventListener('click', deselect);
    document.getElementById('rkiSave').addEventListener('click', function () {
      var it = items.find(function (x) { return x.id === selectedId; });
      if (!it) return;
      api('update', {
        id: it.id, name: document.getElementById('rkiName').value,
        kind: document.getElementById('rkiKind').value,
        color: document.getElementById('rkiColor').value,
        ip_id: document.getElementById('rkiIp').value || '',
        description: document.getElementById('rkiNotes').value
      }).then(function (res) {
        if (!res.ok) { toast(res.error || 'Save failed.', 'error'); return; }
        upsert(res.item); select(res.item.id); toast('Saved.', 'ok');
      });
    });
    document.getElementById('rkiDelete').addEventListener('click', function () {
      var it = items.find(function (x) { return x.id === selectedId; });
      if (!it || !window.confirm('Remove "' + it.name + '" from the rack?')) return;
      removeItem(it.id);
    });
    document.getElementById('rkPhotoForm').addEventListener('submit', function () {
      var it = items.find(function (x) { return x.id === selectedId; });
      if (!it) return;
      document.getElementById('rkpItemId').value = it.id;
      document.getElementById('rkpName').value = it.name || '';
      document.getElementById('rkpKind').value = it.kind || 'device';
      document.getElementById('rkpIp').value = it.ip_id || '';
      document.getElementById('rkpPos').value = it.u_position;
      document.getElementById('rkpSize').value = it.u_size;
      document.getElementById('rkpFace').value = it.face;
      document.getElementById('rkpColor').value = it.color || '';
      document.getElementById('rkpNotes').value = it.notes || '';
    });
  }

  function removeItem(id) {
    api('delete', { id: id }).then(function (res) {
      if (!res.ok) { toast(res.error || 'Could not remove.', 'error'); return; }
      items = items.filter(function (x) { return x.id !== id; });
      if (selectedId === id) deselect(); else render();
      toast('Removed.', 'ok');
    });
  }

  function showPreview(pos, size, invalid) {
    preview.hidden = false;
    preview.style.top = ((H - (pos + size - 1)) * ROW) + 'px';
    preview.style.height = (size * ROW) + 'px';
    preview.classList.toggle('invalid', !!invalid);
  }
  function hidePreview() { preview.hidden = true; }

  var drag = null;
  frame.addEventListener('pointerdown', function (ev) {
    if (!canManage) return;
    var itemEl = ev.target.closest('.rk-item');
    if (!itemEl) return;
    var id = parseInt(itemEl.dataset.id, 10);
    var it = items.find(function (x) { return x.id === id; });
    if (!it) return;
    if (ev.target.classList.contains('rk-eject')) { removeItem(id); return; }

    var grip = ev.target.dataset.grip;
    var rect = frame.getBoundingClientRect();
    var startU = uAtY(ev.clientY - rect.top);
    drag = {
      it: it, mode: grip ? 'resize' : 'move', grip: grip,
      rect: rect, startU: startU,
      offset: (it.u_position + it.u_size - 1) - startU,
      origPos: it.u_position, origSize: it.u_size,
      moved: false, pos: it.u_position, size: it.u_size
    };
    itemEl.setPointerCapture(ev.pointerId);
    itemEl.classList.add('dragging');
    ev.preventDefault();
  });

  frame.addEventListener('pointermove', function (ev) {
    if (!drag) return;
    var y = ev.clientY - drag.rect.top;
    var u = uAtY(y);
    var pos = drag.origPos, size = drag.origSize;
    if (drag.mode === 'move') {
      var topU = u + drag.offset;
      pos = topU - drag.origSize + 1;
      if (pos < 1) pos = 1;
      if (pos + size - 1 > H) pos = H - size + 1;
    } else if (drag.grip === 'top') {
      var topU2 = Math.max(drag.origPos, u);
      size = topU2 - drag.origPos + 1;
      pos = drag.origPos;
    } else {
      var botU = Math.min(drag.origPos + drag.origSize - 1, u);
      pos = botU;
      size = (drag.origPos + drag.origSize - 1) - botU + 1;
    }
    if (size < 1) size = 1;
    if (size > 20) size = 20;
    drag.pos = pos; drag.size = size;
    drag.moved = drag.moved || pos !== drag.origPos || size !== drag.origSize;
    showPreview(pos, size, collides(pos, size, drag.it.face, drag.it.id));
  });

  function endDrag() {
    if (!drag) return;
    var d = drag; drag = null;
    hidePreview();
    var el = itemsEl.querySelector('.rk-item.dragging');
    if (el) el.classList.remove('dragging');
    if (!d.moved) { select(d.it.id); return; }
    if (collides(d.pos, d.size, d.it.face, d.it.id)) {
      toast('That spot is occupied.', 'error'); render(); return;
    }
    var op = d.mode === 'resize' ? 'resize' : 'move';
    d.it.u_position = d.pos; d.it.u_size = d.size; render();
    api(op, { id: d.it.id, u_position: d.pos, u_size: d.size, face: d.it.face })
      .then(function (res) {
        if (!res.ok) {
          d.it.u_position = d.origPos; d.it.u_size = d.origSize;
          toast(res.error || 'Move rejected.', 'error'); render();
        } else { upsert(res.item); render(); }
      });
  }
  frame.addEventListener('pointerup', endDrag);
  frame.addEventListener('pointercancel', endDrag);

  frame.addEventListener('click', function (ev) {
    if (ev.target === frame || ev.target.classList.contains('rk-slot') || ev.target.classList.contains('rk-slots')) deselect();
  });

  var palDrag = null, ghost = null;
  function startPaletteDrag(chip, ev) {
    palDrag = {
      src: chip.dataset.src, kind: chip.dataset.kind || 'device',
      size: Math.max(1, parseInt(chip.dataset.size, 10) || 1),
      name: chip.dataset.name || '', dtid: chip.dataset.dtid || '',
      ipid: chip.dataset.ipid || '', image: chip.dataset.image || ''
    };
    ghost = document.createElement('div');
    ghost.className = 'rk-ghost';
    ghost.textContent = palDrag.name + ' · ' + palDrag.size + 'U';
    document.body.appendChild(ghost);
    moveGhost(ev);
    chip.setPointerCapture(ev.pointerId);
    ev.preventDefault();
  }
  function moveGhost(ev) {
    if (!ghost) return;
    ghost.style.left = (ev.clientX + 12) + 'px';
    ghost.style.top = (ev.clientY + 12) + 'px';
    var rect = frame.getBoundingClientRect();
    var inside = ev.clientX >= rect.left && ev.clientX <= rect.right && ev.clientY >= rect.top && ev.clientY <= rect.bottom;
    if (inside) {
      var topU = uAtY(ev.clientY - rect.top);
      var pos = topU - palDrag.size + 1;
      if (pos < 1) pos = 1;
      if (pos + palDrag.size - 1 > H) pos = H - palDrag.size + 1;
      palDrag.pos = pos;
      showPreview(pos, palDrag.size, collides(pos, palDrag.size, face, 0));
    } else { hidePreview(); palDrag.pos = null; }
  }
  function endPaletteDrag() {
    if (!palDrag) return;
    var d = palDrag; palDrag = null;
    if (ghost) { ghost.remove(); ghost = null; }
    hidePreview();
    if (d.pos == null) return;
    if (collides(d.pos, d.size, face, 0)) { toast('That spot is occupied.', 'error'); return; }
    api('create', {
      u_position: d.pos, u_size: d.size, face: face, kind: d.kind,
      name: d.name, device_type_id: d.dtid || '', ip_id: d.ipid || ''
    }).then(function (res) {
      if (!res.ok) { toast(res.error || 'Could not mount.', 'error'); return; }
      upsert(res.item); select(res.item.id);
      toast(res.item.name + ' mounted at U' + res.item.u_position + '.', 'ok');
    });
  }
  if (canManage) {
    document.querySelectorAll('.rk-chip').forEach(function (chip) {
      chip.addEventListener('pointerdown', function (ev) { startPaletteDrag(chip, ev); });
      chip.addEventListener('pointermove', function (ev) { if (palDrag) moveGhost(ev); });
      chip.addEventListener('pointerup', endPaletteDrag);
      chip.addEventListener('pointercancel', endPaletteDrag);
    });
  }

  var search = document.getElementById('rkSearch');
  if (search) {
    search.addEventListener('input', function () {
      var q = search.value.trim().toLowerCase();
      document.querySelectorAll('.rk-chip').forEach(function (chip) {
        var hay = chip.dataset.search || '';
        chip.style.display = (!q || hay.indexOf(q) >= 0) ? '' : 'none';
      });
    });
  }

  if (mounted) {
    mounted.addEventListener('click', function (ev) {
      var tr = ev.target.closest('tr[data-goto]');
      if (!tr || ev.target.closest('a')) return;
      var id = parseInt(tr.dataset.goto, 10);
      if (tr.dataset.face !== face) setFace(tr.dataset.face);
      select(id);
    });
  }

  function setFace(f) {
    face = f;
    document.querySelectorAll('.btn-group [data-face]').forEach(function (b) {
      b.classList.toggle('active', b.dataset.face === f);
    });
    deselect();
  }
  document.querySelectorAll('.btn-group [data-face]').forEach(function (btn) {
    btn.addEventListener('click', function () { setFace(btn.dataset.face); });
  });

  function buildSvg(cb) {
    var W = 360, pad = 34, rowH = 26;
    var innerW = W - pad * 2, totalH = H * rowH;
    var shown = items.filter(function (it) { return it.face === face; });
    var withImg = shown.filter(function (it) { return it.image; });
    var loaded = 0, imgData = {};
    function done() {
      var svg = '<svg xmlns="http://www.w3.org/2000/svg" width="' + (W * 2) + '" height="' + ((totalH + pad * 2) * 2) + '" viewBox="0 0 ' + W + ' ' + (totalH + pad * 2) + '">';
      svg += '<defs><linearGradient id="shade" x1="0" x2="1"><stop offset="0" stop-color="#06060b" stop-opacity="0.9"/><stop offset="0.5" stop-color="#06060b" stop-opacity="0.35"/><stop offset="1" stop-color="#06060b" stop-opacity="0.05"/></linearGradient></defs>';
      svg += '<rect width="100%" height="100%" fill="#0d0f14"/>';
      svg += '<text x="' + (W / 2) + '" y="20" fill="#e5e7eb" font-family="system-ui,sans-serif" font-size="13" font-weight="700" text-anchor="middle">' + esc(S.rack.name) + ' — ' + face + ' (' + H + 'U)</text>';
      var top = pad;
      for (var u = H; u >= 1; u--) {
        var y = top + (H - u) * rowH;
        svg += '<line x1="' + pad + '" y1="' + y + '" x2="' + (W - pad) + '" y2="' + y + '" stroke="#1c2030"/>';
        svg += '<text x="' + (pad - 6) + '" y="' + (y + rowH / 2 + 3) + '" fill="#6b7280" font-family="monospace" font-size="8" text-anchor="end">' + u + '</text>';
        svg += '<text x="' + (W - pad + 6) + '" y="' + (y + rowH / 2 + 3) + '" fill="#6b7280" font-family="monospace" font-size="8">' + u + '</text>';
      }
      svg += '<rect x="' + pad + '" y="' + top + '" width="' + innerW + '" height="' + totalH + '" fill="none" stroke="#2f2f42"/>';
      shown.forEach(function (it) {
        var y = top + (H - (it.u_position + it.u_size - 1)) * rowH;
        var h = it.u_size * rowH;
        var col = it.color || KIND_COLOR[it.kind] || KIND_COLOR.device;
        if (imgData[it.id]) {
          svg += '<image x="' + pad + '" y="' + y + '" width="' + innerW + '" height="' + h + '" preserveAspectRatio="xMidYMid slice" href="' + imgData[it.id] + '"/>';
          svg += '<rect x="' + pad + '" y="' + y + '" width="' + innerW + '" height="' + h + '" fill="url(#shade)"/>';
        } else {
          svg += '<rect x="' + pad + '" y="' + y + '" width="' + innerW + '" height="' + h + '" fill="' + col + '" fill-opacity="0.22"/>';
        }
        svg += '<rect x="' + pad + '" y="' + y + '" width="' + innerW + '" height="' + h + '" fill="none" stroke="' + col + '" stroke-opacity="0.8"/>';
        svg += '<text x="' + (pad + 8) + '" y="' + (y + h / 2 + 3) + '" fill="#f3f4f6" font-family="system-ui,sans-serif" font-size="9" font-weight="600">' + esc(it.name) + '</text>';
      });
      svg += '</svg>';
      cb(svg);
    }
    if (!withImg.length) return done();
    withImg.forEach(function (it) {
      fetch('/' + it.image).then(function (r) { return r.blob(); }).then(function (b) {
        return new Promise(function (res) {
          var fr = new FileReader();
          fr.onload = function () { imgData[it.id] = fr.result; res(); };
          fr.onerror = function () { res(); };
          fr.readAsDataURL(b);
        });
      }).catch(function () {}).then(function () { if (++loaded === withImg.length) done(); });
    });
  }
  function downloadBlob(blob, name) {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }
  var svgBtn = document.getElementById('rkExportSvg');
  var pngBtn = document.getElementById('rkExportPng');
  var slug = (S.rack.name || 'rack').replace(/[^a-z0-9]+/gi, '-').toLowerCase();
  if (svgBtn) svgBtn.addEventListener('click', function () {
    buildSvg(function (svg) { downloadBlob(new Blob([svg], { type: 'image/svg+xml' }), slug + '-' + face + '.svg'); });
  });
  if (pngBtn) pngBtn.addEventListener('click', function () {
    buildSvg(function (svg) {
      var img = new Image();
      var url = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' }));
      img.onload = function () {
        var c = document.createElement('canvas');
        c.width = img.width; c.height = img.height;
        var ctx = c.getContext('2d');
        ctx.fillStyle = '#0d0f14'; ctx.fillRect(0, 0, c.width, c.height);
        ctx.drawImage(img, 0, 0);
        URL.revokeObjectURL(url);
        c.toBlob(function (b) { if (b) downloadBlob(b, slug + '-' + face + '.png'); else toast('PNG export failed.', 'error'); });
      };
      img.onerror = function () { URL.revokeObjectURL(url); toast('PNG export failed.', 'error'); };
      img.src = url;
    });
  });

  render();
})();
</script>
<?php endif; ?>
