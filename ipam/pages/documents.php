<?php
use DarkVeda\{Auth, Database, Uploads};
use function DarkVeda\e;

$canManage = Auth::can('docs.manage');
$uploadsOk = Uploads::writable();

$cat    = in_array($_GET['cat'] ?? '', Uploads::CATEGORIES, true) ? $_GET['cat'] : '';
$search = trim((string)($_GET['q'] ?? ''));

$where  = [];
$args   = [];
if ($cat !== '') {
    $where[] = 'a.category = ?';
    $args[]  = $cat;
}
if ($search !== '') {
    $where[] = '(a.filename LIKE ? OR a.title LIKE ? OR a.notes LIKE ? OR i.address LIKE ? OR i.hostname LIKE ?)';
    $like = '%' . $search . '%';
    array_push($args, $like, $like, $like, $like, $like);
}
$sqlWhere = $where ? ' WHERE ' . implode(' AND ', $where) : '';

$docs = Database::q(
    'SELECT a.*, u.username,
            i.address, i.hostname, i.subnet_id,
            r.name AS rack_name, st.name AS site_name
     FROM attachments a
     LEFT JOIN users u ON u.id = a.uploaded_by
     LEFT JOIN ip_addresses i ON (a.entity_type = "ip_address" AND i.id = a.entity_id)
     LEFT JOIN racks r        ON (a.entity_type = "rack"       AND r.id = a.entity_id)
     LEFT JOIN sites st       ON (a.entity_type = "site"       AND st.id = a.entity_id)
     ' . $sqlWhere . '
     ORDER BY a.id DESC LIMIT 300',
    $args
);

$counts = [];
foreach (Database::q('SELECT category, COUNT(*) c, COALESCE(SUM(size_bytes),0) b FROM attachments GROUP BY category') as $r) {
    $counts[$r['category']] = ['c' => (int)$r['c'], 'b' => (int)$r['b']];
}
$totalCount = array_sum(array_column($counts, 'c'));
$totalBytes = array_sum(array_column($counts, 'b'));

$ips   = Database::q('SELECT i.id, i.address, i.hostname, s.cidr FROM ip_addresses i JOIN subnets s ON s.id = i.subnet_id ORDER BY i.address_bin LIMIT 500');
$racks = Database::q('SELECT id, name FROM racks ORDER BY name');
$sites = Database::q('SELECT id, name FROM sites ORDER BY name');

$catLabels = [
    'document' => 'Document', 'manual' => 'Manual', 'diagram' => 'Diagram',
    'photo' => 'Photo', 'license' => 'License', 'contract' => 'Contract',
];
$catIcons = [
    'document' => 'bi-file-earmark-text', 'manual' => 'bi-book', 'diagram' => 'bi-diagram-2',
    'photo' => 'bi-image', 'license' => 'bi-award', 'contract' => 'bi-file-earmark-ruled',
];
?>
<?php if (!$uploadsOk): ?>
<div class="alert alert-warning">
  <strong>Uploads directory is not writable.</strong> Create <code>public/uploads</code> and give the web server
  write access before attaching files (on linuxserver images: <code>chown -R abc:abc public/uploads</code>).
</div>
<?php endif; ?>

<div class="row g-3 mb-3">
  <div class="col-6 col-lg-3">
    <div class="card"><div class="dv-stat">
      <i class="bi bi-folder2-open"></i>
      <div><div class="dv-stat-value"><?= (int)$totalCount ?></div><div class="dv-stat-label">Documents</div></div>
    </div></div>
  </div>
  <div class="col-6 col-lg-3">
    <div class="card"><div class="dv-stat">
      <i class="bi bi-hdd"></i>
      <div><div class="dv-stat-value" style="font-size:1.3rem"><?= e(Uploads::human($totalBytes)) ?></div><div class="dv-stat-label">Total size</div></div>
    </div></div>
  </div>
  <div class="col-12 col-lg-6">
    <div class="card h-100"><div class="card-body py-2 d-flex flex-wrap gap-1 align-items-center">
      <a class="btn btn-sm <?= $cat === '' ? 'btn-primary' : 'btn-outline-secondary' ?>" href="/?page=documents">All</a>
      <?php foreach (Uploads::CATEGORIES as $c): ?>
        <a class="btn btn-sm <?= $cat === $c ? 'btn-primary' : 'btn-outline-secondary' ?>" href="/?page=documents&cat=<?= e($c) ?>">
          <i class="bi <?= e($catIcons[$c]) ?>"></i> <?= e($catLabels[$c]) ?>
          <span class="badge text-bg-secondary ms-1"><?= (int)($counts[$c]['c'] ?? 0) ?></span>
        </a>
      <?php endforeach; ?>
    </div></div>
  </div>
</div>

<?php if ($canManage): ?>
<div class="card mb-3">
  <div class="card-header"><i class="bi bi-cloud-upload"></i> Attach a document</div>
  <div class="card-body">
    <form method="post" enctype="multipart/form-data" class="row g-3">
      <?= Auth::csrfField() ?>
      <input type="hidden" name="action" value="doc_upload">
      <input type="hidden" name="back" value="/?page=documents<?= $cat ? '&cat=' . e($cat) : '' ?>">

      <div class="col-md-2">
        <label class="form-label">Attach to</label>
        <select name="entity_type" class="form-select" id="docEntityType">
          <option value="ip_address">Device (IP)</option>
          <option value="rack">Rack</option>
          <option value="site">Site</option>
        </select>
      </div>
      <div class="col-md-4">
        <label class="form-label">Target *</label>
        <select name="entity_id" class="form-select" id="docEntityId" required>
          <?php foreach ($ips as $i): ?>
            <option value="<?= (int)$i['id'] ?>" data-type="ip_address">
              <?= e($i['address']) ?><?= $i['hostname'] ? ' · ' . e($i['hostname']) : '' ?> (<?= e($i['cidr']) ?>)
            </option>
          <?php endforeach; ?>
          <?php foreach ($racks as $r): ?>
            <option value="<?= (int)$r['id'] ?>" data-type="rack" hidden><?= e($r['name']) ?></option>
          <?php endforeach; ?>
          <?php foreach ($sites as $s): ?>
            <option value="<?= (int)$s['id'] ?>" data-type="site" hidden><?= e($s['name']) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-md-2">
        <label class="form-label">Category</label>
        <select name="category" class="form-select">
          <?php foreach (Uploads::CATEGORIES as $c): ?>
            <option value="<?= e($c) ?>" <?= $cat === $c ? 'selected' : '' ?>><?= e($catLabels[$c]) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-md-4">
        <label class="form-label">Title</label>
        <input name="title" class="form-control" placeholder="e.g. RB5009 quick start guide">
      </div>

      <div class="col-md-5">
        <label class="form-label">File * <span class="text-secondary">(PDF, images, Office, ZIP — max 32 MB)</span></label>
        <input type="file" name="file" class="form-control" required <?= $uploadsOk ? '' : 'disabled' ?>>
      </div>
      <div class="col-md-5">
        <label class="form-label">Notes</label>
        <input name="notes" class="form-control">
      </div>
      <div class="col-md-2 d-flex align-items-end">
        <button class="btn btn-primary w-100" <?= $uploadsOk ? '' : 'disabled' ?>>
          <i class="bi bi-upload"></i> Upload
        </button>
      </div>
    </form>
  </div>
</div>
<?php endif; ?>

<div class="card">
  <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
    <span><i class="bi bi-files"></i> Documents</span>
    <form method="get" class="d-flex gap-2">
      <input type="hidden" name="page" value="documents">
      <?php if ($cat): ?><input type="hidden" name="cat" value="<?= e($cat) ?>"><?php endif; ?>
      <input name="q" class="form-control form-control-sm" style="width:230px"
             value="<?= e($search) ?>" placeholder="Search name, notes or device…">
      <button class="btn btn-sm btn-outline-secondary"><i class="bi bi-search"></i></button>
    </form>
  </div>
  <div class="table-responsive">
    <table class="table table-hover mb-0">
      <thead><tr>
        <th></th><th>Title / file</th><th>Category</th><th>Attached to</th>
        <th>Size</th><th>Uploaded</th><th class="text-end"></th>
      </tr></thead>
      <tbody>
      <?php foreach ($docs as $d): ?>
        <tr>
          <td class="text-secondary"><i class="bi <?= e(Uploads::icon($d['mime_type'])) ?>"></i></td>
          <td>
            <strong><?= e($d['title'] ?: $d['filename']) ?></strong>
            <?php if ($d['title']): ?><div class="small text-secondary"><?= e($d['filename']) ?></div><?php endif; ?>
            <?php if ($d['notes']): ?><div class="small text-secondary"><?= e($d['notes']) ?></div><?php endif; ?>
          </td>
          <td><span class="badge text-bg-secondary"><?= e($catLabels[$d['category']] ?? $d['category']) ?></span></td>
          <td>
            <?php if ($d['entity_type'] === 'ip_address' && $d['address']): ?>
              <a href="/?page=subnet_view&id=<?= (int)$d['subnet_id'] ?>">
                <code><?= e($d['address']) ?></code>
              </a>
              <?php if ($d['hostname']): ?><div class="small text-secondary"><?= e($d['hostname']) ?></div><?php endif; ?>
            <?php elseif ($d['entity_type'] === 'rack' && $d['rack_name']): ?>
              <a href="/?page=racks&id=<?= (int)$d['entity_id'] ?>"><i class="bi bi-hdd-stack"></i> <?= e($d['rack_name']) ?></a>
            <?php elseif ($d['entity_type'] === 'site' && $d['site_name']): ?>
              <a href="/?page=sites"><i class="bi bi-buildings"></i> <?= e($d['site_name']) ?></a>
            <?php else: ?>
              <span class="text-secondary small">— deleted <?= e($d['entity_type']) ?> —</span>
            <?php endif; ?>
          </td>
          <td class="small"><?= e(Uploads::human((int)$d['size_bytes'])) ?></td>
          <td class="small text-secondary">
            <?= e($d['created_at']) ?>
            <?php if ($d['username']): ?><div><?= e($d['username']) ?></div><?php endif; ?>
          </td>
          <td class="text-end text-nowrap">
            <a class="btn btn-sm btn-outline-primary" href="/?page=doc_download&id=<?= (int)$d['id'] ?>" title="Download">
              <i class="bi bi-download"></i>
            </a>
            <?php if ($canManage): ?>
            <form method="post" class="d-inline m-0" data-confirm="Delete &quot;<?= e($d['filename']) ?>&quot;? The file is removed from disk.">
              <?= Auth::csrfField() ?>
              <input type="hidden" name="action" value="doc_delete">
              <input type="hidden" name="id" value="<?= (int)$d['id'] ?>">
              <input type="hidden" name="back" value="/?page=documents<?= $cat ? '&cat=' . e($cat) : '' ?>">
              <button class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button>
            </form>
            <?php endif; ?>
          </td>
        </tr>
      <?php endforeach; ?>
      <?php if (!$docs): ?>
        <tr><td colspan="7" class="text-center text-secondary py-4">
          <?= $search !== '' || $cat !== '' ? 'No documents match this filter.' : 'No documents attached yet.' ?>
        </td></tr>
      <?php endif; ?>
      </tbody>
    </table>
  </div>
</div>

<script>
(function () {
  var type = document.getElementById('docEntityType');
  var sel  = document.getElementById('docEntityId');
  if (!type || !sel) return;
  function filter() {
    var want = type.value, first = null;
    Array.prototype.forEach.call(sel.options, function (o) {
      var match = o.getAttribute('data-type') === want;
      o.hidden = !match;
      o.disabled = !match;
      if (match && !first) first = o;
    });
    if (first) sel.value = first.value;
  }
  type.addEventListener('change', filter);
  filter();
})();
</script>
