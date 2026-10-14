<?php
use DarkVeda\Database;
use function DarkVeda\e;

$filterAction = $_GET['f_action'] ?? '';
$params = [];
$where  = '';
if ($filterAction !== '' && preg_match('/^\w+$/', $filterAction)) {
    $where  = 'WHERE a.action = ?';
    $params[] = $filterAction;
}

$logs = Database::q(
    "SELECT a.*, u.username FROM audit_logs a
     LEFT JOIN users u ON u.id = a.user_id
     $where
     ORDER BY a.id DESC LIMIT 200",
    $params
);
$actions = Database::q('SELECT DISTINCT action FROM audit_logs ORDER BY action');
?>
<form method="get" class="d-flex gap-2 mb-3">
  <input type="hidden" name="page" value="audit">
  <select name="f_action" class="form-select" style="max-width:220px">
    <option value="">All actions</option>
    <?php foreach ($actions as $a): ?>
      <option value="<?= e($a['action']) ?>" <?= $filterAction === $a['action'] ? 'selected' : '' ?>>
        <?= e($a['action']) ?>
      </option>
    <?php endforeach; ?>
  </select>
  <button class="btn btn-outline-secondary">Filter</button>
</form>

<div class="card">
  <div class="table-responsive">
    <table class="table table-hover">
      <thead><tr><th>#</th><th>Time</th><th>User</th><th>Action</th><th>Entity</th><th>Details</th><th>IP</th></tr></thead>
      <tbody>
      <?php foreach ($logs as $l): ?>
        <tr>
          <td class="text-secondary"><?= (int)$l['id'] ?></td>
          <td class="text-nowrap"><?= e($l['created_at']) ?></td>
          <td><?= e($l['username'] ?? 'system') ?></td>
          <td><span class="badge text-bg-secondary"><?= e($l['action']) ?></span></td>
          <td><?= e($l['entity_type']) ?><?= $l['entity_id'] ? ' #' . e($l['entity_id']) : '' ?></td>
          <td><?= e($l['details'] ?? '') ?></td>
          <td class="text-secondary small"><?= e($l['ip_address'] ?? '') ?></td>
        </tr>
      <?php endforeach; ?>
      <?php if (!$logs): ?>
        <tr><td colspan="7" class="text-center text-secondary py-4">No audit entries.</td></tr>
      <?php endif; ?>
      </tbody>
    </table>
  </div>
</div>
