<?php
use DarkVeda\{Auth, Database};
use function DarkVeda\e;

$tokens = Database::q(
    'SELECT t.*, u.username FROM api_tokens t JOIN users u ON u.id = t.user_id ORDER BY t.id DESC'
);

$users = Database::q(
    'SELECT u.*, r.name AS role_name FROM users u JOIN roles r ON r.id = u.role_id ORDER BY u.username'
);
$roles  = Database::q('SELECT id, name FROM roles ORDER BY id');
?>
<div class="row g-3">
  <div class="col-lg-7">
    <div class="card mb-3"><div class="card-body">
      <h6 class="mb-3"><i class="bi bi-person-plus"></i> Create user</h6>
      <form method="post" class="row g-3">
        <?= Auth::csrfField() ?>
        <input type="hidden" name="action" value="user_create">
        <div class="col-md-4"><label class="form-label">Username *</label>
          <input name="username" class="form-control" required></div>
        <div class="col-md-4"><label class="form-label">Email *</label>
          <input type="email" name="email" class="form-control" required></div>
        <div class="col-md-4"><label class="form-label">Full name</label>
          <input name="full_name" class="form-control"></div>
        <div class="col-md-4"><label class="form-label">Password * (min 10)</label>
          <input type="password" name="password" class="form-control" minlength="10" required></div>
        <div class="col-md-4"><label class="form-label">Role</label>
          <select name="role_id" class="form-select">
            <?php foreach ($roles as $r): ?>
              <option value="<?= (int)$r['id'] ?>"><?= e($r['name']) ?></option>
            <?php endforeach; ?>
          </select></div>
        <div class="col-md-4 d-flex align-items-end">
          <button class="btn btn-primary w-100">Create</button></div>
      </form>
    </div></div>

    <div class="card">
      <div class="card-header"><i class="bi bi-people"></i> Users</div>
      <div class="table-responsive">
        <table class="table table-hover">
          <thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Last login</th><th></th></tr></thead>
          <tbody>
          <?php foreach ($users as $u): ?>
            <tr>
              <td><strong><?= e($u['username']) ?></strong></td>
              <td><?= e($u['email']) ?></td>
              <td><span class="badge text-bg-secondary"><?= e($u['role_name']) ?></span></td>
              <td><?= $u['is_active'] ? '<span class="badge dv-status dv-badge-active">active</span>'
                                        : '<span class="badge dv-status dv-badge-deprecated">disabled</span>' ?></td>
              <td class="text-secondary small"><?= e($u['last_login_at'] ?? 'never') ?></td>
              <td class="text-end text-nowrap">
                <button class="btn btn-sm btn-outline-secondary" data-bs-toggle="collapse"
                        data-bs-target="#edituser-<?= (int)$u['id'] ?>" title="Edit">
                  <i class="bi bi-pencil"></i>
                </button>
                <?php if ((int)$u['id'] !== Auth::id()): ?>
                <form method="post" class="d-inline">
                  <?= Auth::csrfField() ?>
                  <input type="hidden" name="action" value="user_toggle">
                  <input type="hidden" name="id" value="<?= (int)$u['id'] ?>">
                  <button class="btn btn-sm btn-outline-warning" title="Enable/disable">
                    <i class="bi bi-power"></i>
                  </button>
                </form>
                <form method="post" class="d-inline" data-confirm="Delete user <?= e($u['username']) ?>? Their API tokens are revoked; audit history is kept.">
                  <?= Auth::csrfField() ?>
                  <input type="hidden" name="action" value="user_delete">
                  <input type="hidden" name="id" value="<?= (int)$u['id'] ?>">
                  <button class="btn btn-sm btn-outline-danger" title="Delete user">
                    <i class="bi bi-trash"></i>
                  </button>
                </form>
                <?php endif; ?>
              </td>
            </tr>
            <tr class="dv-expand-row">
              <td colspan="6" class="p-0 border-0">
                <div class="collapse" id="edituser-<?= (int)$u['id'] ?>">
                  <div class="p-3 dv-nested">
                    <form method="post" class="row g-3">
                      <?= Auth::csrfField() ?>
                      <input type="hidden" name="action" value="user_update">
                      <input type="hidden" name="id" value="<?= (int)$u['id'] ?>">
                      <div class="col-md-4">
                        <label class="form-label">Email *</label>
                        <input type="email" name="email" class="form-control" required value="<?= e($u['email']) ?>">
                      </div>
                      <div class="col-md-4">
                        <label class="form-label">Full name</label>
                        <input name="full_name" class="form-control" value="<?= e($u['full_name'] ?? '') ?>">
                      </div>
                      <div class="col-md-4">
                        <label class="form-label">Role</label>
                        <select name="role_id" class="form-select" <?= (int)$u['id'] === Auth::id() ? 'disabled title="You cannot change your own role"' : '' ?>>
                          <?php foreach ($roles as $r): ?>
                            <option value="<?= (int)$r['id'] ?>" <?= (int)$u['role_id'] === (int)$r['id'] ? 'selected' : '' ?>><?= e($r['name']) ?></option>
                          <?php endforeach; ?>
                        </select>
                      </div>
                      <div class="col-md-4">
                        <label class="form-label">New password <span class="text-secondary">(blank = keep)</span></label>
                        <input type="password" name="password" class="form-control" minlength="10" autocomplete="new-password">
                      </div>
                      <div class="col-md-4 d-flex align-items-end">
                        <div class="form-check mb-2">
                          <input class="form-check-input" type="checkbox" name="is_active" id="ua-<?= (int)$u['id'] ?>"
                                 <?= $u['is_active'] ? 'checked' : '' ?> <?= (int)$u['id'] === Auth::id() ? 'disabled' : '' ?>>
                          <label class="form-check-label" for="ua-<?= (int)$u['id'] ?>">Active</label>
                        </div>
                      </div>
                      <div class="col-md-4 d-flex align-items-end">
                        <button class="btn btn-primary w-100"><i class="bi bi-check-lg"></i> Save</button>
                      </div>
                    </form>
                  </div>
                </div>
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="col-lg-5">
    <div class="card mb-3"><div class="card-body">
      <h6 class="mb-2"><i class="bi bi-robot"></i> Automation tokens</h6>
      <p class="small text-secondary">
        These are <strong>not</strong> user logins. A token lets an external system — Zabbix,
        Ansible, a cron script — read and update this IPAM through the REST API without a
        browser session. Create one only if you have something to automate; skip this
        section entirely otherwise.
      </p>
      <form method="post" class="row g-2">
        <?= Auth::csrfField() ?>
        <input type="hidden" name="action" value="token_create">
        <div class="col-8">
          <input name="label" class="form-control" placeholder="What will use it? e.g. zabbix-sync" required>
        </div>
        <div class="col-4">
          <button class="btn btn-primary w-100">Generate</button>
        </div>
      </form>
      <div class="form-text mt-2">Send as <code>Authorization: Bearer &lt;token&gt;</code> to <code>/api/v1/…</code></div>
    </div></div>

    <div class="card">
      <div class="card-header"><i class="bi bi-shield-lock"></i> Active tokens</div>
      <ul class="list-group list-group-flush">
        <?php foreach ($tokens as $t): ?>
          <li class="list-group-item d-flex justify-content-between align-items-center" style="background:transparent">
            <span>
              <?= e($t['label']) ?>
              <small class="text-secondary d-block">
                <?= e($t['username']) ?> · last used: <?= e($t['last_used'] ?? 'never') ?>
              </small>
            </span>
            <form method="post" class="m-0" data-confirm="Revoke token &quot;<?= e($t['label']) ?>&quot;? Anything using it stops working immediately.">
              <?= Auth::csrfField() ?>
              <input type="hidden" name="action" value="token_delete">
              <input type="hidden" name="id" value="<?= (int)$t['id'] ?>">
              <button class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button>
            </form>
          </li>
        <?php endforeach; ?>
        <?php if (!$tokens): ?>
          <li class="list-group-item text-secondary" style="background:transparent">No tokens issued.</li>
        <?php endif; ?>
      </ul>
    </div>
  </div>
</div>
