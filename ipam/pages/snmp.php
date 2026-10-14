<?php
use DarkVeda\{Auth, Database, Snmp};
use function DarkVeda\e;

$creds = Database::q('SELECT * FROM snmp_credentials ORDER BY is_default DESC, name');
$extOk = Snmp::available();
?>
<?php if (!$extOk): ?>
<div class="alert alert-warning">
  <strong>PHP SNMP extension not detected.</strong> Profiles can be saved, but polling is skipped until it's installed:
  <code>apt install php8.3-snmp</code> (Debian/Ubuntu) or <code>apk add php83-snmp</code> (Alpine / linuxserver images),
  then restart PHP-FPM. Discovery keeps working without it — only SNMP enrichment and LLDP/CDP topology are unavailable.
</div>
<?php endif; ?>

<div class="card mb-3">
  <div class="card-header"><i class="bi bi-key"></i> New SNMP profile</div>
  <div class="card-body">
    <form method="post" class="row g-3" id="snmpForm">
      <?= Auth::csrfField() ?>
      <input type="hidden" name="action" value="snmp_save">
      <div class="col-md-3">
        <label class="form-label">Profile name *</label>
        <input name="name" class="form-control" required placeholder="Core switches">
      </div>
      <div class="col-md-2">
        <label class="form-label">Version</label>
        <select name="version" class="form-select" id="snmpVersion">
          <option value="2c">SNMPv2c</option>
          <option value="3">SNMPv3</option>
        </select>
      </div>

      <div class="col-md-3 dv-snmp-v2c">
        <label class="form-label">Community</label>
        <input name="community" class="form-control" placeholder="public">
      </div>

      <div class="col-md-2 dv-snmp-v3 d-none">
        <label class="form-label">Security name</label>
        <input name="sec_name" class="form-control">
      </div>
      <div class="col-md-2 dv-snmp-v3 d-none">
        <label class="form-label">Level</label>
        <select name="sec_level" class="form-select">
          <option>authPriv</option><option>authNoPriv</option><option>noAuthNoPriv</option>
        </select>
      </div>
      <div class="col-md-2 dv-snmp-v3 d-none">
        <label class="form-label">Auth</label>
        <select name="auth_protocol" class="form-select">
          <option>SHA</option><option>SHA256</option><option>SHA512</option><option>MD5</option>
        </select>
      </div>
      <div class="col-md-2 dv-snmp-v3 d-none">
        <label class="form-label">Auth password</label>
        <input type="password" name="auth_pass" class="form-control" autocomplete="new-password">
      </div>
      <div class="col-md-2 dv-snmp-v3 d-none">
        <label class="form-label">Priv</label>
        <select name="priv_protocol" class="form-select">
          <option>AES</option><option>AES256</option><option>DES</option>
        </select>
      </div>
      <div class="col-md-2 dv-snmp-v3 d-none">
        <label class="form-label">Priv password</label>
        <input type="password" name="priv_pass" class="form-control" autocomplete="new-password">
      </div>

      <div class="col-md-2">
        <label class="form-label">Timeout (µs)</label>
        <input name="timeout_us" type="number" min="100000" step="100000" value="1000000" class="form-control">
      </div>
      <div class="col-md-1">
        <label class="form-label">Retries</label>
        <input name="retries" type="number" min="0" max="5" value="1" class="form-control">
      </div>
      <div class="col-md-2 d-flex align-items-end">
        <div class="form-check mb-2">
          <input class="form-check-input" type="checkbox" name="is_default" id="snmpDefault" checked>
          <label class="form-check-label" for="snmpDefault">Default profile</label>
        </div>
      </div>
      <div class="col-md-2 d-flex align-items-end">
        <button class="btn btn-primary w-100"><i class="bi bi-plus-lg"></i> Save profile</button>
      </div>
    </form>
  </div>
</div>

<div class="card mb-3">
  <div class="card-header"><i class="bi bi-shield-lock"></i> Profiles</div>
  <div class="table-responsive">
    <table class="table table-hover mb-0">
      <thead><tr><th>Name</th><th>Version</th><th>Credentials</th><th>Timeout</th><th>Default</th><th>Subnets bound</th><th class="text-end"></th></tr></thead>
      <tbody>
      <?php foreach ($creds as $c):
          $bound = Database::one('SELECT COUNT(*) c FROM subnets WHERE snmp_credential_id = ?', [(int)$c['id']])['c'];
      ?>
        <tr>
          <td><strong><?= e($c['name']) ?></strong></td>
          <td><span class="badge text-bg-<?= $c['version'] === '3' ? 'primary' : 'secondary' ?>">v<?= e($c['version']) ?></span></td>
          <td class="small text-secondary">
            <?php if ($c['version'] === '2c'): ?>
              community <code>••••</code>
            <?php else: ?>
              <?= e($c['sec_name'] ?? '—') ?> · <?= e($c['sec_level'] ?? '') ?>
              · <?= e($c['auth_protocol'] ?? '') ?>/<?= e($c['priv_protocol'] ?? '') ?>
            <?php endif; ?>
          </td>
          <td class="small"><?= number_format((int)$c['timeout_us'] / 1000) ?> ms × <?= (int)$c['retries'] + 1 ?></td>
          <td><?= $c['is_default'] ? '<span class="badge text-bg-success">default</span>' : '' ?></td>
          <td><?= (int)$bound ?></td>
          <td class="text-end text-nowrap">
            <form method="post" class="d-inline-flex gap-1 align-items-center m-0">
              <?= Auth::csrfField() ?>
              <input type="hidden" name="action" value="snmp_test">
              <input type="hidden" name="id" value="<?= (int)$c['id'] ?>">
              <input name="host" class="form-control form-control-sm" style="width:130px" placeholder="test IP">
              <button class="btn btn-sm btn-outline-primary" <?= $extOk ? '' : 'disabled' ?>>
                <i class="bi bi-broadcast"></i> Test
              </button>
            </form>
            <form method="post" class="d-inline m-0" data-confirm="Delete profile <?= e($c['name']) ?>?">
              <?= Auth::csrfField() ?>
              <input type="hidden" name="action" value="snmp_delete">
              <input type="hidden" name="id" value="<?= (int)$c['id'] ?>">
              <button class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i></button>
            </form>
          </td>
        </tr>
      <?php endforeach; ?>
      <?php if (!$creds): ?>
        <tr><td colspan="7" class="text-center text-secondary py-4">No SNMP profiles yet.</td></tr>
      <?php endif; ?>
      </tbody>
    </table>
  </div>
  <div class="card-footer small text-secondary">
    The default profile is used for every subnet unless a subnet has its own profile bound
    (set that on the subnet's detail page). Discovery polls SNMP for each responding host to collect
    sysName, OS/version, chassis serial, interface MACs and LLDP/CDP neighbours.
  </div>
</div>

<script>
(function () {
  const sel = document.getElementById('snmpVersion');
  if (!sel) return;
  function toggle() {
    const v3 = sel.value === '3';
    document.querySelectorAll('.dv-snmp-v3').forEach(el => el.classList.toggle('d-none', !v3));
    document.querySelectorAll('.dv-snmp-v2c').forEach(el => el.classList.toggle('d-none', v3));
  }
  sel.addEventListener('change', toggle);
  toggle();
})();
</script>
