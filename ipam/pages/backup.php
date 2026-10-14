<?php
use DarkVeda\{Auth, Database, Backup, Uploads};
use function DarkVeda\e;

$rows = 0;
$tableCount = 0;
try {
    foreach (Backup::tables() as $t) {
        $c = Database::one('SELECT COUNT(*) c FROM `' . $t . '`');
        $rows += (int)($c['c'] ?? 0);
        $tableCount++;
    }
} catch (Throwable $e) {
    // counts are informational only
}

$uploadBytes = 0;
$uploadFiles = 0;
$uploadsDir = Uploads::baseDir();
if (is_dir($uploadsDir)) {
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($uploadsDir, FilesystemIterator::SKIP_DOTS)) as $f) {
        if ($f->isFile()) {
            $uploadFiles++;
            $uploadBytes += $f->getSize();
        }
    }
}

$lastBackup  = Database::one("SELECT created_at FROM audit_logs WHERE action = 'backup' ORDER BY id DESC LIMIT 1");
$lastRestore = Database::one("SELECT created_at FROM audit_logs WHERE action = 'restore' ORDER BY id DESC LIMIT 1");
$archives = Backup::archivesSupported();
?>
<div class="row g-3 justify-content-center">
  <div class="col-lg-5">
    <div class="card h-100">
      <div class="card-body text-center d-flex flex-column">
        <div class="mb-3">
          <i class="bi bi-download" style="font-size:2.4rem;color:#8b5cf6"></i>
        </div>
        <h5>Download a backup</h5>
        <p class="text-secondary small mb-4">
          Everything in one file: <?= number_format($rows) ?> records across <?= (int)$tableCount ?> tables<?php
          if ($uploadFiles): ?>, plus <?= (int)$uploadFiles ?> photo(s) and document(s)<?php endif; ?>.
        </p>

        <form method="get" class="mt-auto">
          <input type="hidden" name="page" value="backup_download">
          <?php if ($archives): ?>
            <input type="hidden" name="uploads" value="1">
            <div class="form-check d-inline-flex gap-2 mb-3">
              <input class="form-check-input" type="checkbox" name="config" id="bkConfig" value="1">
              <label class="form-check-label small text-secondary" for="bkConfig">
                Include passwords from <code>config.php</code>
              </label>
            </div>
          <?php endif; ?>
          <button class="btn btn-primary btn-lg w-100">
            <i class="bi bi-download"></i> Download backup
          </button>
        </form>

        <div class="small text-secondary mt-3">
          <?= $lastBackup ? 'Last downloaded ' . e($lastBackup['created_at']) : 'No backup taken yet' ?>
        </div>
      </div>
    </div>
  </div>

  <div class="col-lg-5">
    <div class="card h-100">
      <div class="card-body text-center d-flex flex-column">
        <div class="mb-3">
          <i class="bi bi-upload" style="font-size:2.4rem;color:#ef4444"></i>
        </div>
        <h5>Restore a backup</h5>
        <p class="text-secondary small mb-4">
          Replaces everything currently in the system with the contents of the file.
        </p>

        <form method="post" enctype="multipart/form-data" class="mt-auto text-start"
              data-confirm="This replaces all current data with the backup. Continue?">
          <?= Auth::csrfField() ?>
          <input type="hidden" name="action" value="backup_restore">
          <input type="hidden" name="confirm" value="RESTORE">
          <?php if ($archives): ?><input type="hidden" name="restore_uploads" value="1"><?php endif; ?>
          <div class="mb-3">
            <input type="file" name="archive" class="form-control" required
                   accept=".gz,.tar,.sql,application/gzip,application/sql,text/plain">
          </div>
          <button class="btn btn-outline-danger btn-lg w-100">
            <i class="bi bi-arrow-counterclockwise"></i> Restore
          </button>
        </form>

        <div class="small text-secondary mt-3">
          <?= $lastRestore ? 'Last restored ' . e($lastRestore['created_at']) : 'Never restored' ?>
        </div>
      </div>
    </div>
  </div>

  <div class="col-lg-10">
    <div class="text-center small text-secondary">
      <i class="bi bi-clock-history"></i>
      Automate it from cron on the host:
      <code>docker exec darkveda-ipam-db mariadb-dump -u root -p<em>PASS</em> <?= e(\DarkVeda\App::config()['db']['name'] ?? 'darkveda_ipam') ?> &gt; backup.sql</code>
    </div>
  </div>
</div>
