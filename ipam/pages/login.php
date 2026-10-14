<?php
use DarkVeda\App;
use function DarkVeda\e;
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0F0C23">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="format-detection" content="telephone=no">
<title>Sign in · DarkVeda IPAM</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
<link href="/assets/css/darkveda.css?v=5.1-mobile" rel="stylesheet">
</head>
<body>
<div class="dv-login-bg">
  <div class="card dv-login-card shadow-lg">
    <div class="card-body p-4">
      <div class="text-center mb-4">
        <i class="bi bi-motherboard" style="font-size:2.4rem;color:var(--dv-accent)"></i>
        <h1 class="h4 mt-2 mb-0">DarkVeda <span style="color:var(--dv-accent)">IPAM</span></h1>
        <div class="text-secondary small">Enterprise IP Address Management</div>
      </div>

      <?php foreach (App::takeFlashes() as $f): ?>
        <div class="alert alert-<?= e($f['type']) ?> py-2"><?= e($f['message']) ?></div>
      <?php endforeach; ?>

      <form method="post" action="/">
        <input type="hidden" name="action" value="login">
        <div class="mb-3">
          <label class="form-label">Username</label>
          <input type="text" name="username" class="form-control" required autofocus autocomplete="username">
        </div>
        <div class="mb-4">
          <label class="form-label">Password</label>
          <input type="password" name="password" class="form-control" required autocomplete="current-password">
        </div>
        <button class="btn btn-primary w-100"><i class="bi bi-box-arrow-in-right"></i> Sign in</button>
      </form>
    </div>
  </div>
</div>
</body>
</html>
