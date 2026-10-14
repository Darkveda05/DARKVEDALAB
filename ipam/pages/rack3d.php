<?php
use DarkVeda\{Auth, Database, Zabbix};
use function DarkVeda\e;

$siteFilter = (int)($_GET['site'] ?? 0);
$sites = Database::q('SELECT id, name FROM sites ORDER BY name');

$racks = $siteFilter
    ? Database::q('SELECT r.*, s.name AS site_name FROM racks r LEFT JOIN sites s ON s.id = r.site_id WHERE r.site_id = ? ORDER BY r.name', [$siteFilter])
    : Database::q('SELECT r.*, s.name AS site_name FROM racks r LEFT JOIN sites s ON s.id = r.site_id ORDER BY s.name, r.name');

$mon = Zabbix::statusMap();

$scene = [];
foreach ($racks as $r) {
    $items = Database::q(
        'SELECT ri.id, ri.name, ri.kind, ri.u_position, ri.u_size, ri.face, ri.color, ri.photo_path,
                COALESCE(NULLIF(ri.photo_path, ""), dt.image_path, dtd.image_path) AS display_image,
                ri.description, i.address, i.subnet_id, i.os, i.software_version, i.serial_number,
                TRIM(CONCAT(
                    COALESCE(v.name, vd.name, ""), " ",
                    COALESCE(dt.model, dtd.model, "")
                )) AS device_type
         FROM rack_items ri
         LEFT JOIN ip_addresses i ON i.id = ri.ip_id
         LEFT JOIN device_types dt ON dt.id = i.device_type_id
         LEFT JOIN vendors v ON v.id = dt.vendor_id
         LEFT JOIN device_types dtd ON dtd.id = ri.device_type_id
         LEFT JOIN vendors vd ON vd.id = dtd.vendor_id
         WHERE ri.rack_id = ?
         ORDER BY ri.u_position',
        [(int)$r['id']]
    );
    foreach ($items as &$it) {
        $it['state'] = $it['address'] ? ($mon[$it['address']]['state'] ?? null) : null;
        $st = $it['address'] ? ($mon[$it['address']] ?? null) : null;
        $it['cpu'] = $st['cpu_pct'] ?? null;
        $it['mem'] = $st['memory_pct'] ?? null;
    }
    unset($it);

    $scene[] = [
        'id'       => (int)$r['id'],
        'name'     => $r['name'],
        'site'     => $r['site_name'],
        'u_height' => (int)$r['u_height'],
        'items'    => $items,
    ];
}
$payload = json_encode($scene, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
$totalItems = array_sum(array_map(fn($r) => count($r['items']), $scene));
?>
<div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3">
  <div class="text-secondary small">
    <?= count($scene) ?> rack(s) · <?= (int)$totalItems ?> mounted item(s)
  </div>
  <form method="get" class="d-flex gap-2 align-items-center">
    <input type="hidden" name="page" value="rack3d">
    <label class="small text-secondary">Site</label>
    <select name="site" class="form-select form-select-sm" style="width:auto" onchange="this.form.submit()">
      <option value="0">All sites</option>
      <?php foreach ($sites as $s): ?>
        <option value="<?= (int)$s['id'] ?>" <?= $siteFilter === (int)$s['id'] ? 'selected' : '' ?>><?= e($s['name']) ?></option>
      <?php endforeach; ?>
    </select>
    <a class="btn btn-sm btn-outline-secondary" href="/?page=racks"><i class="bi bi-list"></i> 2D racks</a>
  </form>
</div>

<?php if (!$scene): ?>
  <div class="card"><div class="card-body text-center text-secondary py-5">
    <i class="bi bi-box d-block mb-2" style="font-size:2rem"></i>
    No racks to render. Create one under <a href="/?page=racks">Racks</a> first.
  </div></div>
<?php else: ?>
<div class="card">
  <div class="card-body p-0 position-relative">
    <canvas id="room3d"></canvas>
    <div class="dv-3d-panel d-none" id="panel3d"></div>
    <div class="dv-3d-hint">
      Drag to rotate · scroll to zoom · right-drag to pan · click equipment for details. Devices show the photo saved against their model.
    </div>
  </div>
</div>
<?php endif; ?>

<?php if ($scene): ?>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
<script>
(function () {
  var DATA   = <?= $payload ?>;
  var canvas = document.getElementById('room3d');
  var panel  = document.getElementById('panel3d');
  if (!canvas || typeof THREE === 'undefined') {
    if (canvas) {
      canvas.insertAdjacentHTML('afterend',
        '<div class="p-4 text-center text-secondary">3D library could not be loaded. ' +
        'This view needs access to a CDN; the 2D rack view works offline.</div>');
    }
    return;
  }

  // ---- real-world dimensions (metres) ----
  var U      = 0.04445;            // one rack unit = 1.75"
  var RACK_W = 0.60;               // 19" rack + frame
  var RACK_D = 0.90;
  var PLINTH = 0.09;               // castors / base so racks sit on the floor
  var BAY_W  = RACK_W - 0.09;      // usable width between rails

  // ---- renderer ----
  var renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: true, alpha: false });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.shadowMap.enabled = true;
  renderer.shadowMap.type = THREE.PCFSoftShadowMap;
  if (renderer.outputEncoding !== undefined) { renderer.outputEncoding = THREE.sRGBEncoding; }

  var scene = new THREE.Scene();
  scene.background = new THREE.Color(0x14161d);
  scene.fog = new THREE.Fog(0x14161d, 22, 60);

  var camera = new THREE.PerspectiveCamera(45, 1, 0.05, 300);

  // ---- lighting: bright enough to actually read the hardware ----
  scene.add(new THREE.HemisphereLight(0xdfe7ff, 0x2a2f3d, 0.95));

  var key = new THREE.DirectionalLight(0xffffff, 0.85);
  key.position.set(5, 9, 7);
  key.castShadow = true;
  key.shadow.mapSize.set(1024, 1024);
  key.shadow.camera.near = 1;
  key.shadow.camera.far = 40;
  key.shadow.camera.left = -12; key.shadow.camera.right = 12;
  key.shadow.camera.top = 12;   key.shadow.camera.bottom = -12;
  scene.add(key);

  var fill = new THREE.DirectionalLight(0xc9d4ff, 0.4);
  fill.position.set(-7, 5, -5);
  scene.add(fill);

  // soft ceiling strips, like a real server room
  [-3, 3].forEach(function (z) {
    var strip = new THREE.RectAreaLight ? null : null;   // RectAreaLight needs extra deps
    var lamp = new THREE.PointLight(0xbcd0ff, 0.35, 24, 2);
    lamp.position.set(0, 3.6, z);
    scene.add(lamp);
  });

  // ---- room ----
  var spacing = 0.9;                                   // racks stand shoulder to shoulder
  var spanX   = Math.max(6, DATA.length * spacing + 5);
  var floorMat = new THREE.MeshStandardMaterial({ color: 0x272b36, roughness: 0.85, metalness: 0.05 });
  var floor = new THREE.Mesh(new THREE.PlaneGeometry(spanX, 16), floorMat);
  floor.rotation.x = -Math.PI / 2;
  floor.receiveShadow = true;
  scene.add(floor);

  var grid = new THREE.GridHelper(spanX, Math.round(spanX / 0.6), 0x39404f, 0x2c313c);
  grid.position.y = 0.002;
  scene.add(grid);

  // back wall gives the scene depth instead of a void
  var wall = new THREE.Mesh(
    new THREE.PlaneGeometry(spanX, 6),
    new THREE.MeshStandardMaterial({ color: 0x1c2029, roughness: 1 })
  );
  wall.position.set(0, 3, -7);
  wall.receiveShadow = true;
  scene.add(wall);

  // ---- materials ----
  var matFrame = new THREE.MeshStandardMaterial({ color: 0x33384a, roughness: 0.55, metalness: 0.65 });
  var matPanel = new THREE.MeshStandardMaterial({ color: 0x21252f, roughness: 0.7,  metalness: 0.4 });
  var matRail  = new THREE.MeshStandardMaterial({ color: 0x4a5163, roughness: 0.5,  metalness: 0.7 });

  var texLoader = new THREE.TextureLoader();
  texLoader.setCrossOrigin('anonymous');

  var _blank = {};
  function blankTexture(kind) {
    if (_blank[kind]) return _blank[kind];
    var c = document.createElement('canvas');
    c.width = 512; c.height = 72;
    var g = c.getContext('2d');
    var base = { patch_panel: '#2f3a2c', power: '#3a2a24', screen: '#1c2438',
                 shelf: '#2e323c', blank: '#242833' }[kind] || '#2b3040';
    var grad = g.createLinearGradient(0, 0, 0, 72);
    grad.addColorStop(0, shade(base, 22)); grad.addColorStop(0.45, base); grad.addColorStop(1, shade(base, -18));
    g.fillStyle = grad; g.fillRect(0, 0, 512, 72);

    if (kind === 'patch_panel') {
      for (var p = 0; p < 24; p++) {
        var px = 26 + p * 19;
        g.fillStyle = '#11141b'; g.fillRect(px, 22, 14, 28);
        g.fillStyle = '#c9a227'; g.fillRect(px + 3, 44, 8, 3);
      }
    } else if (kind === 'power') {
      for (var s = 0; s < 8; s++) {
        g.fillStyle = '#15181f'; g.beginPath();
        g.arc(50 + s * 58, 36, 13, 0, Math.PI * 2); g.fill();
        g.fillStyle = '#e2564a'; g.fillRect(44 + s * 58, 33, 12, 6);
      }
    } else {
      g.strokeStyle = 'rgba(255,255,255,0.07)'; g.lineWidth = 2;
      for (var x = 60; x < 452; x += 13) { g.beginPath(); g.moveTo(x, 18); g.lineTo(x, 54); g.stroke(); }
      g.fillStyle = '#3fbf5f'; g.beginPath(); g.arc(28, 36, 4.5, 0, Math.PI * 2); g.fill();
      g.fillStyle = '#4a8fd8'; g.beginPath(); g.arc(42, 36, 4.5, 0, Math.PI * 2); g.fill();
    }
    // screw holes top and bottom, like a real faceplate
    g.fillStyle = 'rgba(0,0,0,0.55)';
    [10, 62].forEach(function (yy) { [10, 502].forEach(function (xx) {
      g.beginPath(); g.arc(xx, yy, 3, 0, Math.PI * 2); g.fill(); }); });

    var t = new THREE.CanvasTexture(c);
    t.anisotropy = 4;
    _blank[kind] = t;
    return t;
  }

  function shade(hex, amt) {
    var n = parseInt(hex.slice(1), 16);
    var r = Math.max(0, Math.min(255, (n >> 16) + amt));
    var g2 = Math.max(0, Math.min(255, ((n >> 8) & 255) + amt));
    var b = Math.max(0, Math.min(255, (n & 255) + amt));
    return '#' + ((r << 16) | (g2 << 8) | b).toString(16).padStart(6, '0');
  }

  function labelSprite(text) {
    var c = document.createElement('canvas');
    c.width = 512; c.height = 96;
    var g = c.getContext('2d');
    g.fillStyle = 'rgba(14,16,22,0.88)';
    roundRect(g, 6, 18, 500, 60, 12); g.fill();
    g.strokeStyle = 'rgba(139,92,246,0.85)'; g.lineWidth = 3;
    roundRect(g, 6, 18, 500, 60, 12); g.stroke();
    g.fillStyle = '#ede9fe';
    g.font = 'bold 40px system-ui, -apple-system, Segoe UI, sans-serif';
    g.textAlign = 'center'; g.textBaseline = 'middle';
    g.fillText(text.substring(0, 20), 256, 49);
    var tex = new THREE.CanvasTexture(c);
    var sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false }));
    sp.scale.set(0.72, 0.135, 1);
    return sp;
  }
  function roundRect(g, x, y, w, h, r) {
    g.beginPath();
    g.moveTo(x + r, y); g.lineTo(x + w - r, y); g.quadraticCurveTo(x + w, y, x + w, y + r);
    g.lineTo(x + w, y + h - r); g.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    g.lineTo(x + r, y + h); g.quadraticCurveTo(x, y + h, x, y + h - r);
    g.lineTo(x, y + r); g.quadraticCurveTo(x, y, x + r, y); g.closePath();
  }

  // ---- build racks ----
  var pickables = [];
  var startX = -((DATA.length - 1) * spacing) / 2;
  var tallest = 0;

  DATA.forEach(function (rack, ri) {
    var bayH = rack.u_height * U;
    var totalH = bayH + PLINTH + 0.06;
    tallest = Math.max(tallest, totalH);

    var group = new THREE.Group();
    group.position.x = startX + ri * spacing;
    scene.add(group);

    // plinth
    var plinth = new THREE.Mesh(new THREE.BoxGeometry(RACK_W, PLINTH, RACK_D), matPanel);
    plinth.position.set(0, PLINTH / 2, 0);
    plinth.castShadow = plinth.receiveShadow = true;
    group.add(plinth);

    // solid sides, back and top: a real enclosure, open at the front
    var sideGeo = new THREE.BoxGeometry(0.022, bayH, RACK_D);
    [-1, 1].forEach(function (s) {
      var side = new THREE.Mesh(sideGeo, matPanel);
      side.position.set(s * (RACK_W / 2 - 0.011), PLINTH + bayH / 2, 0);
      side.castShadow = side.receiveShadow = true;
      group.add(side);
    });
    var back = new THREE.Mesh(new THREE.BoxGeometry(RACK_W, bayH, 0.02), matPanel);
    back.position.set(0, PLINTH + bayH / 2, -RACK_D / 2 + 0.01);
    back.castShadow = back.receiveShadow = true;
    group.add(back);
    var top = new THREE.Mesh(new THREE.BoxGeometry(RACK_W, 0.03, RACK_D), matFrame);
    top.position.set(0, PLINTH + bayH + 0.015, 0);
    top.castShadow = true;
    group.add(top);

    // front mounting rails
    [-1, 1].forEach(function (s) {
      var rail = new THREE.Mesh(new THREE.BoxGeometry(0.03, bayH, 0.03), matRail);
      rail.position.set(s * (BAY_W / 2 + 0.012), PLINTH + bayH / 2, RACK_D / 2 - 0.03);
      rail.castShadow = true;
      group.add(rail);
    });

    var label = labelSprite(rack.name);
    label.position.set(0, PLINTH + bayH + 0.16, 0);
    group.add(label);

    rack.items.forEach(function (item) {
      var size  = Math.max(1, item.u_size);
      var h     = size * U - 0.004;
      var y     = PLINTH + (item.u_position - 1) * U + (size * U) / 2;
      var depth = item.kind === 'patch_panel' || item.kind === 'blank' ? 0.10 : RACK_D * 0.72;
      var z     = item.face === 'rear'
                ? -RACK_D / 2 + depth / 2 + 0.02
                :  RACK_D / 2 - depth / 2 - 0.035;

      var body = new THREE.MeshStandardMaterial({ color: 0x1b1e26, roughness: 0.75, metalness: 0.35 });
      var faceMat = new THREE.MeshStandardMaterial({ color: 0xffffff, roughness: 0.6, metalness: 0.25 });
      var mats = [body, body, body, body, body.clone(), body.clone()];
      var frontIndex = item.face === 'rear' ? 5 : 4;

      if (item.display_image) {
        texLoader.load('/' + item.display_image, function (tex) {
          tex.minFilter = THREE.LinearFilter;
          tex.anisotropy = 4;
          if (tex.encoding !== undefined) { tex.encoding = THREE.sRGBEncoding; }
          faceMat.map = tex;
          faceMat.needsUpdate = true;
          render();
        }, undefined, function () {
          faceMat.map = blankTexture(item.kind);
          faceMat.needsUpdate = true;
          render();
        });
      } else {
        faceMat.map = blankTexture(item.kind);
      }
      mats[frontIndex] = faceMat;

      var box = new THREE.Mesh(new THREE.BoxGeometry(BAY_W, h, depth), mats);
      box.position.set(0, y, z);
      box.castShadow = box.receiveShadow = true;
      box.userData = { item: item, rack: rack, frontIndex: frontIndex, faceMat: faceMat };
      group.add(box);
      pickables.push(box);

      if (item.state) {
        var led = new THREE.Mesh(
          new THREE.SphereGeometry(0.008, 12, 12),
          new THREE.MeshBasicMaterial({
            color: item.state === 'online' ? 0x2ee06a : (item.state === 'offline' ? 0xff4444 : 0x8a8f99)
          })
        );
        led.position.set(BAY_W / 2 - 0.02, y, z + (item.face === 'rear' ? -depth / 2 - 0.004 : depth / 2 + 0.004));
        group.add(led);
      }
    });
  });

  // ---- camera: smooth, damped orbit that frames the whole room ----
  var target  = new THREE.Vector3(0, Math.max(0.5, tallest * 0.45), 0);
  var desired = { radius: Math.max(3.2, DATA.length * spacing * 1.5 + 2.6), theta: 0.55, phi: 1.15 };
  var actual  = { radius: desired.radius * 1.6, theta: desired.theta, phi: desired.phi };
  var camTarget = target.clone();
  var camPos    = new THREE.Vector3();

  function clampDesired() {
    desired.phi    = Math.max(0.22, Math.min(Math.PI / 2 - 0.03, desired.phi));
    desired.radius = Math.max(0.8, Math.min(45, desired.radius));
  }

  function positionFrom(s, t) {
    return new THREE.Vector3(
      t.x + s.radius * Math.sin(s.phi) * Math.sin(s.theta),
      t.y + s.radius * Math.cos(s.phi),
      t.z + s.radius * Math.sin(s.phi) * Math.cos(s.theta)
    );
  }

  var dragging = false, panning = false, lx = 0, ly = 0, moved = 0;
  canvas.addEventListener('mousedown', function (ev) {
    if (ev.button === 2) { panning = true; } else { dragging = true; }
    lx = ev.clientX; ly = ev.clientY; moved = 0;
    ev.preventDefault();
  });
  window.addEventListener('mouseup', function () { dragging = panning = false; });
  window.addEventListener('mousemove', function (ev) {
    if (!dragging && !panning) return;
    var dx = ev.clientX - lx, dy = ev.clientY - ly;
    lx = ev.clientX; ly = ev.clientY;
    moved += Math.abs(dx) + Math.abs(dy);
    if (dragging) {
      desired.theta -= dx * 0.005;
      desired.phi   -= dy * 0.005;
    } else {
      var sp = actual.radius * 0.0014;
      var right = new THREE.Vector3(Math.cos(desired.theta), 0, -Math.sin(desired.theta));
      target.addScaledVector(right, -dx * sp);
      target.y = Math.max(0.1, target.y + dy * sp);
    }
    clampDesired();
  });
  canvas.addEventListener('contextmenu', function (e) { e.preventDefault(); });
  canvas.addEventListener('wheel', function (ev) {
    ev.preventDefault();
    desired.radius *= ev.deltaY > 0 ? 1.11 : 0.9;
    clampDesired();
  }, { passive: false });

  var lastTouch = null, lastDist = null;
  canvas.addEventListener('touchstart', function (ev) {
    if (ev.touches.length === 1) { lastTouch = { x: ev.touches[0].clientX, y: ev.touches[0].clientY }; }
    else if (ev.touches.length === 2) { lastDist = touchDist(ev); }
  }, { passive: true });
  canvas.addEventListener('touchmove', function (ev) {
    if (ev.touches.length === 1 && lastTouch) {
      var dx = ev.touches[0].clientX - lastTouch.x, dy = ev.touches[0].clientY - lastTouch.y;
      lastTouch = { x: ev.touches[0].clientX, y: ev.touches[0].clientY };
      desired.theta -= dx * 0.006; desired.phi -= dy * 0.006;
      clampDesired(); ev.preventDefault();
    } else if (ev.touches.length === 2 && lastDist) {
      var d = touchDist(ev);
      desired.radius *= lastDist / d; lastDist = d;
      clampDesired(); ev.preventDefault();
    }
  }, { passive: false });
  function touchDist(ev) {
    var a = ev.touches[0], b = ev.touches[1];
    return Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY);
  }

  // ---- picking ----
  var ray = new THREE.Raycaster();
  var mouse = new THREE.Vector2();
  var selected = null;

  canvas.addEventListener('mouseup', function (ev) {
    if (moved > 6) return;                       // that was a drag, not a click
    var rect = canvas.getBoundingClientRect();
    mouse.x = ((ev.clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((ev.clientY - rect.top) / rect.height) * 2 + 1;
    ray.setFromCamera(mouse, camera);
    var hits = ray.intersectObjects(pickables, false);

    if (selected) { selected.userData.faceMat.emissive && selected.userData.faceMat.emissive.setHex(0x000000); }
    if (hits.length) {
      selected = hits[0].object;
      if (selected.userData.faceMat.emissive) {
        selected.userData.faceMat.emissive.setHex(0x4c2f8f);
      }
      showPanel(selected.userData.item, selected.userData.rack);
    } else {
      selected = null;
      panel.classList.add('d-none');
    }
  });

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  function showPanel(item, rack) {
    var top = item.u_position + item.u_size - 1;
    var rows = [
      ['Rack', rack.name + (rack.site ? ' · ' + rack.site : '')],
      ['Position', item.u_size > 1 ? ('U' + item.u_position + '–U' + top + ' (' + item.u_size + 'U)') : ('U' + item.u_position)],
      ['Face', item.face],
      ['Type', String(item.kind).replace('_', ' ')],
      ['IP', item.address],
      ['Model', item.device_type],
      ['Serial', item.serial_number],
      ['OS', item.os ? (item.os + ' ' + (item.software_version || '')) : null],
      ['CPU', item.cpu != null ? item.cpu + '%' : null],
      ['Memory', item.mem != null ? item.mem + '%' : null],
      ['Notes', item.description]
    ];
    var html = '<div class="d-flex justify-content-between align-items-start mb-2">'
      + '<strong>' + esc(item.name) + '</strong>'
      + '<button class="btn btn-sm btn-outline-secondary py-0 px-1" onclick="document.getElementById(\'panel3d\').classList.add(\'d-none\')">&times;</button></div>';
    if (item.state) {
      html += '<div class="mb-2"><span class="dv-dot dv-dot-' + esc(item.state) + '"></span>'
           + '<span class="small">' + esc(item.state) + '</span></div>';
    }
    if (item.display_image) {
      html += '<img src="/' + esc(item.display_image) + '" alt="" style="width:100%;border-radius:6px;margin-bottom:.5rem;background:#0b0b12">';
    }
    html += '<table class="table table-sm mb-2">';
    rows.forEach(function (r) {
      if (r[1] === null || r[1] === undefined || r[1] === '') return;
      html += '<tr><td class="text-secondary py-1" style="width:40%">' + esc(r[0]) + '</td>'
           + '<td class="py-1">' + esc(r[1]) + '</td></tr>';
    });
    html += '</table><div class="d-grid gap-1">';
    if (item.subnet_id) {
      html += '<a class="btn btn-sm btn-outline-primary" href="/?page=subnet_view&id=' + item.subnet_id + '">Open IP record</a>';
    }
    html += '<a class="btn btn-sm btn-outline-secondary" href="/?page=racks&id=' + rack.id + '">Open in 2D view</a></div>';
    panel.innerHTML = html;
    panel.classList.remove('d-none');
  }

  // ---- resize + damped render loop ----
  function resize() {
    var w = canvas.clientWidth || canvas.parentElement.clientWidth;
    var h = canvas.clientHeight || 620;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  window.addEventListener('resize', resize);
  resize();

  var needsRender = true;
  function render() { needsRender = true; }

  (function loop() {
    requestAnimationFrame(loop);

    // ease the camera toward where the input asked it to be: no snapping
    var k = 0.12;
    var dr = desired.radius - actual.radius;
    var dt = desired.theta  - actual.theta;
    var dp = desired.phi    - actual.phi;
    var dTarget = target.clone().sub(camTarget);

    if (Math.abs(dr) > 1e-4 || Math.abs(dt) > 1e-4 || Math.abs(dp) > 1e-4 || dTarget.lengthSq() > 1e-8) {
      actual.radius += dr * k;
      actual.theta  += dt * k;
      actual.phi    += dp * k;
      camTarget.addScaledVector(dTarget, k);
      needsRender = true;
    }

    if (needsRender) {
      camPos.copy(positionFrom(actual, camTarget));
      camera.position.copy(camPos);
      camera.lookAt(camTarget);
      renderer.render(scene, camera);
      needsRender = false;
    }
  })();
})();
</script>
<?php endif; ?>
