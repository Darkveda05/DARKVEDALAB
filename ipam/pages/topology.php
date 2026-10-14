<?php
use DarkVeda\Topology;
use function DarkVeda\e;

$snap = Topology::snapshot();
$nodes = $snap['nodes'];
$edges = $snap['edges'];
$stats = $snap['stats'];
$links = $snap['links'];
$protoColor = $snap['colors'];
// Initial map payload (stats + table are server-rendered; the Refresh
// button fetches the full snapshot and re-renders everything in place).
$payload = json_encode(
    ['nodes' => $nodes, 'edges' => $edges, 'colors' => $protoColor],
    JSON_UNESCAPED_SLASHES
);
?>
<div class="row g-3 mb-3">
  <?php foreach ([
      ['Nodes', $stats['nodes'], 'bi-hdd-network', 'topoStatNodes'],
      ['Links', $stats['edges'], 'bi-share', 'topoStatEdges'],
      ['Gateway-ARP edges', $stats['arp'], 'bi-router', 'topoStatArp'],
  ] as [$label, $value, $icon, $sid]): ?>
  <div class="col-6 col-md-4">
    <div class="card"><div class="dv-stat">
      <i class="bi <?= e($icon) ?>"></i>
      <div><div class="dv-stat-value" id="<?= $sid ?>"><?= (int)$value ?></div><div class="dv-stat-label"><?= e($label) ?></div></div>
    </div></div>
  </div>
  <?php endforeach; ?>
</div>

<div class="card mb-3">
  <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2">
    <span><i class="bi bi-diagram-3"></i> Topology map — Gateway ARP</span>
    <span class="d-flex align-items-center gap-2">
      <small class="text-secondary" id="topoUpdated"></small>
      <button type="button" class="btn btn-sm btn-outline-primary" id="topoRefresh" title="Reload the latest topology data">
        <i class="bi bi-arrow-clockwise"></i> Refresh
      </button>
      <span class="badge text-bg-warning"><i class="bi bi-router"></i> Gateway ARP</span>
    </span>
  </div>
  <div class="card-body p-0 position-relative">
    <?php if (!$edges): ?>
      <div class="p-5 text-center text-secondary">
        <i class="bi bi-diagram-3 d-block mb-2" style="font-size:2rem"></i>
        No Gateway ARP data yet. Configure an <a href="/?page=snmp">SNMP profile</a> and run a
        <a href="/?page=discovery">discovery scan</a> — gateway ARP entries are collected automatically.
      </div>
    <?php else: ?>
      <div id="topoWrap" style="height:560px; overflow:hidden">
        <svg id="topo" width="100%" height="560" style="cursor:grab"></svg>
      </div>
      <div id="topoTip" class="position-absolute d-none p-2 rounded"
           style="pointer-events:none; background:rgba(15,15,25,.95); border:1px solid #3a3a55; font-size:.8rem; z-index:5"></div>
    <?php endif; ?>
  </div>
  <?php if ($edges): ?>
  <div class="card-footer small text-secondary">
    Drag nodes to rearrange · scroll to zoom · click a managed node to open its IP record.
    Violet = managed in IPAM, grey = neighbour seen only via discovery.
    Amber edges = gateway ARP.
  </div>
  <?php endif; ?>
</div>

<div class="card">
  <div class="card-header"><i class="bi bi-list-ul"></i> Gateway ARP table</div>
  <div class="table-responsive">
    <table class="table table-sm table-hover mb-0">
      <thead><tr>
        <th>Proto</th><th>Local device</th><th>Local port</th>
        <th>Remote device</th><th>Remote port</th><th>Remote IP</th><th>Platform</th><th>Last seen</th>
      </tr></thead>
      <tbody id="topoTableBody">
      <?php foreach ($links as $l): ?>
        <tr>
          <td><span class="badge text-bg-warning">arp</span></td>
          <td>
            <?php if (!empty($l['local_subnet_id'])): ?>
              <a href="/?page=subnet_view&id=<?= (int)$l['local_subnet_id'] ?>"><?= e($l['local_name'] ?: $l['local_ip']) ?></a>
            <?php else: ?>
              <?= e($l['local_name'] ?: $l['local_ip']) ?>
            <?php endif; ?>
            <div class="small text-secondary"><code><?= e($l['local_ip']) ?></code></div>
          </td>
          <td><code class="small"><?= e($l['local_port'] ?: '—') ?></code></td>
          <td><?= e($l['remote_name'] ?: '—') ?></td>
          <td><code class="small"><?= e($l['remote_port'] ?: '—') ?></code></td>
          <td><code class="small"><?= e($l['remote_ip'] ?: '—') ?></code></td>
          <td class="text-secondary small"><?= e($l['remote_descr'] ?: '—') ?></td>
          <td class="small text-secondary"><?= e($l['last_seen']) ?></td>
        </tr>
      <?php endforeach; ?>
      <?php if (!$links): ?>
        <tr><td colspan="8" class="text-center text-secondary py-4">No neighbour entries.</td></tr>
      <?php endif; ?>
      </tbody>
    </table>
  </div>
</div>

<?php if ($edges): ?>
<script>
(function () {
  const svg       = document.getElementById('topo');
  const tip       = document.getElementById('topoTip');
  const btn       = document.getElementById('topoRefresh');
  const updatedEl = document.getElementById('topoUpdated');
  if (!svg) return;

  const NS = 'http://www.w3.org/2000/svg';
  const H  = 560;
  let view = null; // {pan, draw, dragNode, panning, sx, sy} of the current render

  function esc(s) {
    return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  }

  // Shared listeners, attached once; they always operate on the current view
  // so repeated refreshes never stack duplicate handlers.
  window.addEventListener('mouseup', () => {
    if (view) { view.panning = false; view.dragNode = null; }
    svg.style.cursor = 'grab';
  });
  window.addEventListener('mousemove', ev => {
    if (!view) return;
    if (view.dragNode) {
      const r = svg.getBoundingClientRect();
      view.dragNode.x = (ev.clientX - r.left - view.pan.x) / view.pan.k;
      view.dragNode.y = (ev.clientY - r.top  - view.pan.y) / view.pan.k;
      view.draw();
    } else if (view.panning) {
      view.pan.x = ev.clientX - view.sx;
      view.pan.y = ev.clientY - view.sy;
      view.draw();
    }
  });
  svg.addEventListener('mousedown', ev => {
    if (!view || ev.target !== svg) return;
    view.panning = true;
    view.sx = ev.clientX - view.pan.x;
    view.sy = ev.clientY - view.pan.y;
    svg.style.cursor = 'grabbing';
  });
  svg.addEventListener('wheel', ev => {
    if (!view) return;
    ev.preventDefault();
    const f = ev.deltaY < 0 ? 1.12 : 0.89;
    view.pan.k = Math.max(0.3, Math.min(3, view.pan.k * f));
    view.draw();
  }, { passive: false });

  function updateStats(stats) {
    if (!stats) return;
    const map = { nodes: 'topoStatNodes', edges: 'topoStatEdges', arp: 'topoStatArp' };
    for (const [k, id] of Object.entries(map)) {
      const el = document.getElementById(id);
      if (el && stats[k] !== undefined) el.textContent = stats[k];
    }
  }

  function updateTable(links) {
    const tb = document.getElementById('topoTableBody');
    if (!tb || !Array.isArray(links)) return;
    if (!links.length) {
      tb.innerHTML = '<tr><td colspan="8" class="text-center text-secondary py-4">No neighbour entries.</td></tr>';
      return;
    }
    tb.innerHTML = links.map(l => {
      const localName = esc(l.local_name || l.local_ip || '');
      const localCell = l.local_subnet_id
        ? '<a href="/?page=subnet_view&id=' + encodeURIComponent(l.local_subnet_id) + '">' + localName + '</a>'
        : localName;
      return '<tr>'
        + '<td><span class="badge text-bg-warning">arp</span></td>'
        + '<td>' + localCell + '<div class="small text-secondary"><code>' + esc(l.local_ip || '') + '</code></div></td>'
        + '<td><code class="small">' + esc(l.local_port || '—') + '</code></td>'
        + '<td>' + esc(l.remote_name || '—') + '</td>'
        + '<td><code class="small">' + esc(l.remote_port || '—') + '</code></td>'
        + '<td><code class="small">' + esc(l.remote_ip || '—') + '</code></td>'
        + '<td class="text-secondary small">' + esc(l.remote_descr || '—') + '</td>'
        + '<td class="small text-secondary">' + esc(l.last_seen || '') + '</td>'
        + '</tr>';
    }).join('');
  }

  function renderTopo(data) {
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const W = svg.clientWidth || 900;

    // ---- seed positions on a circle, then relax with a small force sim ----
    const nodes = data.nodes.map((n, i) => {
      const a = (i / data.nodes.length) * Math.PI * 2;
      return Object.assign({}, n, {
        x: W / 2 + Math.cos(a) * Math.min(W, H) * 0.32,
        y: H / 2 + Math.sin(a) * Math.min(W, H) * 0.32,
        vx: 0, vy: 0
      });
    });
    const index = new Map(nodes.map(n => [n.id, n]));
    const edges = data.edges.filter(e => index.has(e.source) && index.has(e.target));

    for (let iter = 0; iter < 320; iter++) {
      // repulsion
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          let dx = a.x - b.x, dy = a.y - b.y;
          let d2 = dx * dx + dy * dy || 0.01;
          const f = 5200 / d2;
          const d = Math.sqrt(d2);
          const ux = dx / d, uy = dy / d;
          a.vx += ux * f; a.vy += uy * f;
          b.vx -= ux * f; b.vy -= uy * f;
        }
      }
      // springs
      edges.forEach(e => {
        const a = index.get(e.source), b = index.get(e.target);
        const dx = b.x - a.x, dy = b.y - a.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const f = (d - 130) * 0.02;
        const ux = dx / d, uy = dy / d;
        a.vx += ux * f; a.vy += uy * f;
        b.vx -= ux * f; b.vy -= uy * f;
      });
      // centre pull + integrate
      nodes.forEach(n => {
        n.vx += (W / 2 - n.x) * 0.002;
        n.vy += (H / 2 - n.y) * 0.002;
        n.x += n.vx * 0.5; n.y += n.vy * 0.5;
        n.vx *= 0.82; n.vy *= 0.82;
        n.x = Math.max(40, Math.min(W - 40, n.x));
        n.y = Math.max(30, Math.min(H - 30, n.y));
      });
    }

    const root = document.createElementNS(NS, 'g');
    svg.appendChild(root);
    const gEdges = document.createElementNS(NS, 'g');
    const gNodes = document.createElementNS(NS, 'g');
    root.appendChild(gEdges); root.appendChild(gNodes);

    const pan = { x: 0, y: 0, k: 1 };
    function draw() {
      root.setAttribute('transform', 'translate(' + pan.x + ',' + pan.y + ') scale(' + pan.k + ')');
      edgeEls.forEach(({ el, e }) => {
        const a = index.get(e.source), b = index.get(e.target);
        el.setAttribute('x1', a.x); el.setAttribute('y1', a.y);
        el.setAttribute('x2', b.x); el.setAttribute('y2', b.y);
      });
      nodeEls.forEach(({ g, n }) => g.setAttribute('transform', 'translate(' + n.x + ',' + n.y + ')'));
    }
    view = { pan, draw, dragNode: null, panning: false, sx: 0, sy: 0 };

    const edgeColors = data.colors || {};
    const edgeEls = edges.map(e => {
      const line = document.createElementNS(NS, 'line');
      line.setAttribute('stroke', edgeColors[e.protocol] || '#f59e0b');
      line.setAttribute('stroke-width', '1.6');
      line.setAttribute('stroke-opacity', '.55');
      gEdges.appendChild(line);
      return { el: line, e };
    });

    const nodeEls = nodes.map(n => {
      const g = document.createElementNS(NS, 'g');
      g.setAttribute('cursor', 'pointer');

      const c = document.createElementNS(NS, 'circle');
      c.setAttribute('r', String(Math.min(20, 9 + n.degree)));
      c.setAttribute('fill', n.managed ? '#8b5cf6' : '#4b5563');
      c.setAttribute('stroke', '#0b0b12');
      c.setAttribute('stroke-width', '2');
      g.appendChild(c);

      const t = document.createElementNS(NS, 'text');
      t.textContent = String(n.label || '').length > 22 ? String(n.label).slice(0, 21) + '…' : (n.label || '');
      t.setAttribute('font-size', '11');
      t.setAttribute('text-anchor', 'middle');
      t.setAttribute('fill', 'currentColor');
      t.setAttribute('y', '-16');
      g.appendChild(t);

      if (tip) {
        g.addEventListener('mouseenter', () => {
          tip.classList.remove('d-none');
          tip.innerHTML = '<strong>' + esc(n.label) + '</strong>'
            + (n.ip ? '<br><code>' + esc(n.ip) + '</code>' : '')
            + (n.descr ? '<br><span class="text-secondary">' + esc(n.descr) + '</span>' : '')
            + '<br><span class="text-secondary">' + n.degree + ' link(s)'
            + (n.managed ? ' · managed' : ' · discovered') + '</span>';
        });
        g.addEventListener('mousemove', ev => {
          const r = svg.getBoundingClientRect();
          tip.style.left = (ev.clientX - r.left + 12) + 'px';
          tip.style.top  = (ev.clientY - r.top + 12) + 'px';
        });
        g.addEventListener('mouseleave', () => tip.classList.add('d-none'));
      }
      g.addEventListener('click', () => {
        if (n.subnet_id) location.href = '/?page=subnet_view&id=' + n.subnet_id;
      });

      // drag (shared window mousemove does the moving)
      g.addEventListener('mousedown', ev => {
        if (view) view.dragNode = n;
        ev.preventDefault();
      });

      gNodes.appendChild(g);
      return { g, n };
    });

    draw();
    updateStats(data.stats);
    updateTable(data.links);
    if (updatedEl) updatedEl.textContent = 'Updated ' + new Date().toLocaleTimeString();
  }

  if (btn) {
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      const orig = btn.innerHTML;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Refreshing…';
      if (updatedEl) updatedEl.textContent = '';
      try {
        const res = await fetch('?page=topology&format=json', { headers: { 'Accept': 'application/json' } });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        if (!data || !Array.isArray(data.edges) || !data.edges.length) {
          // Nothing to draw — let the server render the empty state.
          location.reload();
          return;
        }
        renderTopo(data);
      } catch (err) {
        if (updatedEl) updatedEl.textContent = 'Refresh failed: ' + err.message;
      } finally {
        btn.disabled = false;
        btn.innerHTML = orig;
      }
    });
  }

  renderTopo(<?= $payload ?>);
})();
</script>
<?php endif; ?>
