/* DarkVeda IPAM — client behavior (v5.1 mobile smooth) */
(function () {
  'use strict';

  // ---------- Theme toggle (dark default) ----------
  const root = document.documentElement;
  const saved = localStorage.getItem('dv-theme');
  if (saved === 'light' || saved === 'dark') {
    root.setAttribute('data-bs-theme', saved);
  }

  const toggle = document.getElementById('themeToggle');
  if (toggle) {
    const icon = toggle.querySelector('i');
    const sync = () => {
      const dark = root.getAttribute('data-bs-theme') === 'dark';
      if (icon) icon.className = dark ? 'bi bi-sun' : 'bi bi-moon-stars';
    };
    sync();
    toggle.addEventListener('click', () => {
      const next = root.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-bs-theme', next);
      try { localStorage.setItem('dv-theme', next); } catch (e) {}
      sync();
    });
  }

  // ---------- Mobile sidebar drawer (Android + iPhone) ----------
  const sidebar = document.getElementById('dvSidebar');
  const overlay = document.getElementById('dvOverlay');
  const menuBtn = document.getElementById('dvMenuBtn');
  const closeBtn = document.getElementById('dvCloseBtn');
  const mq = window.matchMedia ? window.matchMedia('(max-width: 991.98px)') : null;

  const isOpen = () => document.body.classList.contains('dv-sidebar-open');
  const openNav = () => {
    document.body.classList.add('dv-sidebar-open');
    if (menuBtn) menuBtn.setAttribute('aria-expanded', 'true');
    if (overlay) overlay.setAttribute('aria-hidden', 'false');
  };
  const closeNav = () => {
    document.body.classList.remove('dv-sidebar-open');
    if (menuBtn) menuBtn.setAttribute('aria-expanded', 'false');
    if (overlay) overlay.setAttribute('aria-hidden', 'true');
  };

  if (menuBtn) menuBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (isOpen()) closeNav(); else openNav();
  });
  if (closeBtn) closeBtn.addEventListener('click', closeNav);
  if (overlay) overlay.addEventListener('click', closeNav);

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && isOpen()) closeNav();
  });

  // Close drawer after tapping a link (mobile only)
  if (sidebar) {
    sidebar.querySelectorAll('.nav-link').forEach((a) => {
      a.addEventListener('click', () => {
        if (mq && mq.matches) closeNav();
      });
    });
    // Keep active item visible on open
    const active = sidebar.querySelector('.nav-link.active');
    if (active && active.scrollIntoView) {
      try { active.scrollIntoView({ block: 'nearest' }); } catch (e) {}
    }
    // Swipe-left on sidebar to close (touch)
    let sx = null;
    sidebar.addEventListener('touchstart', (t) => {
      if (t.touches.length === 1) sx = t.touches[0].clientX;
    }, { passive: true });
    sidebar.addEventListener('touchend', (t) => {
      if (sx === null) return;
      const dx = t.changedTouches[0].clientX - sx;
      if (dx < -60) closeNav();
      sx = null;
    }, { passive: true });
  }

  // Auto-close drawer on resize up to desktop
  if (mq && mq.addEventListener) {
    mq.addEventListener('change', (e) => { if (!e.matches) closeNav(); });
  }

  // ---------- Delete confirmations ----------
  document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (e) => {
      if (!window.confirm(form.dataset.confirm)) e.preventDefault();
    });
  });

  // ---------- Smooth: scroll expanded rows into view on phones ----------
  document.querySelectorAll('[data-bs-toggle="collapse"]').forEach((el) => {
    el.addEventListener('click', () => {
      const sel = el.getAttribute('data-bs-target');
      if (!sel) return;
      const target = document.querySelector(sel);
      if (!target) return;
      // wait for Bootstrap collapse animation, then reveal
      setTimeout(() => {
        try {
          const r = target.getBoundingClientRect();
          const below = r.bottom > window.innerHeight - 16;
          if (below && mq && mq.matches) {
            target.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          }
        } catch (e) {}
      }, 380);
    });
  });

  // ---------- iOS 100vh fix fallback (dvh supported natively, harmless) ----------
  const fixVh = () => {
    try {
      document.documentElement.style.setProperty('--dv-vh', (window.innerHeight * 0.01) + 'px');
    } catch (e) {}
  };
  fixVh();
  window.addEventListener('resize', fixVh, { passive: true });
  window.addEventListener('orientationchange', () => setTimeout(fixVh, 150));
})();
