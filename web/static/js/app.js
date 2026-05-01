// SürümKapısı — Client-Side JS Utilities

document.addEventListener('DOMContentLoaded', () => {
  // Mobile sidebar toggle
  const toggle = document.getElementById('sidebar-toggle');
  const sidebar = document.querySelector('.sidebar');
  if (toggle && sidebar) {
    toggle.addEventListener('click', () => sidebar.classList.toggle('open'));
  }

  // Auto-refresh timestamps as relative
  document.querySelectorAll('[data-time]').forEach(el => {
    const t = new Date(el.getAttribute('data-time'));
    el.textContent = timeAgo(t);
    el.title = t.toLocaleString('tr-TR');
  });

  // Animate stat numbers on load
  document.querySelectorAll('.stat-value[data-count]').forEach(el => {
    const target = parseInt(el.dataset.count);
    animateCount(el, 0, target, 800);
  });

  // Animate progress rings
  document.querySelectorAll('.progress-ring .fill').forEach(circle => {
    const pct = parseFloat(circle.dataset.pct) || 0;
    const r = circle.r.baseVal.value;
    const circ = 2 * Math.PI * r;
    circle.style.strokeDasharray = circ;
    circle.style.strokeDashoffset = circ;
    requestAnimationFrame(() => {
      circle.style.strokeDashoffset = circ - (pct / 100) * circ;
    });
  });

  // Clipboard copy
  document.querySelectorAll('[data-copy]').forEach(el => {
    el.style.cursor = 'pointer';
    el.title = 'Kopyalamak için tıklayın';
    el.addEventListener('click', () => {
      navigator.clipboard.writeText(el.dataset.copy || el.textContent);
      showToast('Panoya kopyalandı ✓');
    });
  });

  // Search filter for tables
  const search = document.getElementById('table-search');
  if (search) {
    search.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase();
      document.querySelectorAll('tbody tr').forEach(tr => {
        tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  }
});

function timeAgo(date) {
  const seconds = Math.floor((new Date() - date) / 1000);
  if (seconds < 60) return 'Az önce';
  if (seconds < 3600) return Math.floor(seconds / 60) + ' dk önce';
  if (seconds < 86400) return Math.floor(seconds / 3600) + ' saat önce';
  if (seconds < 2592000) return Math.floor(seconds / 86400) + ' gün önce';
  return date.toLocaleDateString('tr-TR');
}

function animateCount(el, start, end, duration) {
  const range = end - start;
  const startTime = performance.now();
  function tick(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const ease = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.floor(start + range * ease);
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function showToast(msg) {
  const t = document.createElement('div');
  t.style.cssText = `
    position:fixed;bottom:24px;right:24px;
    background:rgba(34,197,94,0.9);color:#fff;
    padding:12px 20px;border-radius:10px;
    font-size:0.88rem;font-weight:600;
    box-shadow:0 4px 20px rgba(0,0,0,0.3);
    z-index:9999;animation:fadeIn 0.3s ease;
  `;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity 0.3s'; }, 2000);
  setTimeout(() => t.remove(), 2500);
}
