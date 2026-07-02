/**
 * web/dist/js/dashboard-common.js
 * Shared utilities used by all dashboard pages.
 */

// ── Auth guard ───────────────────────────────────────────
(async function guardAuth() {
  try {
    const sessionData = await API.auth.session();
    if (!sessionData) {
      window.location.href = '/admin/login';
      return;
    }
    // Store session info for use by dashboard pages
    sessionStorage.setItem('user_id',  sessionData.user_id);
    sessionStorage.setItem('username', sessionData.username);
    sessionStorage.setItem('email',    sessionData.email);
    sessionStorage.setItem('app_role', sessionData.app_role);
    sessionStorage.setItem('realm',    sessionData.realm);

    // Populate user info in nav
    const username = sessionData.username || 'User';
    const avatarEl = document.getElementById('avatar-btn');
    if (avatarEl) {
      avatarEl.textContent = (username[0] || 'U').toUpperCase();
    }
    const menuUsr = document.getElementById('menu-username');
    const menuEml = document.getElementById('menu-email');
    if (menuUsr) menuUsr.textContent = sessionData.username;
    if (menuEml) menuEml.textContent = sessionData.email;
  } catch (err) {
    // Session invalid or expired – redirect to admin login
    sessionStorage.clear();
    window.location.href = '/admin/login';
  }
})();

// ── Avatar dropdown ──────────────────────────────────────
const avatarBtn = document.getElementById('avatar-btn');
const userMenu  = document.getElementById('user-menu');
if (avatarBtn && userMenu) {
  avatarBtn.addEventListener('click', () => {
    const open = !userMenu.hidden;
    userMenu.hidden = open;
    avatarBtn.setAttribute('aria-expanded', String(!open));
  });
  document.addEventListener('click', (e) => {
    if (!avatarBtn.contains(e.target) && !userMenu.contains(e.target)) {
      userMenu.hidden = true;
      avatarBtn.setAttribute('aria-expanded', 'false');
    }
  });
}

// ── Logout ───────────────────────────────────────────────
const logoutBtn = document.getElementById('btn-logout');
if (logoutBtn) {
  logoutBtn.addEventListener('click', async () => {
    try { await API.auth.logout(); } catch (_) {}
    sessionStorage.clear();
    window.location.href = '/admin/login';
  });
}

// ── Page navigation ──────────────────────────────────────
/**
 * Show a named page section and update the active nav item.
 * @param {string} pageName – the value of data-page on the nav button
 */
function showPage(pageName) {
  document.querySelectorAll('[id^="page-"]').forEach(el => { el.hidden = true; });
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));

  const page = document.getElementById('page-' + pageName);
  if (page) page.hidden = false;

  const navBtn = document.querySelector(`[data-page="${pageName}"]`);
  if (navBtn) navBtn.classList.add('active');
}

document.querySelectorAll('.nav-item[data-page]').forEach(btn => {
  btn.addEventListener('click', () => showPage(btn.dataset.page));
});

// ── Toast notifications ──────────────────────────────────
function toast(message, type = 'success') {
  const el = document.createElement('div');
  el.className = `alert alert-${type}`;
  el.textContent = message;
  Object.assign(el.style, {
    position: 'fixed', bottom: '24px', right: '24px',
    zIndex: '9999', maxWidth: '360px',
    animation: 'slideUp 0.25s ease',
    boxShadow: 'var(--shadow-lg)',
  });
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

// ── Confirm modal helper ─────────────────────────────────
function confirm(title, message) {
  return new Promise((resolve) => {
    const modal    = document.getElementById('confirm-modal');
    const titleEl  = document.getElementById('confirm-title');
    const msgEl    = document.getElementById('confirm-message');
    const okBtn    = document.getElementById('confirm-ok');
    const cancelBtn = document.getElementById('confirm-cancel');

    if (!modal) { resolve(false); return; }

    titleEl.textContent = title;
    msgEl.textContent   = message;
    modal.hidden = false;

    function cleanup(val) {
      modal.hidden = true;
      okBtn.removeEventListener('click', onOk);
      cancelBtn.removeEventListener('click', onCancel);
      resolve(val);
    }
    const onOk     = () => cleanup(true);
    const onCancel = () => cleanup(false);

    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onCancel);
  });
}

// ── Formatting helpers ───────────────────────────────────
function fmtDate(dateStr) {
  if (!dateStr) return '–';
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function statusBadge(status) {
  const map = {
    active:    '<span class="badge badge-active">● Active</span>',
    suspended: '<span class="badge badge-suspended">⏸ Suspended</span>',
    deleted:   '<span class="badge badge-deleted">✕ Deleted</span>',
  };
  return map[status] || `<span class="badge">${status}</span>`;
}

function roleBadge(role) {
  const map = {
    super_admin: '<span class="badge badge-super">⭐ Super Admin</span>',
    realm_admin: '<span class="badge badge-admin">🔑 Realm Admin</span>',
    end_user:    '<span class="badge badge-user">👤 User</span>',
  };
  return map[role] || `<span class="badge">${role}</span>`;
}

function planBadge(plan) {
  const colors = { free:'badge-user', starter:'badge-admin', pro:'badge-super', enterprise:'badge-super' };
  return `<span class="badge ${colors[plan] || 'badge-user'}">${plan}</span>`;
}

// ── Pagination renderer ──────────────────────────────────
function renderPagination(containerId, total, limit, offset, onPageChange) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = '';

  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;
  if (totalPages <= 1) return;

  const prevBtn = document.createElement('button');
  prevBtn.textContent = '← Prev';
  prevBtn.disabled = currentPage === 1;
  prevBtn.addEventListener('click', () => onPageChange((currentPage - 2) * limit));
  container.appendChild(prevBtn);

  const info = document.createElement('span');
  info.style.cssText = 'font-size:.85rem;color:var(--clr-text-muted);padding:0 8px';
  info.textContent = `Page ${currentPage} of ${totalPages} (${total} total)`;
  container.appendChild(info);

  const nextBtn = document.createElement('button');
  nextBtn.textContent = 'Next →';
  nextBtn.disabled = currentPage === totalPages;
  nextBtn.addEventListener('click', () => onPageChange(currentPage * limit));
  container.appendChild(nextBtn);
}
