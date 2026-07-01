/**
 * web/dist/js/realm-admin.js
 * Realm Admin Dashboard logic: users, groups, roles, sessions, audit, profile.
 */
(() => {
  const realm = sessionStorage.getItem('realm') || 'master';
  let usersOffset = 0;
  const LIMIT = 20;

  // ── Init ──────────────────────────────────────────────────
  async function init() {
    document.getElementById('realm-badge-label').textContent = `🏢 ${realm}`;
    document.getElementById('stat-realm').textContent = realm;
    document.getElementById('dashboard-subtitle').textContent = `Managing realm: ${realm}`;

    await Promise.all([loadDashboardStats(), loadRecentUsers()]);
    wireCreateUserForm();
    wireGroupsPage();
    wireRolesPage();
    wireSessionsPage();
    wireAuditPage();
    wireProfilePage();

    // Wire nav items to their load functions
    document.querySelector('[data-page="users"]')?.addEventListener('click',    () => loadUsers(0));
    document.querySelector('[data-page="groups"]')?.addEventListener('click',   () => loadGroups());
    document.querySelector('[data-page="roles"]')?.addEventListener('click',    () => loadRoles());
    document.querySelector('[data-page="audit"]')?.addEventListener('click',    () => loadRealmAudit(0));
    document.querySelector('[data-page="sessions"]')?.addEventListener('click', () => {});
    document.querySelector('[data-page="profile"]')?.addEventListener('click',  () => loadProfile());
  }

  // ── Stats ──────────────────────────────────────────────────
  async function loadDashboardStats() {
    try {
      const [usersRes, groupsRes, rolesRes] = await Promise.all([
        API.users.list(realm, { limit: 1 }),
        API.groups.list(realm),
        API.roles.list(realm),
      ]);
      document.getElementById('stat-users').textContent  = usersRes.meta?.total ?? (usersRes.data?.length ?? '–');
      document.getElementById('stat-groups').textContent = (groupsRes.data || groupsRes)?.length ?? '–';
      document.getElementById('stat-roles').textContent  = (rolesRes.data || rolesRes)?.length ?? '–';
    } catch (err) { console.error('Stats load failed:', err); }
  }

  // ── Recent Users ───────────────────────────────────────────
  async function loadRecentUsers() {
    const tbody = document.getElementById('dashboard-users-body');
    try {
      const res   = await API.users.list(realm, { limit: 8 });
      const users = res.data || [];
      tbody.innerHTML = users.length === 0
        ? `<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--clr-text-faint)">No users yet</td></tr>`
        : users.map(u => userRow(u, 5)).join('');
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="5" class="text-danger" style="padding:12px">Error: ${esc(err.message)}</td></tr>`;
    }
  }

  // ── Full user list ─────────────────────────────────────────
  async function loadUsers(offset = 0) {
    usersOffset = offset;
    const tbody  = document.getElementById('users-body');
    const search = document.getElementById('user-search')?.value || '';
    tbody.innerHTML = '<tr><td colspan="6"><div class="skeleton skeleton-row"></div></td></tr>';
    try {
      const params = { limit: LIMIT, offset };
      if (search) params.search = search;
      const res   = await API.users.list(realm, params);
      const users = res.data || [];
      const total = res.meta?.total || users.length;
      tbody.innerHTML = users.length === 0
        ? `<tr><td colspan="6"><div class="empty-state"><div class="empty-icon">👥</div><h3>No users found</h3></div></td></tr>`
        : users.map(u => userRow(u, 6)).join('');
      renderPagination('users-pagination', total, LIMIT, offset, loadUsers);
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-danger" style="padding:12px">Error: ${esc(err.message)}</td></tr>`;
    }
  }

  function userRow(u, cols) {
    const name = [u.first_name, u.last_name].filter(Boolean).join(' ') || u.username || '–';
    const enabled = u.enabled
      ? '<span class="badge badge-active">Active</span>'
      : '<span class="badge badge-deleted">Disabled</span>';
    const actions = `
      <div class="flex gap-1">
        <button class="btn btn-sm btn-secondary" onclick="editUser('${u.id}')">Edit</button>
        <button class="btn btn-sm ${u.enabled ? 'btn-secondary' : 'btn-success'}" onclick="toggleUser('${u.id}',${!u.enabled})">
          ${u.enabled ? 'Disable' : 'Enable'}
        </button>
        <button class="btn btn-sm btn-danger" onclick="deleteUser('${u.id}','${esc(u.email)}')">Delete</button>
      </div>`;
    if (cols === 5) {
      return `<tr><td>${esc(name)}</td><td>${esc(u.email)}</td><td>${esc(u.username)}</td><td>${enabled}</td><td>${actions}</td></tr>`;
    }
    return `<tr><td>${esc(name)}</td><td>${esc(u.email)}</td><td>${esc(u.username)}</td><td>${enabled}</td><td class="text-faint">${fmtDate(u.created_at)}</td><td>${actions}</td></tr>`;
  }

  window.toggleUser = async (id, enabled) => {
    try {
      await API.users.setEnabled(realm, id, enabled);
      toast(`User ${enabled ? 'enabled' : 'disabled'}`);
      loadUsers(usersOffset);
    } catch (err) { toast(err.message, 'error'); }
  };

  window.deleteUser = async (id, email) => {
    const ok = await confirm('Delete User', `Permanently delete user "${email}"?`);
    if (!ok) return;
    try { await API.users.delete(realm, id); toast('User deleted'); loadUsers(usersOffset); }
    catch (err) { toast(err.message, 'error'); }
  };

  window.editUser = (id) => {
    // Navigate to user detail – simplified: show reset-password prompt
    const pwd = prompt('Enter new password for user (leave blank to cancel):');
    if (!pwd) return;
    API.users.resetPassword(realm, id, pwd, false)
      .then(() => toast('Password reset successfully'))
      .catch(err => toast(err.message, 'error'));
  };

  // ── Create User form ───────────────────────────────────────
  function wireCreateUserForm() {
    const form = document.getElementById('create-user-form');
    form?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const alertEl   = document.getElementById('cu-alert');
      const successEl = document.getElementById('cu-success');
      const btnText   = document.getElementById('cu-btn-text');
      const spinner   = document.getElementById('cu-spinner');
      alertEl.hidden = successEl.hidden = true;
      btnText.textContent = 'Creating…'; spinner.hidden = false;

      const email = document.getElementById('cu-email').value.trim();
      const pwd   = document.getElementById('cu-password').value;
      if (!email) { alertEl.textContent = 'Email is required'; alertEl.hidden = false; btnText.textContent = 'Create User'; spinner.hidden = true; return; }
      if (pwd.length < 8) { alertEl.textContent = 'Password must be at least 8 characters'; alertEl.hidden = false; btnText.textContent = 'Create User'; spinner.hidden = true; return; }

      try {
        await API.users.create(realm, {
          email,
          username: document.getElementById('cu-username').value.trim() || email,
          first_name: document.getElementById('cu-firstname').value.trim(),
          last_name:  document.getElementById('cu-lastname').value.trim(),
          password:   pwd,
          temporary_password: document.getElementById('cu-temporary').checked,
          enabled:    document.getElementById('cu-enabled').checked,
        });
        successEl.textContent = `User "${email}" created successfully!`;
        successEl.hidden = false;
        form.reset();
        loadDashboardStats();
        toast(`User ${email} created!`);
      } catch (err) {
        alertEl.textContent = err.message; alertEl.hidden = false;
      } finally {
        btnText.textContent = 'Create User'; spinner.hidden = true;
      }
    });

    document.getElementById('user-search')?.addEventListener('input',
      debounce(() => loadUsers(0), 300));
  }

  // ── Groups ─────────────────────────────────────────────────
  function wireGroupsPage() {
    document.getElementById('btn-create-group')?.addEventListener('click', () => {
      document.getElementById('group-modal').hidden = false;
      document.getElementById('new-group-name').focus();
    });
    document.getElementById('group-modal-close')?.addEventListener('click', () => { document.getElementById('group-modal').hidden = true; });
    document.getElementById('group-modal-cancel')?.addEventListener('click', () => { document.getElementById('group-modal').hidden = true; });
    document.getElementById('group-modal-ok')?.addEventListener('click', async () => {
      const name = document.getElementById('new-group-name').value.trim();
      if (!name) return;
      try {
        await API.groups.create(realm, name);
        document.getElementById('group-modal').hidden = true;
        document.getElementById('new-group-name').value = '';
        toast(`Group "${name}" created`);
        loadGroups();
      } catch (err) { toast(err.message, 'error'); }
    });
  }

  async function loadGroups() {
    const tbody = document.getElementById('groups-body');
    tbody.innerHTML = '<tr><td colspan="3"><div class="skeleton skeleton-row"></div></td></tr>';
    try {
      const res    = await API.groups.list(realm);
      const groups = res.data || res || [];
      tbody.innerHTML = groups.length === 0
        ? `<tr><td colspan="3"><div class="empty-state"><div class="empty-icon">📁</div><h3>No groups yet</h3></div></td></tr>`
        : groups.map(g => `
          <tr>
            <td><strong>${esc(g.name)}</strong></td>
            <td class="text-faint"><code style="font-size:.8rem">${esc(g.path || '/' + g.name)}</code></td>
            <td>
              <div class="flex gap-1">
                <button class="btn btn-sm btn-danger" onclick="deleteGroup('${g.id}','${esc(g.name)}')">Delete</button>
              </div>
            </td>
          </tr>`).join('');
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="3" class="text-danger">${esc(err.message)}</td></tr>`;
    }
  }

  window.deleteGroup = async (id, name) => {
    const ok = await confirm('Delete Group', `Delete group "${name}"?`);
    if (!ok) return;
    try { await API.groups.delete(realm, id); toast(`Group "${name}" deleted`); loadGroups(); }
    catch (err) { toast(err.message, 'error'); }
  };

  // ── Roles ──────────────────────────────────────────────────
  function wireRolesPage() {
    document.getElementById('btn-create-role')?.addEventListener('click', () => {
      document.getElementById('role-modal').hidden = false;
      document.getElementById('new-role-name').focus();
    });
    document.getElementById('role-modal-close')?.addEventListener('click',  () => { document.getElementById('role-modal').hidden = true; });
    document.getElementById('role-modal-cancel')?.addEventListener('click', () => { document.getElementById('role-modal').hidden = true; });
    document.getElementById('role-modal-ok')?.addEventListener('click', async () => {
      const name = document.getElementById('new-role-name').value.trim();
      const desc = document.getElementById('new-role-desc').value.trim();
      if (!name) return;
      try {
        await API.roles.create(realm, name, desc);
        document.getElementById('role-modal').hidden = true;
        document.getElementById('new-role-name').value = '';
        document.getElementById('new-role-desc').value = '';
        toast(`Role "${name}" created`);
        loadRoles();
      } catch (err) { toast(err.message, 'error'); }
    });
  }

  async function loadRoles() {
    const tbody = document.getElementById('roles-body');
    tbody.innerHTML = '<tr><td colspan="4"><div class="skeleton skeleton-row"></div></td></tr>';
    try {
      const res   = await API.roles.list(realm);
      const roles = res.data || res || [];
      tbody.innerHTML = roles.length === 0
        ? `<tr><td colspan="4"><div class="empty-state"><div class="empty-icon">🎭</div><h3>No roles yet</h3></div></td></tr>`
        : roles.map(r => `
          <tr>
            <td><strong>${esc(r.name)}</strong></td>
            <td class="text-muted">${esc(r.description || '–')}</td>
            <td>${r.composite ? '✅' : '–'}</td>
            <td>
              ${!r.clientRole ? `<button class="btn btn-sm btn-danger" onclick="deleteRole('${esc(r.name)}')">Delete</button>` : '<span class="text-faint">System</span>'}
            </td>
          </tr>`).join('');
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="4" class="text-danger">${esc(err.message)}</td></tr>`;
    }
  }

  window.deleteRole = async (name) => {
    const ok = await confirm('Delete Role', `Delete role "${name}"?`);
    if (!ok) return;
    try { await API.roles.delete(realm, name); toast(`Role "${name}" deleted`); loadRoles(); }
    catch (err) { toast(err.message, 'error'); }
  };

  // ── Sessions ───────────────────────────────────────────────
  function wireSessionsPage() {
    document.getElementById('btn-load-sessions')?.addEventListener('click', async () => {
      const uid   = document.getElementById('session-user-id').value.trim();
      const tbody = document.getElementById('sessions-body');
      if (!uid) return;
      tbody.innerHTML = '<tr><td colspan="5"><div class="skeleton skeleton-row"></div></td></tr>';
      try {
        const res = await API.users.getSessions(realm, uid);
        const sessions = res.data || [];
        tbody.innerHTML = sessions.length === 0
          ? `<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--clr-text-faint)">No active sessions</td></tr>`
          : sessions.map(s => `
            <tr>
              <td class="text-faint"><code style="font-size:.78rem">${esc(s.id?.substring(0,16))}…</code></td>
              <td>${esc(s.ip_address)}</td>
              <td>${fmtDate(s.started)}</td>
              <td>${fmtDate(s.last_access)}</td>
              <td><button class="btn btn-sm btn-danger" onclick="terminateSession('${esc(s.id)}')">Terminate</button></td>
            </tr>`).join('');
      } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-danger">${esc(err.message)}</td></tr>`;
      }
    });
  }

  window.terminateSession = async (id) => {
    const ok = await confirm('Terminate Session', 'Force-logout this session?');
    if (!ok) return;
    try {
      // Use the realm admin endpoint
      await fetch(`/api/v1/realms/${realm}/sessions/${id}`, { method:'DELETE', credentials:'include', headers:{'X-Tenant-Realm':realm} });
      toast('Session terminated');
      document.getElementById('btn-load-sessions').click();
    } catch (err) { toast(err.message, 'error'); }
  };

  // ── Audit ──────────────────────────────────────────────────
  function wireAuditPage() {}

  async function loadRealmAudit(offset = 0) {
    const tbody = document.getElementById('realm-audit-body');
    tbody.innerHTML = '<tr><td colspan="5"><div class="skeleton skeleton-row"></div></td></tr>';
    try {
      const res  = await API.audit.listForRealm(realm, { limit: LIMIT, offset });
      const logs = res.data || [];
      const total = res.meta?.total || logs.length;
      tbody.innerHTML = logs.length === 0
        ? `<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">📋</div><h3>No audit logs</h3></div></td></tr>`
        : logs.map(log => `
          <tr>
            <td class="text-faint">${fmtDate(log.created_at)}</td>
            <td>${esc(log.actor_email)}</td>
            <td><code style="font-size:.78rem">${esc(log.action)}</code></td>
            <td class="text-muted">${esc(log.resource_type)}: ${esc(log.resource_id || '–')}</td>
            <td><span class="badge ${log.status==='success'?'badge-active':'badge-deleted'}">${log.status}</span></td>
          </tr>`).join('');
      renderPagination('realm-audit-pagination', total, LIMIT, offset, loadRealmAudit);
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="5" class="text-danger">${esc(err.message)}</td></tr>`;
    }
  }

  // ── Profile ────────────────────────────────────────────────
  function wireProfilePage() {
    document.getElementById('profile-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fn = document.getElementById('pf-firstname').value.trim();
      const ln = document.getElementById('pf-lastname').value.trim();
      try {
        await API.profile.update({ first_name: fn, last_name: ln });
        document.getElementById('profile-success').textContent = 'Profile updated!';
        document.getElementById('profile-success').hidden = false;
        setTimeout(() => { document.getElementById('profile-success').hidden = true; }, 3000);
      } catch (err) {
        document.getElementById('profile-alert').textContent = err.message;
        document.getElementById('profile-alert').hidden = false;
      }
    });

    document.getElementById('password-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const pwd = document.getElementById('pf-new-pwd').value;
      if (pwd.length < 8) { toast('Password must be at least 8 characters', 'error'); return; }
      try {
        await API.profile.changePassword(pwd);
        toast('Password changed!');
        document.getElementById('pf-new-pwd').value = '';
      } catch (err) { toast(err.message, 'error'); }
    });
  }

  async function loadProfile() {
    try {
      const res = await API.profile.get();
      const pf  = res.data || res;
      document.getElementById('pf-email').value    = pf.email || '';
      document.getElementById('pf-firstname').value = pf.first_name || '';
      document.getElementById('pf-lastname').value  = pf.last_name  || '';
    } catch (err) { console.error('Profile load failed:', err); }
  }

  // ── Utilities ──────────────────────────────────────────────
  function esc(str) {
    return String(str || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'})[c]);
  }
  function debounce(fn, ms) {
    let tid; return (...args) => { clearTimeout(tid); tid = setTimeout(() => fn(...args), ms); };
  }

  init();
})();
