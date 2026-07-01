/**
 * web/dist/js/super-admin.js
 * Super Admin Dashboard logic.
 * Manages tenants, stats, audit logs, and tenant creation.
 */
(() => {
  let tenantsOffset = 0;
  const LIMIT = 20;

  // ── Init ─────────────────────────────────────────────────
  async function init() {
    await loadDashboardStats();
    await loadRecentTenants();
    wireButtons();
    wireCreateTenantForm();
    wireAuditPage();
  }

  // ── Dashboard Stats ──────────────────────────────────────
  async function loadDashboardStats() {
    try {
      const res = await API.tenants.list({ limit: 200 });
      const tenantList = res.data || [];
      const meta = res.meta || {};
      const total = meta.total || tenantList.length;
      const active = tenantList.filter(t => t.status === 'active').length;
      const suspended = tenantList.filter(t => t.status === 'suspended').length;

      document.getElementById('stat-tenants').textContent = total;
      document.getElementById('stat-tenants-sub').textContent = `${tenantList.length} shown`;
      document.getElementById('stat-active').textContent    = active;
      document.getElementById('stat-suspended').textContent = suspended;
    } catch (err) {
      console.error('Failed to load stats:', err);
    }
  }

  // ── Recent Tenants ───────────────────────────────────────
  async function loadRecentTenants() {
    const tbody = document.getElementById('dashboard-tenants-body');
    try {
      const res = await API.tenants.list({ limit: 10 });
      const tenants = res.data || [];
      tbody.innerHTML = tenants.length === 0
        ? '<tr><td colspan="6" style="text-align:center;padding:32px;color:var(--clr-text-faint)">No tenants yet. Create your first tenant!</td></tr>'
        : tenants.map(t => `
          <tr>
            <td><strong>${escHtml(t.name)}</strong></td>
            <td><code style="font-size:.8rem;background:var(--clr-surface-3);padding:2px 6px;border-radius:4px">${escHtml(t.realm_name)}</code></td>
            <td>${planBadge(t.plan)}</td>
            <td>${statusBadge(t.status)}</td>
            <td class="text-faint">${fmtDate(t.created_at)}</td>
            <td>
              <div class="flex gap-1">
                <button class="btn btn-secondary btn-sm" onclick="viewTenantDetail('${t.id}')">View</button>
                ${t.status === 'active'
                  ? `<button class="btn btn-sm" style="background:rgba(245,158,11,.15);color:#fde68a;border:1px solid rgba(245,158,11,.3)" onclick="suspendTenant('${t.id}','${escHtml(t.name)}')">Suspend</button>`
                  : `<button class="btn btn-sm" style="background:rgba(16,185,129,.15);color:#6ee7b7;border:1px solid rgba(16,185,129,.3)" onclick="enableTenant('${t.id}','${escHtml(t.name)}')">Enable</button>`
                }
                <button class="btn btn-danger btn-sm" onclick="deleteTenant('${t.id}','${escHtml(t.name)}')">Delete</button>
              </div>
            </td>
          </tr>`).join('');
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-danger" style="padding:16px">Error: ${escHtml(err.message)}</td></tr>`;
    }
  }

  // ── Full Tenants List ────────────────────────────────────
  async function loadTenants(offset = 0) {
    tenantsOffset = offset;
    const tbody  = document.getElementById('tenants-body');
    const search = document.getElementById('tenant-search')?.value || '';
    const status = document.getElementById('tenant-status-filter')?.value || '';

    tbody.innerHTML = '<tr><td colspan="8"><div class="skeleton skeleton-row"></div></td></tr>';

    try {
      const params = { limit: LIMIT, offset };
      if (status) params.status = status;
      const res = await API.tenants.list(params);
      const tenants = (res.data || []).filter(t =>
        !search || t.name.toLowerCase().includes(search.toLowerCase()) ||
        t.realm_name.toLowerCase().includes(search.toLowerCase())
      );
      const total = res.meta?.total || tenants.length;

      tbody.innerHTML = tenants.length === 0
        ? `<tr><td colspan="8"><div class="empty-state"><div class="empty-icon">🏢</div><h3>No tenants found</h3><p>Try a different filter</p></div></td></tr>`
        : tenants.map(t => `
          <tr>
            <td><strong>${escHtml(t.name)}</strong><br/><small class="text-faint">${t.id}</small></td>
            <td><code style="font-size:.8rem">${escHtml(t.realm_name)}</code></td>
            <td class="text-muted">${escHtml(t.domain || '–')}</td>
            <td>${planBadge(t.plan)}</td>
            <td class="text-muted">${t.user_count ?? '–'}</td>
            <td>${statusBadge(t.status)}</td>
            <td class="text-faint">${fmtDate(t.created_at)}</td>
            <td>
              <div class="flex gap-1">
                ${t.status === 'active'
                  ? `<button class="btn btn-sm btn-secondary" onclick="suspendTenant('${t.id}','${escHtml(t.name)}')">Suspend</button>`
                  : `<button class="btn btn-sm btn-success"   onclick="enableTenant('${t.id}','${escHtml(t.name)}')">Enable</button>`
                }
                <button class="btn btn-sm btn-danger" onclick="deleteTenant('${t.id}','${escHtml(t.name)}')">Delete</button>
              </div>
            </td>
          </tr>`).join('');

      renderPagination('tenants-pagination', total, LIMIT, offset, loadTenants);
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="8" class="text-danger" style="padding:16px">Error: ${escHtml(err.message)}</td></tr>`;
    }
  }

  // ── Tenant actions ────────────────────────────────────────
  window.suspendTenant = async (id, name) => {
    const ok = await confirm('Suspend Tenant', `Suspend "${name}"? Users will not be able to log in.`);
    if (!ok) return;
    try {
      await API.tenants.suspend(id);
      toast(`Tenant "${name}" suspended`);
      loadTenants(tenantsOffset);
      loadDashboardStats();
    } catch (err) {
      toast(err.message, 'error');
    }
  };

  window.enableTenant = async (id, name) => {
    try {
      await API.tenants.enable(id);
      toast(`Tenant "${name}" re-enabled`);
      loadTenants(tenantsOffset);
      loadDashboardStats();
    } catch (err) {
      toast(err.message, 'error');
    }
  };

  window.deleteTenant = async (id, name) => {
    const ok = await confirm('Delete Tenant', `Permanently delete "${name}"? This will delete the Keycloak realm and ALL data.`);
    if (!ok) return;
    try {
      await API.tenants.delete(id);
      toast(`Tenant "${name}" deleted`);
      loadTenants(tenantsOffset);
      loadDashboardStats();
    } catch (err) {
      toast(err.message, 'error');
    }
  };

  // ── Create tenant form ────────────────────────────────────
  function wireCreateTenantForm() {
    const form = document.getElementById('create-tenant-form');
    if (!form) return;

    // Auto-generate realm name from display name
    const nameInput  = document.getElementById('ct-name');
    const realmInput = document.getElementById('ct-realm');
    nameInput?.addEventListener('input', () => {
      realmInput.value = nameInput.value
        .toLowerCase().trim()
        .replace(/[^a-z0-9\s-]/g, '')
        .replace(/\s+/g, '-');
    });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const alertEl   = document.getElementById('create-tenant-alert');
      const successEl = document.getElementById('create-tenant-success');
      const btnText   = document.getElementById('ct-btn-text');
      const spinner   = document.getElementById('ct-spinner');

      alertEl.hidden = successEl.hidden = true;
      btnText.textContent = 'Creating…';
      spinner.hidden = false;

      const data = {
        name:       document.getElementById('ct-name').value.trim(),
        realm_name: document.getElementById('ct-realm').value.trim(),
        domain:     document.getElementById('ct-domain').value.trim(),
        plan:       document.getElementById('ct-plan').value,
        settings: {
          max_users: parseInt(document.getElementById('ct-max-users').value) || 0,
        },
      };

      try {
        await API.tenants.create(data);
        successEl.textContent = `Tenant "${data.name}" created successfully! Realm: ${data.realm_name}`;
        successEl.hidden = false;
        form.reset();
        loadDashboardStats();
        toast(`Tenant "${data.name}" created!`);
      } catch (err) {
        alertEl.textContent = err.message;
        alertEl.hidden = false;
      } finally {
        btnText.textContent = 'Create Tenant';
        spinner.hidden = true;
      }
    });
  }

  // ── Audit logs ────────────────────────────────────────────
  function wireAuditPage() {
    document.getElementById('nav-audit')?.addEventListener('click', () => loadAuditLogs(0));
    document.getElementById('audit-action-filter')?.addEventListener('change', () => loadAuditLogs(0));
  }

  async function loadAuditLogs(offset = 0) {
    const tbody  = document.getElementById('audit-body');
    const action = document.getElementById('audit-action-filter')?.value || '';
    const tenantId = document.getElementById('audit-tenant-filter')?.value || '';

    tbody.innerHTML = '<tr><td colspan="7"><div class="skeleton skeleton-row"></div></td></tr>';

    try {
      const params = { limit: LIMIT, offset };
      if (action) params.action = action;
      if (tenantId) params.tenant_id = tenantId;
      const res = await API.audit.list(params);
      const logs = res.data || [];
      const total = res.meta?.total || logs.length;

      tbody.innerHTML = logs.length === 0
        ? `<tr><td colspan="7"><div class="empty-state"><div class="empty-icon">📋</div><h3>No audit logs</h3></div></td></tr>`
        : logs.map(log => `
          <tr>
            <td class="text-faint" style="white-space:nowrap">${fmtDate(log.created_at)}</td>
            <td>${escHtml(log.actor_email)}</td>
            <td>${roleBadge(log.actor_role)}</td>
            <td><code style="font-size:.78rem">${escHtml(log.action)}</code></td>
            <td class="text-muted">${escHtml(log.resource_type)}${log.resource_id ? `: <span class="text-faint">${log.resource_id.substring(0,8)}…</span>` : ''}</td>
            <td><span class="badge ${log.status==='success' ? 'badge-active':'badge-deleted'}">${log.status}</span></td>
            <td class="text-faint">${escHtml(log.ip_address || '–')}</td>
          </tr>`).join('');

      renderPagination('audit-pagination', total, LIMIT, offset, loadAuditLogs);
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-danger" style="padding:16px">Error: ${escHtml(err.message)}</td></tr>`;
    }
  }

  // ── Wire buttons ──────────────────────────────────────────
  function wireButtons() {
    document.getElementById('btn-new-tenant')?.addEventListener('click', () => showPage('create-tenant'));
    document.getElementById('btn-create-tenant-from-list')?.addEventListener('click', () => showPage('create-tenant'));
    document.getElementById('btn-view-all-tenants')?.addEventListener('click', () => {
      showPage('tenants');
      loadTenants(0);
    });
    document.getElementById('nav-tenants')?.addEventListener('click', () => loadTenants(0));
    document.getElementById('tenant-search')?.addEventListener('input', debounce(() => loadTenants(0), 300));
    document.getElementById('tenant-status-filter')?.addEventListener('change', () => loadTenants(0));
  }

  // ── Utilities ─────────────────────────────────────────────
  function escHtml(str) {
    return String(str || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'})[c]);
  }

  function debounce(fn, ms) {
    let tid;
    return (...args) => { clearTimeout(tid); tid = setTimeout(() => fn(...args), ms); };
  }

  // ── Boot ──────────────────────────────────────────────────
  init();
})();
