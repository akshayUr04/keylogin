/**
 * web/dist/js/api.js
 * Centralised API client for all backend REST calls.
 * All methods return Promises.  On authentication errors (401) the user
 * is automatically redirected to the login page.
 */

const API = (() => {
  const BASE = '/api/v1';

  /** Reads the session_id from a cookie (set by the backend on login). */
  function getSessionId() {
    const match = document.cookie.match(/(?:^|;\s*)session_id=([^;]+)/);
    return match ? match[1] : null;
  }

  /** Builds default headers for every request. */
  function headers(extra = {}) {
    const h = { 'Content-Type': 'application/json', ...extra };
    const sid = getSessionId();
    // Include realm header if stored in sessionStorage
    const realm = sessionStorage.getItem('realm');
    if (realm) h['X-Tenant-Realm'] = realm;
    return h;
  }

  /**
   * Core fetch wrapper with automatic error handling.
   * @param {string} path - API path (relative to BASE)
   * @param {RequestInit} opts - fetch options
   */
  async function request(path, opts = {}) {
    opts.headers = { ...headers(), ...opts.headers };
    opts.credentials = 'include'; // send session cookie
    try {
      const res = await fetch(BASE + path, opts);

      // Handle 401 – redirect to login
      if (res.status === 401) {
        sessionStorage.clear();
        window.location.href = '/';
        return;
      }

      // Parse JSON body
      const contentType = res.headers.get('Content-Type') || '';
      const body = contentType.includes('application/json')
        ? await res.json()
        : await res.text();

      if (!res.ok) {
        const err = new Error(body?.message || body || `HTTP ${res.status}`);
        err.status = res.status;
        err.code   = body?.code;
        throw err;
      }
      return body;
    } catch (err) {
      if (err instanceof TypeError) {
        // Network error
        throw new Error('Network error – please check your connection');
      }
      throw err;
    }
  }

  // ── Auth ────────────────────────────────────────────────
  const auth = {
    login(realm, username, password) {
      return request('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ realm, username, password }),
      });
    },
    logout() {
      return request('/auth/logout', { method: 'POST' });
    },
    refresh() {
      return request('/auth/refresh', { method: 'POST' });
    },
    me() {
      return request('/auth/me');
    },
  };

  // ── Tenants (Super Admin) ────────────────────────────────
  const tenants = {
    list(params = {}) {
      const q = new URLSearchParams(params).toString();
      return request(`/admin/tenants${q ? '?' + q : ''}`);
    },
    get(id) {
      return request(`/admin/tenants/${id}`);
    },
    create(data) {
      return request('/admin/tenants', { method: 'POST', body: JSON.stringify(data) });
    },
    delete(id) {
      return request(`/admin/tenants/${id}`, { method: 'DELETE' });
    },
    suspend(id) {
      return request(`/admin/tenants/${id}/suspend`, { method: 'POST' });
    },
    enable(id) {
      return request(`/admin/tenants/${id}/enable`, { method: 'POST' });
    },
  };

  // ── Users ────────────────────────────────────────────────
  const users = {
    list(realm, params = {}) {
      const q = new URLSearchParams(params).toString();
      return request(`/realms/${realm}/users${q ? '?' + q : ''}`);
    },
    get(realm, id) {
      return request(`/realms/${realm}/users/${id}`);
    },
    create(realm, data) {
      return request(`/realms/${realm}/users`, { method: 'POST', body: JSON.stringify(data) });
    },
    update(realm, id, data) {
      return request(`/realms/${realm}/users/${id}`, { method: 'PUT', body: JSON.stringify(data) });
    },
    delete(realm, id) {
      return request(`/realms/${realm}/users/${id}`, { method: 'DELETE' });
    },
    setEnabled(realm, id, enabled) {
      return request(`/realms/${realm}/users/${id}/enabled`, {
        method: 'PUT', body: JSON.stringify({ enabled }),
      });
    },
    resetPassword(realm, id, password, temporary = false) {
      return request(`/realms/${realm}/users/${id}/reset-password`, {
        method: 'PUT', body: JSON.stringify({ password, temporary }),
      });
    },
    assignRoles(realm, id, roles) {
      return request(`/realms/${realm}/users/${id}/roles`, {
        method: 'POST', body: JSON.stringify({ roles }),
      });
    },
    removeRoles(realm, id, roles) {
      return request(`/realms/${realm}/users/${id}/roles`, {
        method: 'DELETE', body: JSON.stringify({ roles }),
      });
    },
    getSessions(realm, id) {
      return request(`/realms/${realm}/users/${id}/sessions`);
    },
  };

  // ── Groups ───────────────────────────────────────────────
  const groups = {
    list(realm, params = {}) {
      const q = new URLSearchParams(params).toString();
      return request(`/realms/${realm}/groups${q ? '?' + q : ''}`);
    },
    get(realm, id) {
      return request(`/realms/${realm}/groups/${id}`);
    },
    create(realm, name) {
      return request(`/realms/${realm}/groups`, { method: 'POST', body: JSON.stringify({ name }) });
    },
    update(realm, id, name) {
      return request(`/realms/${realm}/groups/${id}`, { method: 'PUT', body: JSON.stringify({ name }) });
    },
    delete(realm, id) {
      return request(`/realms/${realm}/groups/${id}`, { method: 'DELETE' });
    },
    getMembers(realm, id, params = {}) {
      const q = new URLSearchParams(params).toString();
      return request(`/realms/${realm}/groups/${id}/members${q ? '?' + q : ''}`);
    },
    addMember(realm, groupId, userId) {
      return request(`/realms/${realm}/groups/${groupId}/members/${userId}`, { method: 'PUT' });
    },
    removeMember(realm, groupId, userId) {
      return request(`/realms/${realm}/groups/${groupId}/members/${userId}`, { method: 'DELETE' });
    },
  };

  // ── Roles ────────────────────────────────────────────────
  const roles = {
    list(realm) {
      return request(`/realms/${realm}/roles`);
    },
    get(realm, name) {
      return request(`/realms/${realm}/roles/${name}`);
    },
    create(realm, name, description = '') {
      return request(`/realms/${realm}/roles`, { method: 'POST', body: JSON.stringify({ name, description }) });
    },
    delete(realm, name) {
      return request(`/realms/${realm}/roles/${name}`, { method: 'DELETE' });
    },
    getUsers(realm, name) {
      return request(`/realms/${realm}/roles/${name}/users`);
    },
  };

  // ── Profile ──────────────────────────────────────────────
  const profile = {
    get() {
      return request('/profile');
    },
    update(data) {
      return request('/profile', { method: 'PUT', body: JSON.stringify(data) });
    },
    changePassword(newPassword) {
      return request('/profile/change-password', {
        method: 'POST', body: JSON.stringify({ new_password: newPassword }),
      });
    },
  };

  // ── Audit Logs ───────────────────────────────────────────
  const audit = {
    list(params = {}) {
      const q = new URLSearchParams(params).toString();
      return request(`/admin/audit-logs${q ? '?' + q : ''}`);
    },
    listForRealm(realm, params = {}) {
      const q = new URLSearchParams(params).toString();
      return request(`/realms/${realm}/audit-logs${q ? '?' + q : ''}`);
    },
  };

  return { auth, tenants, users, groups, roles, profile, audit, getSessionId };
})();
