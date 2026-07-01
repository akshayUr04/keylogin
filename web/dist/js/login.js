/**
 * web/dist/js/login.js
 * Login page controller.
 */
(() => {
  const form    = document.getElementById('login-form');
  const btn     = document.getElementById('login-btn');
  const btnText = document.getElementById('login-btn-text');
  const spinner = document.getElementById('login-spinner');
  const alert   = document.getElementById('login-alert');
  const alertTx = document.getElementById('login-alert-text');
  const pwdInput = document.getElementById('password');

  // Password toggle
  const toggleBtn = document.getElementById('toggle-password');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      const isText = pwdInput.type === 'text';
      pwdInput.type = isText ? 'password' : 'text';
      document.getElementById('eye-open').style.display  = isText ? '' : 'none';
      document.getElementById('eye-closed').style.display = isText ? 'none' : '';
    });
  }

  // If already logged in (session cookie present), try to redirect
  if (API.getSessionId()) {
    const role = sessionStorage.getItem('app_role');
    redirect(role || 'end_user');
  }

  function setLoading(loading) {
    btn.disabled     = loading;
    btnText.textContent = loading ? 'Signing in…' : 'Sign in';
    spinner.hidden   = !loading;
  }

  function showError(msg) {
    alertTx.textContent = msg;
    alert.hidden = false;
    // Shake animation
    alert.style.animation = 'none';
    requestAnimationFrame(() => { alert.style.animation = ''; });
  }

  function hideError() { alert.hidden = true; }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    hideError();

    const realm    = document.getElementById('realm').value.trim();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    if (!username) { showError('Please enter your username or email.'); return; }
    if (!password) { showError('Please enter your password.'); return; }

    setLoading(true);
    try {
      const result = await API.auth.login(realm || 'master', username, password);

      // Store session info for client-side routing
      sessionStorage.setItem('user_id',   result.data.user_id);
      sessionStorage.setItem('username',  result.data.username);
      sessionStorage.setItem('email',     result.data.email);
      sessionStorage.setItem('app_role',  result.data.app_role);
      sessionStorage.setItem('realm',     result.data.realm_name);

      redirect(result.data.app_role);
    } catch (err) {
      showError(err.message || 'Login failed. Please check your credentials.');
      setLoading(false);
    }
  });

  function redirect(role) {
    switch (role) {
      case 'super_admin':  window.location.href = '/dashboard/super-admin.html'; break;
      case 'realm_admin':  window.location.href = '/dashboard/realm-admin.html'; break;
      default:             window.location.href = '/dashboard/user.html';
    }
  }
})();
