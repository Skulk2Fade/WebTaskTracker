let csrfToken = '';

async function updateCsrfToken() {
  const res = await fetch('/api/csrf-token');
  csrfToken = (await res.json()).csrfToken;
}

async function init() {
  await updateCsrfToken();
  const me = await fetch('/api/me').then(r => r.json());
  if (!me.user || me.user.role !== 'admin') {
    document.getElementById('not-admin').style.display = 'block';
    return;
  }
  document.getElementById('admin-content').style.display = 'block';
  loadStats();
  loadUsers();
  loadLogs();
}

async function loadStats() {
  const res = await fetch('/api/admin/stats');
  if (res.ok) {
    const stats = await res.json();
    document.getElementById('stats').textContent = JSON.stringify(stats, null, 2);
  }
}

async function loadUsers() {
  const res = await fetch('/api/admin/users');
  if (res.ok) {
    const users = await res.json();
    const list = document.getElementById('user-list');
    list.innerHTML = '';
    users.forEach(u => {
      const li = document.createElement('li');
      li.textContent = `${u.username} (${u.role})`;
      const btn = document.createElement('button');
      btn.textContent = 'Delete';
      btn.onclick = async () => {
        await updateCsrfToken();
        const resp = await fetch(`/api/admin/users/${u.id}`, {
          method: 'DELETE',
          headers: { 'CSRF-Token': csrfToken }
        });
        if (resp.ok) loadUsers();
      };
      li.appendChild(btn);
      list.appendChild(li);
    });
  }
}

async function loadLogs() {
  const res = await fetch('/api/admin/logs');
  if (res.ok) {
    const logs = await res.json();
    const list = document.getElementById('logs');
    list.innerHTML = '';
    logs.forEach(l => {
      const li = document.createElement('li');
      li.textContent = `${l.createdAt}: ${l.username || 'system'} ${l.action} ${l.taskText || ''} ${l.details || ''}`.trim();
      list.appendChild(li);
    });
  }
}

window.onload = init;
