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
  loadReports();
  loadUsers();
  loadStatuses();
  loadLogs();
}

async function loadStats() {
  const res = await fetch('/api/admin/stats');
  if (res.ok) {
    const stats = await res.json();
    document.getElementById('stats').textContent = JSON.stringify(stats, null, 2);
  }
}

async function loadReports() {
  const res = await fetch('/api/admin/reports');
  if (res.ok) {
    const reports = await res.json();
    document.getElementById('reports').textContent = JSON.stringify(reports, null, 2);
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

async function loadStatuses() {
  const res = await fetch('/api/statuses');
  if (res.ok) {
    const statuses = await res.json();
    const list = document.getElementById('status-list');
    list.innerHTML = '';
    statuses.forEach(s => {
      const li = document.createElement('li');
      li.textContent = s.name;
      const btn = document.createElement('button');
      btn.textContent = 'Delete';
      btn.onclick = async () => {
        await updateCsrfToken();
        const resp = await fetch(`/api/statuses/${s.id}`, {
          method: 'DELETE',
          headers: { 'CSRF-Token': csrfToken }
        });
        if (resp.ok) loadStatuses();
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

document.getElementById('add-status-btn').onclick = async () => {
  const input = document.getElementById('new-status-input');
  const name = input.value.trim();
  if (!name) return;
  await updateCsrfToken();
  const res = await fetch('/api/statuses', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
    body: JSON.stringify({ name })
  });
  if (res.ok) {
    input.value = '';
    loadStatuses();
  }
};

window.onload = init;
