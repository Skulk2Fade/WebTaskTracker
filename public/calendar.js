let currentUser = null;
let csrfToken = '';
let currentYear;
let currentMonth;

async function updateCsrfToken() {
  const res = await fetch('/api/csrf-token');
  const data = await res.json();
  csrfToken = data.csrfToken;
}

async function fetchTasksInRange(startDate, endDate) {
  const params = new URLSearchParams();
  if (startDate) params.append('startDate', startDate);
  if (endDate) params.append('endDate', endDate);
  const res = await fetch('/api/tasks?' + params.toString());
  return await res.json();
}

async function checkAuth() {
  const res = await fetch('/api/me');
  const data = await res.json();
  currentUser = data.user;
  const loginForm = document.getElementById('login-form');
  const userInfo = document.getElementById('user-info');
  const controls = document.getElementById('calendar-controls');
  if (currentUser) {
    loginForm.style.display = 'none';
    userInfo.style.display = 'block';
    controls.style.display = 'block';
    document.getElementById('current-user').textContent = currentUser.username;
    renderCalendar(currentYear, currentMonth);
    loadReminders();
  } else {
    loginForm.style.display = 'block';
    userInfo.style.display = 'none';
    controls.style.display = 'none';
    document.getElementById('calendar').innerHTML = '';
    document.getElementById('notifications').style.display = 'none';
  }
}

function renderCalendar(year, month) {
  if (!currentUser) return;
  const first = new Date(Date.UTC(year, month, 1));
  const last = new Date(Date.UTC(year, month + 1, 0));
  const start = new Date(first);
  start.setUTCDate(start.getUTCDate() - ((start.getUTCDay() + 6) % 7));
  const end = new Date(last);
  end.setUTCDate(end.getUTCDate() + (6 - ((end.getUTCDay() + 6) % 7)));
  const startStr = start.toISOString().slice(0, 10);
  const endStr = end.toISOString().slice(0, 10);

  fetchTasksInRange(startStr, endStr).then(tasks => {
    const byDate = {};
    tasks.forEach(t => {
      if (!t.dueDate) return;
      if (!byDate[t.dueDate]) byDate[t.dueDate] = [];
      byDate[t.dueDate].push(t);
    });
    const tbl = document.getElementById('calendar');
    tbl.innerHTML = '';
    const header = document.createElement('tr');
    ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].forEach(d => {
      const th = document.createElement('th');
      th.textContent = d;
      header.appendChild(th);
    });
    tbl.appendChild(header);

    let cur = new Date(start);
    while (cur <= end) {
      const row = document.createElement('tr');
      for (let i = 0; i < 7; i++) {
        const cell = document.createElement('td');
        const dateStr = cur.toISOString().slice(0, 10);
        cell.innerHTML = `<div class="date">${cur.getUTCDate()}</div>`;
        const list = document.createElement('ul');
        if (byDate[dateStr]) {
          byDate[dateStr].forEach(t => {
            const li = document.createElement('li');
            li.textContent = t.text;
            if (t.done) li.classList.add('done');
            list.appendChild(li);
          });
        }
        cell.appendChild(list);
        row.appendChild(cell);
        cur.setUTCDate(cur.getUTCDate() + 1);
      }
      tbl.appendChild(row);
    }
  });

  const label = document.getElementById('month-label');
  label.textContent = first.toLocaleString('default', { month: 'long', year: 'numeric' });
}

async function loadReminders() {
  const res = await fetch('/api/reminders');
  const reminders = await res.json();
  const container = document.getElementById('notifications');
  container.innerHTML = '';
  if (Array.isArray(reminders) && reminders.length > 0) {
    container.style.display = 'block';
    reminders.forEach(r => {
      const li = document.createElement('li');
      li.textContent = `Reminder: "${r.text}" due ${r.dueDate}`;
      container.appendChild(li);
    });
  } else {
    container.style.display = 'none';
  }
}

async function handleLogin(event) {
  if (event) event.preventDefault();
  const username = document.getElementById('username-input').value.trim();
  const password = document.getElementById('password-input').value;
  const errorEl = document.getElementById('login-error');
  errorEl.textContent = '';
  if (username && password) {
    await updateCsrfToken();
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
      body: JSON.stringify({ username, password })
    });
    document.getElementById('password-input').value = '';
    if (res.ok) {
      await updateCsrfToken();
      checkAuth();
    } else {
      const data = await res.json().catch(() => ({}));
      errorEl.textContent = data.error || 'Login failed';
    }
  }
}

document.getElementById('login-button').onclick = handleLogin;
document.getElementById('login-form').addEventListener('submit', handleLogin);

document.getElementById('register-button').onclick = async () => {
  const username = document.getElementById('username-input').value.trim();
  const password = document.getElementById('password-input').value;
  document.getElementById('login-error').textContent = '';
  if (username && password) {
    await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
      body: JSON.stringify({ username, password })
    });
    document.getElementById('password-input').value = '';
    await updateCsrfToken();
    checkAuth();
  }
};

document.getElementById('logout-button').onclick = async () => {
  await fetch('/api/logout', { method: 'POST', headers: { 'CSRF-Token': csrfToken } });
  await updateCsrfToken();
  checkAuth();
};

document.getElementById('prev-month').onclick = () => {
  currentMonth--;
  if (currentMonth < 0) {
    currentMonth = 11;
    currentYear--;
  }
  renderCalendar(currentYear, currentMonth);
};

document.getElementById('next-month').onclick = () => {
  currentMonth++;
  if (currentMonth > 11) {
    currentMonth = 0;
    currentYear++;
  }
  renderCalendar(currentYear, currentMonth);
};

window.onload = async () => {
  const today = new Date();
  currentYear = today.getUTCFullYear();
  currentMonth = today.getUTCMonth();
  await updateCsrfToken();
  checkAuth();
};
