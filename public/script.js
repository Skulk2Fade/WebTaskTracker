async function fetchTasks(filters = {}) {
  const params = new URLSearchParams();
  if (filters.priority && filters.priority !== 'all') {
    params.append('priority', filters.priority);
  }
  if (filters.status === 'completed') {
    params.append('done', 'true');
  } else if (filters.status === 'active') {
    params.append('done', 'false');
  }
  if (filters.sort) {
    params.append('sort', filters.sort);
  }
  const query = params.toString();
  const res = await fetch('/api/tasks' + (query ? `?${query}` : ''));
  return await res.json();
}

let currentUser = null;

async function checkAuth() {
  const res = await fetch('/api/me');
  const data = await res.json();
  currentUser = data.user;
  document.getElementById('login-error').textContent = '';
  const loginForm = document.getElementById('login-form');
  const userInfo = document.getElementById('user-info');
  const taskForm = document.getElementById('task-form');
  const controls = document.getElementById('controls');
  if (currentUser) {
    loginForm.style.display = 'none';
    userInfo.style.display = 'block';
    document.getElementById('current-user').textContent = currentUser.username;
    taskForm.style.display = 'block';
    controls.style.display = 'block';
    loadTasks();
  } else {
    loginForm.style.display = 'block';
    userInfo.style.display = 'none';
    taskForm.style.display = 'none';
    controls.style.display = 'none';
    document.getElementById('task-list').innerHTML = '';
  }
}

function renderTasks(tasks) {
  const list = document.getElementById('task-list');
  list.innerHTML = '';
  tasks.forEach(task => {
    const li = document.createElement('li');
    li.dataset.id = task.id;
    li.textContent = `${task.text} (Due: ${task.dueDate || 'N/A'}) [${task.priority}]`;
    li.classList.add(task.priority);
    if (task.done) {
      li.classList.add('done');
    }

    const toggleBtn = document.createElement('button');
    toggleBtn.textContent = task.done ? 'Undo' : 'Done';
    toggleBtn.onclick = async () => {
      await fetch(`/api/tasks/${task.id}`, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ done: !task.done })
      });
      loadTasks();
    };

    const editBtn = document.createElement('button');
    editBtn.textContent = 'Edit';
    editBtn.onclick = async () => {
      const newText = prompt('Task text:', task.text);
      if (newText === null) return;
      const newDue = prompt('Due date (YYYY-MM-DD):', task.dueDate || '');
      const newPriority = prompt('Priority (high, medium, low):', task.priority);
      await fetch(`/api/tasks/${task.id}`, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ text: newText, dueDate: newDue, priority: newPriority })
      });
      loadTasks();
    };

    const deleteBtn = document.createElement('button');
    deleteBtn.textContent = 'Delete';
    deleteBtn.onclick = async () => {
      await fetch(`/api/tasks/${task.id}`, { method: 'DELETE' });
      loadTasks();
    };

    li.append(' ', toggleBtn, ' ', editBtn, ' ', deleteBtn);
    list.appendChild(li);
  });
}

async function loadTasks() {
  const status = document.getElementById('status-filter').value;
  const priorityFilter = document.getElementById('priority-filter').value;
  const sort = document.getElementById('sort-select').value;
  const tasks = await fetchTasks({ status, priority: priorityFilter, sort });
  renderTasks(tasks);
}

document.getElementById('add-button').onclick = async () => {
  const input = document.getElementById('task-input');
  const dueInput = document.getElementById('due-date-input');
  const prioritySelect = document.getElementById('priority-select');
  const text = input.value.trim();
  const dueDate = dueInput.value;
  const priority = prioritySelect.value;
  if (text) {
    await fetch('/api/tasks', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ text, dueDate, priority })
    });
    input.value = '';
    dueInput.value = '';
    prioritySelect.value = 'medium';
    loadTasks();
  }
};

document.getElementById('status-filter').onchange = loadTasks;
document.getElementById('priority-filter').onchange = loadTasks;
document.getElementById('sort-select').onchange = loadTasks;

document.getElementById('login-button').onclick = async () => {
  const username = document.getElementById('username-input').value.trim();
  const password = document.getElementById('password-input').value;
  const errorEl = document.getElementById('login-error');
  errorEl.textContent = '';
  if (username && password) {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    document.getElementById('password-input').value = '';
    if (res.ok) {
      checkAuth();
    } else {
      const data = await res.json().catch(() => ({}));
      errorEl.textContent = data.error || 'Login failed';
    }
  }
};

document.getElementById('register-button').onclick = async () => {
  const username = document.getElementById('username-input').value.trim();
  const password = document.getElementById('password-input').value;
  document.getElementById('login-error').textContent = '';
  if (username && password) {
    await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    document.getElementById('password-input').value = '';
    checkAuth();
  }
};

document.getElementById('logout-button').onclick = async () => {
  await fetch('/api/logout', { method: 'POST' });
  checkAuth();
};

window.onload = checkAuth;
