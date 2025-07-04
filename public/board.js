let currentUser = null;
let csrfToken = '';

async function updateCsrfToken() {
  const res = await fetch('/api/csrf-token');
  const data = await res.json();
  csrfToken = data.csrfToken;
}

async function checkAuth() {
  const res = await fetch('/api/me');
  const data = await res.json();
  currentUser = data.user;
  const loginForm = document.getElementById('login-form');
  const userInfo = document.getElementById('user-info');
  const taskForm = document.getElementById('task-form');
  const controls = document.getElementById('board-controls');
  if (currentUser) {
    loginForm.style.display = 'none';
    userInfo.style.display = 'block';
    document.getElementById('current-user').textContent = currentUser.username;
    taskForm.style.display = 'block';
    controls.style.display = 'block';
    loadBoard();
  } else {
    loginForm.style.display = 'block';
    userInfo.style.display = 'none';
    taskForm.style.display = 'none';
    controls.style.display = 'none';
    document.getElementById('board').innerHTML = '';
  }
}

async function fetchTasks() {
  const res = await fetch('/api/tasks');
  return await res.json();
}

function createTaskElement(task) {
  const li = document.createElement('li');
  li.draggable = true;
  li.dataset.id = task.id;
  const html = DOMPurify.sanitize(marked.parse(task.text));
  li.innerHTML = html;
  if (task.done) li.classList.add('done');
  li.addEventListener('dragstart', e => {
    e.dataTransfer.setData('text/plain', task.id);
  });
  return li;
}

function renderBoard(tasks) {
  const board = document.getElementById('board');
  board.innerHTML = '';
  const groupBy = document.getElementById('group-select').value;
  const groups = {};
  if (groupBy === 'status') {
    groups.Active = tasks.filter(t => !t.done);
    groups.Completed = tasks.filter(t => t.done);
  } else {
    tasks.forEach(t => {
      const cat = t.category || 'None';
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(t);
    });
  }
  for (const [name, items] of Object.entries(groups)) {
    const col = document.createElement('div');
    col.className = 'board-column';
    col.dataset.name = name;
    const h = document.createElement('h3');
    h.textContent = name;
    const ul = document.createElement('ul');
    items.forEach(t => ul.appendChild(createTaskElement(t)));
    col.appendChild(h);
    col.appendChild(ul);
    col.addEventListener('dragover', e => e.preventDefault());
    col.addEventListener('drop', async e => {
      e.preventDefault();
      const id = e.dataTransfer.getData('text/plain');
      if (!id) return;
      if (groupBy === 'status') {
        const done = name === 'Completed';
        await fetch(`/api/tasks/${id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
          body: JSON.stringify({ done })
        });
      } else {
        const category = name === 'None' ? '' : name;
        await fetch(`/api/tasks/${id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
          body: JSON.stringify({ category })
        });
      }
      loadBoard();
    });
    board.appendChild(col);
  }
}

async function loadBoard() {
  const tasks = await fetchTasks();
  renderBoard(tasks);
}

document.getElementById('group-select').onchange = loadBoard;

document.getElementById('add-button').onclick = async () => {
  const input = document.getElementById('task-input');
  const dueInput = document.getElementById('due-date-input');
  const timeInput = document.getElementById('due-time-input');
  const categoryInput = document.getElementById('category-input');
  const prioritySelect = document.getElementById('priority-select');
  const text = input.value.trim();
  const dueDate = dueInput.value;
  const dueTime = timeInput.value;
  const priority = prioritySelect.value;
  const category = categoryInput.value.trim();
  if (text) {
    await fetch('/api/tasks', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CSRF-Token': csrfToken
      },
      body: JSON.stringify({ text, dueDate, dueTime, priority, category })
    });
    input.value = '';
    dueInput.value = '';
    timeInput.value = '';
    categoryInput.value = '';
    prioritySelect.value = 'medium';
    loadBoard();
  }
};

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

window.onload = async () => {
  await updateCsrfToken();
  checkAuth();
};
