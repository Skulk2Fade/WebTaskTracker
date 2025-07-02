async function fetchTasks(filters = {}) {
  const params = new URLSearchParams();
  if (filters.priority && filters.priority !== 'all') {
    params.append('priority', filters.priority);
  }
  if (filters.category && filters.category.trim() !== '') {
    params.append('category', filters.category.trim());
  }
  if (filters.status === 'completed') {
    params.append('done', 'true');
  } else if (filters.status === 'active') {
    params.append('done', 'false');
  }
  if (filters.sort) {
    params.append('sort', filters.sort);
  }
  if (filters.search && filters.search.trim() !== '') {
    params.append('search', filters.search.trim());
  }
  const query = params.toString();
  const res = await fetch('/api/tasks' + (query ? `?${query}` : ''));
  return await res.json();
}

async function fetchComments(taskId) {
  const res = await fetch(`/api/tasks/${taskId}/comments`);
  return await res.json();
}

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
    const cat = task.category ? ` {${task.category}}` : '';
    li.textContent = `${task.text} (Due: ${task.dueDate || 'N/A'}) [${task.priority}]${cat}`;
    li.classList.add(task.priority);
    if (task.done) {
      li.classList.add('done');
    }

    const toggleBtn = document.createElement('button');
    toggleBtn.textContent = task.done ? 'Undo' : 'Done';
    toggleBtn.onclick = async () => {
      await fetch(`/api/tasks/${task.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'CSRF-Token': csrfToken
        },
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
      const newCategory = prompt('Category:', task.category || '');
      await fetch(`/api/tasks/${task.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'CSRF-Token': csrfToken
        },
        body: JSON.stringify({ text: newText, dueDate: newDue, priority: newPriority, category: newCategory })
      });
      loadTasks();
    };

    const deleteBtn = document.createElement('button');
    deleteBtn.textContent = 'Delete';
    deleteBtn.onclick = async () => {
      await fetch(`/api/tasks/${task.id}`, {
        method: 'DELETE',
        headers: { 'CSRF-Token': csrfToken }
      });
      loadTasks();
    };

    const subList = document.createElement('ul');
    if (Array.isArray(task.subtasks)) {
      task.subtasks.forEach(sub => {
        const subLi = document.createElement('li');
        subLi.textContent = sub.text;
        if (sub.done) subLi.classList.add('done');

        const sToggle = document.createElement('button');
        sToggle.textContent = sub.done ? 'Undo' : 'Done';
        sToggle.onclick = async () => {
          await fetch(`/api/subtasks/${sub.id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
            body: JSON.stringify({ done: !sub.done })
          });
          loadTasks();
        };

        const sDelete = document.createElement('button');
        sDelete.textContent = 'Delete';
        sDelete.onclick = async () => {
          await fetch(`/api/subtasks/${sub.id}`, {
            method: 'DELETE',
            headers: { 'CSRF-Token': csrfToken }
          });
          loadTasks();
        };

        subLi.append(' ', sToggle, ' ', sDelete);
        subList.appendChild(subLi);
      });
    }

    const addSubBtn = document.createElement('button');
    addSubBtn.textContent = 'Add Step';
    addSubBtn.onclick = async () => {
      const text = prompt('Subtask text:');
      if (!text) return;
      await fetch(`/api/tasks/${task.id}/subtasks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
        body: JSON.stringify({ text })
      });
      loadTasks();
    };

    const commentList = document.createElement('ul');
    fetchComments(task.id).then(comments => {
      comments.forEach(c => {
        const cLi = document.createElement('li');
        cLi.textContent = `${c.username}: ${c.text}`;
        if (currentUser && c.userId === currentUser.id) {
          const cDel = document.createElement('button');
          cDel.textContent = 'Delete';
          cDel.onclick = async () => {
            await fetch(`/api/comments/${c.id}`, {
              method: 'DELETE',
              headers: { 'CSRF-Token': csrfToken }
            });
            loadTasks();
          };
          cLi.append(' ', cDel);
        }
        commentList.appendChild(cLi);
      });
    });

    const addCommentBtn = document.createElement('button');
    addCommentBtn.textContent = 'Add Comment';
    addCommentBtn.onclick = async () => {
      const text = prompt('Comment:');
      if (!text) return;
      await fetch(`/api/tasks/${task.id}/comments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
        body: JSON.stringify({ text })
      });
      loadTasks();
    };

    li.append(' ', toggleBtn, ' ', editBtn, ' ', deleteBtn, ' ', addSubBtn, ' ', addCommentBtn);
    li.appendChild(subList);
    li.appendChild(commentList);
    list.appendChild(li);
  });
}

async function loadTasks() {
  const status = document.getElementById('status-filter').value;
  const priorityFilter = document.getElementById('priority-filter').value;
  const categoryFilter = document.getElementById('category-filter').value;
  const search = document.getElementById('search-input').value;
  const sort = document.getElementById('sort-select').value;
  const tasks = await fetchTasks({ status, priority: priorityFilter, category: categoryFilter, sort, search });
  renderTasks(tasks);
}

document.getElementById('add-button').onclick = async () => {
  const input = document.getElementById('task-input');
  const dueInput = document.getElementById('due-date-input');
  const categoryInput = document.getElementById('category-input');
  const prioritySelect = document.getElementById('priority-select');
  const text = input.value.trim();
  const dueDate = dueInput.value;
  const priority = prioritySelect.value;
  const category = categoryInput.value.trim();
  if (text) {
    await fetch('/api/tasks', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CSRF-Token': csrfToken
      },
      body: JSON.stringify({ text, dueDate, priority, category })
    });
    input.value = '';
    dueInput.value = '';
    categoryInput.value = '';
    prioritySelect.value = 'medium';
    loadTasks();
  }
};

document.getElementById('status-filter').onchange = loadTasks;
document.getElementById('priority-filter').onchange = loadTasks;
document.getElementById('category-filter').onchange = loadTasks;
document.getElementById('sort-select').onchange = loadTasks;
document.getElementById('search-input').addEventListener('input', loadTasks);

async function handleLogin(event) {
  if (event) event.preventDefault();
  const username = document.getElementById('username-input').value.trim();
  const password = document.getElementById('password-input').value;
  const errorEl = document.getElementById('login-error');
  errorEl.textContent = '';
  if (username && password) {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CSRF-Token': csrfToken
      },
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
      headers: {
        'Content-Type': 'application/json',
        'CSRF-Token': csrfToken
      },
      body: JSON.stringify({ username, password })
    });
    document.getElementById('password-input').value = '';
    await updateCsrfToken();
    checkAuth();
  }
};

document.getElementById('logout-button').onclick = async () => {
  await fetch('/api/logout', {
    method: 'POST',
    headers: { 'CSRF-Token': csrfToken }
  });
  await updateCsrfToken();
  checkAuth();
};

window.onload = async () => {
  await updateCsrfToken();
  checkAuth();
};
