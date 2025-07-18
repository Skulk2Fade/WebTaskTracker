async function fetchTasks(filters = {}) {
  const params = new URLSearchParams();
  if (filters.priority && filters.priority !== 'all') {
    params.append('priority', filters.priority);
  }
  if (filters.category && filters.category.trim() !== '') {
    params.append('category', filters.category.trim());
  }
  if (filters.tags && filters.tags.trim() !== '') {
    params.append('tags', filters.tags.trim());
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
let eventSource = null;
const selectedTasks = new Set();

function isStrongPassword(pw) {
  return (
    typeof pw === 'string' &&
    pw.length >= 8 &&
    /[a-z]/.test(pw) &&
    /[A-Z]/.test(pw) &&
    /[0-9]/.test(pw) &&
    /[^A-Za-z0-9]/.test(pw)
  );
}

function tagColor(tag) {
  let hash = 0;
  for (let i = 0; i < tag.length; i++) {
    hash = (hash * 31 + tag.charCodeAt(i)) & 0xffffffff;
  }
  const hue = Math.abs(hash) % 360;
  return `hsl(${hue},60%,60%)`;
}

async function requestNotificationPermission() {
  if ('Notification' in window && Notification.permission === 'default') {
    try {
      await Notification.requestPermission();
    } catch (e) {
      // ignore
    }
  }
}

document.getElementById('task-list').addEventListener('keydown', e => {
  if (e.target.tagName === 'LI') {
    if (e.key === 'ArrowUp' && e.target.previousElementSibling) {
      e.target.previousElementSibling.focus();
      e.preventDefault();
    } else if (e.key === 'ArrowDown' && e.target.nextElementSibling) {
      e.target.nextElementSibling.focus();
      e.preventDefault();
    }
  }
});

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
  const bulkControls = document.getElementById('bulk-controls');
  const adminLink = document.getElementById('admin-link');
  const notify = document.getElementById('notifications');
  if (currentUser) {
    requestNotificationPermission();
    loginForm.style.display = 'none';
    userInfo.style.display = 'block';
    document.getElementById('current-user').textContent = currentUser.username;
    taskForm.style.display = 'block';
    controls.style.display = 'block';
    bulkControls.style.display = 'block';
    if (currentUser.role === 'observer') {
      taskForm.style.display = 'none';
      controls.style.display = 'none';
      bulkControls.style.display = 'none';
    }
    if (currentUser.role === 'admin') adminLink.style.display = 'inline';
    else adminLink.style.display = 'none';
    loadTasks();
    loadReminders();
    if (eventSource) eventSource.close();
    eventSource = new EventSource('/api/events');
    eventSource.onmessage = e => {
      const data = JSON.parse(e.data);
      const container = document.getElementById('notifications');
      const li = document.createElement('li');
      if (data.type === 'task_assigned') {
        li.textContent = `Assigned: "${data.text}"`;
        data._title = 'Task Assigned';
        data._body = data.text;
      } else if (data.type === 'task_commented') {
        li.textContent = `New comment on task ${data.taskId}`;
        data._title = 'New Comment';
        data._body = `Task ${data.taskId} has a new comment`;
      } else if (data.type === 'task_due') {
        const due = data.dueTime ? `${data.dueDate} ${data.dueTime}` : data.dueDate;
        li.textContent = `Reminder: "${data.text}" due ${due}`;
        data._title = 'Task Due';
        data._body = `${data.text} due ${due}`;
      }
      container.style.display = 'block';
      container.appendChild(li);
      if (
        document.visibilityState === 'hidden' &&
        navigator.serviceWorker &&
        navigator.serviceWorker.controller &&
        Notification.permission === 'granted'
      ) {
        navigator.serviceWorker.controller.postMessage({ type: 'notify', data });
      }
    };
  } else {
    loginForm.style.display = 'block';
    userInfo.style.display = 'none';
    taskForm.style.display = 'none';
    controls.style.display = 'none';
    bulkControls.style.display = 'none';
    adminLink.style.display = 'none';
    document.getElementById('task-list').innerHTML = '';
    notify.style.display = 'none';
    if (eventSource) { eventSource.close(); eventSource = null; }
  }
}

function renderTasks(tasks) {
  const list = document.getElementById('task-list');
  list.innerHTML = '';
  tasks.forEach(task => {
    const li = document.createElement('li');
    li.tabIndex = 0;
    li.dataset.id = task.id;
    const cat = task.category ? ` {${task.category}}` : '';
    const tags = Array.isArray(task.tags) ? task.tags : [];
    const textSpan = document.createElement('span');
    const taskHtml = DOMPurify.sanitize(marked.parse(task.text));
    const due = task.dueDate ? (task.dueTime ? `${task.dueDate} ${task.dueTime}` : task.dueDate) : 'N/A';
    textSpan.innerHTML = `${taskHtml} (Due: ${due}) [${task.priority}]${cat}`;
    if (tags.length) {
      const tagContainer = document.createElement('span');
      tags.forEach(t => {
        const tagEl = document.createElement('span');
        tagEl.className = 'tag';
        tagEl.textContent = t;
        tagEl.style.backgroundColor = tagColor(t);
        tagContainer.append(' ', tagEl);
      });
      textSpan.appendChild(tagContainer);
    }
    li.appendChild(textSpan);
    li.classList.add(task.priority);
    if (task.done) {
      li.classList.add('done');
    }

    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.className = 'task-select';
    checkbox.checked = selectedTasks.has(task.id);
    checkbox.onchange = () => {
      if (checkbox.checked) selectedTasks.add(task.id);
      else selectedTasks.delete(task.id);
    };
    li.prepend(checkbox, ' ');

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
      loadReminders();
    };

    const editBtn = document.createElement('button');
    editBtn.textContent = 'Edit';
    editBtn.onclick = async () => {
      const newText = prompt('Task text:', task.text);
      if (newText === null) return;
      const newDue = prompt('Due date (YYYY-MM-DD):', task.dueDate || '');
      const newTime = prompt('Due time (HH:MM):', task.dueTime || '');
      const newPriority = prompt('Priority (high, medium, low):', task.priority);
      const newCategory = prompt('Category:', task.category || '');
      const newTags = prompt('Tags (comma separated):', Array.isArray(task.tags) ? task.tags.join(',') : '');
      await fetch(`/api/tasks/${task.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'CSRF-Token': csrfToken
        },
        body: JSON.stringify({ text: newText, dueDate: newDue, dueTime: newTime, priority: newPriority, category: newCategory, tags: newTags.split(',').map(t => t.trim()).filter(t => t) })
      });
      loadTasks();
      loadReminders();
    };

    const deleteBtn = document.createElement('button');
    deleteBtn.textContent = 'Delete';
    deleteBtn.onclick = async () => {
      await fetch(`/api/tasks/${task.id}`, {
        method: 'DELETE',
        headers: { 'CSRF-Token': csrfToken }
      });
      loadTasks();
      loadReminders();
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
          loadReminders();
        };

        const sDelete = document.createElement('button');
        sDelete.textContent = 'Delete';
        sDelete.onclick = async () => {
          await fetch(`/api/subtasks/${sub.id}`, {
            method: 'DELETE',
            headers: { 'CSRF-Token': csrfToken }
          });
          loadTasks();
          loadReminders();
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
      loadReminders();
    };

    const commentList = document.createElement('ul');
    fetchComments(task.id).then(comments => {
      comments.forEach(c => {
        const cLi = document.createElement('li');
        const commentHtml = DOMPurify.sanitize(marked.parse(c.text));
        cLi.innerHTML = `<strong>${c.username}:</strong> ${commentHtml}`;
        if (currentUser && c.userId === currentUser.id) {
          const cDel = document.createElement('button');
          cDel.textContent = 'Delete';
          cDel.onclick = async () => {
            await fetch(`/api/comments/${c.id}`, {
              method: 'DELETE',
              headers: { 'CSRF-Token': csrfToken }
            });
            loadTasks();
            loadReminders();
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
      loadReminders();
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
  const tagsFilter = document.getElementById('tags-filter').value;
  const search = document.getElementById('search-input').value;
  const sort = document.getElementById('sort-select').value;
  selectedTasks.clear();
  const tasks = await fetchTasks({ status, priority: priorityFilter, category: categoryFilter, tags: tagsFilter, sort, search });
  renderTasks(tasks);
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
      const due = r.dueTime ? `${r.dueDate} ${r.dueTime}` : r.dueDate;
      li.textContent = `Reminder: "${r.text}" due ${due}`;
      container.appendChild(li);
    });
  } else {
    container.style.display = 'none';
  }
}

document.getElementById('add-button').onclick = async () => {
  const input = document.getElementById('task-input');
  const dueInput = document.getElementById('due-date-input');
  const timeInput = document.getElementById('due-time-input');
  const categoryInput = document.getElementById('category-input');
  const tagsInput = document.getElementById('tags-input');
  const prioritySelect = document.getElementById('priority-select');
  const text = input.value.trim();
  const dueDate = dueInput.value;
  const dueTime = timeInput.value;
  const priority = prioritySelect.value;
  const category = categoryInput.value.trim();
  const tags = tagsInput.value
    .split(',')
    .map(t => t.trim())
    .filter(t => t);
  if (text) {
    await fetch('/api/tasks', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CSRF-Token': csrfToken
      },
      body: JSON.stringify({ text, dueDate, dueTime, priority, category, tags })
    });
    input.value = '';
    dueInput.value = '';
    timeInput.value = '';
    categoryInput.value = '';
    tagsInput.value = '';
    prioritySelect.value = 'medium';
    loadTasks();
    loadReminders();
  }
};

document.getElementById('status-filter').onchange = loadTasks;
document.getElementById('priority-filter').onchange = loadTasks;
document.getElementById('category-filter').onchange = loadTasks;
document.getElementById('tags-filter').onchange = loadTasks;
document.getElementById('sort-select').onchange = loadTasks;
document.getElementById('search-input').addEventListener('input', loadTasks);

document.getElementById('bulk-done').onclick = async () => {
  if (selectedTasks.size === 0) return;
  await fetch('/api/tasks/bulk', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
    body: JSON.stringify({ ids: Array.from(selectedTasks), done: true })
  });
  selectedTasks.clear();
  loadTasks();
  loadReminders();
};

document.getElementById('bulk-delete').onclick = async () => {
  if (selectedTasks.size === 0) return;
  await fetch('/api/tasks/bulk-delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
    body: JSON.stringify({ ids: Array.from(selectedTasks) })
  });
  selectedTasks.clear();
  loadTasks();
  loadReminders();
};

document.getElementById('bulk-priority-btn').onclick = async () => {
  if (selectedTasks.size === 0) return;
  const priority = document.getElementById('bulk-priority').value;
  await fetch('/api/tasks/bulk', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
    body: JSON.stringify({ ids: Array.from(selectedTasks), priority })
  });
  selectedTasks.clear();
  loadTasks();
  loadReminders();
};

async function handleLogin(event) {
  if (event) event.preventDefault();
  const username = document.getElementById('username-input').value.trim();
  const password = document.getElementById('password-input').value;
  const errorEl = document.getElementById('login-error');
  errorEl.textContent = '';
  if (!username || !password) {
    errorEl.textContent = 'Username and password are required';
    return;
  }
  await updateCsrfToken();
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
const googleBtn = document.getElementById('google-login');
if (googleBtn) googleBtn.onclick = () => (window.location.href = '/auth/google');
const githubBtn = document.getElementById('github-login');
if (githubBtn) githubBtn.onclick = () => (window.location.href = '/auth/github');

document.getElementById('register-button').onclick = async () => {
  const username = document.getElementById('username-input').value.trim();
  const password = document.getElementById('password-input').value;
  const errorEl = document.getElementById('login-error');
  errorEl.textContent = '';
  if (!username || !password) {
    errorEl.textContent = 'Username and password are required';
    return;
  }
  if (!isStrongPassword(password)) {
    errorEl.textContent =
      'Password must be at least 8 characters and include upper and lower case letters, a number and a special character';
    return;
  }
  if (username && password) {
    const res = await fetch('/api/register', {
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
      errorEl.textContent = data.error || 'Registration failed';
      await updateCsrfToken();
    }
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
