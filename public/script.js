async function fetchTasks() {
  const res = await fetch('/api/tasks');
  return await res.json();
}

function renderTasks(tasks) {
  const list = document.getElementById('task-list');
  list.innerHTML = '';
  tasks.forEach(task => {
    const li = document.createElement('li');
    li.dataset.id = task.id;
    li.textContent = task.text;
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

    const deleteBtn = document.createElement('button');
    deleteBtn.textContent = 'Delete';
    deleteBtn.onclick = async () => {
      await fetch(`/api/tasks/${task.id}`, { method: 'DELETE' });
      loadTasks();
    };

    li.append(' ', toggleBtn, ' ', deleteBtn);
    list.appendChild(li);
  });
}

async function loadTasks() {
  const tasks = await fetchTasks();
  renderTasks(tasks);
}

document.getElementById('add-button').onclick = async () => {
  const input = document.getElementById('task-input');
  const text = input.value.trim();
  if (text) {
    await fetch('/api/tasks', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ text })
    });
    input.value = '';
    loadTasks();
  }
};

loadTasks();
