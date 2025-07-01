const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Task persistence
const DATA_FILE = path.join(__dirname, 'tasks.json');
let tasks = [];
let idCounter = 1;

function loadTasks() {
  try {
    const data = fs.readFileSync(DATA_FILE, 'utf-8');
    tasks = JSON.parse(data);
    const maxId = tasks.reduce((m, t) => Math.max(m, t.id), 0);
    idCounter = maxId + 1;
  } catch (err) {
    tasks = [];
    idCounter = 1;
  }
}

function saveTasks() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(tasks, null, 2));
}

loadTasks();

app.get('/api/tasks', (req, res) => {
  res.json(tasks);
});

app.post('/api/tasks', (req, res) => {
  const text = req.body.text;
  const dueDate = req.body.dueDate;
  let priority = req.body.priority || 'medium';
  priority = ['high', 'medium', 'low'].includes(priority) ? priority : 'medium';
  if (!text) {
    return res.status(400).json({ error: 'Task text is required' });
  }
  const task = { id: idCounter++, text, dueDate, priority, done: false };
  tasks.push(task);
  saveTasks();
  res.status(201).json(task);
});

app.put('/api/tasks/:id', (req, res) => {
  const task = tasks.find(t => t.id === parseInt(req.params.id));
  if (!task) {
    return res.status(404).json({ error: 'Task not found' });
  }
  task.done = req.body.done === true;
  saveTasks();
  res.json(task);
});

app.delete('/api/tasks/:id', (req, res) => {
  const idx = tasks.findIndex(t => t.id === parseInt(req.params.id));
  if (idx === -1) {
    return res.status(404).json({ error: 'Task not found' });
  }
  const [deleted] = tasks.splice(idx, 1);
  saveTasks();
  res.json(deleted);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
