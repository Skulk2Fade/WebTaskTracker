const express = require('express');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Simple in-memory task list
let tasks = [];
let idCounter = 1;

app.get('/api/tasks', (req, res) => {
  res.json(tasks);
});

app.post('/api/tasks', (req, res) => {
  const text = req.body.text;
  if (!text) {
    return res.status(400).json({ error: 'Task text is required' });
  }
  const task = { id: idCounter++, text, done: false };
  tasks.push(task);
  res.status(201).json(task);
});

app.put('/api/tasks/:id', (req, res) => {
  const task = tasks.find(t => t.id === parseInt(req.params.id));
  if (!task) {
    return res.status(404).json({ error: 'Task not found' });
  }
  task.done = req.body.done === true;
  res.json(task);
});

app.delete('/api/tasks/:id', (req, res) => {
  const idx = tasks.findIndex(t => t.id === parseInt(req.params.id));
  if (idx === -1) {
    return res.status(404).json({ error: 'Task not found' });
  }
  const [deleted] = tasks.splice(idx, 1);
  res.json(deleted);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
