const express = require('express');
const path = require('path');
const db = require('./db');
const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));


app.get('/api/tasks', async (req, res) => {
  const { priority, done, sort } = req.query;
  try {
    const tasks = await db.listTasks({
      priority,
      done: done === 'true' ? true : done === 'false' ? false : undefined,
      sort
    });
    res.json(tasks);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load tasks' });
  }
});

app.post('/api/tasks', async (req, res) => {
  const text = req.body.text;
  const dueDate = req.body.dueDate;
  let priority = req.body.priority || 'medium';
  priority = ['high', 'medium', 'low'].includes(priority) ? priority : 'medium';
  if (!text) {
    return res.status(400).json({ error: 'Task text is required' });
  }
  try {
    const task = await db.createTask({ text, dueDate, priority, done: false });
    res.status(201).json(task);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save task' });
  }
});

app.put('/api/tasks/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  const { text, dueDate, priority, done } = req.body;
  if (text !== undefined && !text.trim()) {
    return res.status(400).json({ error: 'Task text cannot be empty' });
  }
  if (priority !== undefined && !['high', 'medium', 'low'].includes(priority)) {
    return res.status(400).json({ error: 'Invalid priority value' });
  }
  try {
    const updated = await db.updateTask(id, { text, dueDate, priority, done });
    if (!updated) {
      return res.status(404).json({ error: 'Task not found' });
    }
    res.json(updated);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save task' });
  }
});

app.delete('/api/tasks/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  try {
    const deleted = await db.deleteTask(id);
    if (!deleted) {
      return res.status(404).json({ error: 'Task not found' });
    }
    res.json(deleted);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save task' });
  }
});

(async () => {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
})();
