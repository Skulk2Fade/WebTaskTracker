const pendingRequests = [];
const key = process.env.TRELLO_API_KEY;
const token = process.env.TRELLO_TOKEN;
const listId = process.env.TRELLO_LIST_ID;
const syncedCards = [];

async function fetchCards(boardId) {
  if (!boardId) return [];
  if (!key || !token) {
    pendingRequests.push({ boardId });
    return [];
  }
  try {
    const res = await fetch(
      `https://api.trello.com/1/boards/${encodeURIComponent(boardId)}/cards?key=${encodeURIComponent(key)}&token=${encodeURIComponent(token)}`
    );
    const data = await res.json().catch(() => []);
    if (Array.isArray(data)) {
      return data.map(c => ({ title: c.name }));
    }
    return [];
  } catch {
    return [];
  }
}

function clearRequests() {
  pendingRequests.length = 0;
}

function clearSynced() {
  syncedCards.length = 0;
}

async function syncTask(task) {
  if (!key || !token || !listId) {
    syncedCards.push(task);
    return;
  }
  try {
    await fetch(
      `https://api.trello.com/1/cards?key=${encodeURIComponent(key)}&token=${encodeURIComponent(token)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ idList: listId, name: task.text })
      }
    );
  } catch {
    // ignore
  }
}

module.exports = { fetchCards, pendingRequests, clearRequests, syncTask, syncedCards, clearSynced };
