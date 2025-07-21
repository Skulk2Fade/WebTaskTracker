const pendingRequests = [];
const token = process.env.JIRA_API_TOKEN;
const baseUrl = process.env.JIRA_BASE_URL;
const projectKey = process.env.JIRA_PROJECT_KEY;
const syncedTasks = [];

async function fetchIssues(project) {
  if (!project) return [];
  if (!token || !baseUrl) {
    pendingRequests.push({ project });
    return [];
  }
  try {
    const res = await fetch(
      `${baseUrl.replace(/\/$/, '')}/rest/api/3/search?jql=project=${encodeURIComponent(project)}+AND+statusCategory!=Done`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/json'
        }
      }
    );
    const data = await res.json().catch(() => ({ issues: [] }));
    if (data && Array.isArray(data.issues)) {
      return data.issues.map(i => ({ title: (i.fields && i.fields.summary) || i.summary }));
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
  syncedTasks.length = 0;
}

async function syncTask(task) {
  if (!token || !baseUrl || !projectKey) {
    syncedTasks.push(task);
    return;
  }
  try {
    await fetch(`${baseUrl.replace(/\/$/, '')}/rest/api/3/issue`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({
        fields: { project: { key: projectKey }, summary: task.text }
      })
    });
  } catch {
    // ignore
  }
}

module.exports = { fetchIssues, pendingRequests, clearRequests, syncTask, syncedTasks, clearSynced };
