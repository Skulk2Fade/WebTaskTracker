const pendingRequests = [];
const token = process.env.GITHUB_API_TOKEN;

async function fetchIssues(owner, repo) {
  if (!owner || !repo) return [];
  if (!token) {
    pendingRequests.push({ owner, repo });
    return [];
  }
  try {
    const res = await fetch(
      `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          'User-Agent': 'task-tracker',
          Accept: 'application/vnd.github+json'
        }
      }
    );
    const data = await res.json().catch(() => []);
    if (Array.isArray(data)) return data;
    return [];
  } catch {
    return [];
  }
}

function clearRequests() {
  pendingRequests.length = 0;
}

module.exports = { fetchIssues, pendingRequests, clearRequests };
