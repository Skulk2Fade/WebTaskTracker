const sentEntries = [];
const token = process.env.HARVEST_TOKEN;
const accountId = process.env.HARVEST_ACCOUNT_ID;

async function logTime(entry) {
  if (!token || !accountId) {
    sentEntries.push(entry);
    return;
  }
  try {
    await fetch('https://api.harvestapp.com/v2/time_entries', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Harvest-Account-Id': accountId,
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({
        project_id: entry.projectId,
        task_id: entry.taskId,
        spent_date: entry.spentDate,
        hours: entry.minutes / 60
      })
    });
  } catch {
    // ignore network errors in tests
  }
}

function clearHarvest() {
  sentEntries.length = 0;
}

module.exports = { logTime, clearHarvest, sentEntries };
