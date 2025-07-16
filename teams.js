const sentTeams = [];
const token = process.env.TEAMS_BOT_TOKEN;
async function sendTeams(user, text) {
  if (!user) return Promise.resolve();
  if (!token) {
    sentTeams.push({ user, text });
    return Promise.resolve();
  }
  try {
    await fetch(`https://graph.microsoft.com/v1.0/chats/${user}/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + token
      },
      body: JSON.stringify({ body: { content: text } })
    });
  } catch {
    // ignore network errors
  }
}
function clearTeams() { sentTeams.length = 0; }
module.exports = { sendTeams, sentTeams, clearTeams };
