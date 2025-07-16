const sentSlack = [];
const token = process.env.SLACK_BOT_TOKEN;
async function sendSlack(user, text) {
  if (!user) return Promise.resolve();
  if (!token) {
    sentSlack.push({ user, text });
    return Promise.resolve();
  }
  try {
    await fetch('https://slack.com/api/chat.postMessage', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + token
      },
      body: JSON.stringify({ channel: user, text })
    });
  } catch {
    // ignore network errors in tests/demo
  }
}
function clearSlack() { sentSlack.length = 0; }
module.exports = { sendSlack, sentSlack, clearSlack };
