const sentPush = [];
const serverKey = process.env.FCM_SERVER_KEY;
async function sendPush(token, title, body) {
  if (!token) return Promise.resolve();
  if (!serverKey) {
    sentPush.push({ token, title, body });
    return Promise.resolve();
  }
  try {
    await fetch('https://fcm.googleapis.com/fcm/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'key=' + serverKey
      },
      body: JSON.stringify({ to: token, notification: { title, body } })
    });
  } catch {
    // ignore network errors in tests/demo
  }
}
function clearPush() {
  sentPush.length = 0;
}
module.exports = { sendPush, sentPush, clearPush };
