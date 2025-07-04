const sentWebhooks = [];

const urls = process.env.WEBHOOK_URLS
  ? process.env.WEBHOOK_URLS.split(',').map(u => u.trim()).filter(Boolean)
  : [];

function sendWebhook(event, data) {
  const payload = { event, data };
  for (const url of urls) {
    // In this demo we simply record the webhook instead of performing an HTTP request
    sentWebhooks.push({ url, payload });
  }
  return Promise.resolve();
}

function clearWebhooks() {
  sentWebhooks.length = 0;
}

module.exports = { sendWebhook, sentWebhooks, clearWebhooks };
