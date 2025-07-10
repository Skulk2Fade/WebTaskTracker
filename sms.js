const sentSms = [];

function sendSms(to, body) {
  // For this demo we simply record the sms message.
  sentSms.push({ to, body });
  return Promise.resolve();
}

function clearSms() {
  sentSms.length = 0;
}

module.exports = { sendSms, sentSms, clearSms };
