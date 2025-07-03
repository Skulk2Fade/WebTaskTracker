const sentEmails = [];

function sendEmail(to, subject, body) {
  // For this demo application we simply record the emails that would be sent.
  sentEmails.push({ to, subject, body });
  return Promise.resolve();
}

function clearEmails() {
  sentEmails.length = 0;
}

module.exports = { sendEmail, sentEmails, clearEmails };
