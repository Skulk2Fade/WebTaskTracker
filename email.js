const logger = require('./logger');
const sentEmails = [];

let sgMail = null;
const useSendgrid = Boolean(
  process.env.SENDGRID_API_KEY && process.env.SENDGRID_FROM_EMAIL
);
if (useSendgrid) {
  try {
    sgMail = require('@sendgrid/mail');
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  } catch (err) {
    logger.warn('SendGrid module not installed; falling back to stub email');
    sgMail = null;
  }
}

function sendEmail(to, subject, body) {
  if (sgMail) {
    const msg = {
      to,
      from: process.env.SENDGRID_FROM_EMAIL,
      subject,
      text: body
    };
    return sgMail.send(msg);
  }
  // For this demo application we simply record the emails that would be sent.
  sentEmails.push({ to, subject, body });
  return Promise.resolve();
}

function clearEmails() {
  sentEmails.length = 0;
}

module.exports = { sendEmail, sentEmails, clearEmails };
