const logger = require('./logger');
const sentSms = [];

let twilioClient = null;
const useTwilio = Boolean(
  process.env.TWILIO_ACCOUNT_SID &&
    process.env.TWILIO_AUTH_TOKEN &&
    process.env.TWILIO_FROM_NUMBER
);
if (useTwilio) {
  try {
    const twilio = require('twilio');
    twilioClient = twilio(
      process.env.TWILIO_ACCOUNT_SID,
      process.env.TWILIO_AUTH_TOKEN
    );
  } catch (err) {
    logger.warn('Twilio module not installed; falling back to stub SMS');
  }
}

function sendSms(to, body) {
  if (twilioClient) {
    return twilioClient.messages.create({
      from: process.env.TWILIO_FROM_NUMBER,
      to,
      body
    });
  }
  // For this demo we simply record the sms message.
  sentSms.push({ to, body });
  return Promise.resolve();
}

function clearSms() {
  sentSms.length = 0;
}

module.exports = { sendSms, sentSms, clearSms };
