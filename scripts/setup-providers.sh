#!/bin/sh
set -e
ENV_FILE=".env"
if [ ! -f "$ENV_FILE" ]; then
  cp .env.example "$ENV_FILE"
  echo "Created $ENV_FILE from example template."
fi
update_var() {
  key="$1"
  prompt="$2"
  current="$(grep -E "^$key=" "$ENV_FILE" | cut -d= -f2-)"
  printf "%s [%s]: " "$prompt" "$current"
  read value
  if [ -z "$value" ]; then
    value="$current"
  fi
  if grep -q "^$key=" "$ENV_FILE"; then
    sed -i "s#^$key=.*#$key=$value#" "$ENV_FILE"
  else
    echo "$key=$value" >> "$ENV_FILE"
  fi
}
update_var "SENDGRID_API_KEY" "SendGrid API Key"
update_var "SENDGRID_FROM_EMAIL" "SendGrid From Email"
update_var "TWILIO_ACCOUNT_SID" "Twilio Account SID"
update_var "TWILIO_AUTH_TOKEN" "Twilio Auth Token"
update_var "TWILIO_FROM_NUMBER" "Twilio From Number"
echo "Updated $ENV_FILE with provider credentials."
