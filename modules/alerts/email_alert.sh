#!/bin/bash

# Usage: email_alert.sh "Subject" "Message"
SUBJECT=$1
MESSAGE=$2
EMAIL="admin@example.com"

# Log and simulate email
echo "[ALERT] $SUBJECT - $MESSAGE"
# echo "$MESSAGE" | mail -s "$SUBJECT" "$EMAIL"

