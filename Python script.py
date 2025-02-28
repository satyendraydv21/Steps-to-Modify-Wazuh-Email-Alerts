#Commands: -  sudo nano /var/ossec/etc/ossec.conf
#Find the <integration> section in the ossec.conf file. This is where you configure the general settings for email alerts.
# Configuration example:
# <integration>
#       <name>custom-email-alerts</name>
#       <hook_url>emailrecipient@example.com</hook_url>
#       <group>attacks</group>
#       <alert_format>json</alert_format>
#   </integration>
# 2. Adding the integration script to the manager.
# •	Add the following Python script as /var/ossec/integrations/custom-email.py in the manager:
# Run this Commands to create: - nano /var/ossec/integrations/custom-email.py 
# •	Set the correct permissions and ownership to the integration script:
# Use the following commands:
# chown root:wazuh /var/ossec/integrations/custom-email.py 
# chmod 750 /var/ossec/integrations/custom-email.py

#Python script: -

import imaplib
import email
from email.header import decode_header
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import socket
import re
from datetime import datetime

# Your email credentials
username = "xyz@gmail.com"
password = "useyour-gmail-app-password"  # Use App Password if Two-Factor Authentication is enabled

# Connect to your email server using IMAP
mail = imaplib.IMAP4_SSL("imap.gmail.com")
mail.login(username, password)

# Select the inbox to search
mail.select("inbox")

# Search for emails with the specific subject or from a certain sender
status, messages = mail.search(None, '(FROM "stymzp@gmail.com")')

# Get the list of email IDs
email_ids = messages[0].split()

# Function to extract the agent name from the email body
def extract_agent_name(body):
    agent_pattern = r"Received From: \((.*?)\)"  # Extract text inside parentheses after "Received From: "
    match = re.search(agent_pattern, body)
    if match:
        return match.group(1)
    return "Unknown Agent"

# Function to extract the alert name (rule description)
def extract_alert_name(body):
    alert_pattern = r"Rule: \d+\s+fired \([^\)]+\)\s+->\s+\"([^\"]+)\""  # Match the description after "Rule: <number> fired"
    match = re.search(alert_pattern, body)
    if match:
        return match.group(1)
    return "Unknown Alert"

# Function to extract the agent's IP address dynamically from the logs
def extract_agent_ip(body):
    # New pattern for agent IP to match various possible formats of the IP address
    ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # Matches a standard IPv4 address (e.g., 192.168.1.1)
    match = re.search(ip_pattern, body)
    if match:
        return match.group(1)
    return "N/A"

# Function to extract the rule level dynamically from the body
def extract_rule_level(body):
    # Extract rule level after "Rule: <number> fired (level <rule_level>)"
    rule_level_pattern = r"Rule: \d+\s+fired\s+\(level (\d+)\)"  # Extract level number after "level"
    match = re.search(rule_level_pattern, body)
    if match:
        return match.group(1)
    return "N/A"

# Function to extract timestamp from the email's Date header
def extract_timestamp(msg):
    email_timestamp = msg.get("Date")
    if email_timestamp:
        try:
            timestamp = email.utils.parsedate_tz(email_timestamp)
            timestamp = datetime.fromtimestamp(email.utils.mktime_tz(timestamp))
            return timestamp.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            print(f"Error parsing timestamp: {e}")
            return "Unknown Timestamp"
    return "No Timestamp Found"

# Process each email
for email_id in email_ids:
    status, msg_data = mail.fetch(email_id, "(RFC822)")
    for response_part in msg_data:
        if isinstance(response_part, tuple):
            msg = email.message_from_bytes(response_part[1])
            subject, encoding = decode_header(msg["Subject"])[0]
            if isinstance(subject, bytes):
                subject = subject.decode(encoding if encoding else "utf-8")

            from_ = msg.get("From")
            print(f"Original Subject: {subject}")
            print(f"From: {from_}")

            # Extract timestamp
            timestamp = extract_timestamp(msg)

            # Extract the body of the email
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        body = part.get_payload(decode=True).decode()
            else:
                body = msg.get_payload(decode=True).decode()

            # Extract agent name, alert name, agent IP, alert level, and rule level dynamically
            agent_name = extract_agent_name(body)
            alert_name = extract_alert_name(body)
            agent_ip = extract_agent_ip(body)
            rule_level = extract_rule_level(body)

            # Use the computer name from the body if available, otherwise use default hostname
            hostname_pattern = r"computer\s*=\s*([a-zA-Z0-9-]+)"  # Extract "computer" field value
            hostname_match = re.search(hostname_pattern, body)
            hostname = hostname_match.group(1) if hostname_match else socket.gethostname()

            # Check if rule level is greater than or equal to 7
            if rule_level == "N/A" or int(rule_level) < 9:
                print(f"Skipping email. Rule level is {rule_level}. Email not sent.")
                continue  # Skip the email if rule level is less than 7 or not available

            # Create HTML body for the email with proper structure and spacing, including Rule Level
            modified_body = f"""
            <html>
            <body>
                <p><strong>SQ1</strong><br>
                We detected a threat on the following device. To know more about the threat and the remedial action taken, please check the report below:<br><br>
                <strong>Device Name:</strong> {agent_name} ({agent_ip})<br>

                <table>
                    <tr><td><strong>Alert Name:</strong></td><td>{alert_name}</td></tr>
                    <tr><td><strong>Timestamp:</strong></td><td>{timestamp}</td></tr>
                </table><br>

                This is a system generated email. Please do not reply to this email.<br>
                If you need further assistance, contact SQ1 Support.<br><br>
                SQ1 Security<br>
                Confidence in an insecure world!
                </p>
            </body>
            </html>
            """

            # Now send the modified email to a new recipient or forward it
            new_sender_email = "stymzp@gmail.com"
            new_receiver_email = "stymzp@gmail.com"
            smtp_password = "olwxbkbaxawhyohg"  # Ensure this is your App Password if 2FA is enabled

            # Create new email with modified subject and body
            new_msg = MIMEMultipart()
            new_msg['From'] = new_sender_email
            new_msg['To'] = new_receiver_email
            new_msg['Subject'] = f"Critical Security Alerts from SQ1 Shield || Rule Level: {rule_level}"
            new_msg.attach(MIMEText(modified_body, 'html'))

            # Send the modified email
            try:
                print(f"Sending email to {new_receiver_email}")
                with smtplib.SMTP("smtp.gmail.com", 587, timeout=60) as server:
                    server.starttls()
                    server.login(new_sender_email, smtp_password)
                    server.sendmail(new_sender_email, new_receiver_email, new_msg.as_string())
                    print("Modified email sent!")
            except Exception as e:
                print(f"Failed to send modified email: {e}")
