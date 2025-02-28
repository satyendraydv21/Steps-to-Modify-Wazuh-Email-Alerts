# Steps-to-Modify-Wazuh-Email-Alerts
To modify the email alerts in Wazuh, you’ll need to make adjustments to the Wazuh manager’s configuration files and potentially customize rules or notifications to fit your needs. Below is a step-by-step guide for modifying email alerts in Wazuh
WAZUH EMAIL ALERTS CONFIGURATION
Step 1: Install and Configure Mail Server
Before you can set up Wazuh email alerts, ensure you have an SMTP mail server to send emails. Common options include:
•	Postfix (Linux)
Follow the instructions below to set up Wazuh to send email alerts 
•	1. Install postfix
 #apt-get install postfix mailutils libsasl2-2 ca-certificates libsasl2-modules
•	while installing give no configuration.
 #cp /usr/share/postfix/main.cf.debian /etc/postfix/main.cf 
•	3. Now, the configuration file /etc/postfix/main.cf must be edited with the mail server information:
   Go to /etc/postfix/main.cf
#nano /etc/postfix/main.cf
•	2. Paste the following lines at the end
All commands : -
   #relayhost = [smtp.gmail.com]:587
   #smtp_sasl_auth_enable = yes
   #smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
   #smtp_sasl_security_options = noanonymous
   #smtp_tls_CAfile = /etc/ssl/certs/thawte_Primary_Root_CA.pem
   #smtp_use_tls = yes
   #compatibility_level = 2
•	3. Once the configuration file has been modified and saved, the next commands are run (Run all command without #)
•	Run the following commands to configure credentials (replace USERNAMEby your google username and PASSWORD by the App password): -
•	Runn all command but replace your username and password
  # echo [smtp.gmail.com]:587 username@gmail.com:(useyourgmail apppassword) >   /etc/postfix/sasl_passwd
   # postmap /etc/postfix/sasl_passwd
   # chmod 400 /etc/postfix/sasl_passwd
   # chown root:root /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
   # chmod 0600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
   # systemctl restart postfix
   # postconf -n
   # postconf -e "smtp_use_tls = yes"
   # systemctl restart postfix
   # newaliases
   # postmap /etc/postfix/sasl_passwd
   # postconf -e "smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt"
   # systemctl restart postfix
   # echo "Test email" | mail -s "Test" msguhan5447@gmail.com
•	6. now configure on wazuh server 
Commands: - # nano /var/ossec/etc/ossec.conf 
•	7. Alter the modification as shown below.
•	<ossec_config>
<global>
<jsonout_output>yes</jsonout_output>
<alerts_log>yes</alerts_log>
<logall>no</logall>
<logall_json>no</logall_json>
<email_notification>yes</email_notification>
<smtp_server>localhost</smtp_server>
<email_from>example@gmail.com</email_from>
<email_to>xyz@gmail.com</email_to>
<email_maxperhour>12</email_maxperhour>
<email_log_source>alerts.log</email_log_source>
<agents_disconnection_time>10m</agents_disconnection_time>
<agents_disconnection_alert_time>0</agents_disconnection_alert_time>
<update_check>yes</update_check>
</global>
<alerts>
<log_alert_level>3</log_alert_level>
<email_alert_level>5</email_alert_level>
</alerts>
•	Run this commands : - 
# systemctl restart wazuh-manager
# systemctl restart postfix
 
•	10. Once Postfix has been restarted, we can check whether the configuration is correct by sending a test email.
Commands: - # echo "Hi! We are testing Postfix!" | mail -s "Test Postfix" destinationmail@testserver1.com
•	Referance: 
•	https://wazuh.com/blog/how-to-send-email-notifications-with-wazuh/ 



Steps to Modify Wazuh Email Alerts
To modify the email alerts in Wazuh, you’ll need to make adjustments to the Wazuh manager’s configuration files and potentially customize rules or notifications to fit your needs. Below is a step-by-step guide for modifying email alerts in Wazuh:
Step 1: Log into Wazuh Manager
Step 2: Modify ossec.conf for Email Settings
Edit the ossec.conf File:
•	Open the main Wazuh configuration file ossec.conf in a text editor.
•	This file is located in the /var/ossec/etc/ directory:
Commands: -  sudo nano /var/ossec/etc/ossec.conf
Find the <integration> section in the ossec.conf file. This is where you configure the general settings for email alerts.
# Configuration example:
<integration>
      <name>custom-email-alerts</name>
      <hook_url>emailrecipient@example.com</hook_url>
      <group>attacks</group>
      <alert_format>json</alert_format>
  </integration>
2. Adding the integration script to the manager.
•	Add the following Python script as /var/ossec/integrations/custom-email.py in the manager:
Run this Commands to create: - nano /var/ossec/integrations/custom-email.py 
•	Set the correct permissions and ownership to the integration script:
Use the following commands:
chown root:wazuh /var/ossec/integrations/custom-email.py 
chmod 750 /var/ossec/integrations/custom-email.py




Now paste python script in /var/ossec/integrations/custom-email.py 

For Python script go to Github link: - https://github.com/satyendraydv21/Steps-to-Modify-Wazuh-Email-Alerts
Save it and restart wazuh -manager
Now we will receive email alerts.
