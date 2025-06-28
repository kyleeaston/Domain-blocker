from scapy.all import sniff, IP
import smtplib
import time
from email.mime.text import MIMEText



# Fill in required details
TARGET_DOMAIN = ""  
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = ""
SENDER_PASSWORD = ""
RECEIVER_EMAIL = ""
TARGET_IP = ""

last_notice = 0

def send_email():
    """Function to send an alert email"""
    subject = "Domain Connection Alert"
    body = f"In addition to my screen time on my phone, I do not want to be distracted by my laptop so here is an automated alert. Kyle is being fat and lazy on {TARGET_DOMAIN}."
    
    msg = MIMEText(body)
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL
    msg["Subject"] = subject

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        print("[+] Email sent successfully!")
    except Exception as e:
        print(f"[-] Failed to send email: {e}")

def packet_callback(packet):
    global last_notice
    if packet.haslayer(IP) and packet[IP].dst == TARGET_IP:
        print(f"[!] Connection to {TARGET_IP} detected!")
        # cooldown timer to avoid excessive notifications
        if (time.time() - last_notice > 600):
            last_notice = time.time()
            send_email()
        else:
            print(f"[!] Email not sent, cooldown triggered")

# Start packet sniffing (requires admin privileges)
print(f"[*] Monitoring traffic for {TARGET_DOMAIN}...")
sniff(filter=f"host {TARGET_IP}", prn=packet_callback, store=0)


