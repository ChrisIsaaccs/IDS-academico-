#!/usr/bin/env python3
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dove import load_config

load_config()

SMTP_SERVER = os.getenv("SMTP_SERVER", 'smtp.gmail.com')
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")

def enviar_alerta(asunto, cuerpo):
    if not SMTP_USER or not SMTP_PASSWORD:
        print("[ALERTA] No se han configurado las credenciales SMTP. No se enviará el correo.")
        return False
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = ADMIN_EMAIL
        msg['Subject'] = asunto
        msg.attach(MIMEText(cuerpo, 'plain', 'utf-8'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"[v] Correo enviado: {asunto}")
        return True
    except Exception as e:
        print(f"[x] Error al enviar correo: {e}")
        return False