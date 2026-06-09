#!/usr/bin/env python3
import os, sys, json, threading, smtplib, time, random, string, subprocess
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from scapy.all import sniff, IP, Ether, DNS, DNSQR, TCP, Raw, ICMP, ARP

#
from modules.arp_spoofer import ArpSpoofer

# ── ! ─────────────────────────────────────────────────────
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        for linea in f:
            linea = linea.strip()
            if linea and not linea.startswith('#') and '=' in linea:
                k, v = linea.split('=', 1)
                os.environ[k.strip()] = v.strip()

app = Flask(__name__)
CORS(app)

# ── ¿ ─────────────────────────────────────────────────────────
INTERFAZ_RED = os.getenv("INTERFAZ_RED", "enp0s3")
SMTP_SERVER  = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT    = int(os.getenv("SMTP_PORT", 587))
SMTP_USER    = os.getenv("SMTP_USER", "")
SMTP_PASS    = os.getenv("SMTP_PASS", "")
ADMIN_TOKEN  = os.getenv("ADMIN_TOKEN", "")

WHITELIST_FILE = 'data/whitelist.json'
BLACKLIST_FILE = 'data/blacklist.json'
CONFIG_FILE    = 'data/config.json'
LOG_FILE       = 'logs/traffic.log'
DNS_LOG_FILE   = 'logs/dns.log'

COOLDOWN_CORREOS       = {}
TIEMPO_ESPERA_SEGUNDOS = 300
PENDING_VERIFICATIONS  = {}
LISTA_NEGRA_IPS        = {}


HOST_IPS = set()


arp_spoofer = None  


# ════════════════════════════════════════════════════════════════════════════════
#  ?
# ════════════════════════════════════════════════════════════════════════════════

def load_json(ruta, default):
    if os.path.exists(ruta):
        try:
            with open(ruta, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return default

def save_json(ruta, data):
    os.makedirs(os.path.dirname(ruta), exist_ok=True)
    with open(ruta, 'w') as f:
        json.dump(data, f, indent=4)

def load_whitelist():  return load_json(WHITELIST_FILE, {})
def save_whitelist(d): save_json(WHITELIST_FILE, d)

def load_config():
    cfg = load_json(CONFIG_FILE, {})
    if 'admin_email' not in cfg:
        cfg['admin_email'] = os.getenv("CORREO_ADMINISTRADOR", "")
        save_json(CONFIG_FILE, cfg)
    return cfg

def save_config(d): save_json(CONFIG_FILE, d)
def get_admin_email(): return load_config().get('admin_email', '')

def load_blacklist_from_file():
    global LISTA_NEGRA_IPS
    predefinida = {
        "185.220.101.5":  {"categoria": "Botnet/TOR",    "riesgo": "CRITICO"},
        "194.165.16.6":   {"categoria": "Malware/C2",    "riesgo": "ALTO"},
        "45.142.212.100": {"categoria": "Phishing",      "riesgo": "ALTO"},
        "91.92.109.196":  {"categoria": "Ransomware/C2", "riesgo": "CRITICO"},
        "185.156.72.1":   {"categoria": "Spam/Botnet",   "riesgo": "MEDIO"},
        "8.8.8.8":        {"categoria": "TEST-ListaNegra","riesgo": "BAJO"},
    }
    custom = load_json(BLACKLIST_FILE, {})
    LISTA_NEGRA_IPS = {**predefinida, **custom}

def escribir_log(archivo, mensaje):
    ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    linea = f"[{ts}] {mensaje}"
    os.makedirs('logs', exist_ok=True)
    with open(archivo, 'a') as f:
        f.write(linea + "\n")
    return linea

#
# |

def detectar_ips_propias():
    """
    Obtiene todas las IPs asignadas a este host para no generarse alertas a sí mismo.
    """
    ips = set()
    try:
        import socket
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ips.add(info[4][0])
    except Exception:
        pass

    try:
        out = subprocess.check_output(
            ['ip', '-o', '-4', 'addr', 'show'],
            stderr=subprocess.DEVNULL
        ).decode()
        for linea in out.splitlines():
            partes = linea.split()
            if len(partes) >= 4:
                ip = partes[3].split('/')[0]
                ips.add(ip)
    except Exception:
        pass
    ips.update({"127.0.0.1", "0.0.0.0", "255.255.255.255"})
    return ips


# ════════════════════════════════════════════════════════════════════════════════
#  &
# ════════════════════════════════════════════════════════════════════════════════

def enviar_correo(destinatario, asunto, cuerpo_html):
    if not SMTP_USER or not SMTP_PASS or not destinatario:
        print(f"[SMTP] Sin credenciales. Asunto: {asunto}")
        return

    def _send():
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = asunto
            msg['From']    = SMTP_USER
            msg['To']      = destinatario
            msg.attach(MIMEText(cuerpo_html, 'html'))
            s = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=15)
            s.ehlo(); s.starttls(); s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_USER, destinatario, msg.as_string())
            s.quit()
            print(f"[✓ SMTP] → {destinatario}: {asunto}")
        except Exception as e:
            print(f"[✗ SMTP] {e}")

    threading.Thread(target=_send, daemon=True).start()


    #  %
    #
def _tabla_html(color, titulo, filas):
    rows = "".join(
        f"<tr><td style='padding:8px 12px;font-weight:600;color:#555;width:170px'>{k}</td>"
        f"<td style='padding:8px 12px;color:#222'>{v}</td></tr>"
        for k, v in filas
    )
    return f"""<div style='font-family:Arial,sans-serif;max-width:620px;margin:auto'>
      <div style='background:{color};padding:16px 22px;border-radius:8px 8px 0 0'>
        <h2 style='color:#fff;margin:0;font-size:17px'>{titulo}</h2></div>
      <table style='width:100%;border-collapse:collapse;background:#fafafa;
             border:1px solid #ddd;border-top:none;border-radius:0 0 8px 8px'>{rows}</table>
      <p style='color:#999;font-size:11px;margin-top:10px'>
        IDS Institucional — {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p></div>"""

def correo_codigo_verificacion(correo, codigo):
    html = _tabla_html("#2563eb", "Verificación de correo — IDS", [
        ("Código", f"<span style='font-size:30px;font-weight:bold;color:#2563eb;letter-spacing:8px'>{codigo}</span>"),
        ("Válido por", "5 minutos"),
        ("Acción", "Cambio de correo administrador del IDS"),
    ])
    enviar_correo(correo, f"[IDS] Código de verificación: {codigo}", html)

def correo_intruso(ip, mac, tipo, protocolo=""):
    admin = get_admin_email()
    if not admin: return
    titulo = {"INTRUSO": "⚠️ Dispositivo No Autorizado",
              "SPOOFING": "⚠️ Posible Spoofing de IP"}.get(tipo, "⚠️ Alerta")
    html = _tabla_html("#dc2626", titulo, [
        ("Tipo",         tipo),
        ("IP",           ip),
        ("MAC",          mac or "No disponible"),
        ("Protocolo",    protocolo or "Desconocido"),
        ("Estado",       "NO está en la lista blanca"),
        ("Acción",       "Verificar físicamente el dispositivo"),
    ])
    enviar_correo(admin, f"[IDS ALERTA] {titulo} — {ip}", html)

def correo_amenaza(ip_origen, ip_destino, categoria, riesgo, protocolo, whois_data):
    admin = get_admin_email()
    if not admin: return
    html = _tabla_html("#7c3aed", "🚨 EMERGENCIA — Conexión a IP Peligrosa", [
        ("IP interna",     ip_origen),
        ("IP peligrosa",   ip_destino),
        ("Categoría",      categoria),
        ("Riesgo",         f"<strong style='color:#dc2626'>{riesgo}</strong>"),
        ("Protocolo",      protocolo),
        ("ASN",            whois_data.get('asn', 'N/D')),
        ("Organización",   whois_data.get('org', 'N/D')),
        ("País",           whois_data.get('country', 'N/D')),
        ("Email de abuso", whois_data.get('abuse_email', 'N/D')),
        ("Cómo reportar",  f"Envía evidencia a {whois_data.get('abuse_email','abuse@iana.org')}"),
    ])
    enviar_correo(admin, f"[IDS CRÍTICO] IP peligrosa {ip_destino} — {riesgo}", html)


# ════════════════════════════════════════════════════════════════════════════════
#  +
# ════════════════════════════════════════════════════════════════════════════════

def consultar_whois(ip):
    res = {'asn':'', 'org':'', 'country':'', 'abuse_email':''}
    try:
        raw = subprocess.check_output(
            ['whois', ip], timeout=10, stderr=subprocess.DEVNULL
        ).decode('utf-8', errors='ignore')
        for linea in raw.splitlines():
            if ':' not in linea: continue
            k, _, v = linea.partition(':')
            v = v.strip(); kl = k.strip().lower()
            if not res['org'] and any(x in kl for x in ['orgname','org-name','organization','owner']):
                res['org'] = v
            if not res['country'] and kl in ('country','country-code'):
                res['country'] = v
            if not res['asn'] and 'asn' in kl:
                res['asn'] = v
            if not res['abuse_email'] and 'abuse' in kl and '@' in v:
                res['abuse_email'] = v
    except Exception as e:
        print(f"[WHOIS] whois falló: {e}")
    # Fallback ipinfo.io
    if not res['org'] or not res['country']:
        try:
            import urllib.request
            with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json", timeout=8) as r:
                d = json.loads(r.read())
            res['org']     = res['org']     or d.get('org','')
            res['country'] = res['country'] or d.get('country','')
        except Exception:
            pass
    return res


# ════════════════════════════════════════════════════════════════════════════════
#  *
# ════════════════════════════════════════════════════════════════════════════════

def _protocolo_str(pkt):
    """Detecta el protocolo del paquete de forma legible."""
    if pkt.haslayer(ICMP): return "ICMP (ping)"
    if pkt.haslayer(ARP):  return "ARP"
    if pkt.haslayer(DNS):  return "DNS"
    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else 0
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else 0
        puerto = min(dport, sport) if dport and sport else (dport or sport)
        nombres = {80:"HTTP", 443:"HTTPS", 22:"SSH", 21:"FTP",
                   25:"SMTP", 53:"DNS/TCP", 3389:"RDP", 8080:"HTTP-ALT"}
        return nombres.get(puerto, f"TCP:{dport}")
    if pkt.haslayer('UDP'): return "UDP"
    return "IP"

def _es_ip_ignorable(ip):
    """IPs que nunca deben generar alerta (broadcast, multicast, loopback)."""
    return (
        ip.startswith("224.")
        or ip.startswith("239.")
        or ip.startswith("255.")
        or ip == "0.0.0.0"
        or ip.startswith("127.")
        or ip == "::1"
    )



#
# /
def analizar_paquete(pkt):
    try:
        if pkt.haslayer(ARP):
            ip_arp  = pkt[ARP].psrc  
            mac_arp = pkt[ARP].hwsrc.lower()

            if _es_ip_ignorable(ip_arp) or ip_arp in HOST_IPS:
                return

            wl = load_whitelist()
            ahora = time.time()
            clave = f"arp_{ip_arp}"

            if ip_arp not in wl:
                # Dispositivo desconocido anunciándose en la red
                msg = f"[INTRUSO/ARP] Dispositivo no autorizado: IP={ip_arp} MAC={mac_arp}"
                escribir_log(LOG_FILE, msg)
                if clave not in COOLDOWN_CORREOS or (ahora - COOLDOWN_CORREOS[clave] > TIEMPO_ESPERA_SEGUNDOS):
                    threading.Thread(target=correo_intruso,
                        args=(ip_arp, mac_arp, "INTRUSO", "ARP"), daemon=True).start()
                    COOLDOWN_CORREOS[clave] = ahora
            else:
      
                if wl[ip_arp] != mac_arp:
                    msg = f"[SPOOFING] IP {ip_arp} con MAC distinta: {mac_arp} (esperada: {wl[ip_arp]})"
                    escribir_log(LOG_FILE, msg)
                    if clave not in COOLDOWN_CORREOS or (ahora - COOLDOWN_CORREOS[clave] > TIEMPO_ESPERA_SEGUNDOS):
                        threading.Thread(target=correo_intruso,
                            args=(ip_arp, mac_arp, "SPOOFING", "ARP"), daemon=True).start()
                        COOLDOWN_CORREOS[clave] = ahora
            return 
        
#
# v6

        if not pkt.haslayer(IP):
            return

        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        proto  = _protocolo_str(pkt)
        ahora  = time.time()

        if _es_ip_ignorable(ip_src) or _es_ip_ignorable(ip_dst):
            return
        if ip_src not in HOST_IPS:
            wl    = load_whitelist()
            clave = f"intruso_{ip_src}"


            mac_src = ""
            if pkt.haslayer(Ether):
                mac_src = pkt[Ether].src.lower()

            if ip_src not in wl:
        
                msg = f"[INTRUSO] No autorizado: IP={ip_src} MAC={mac_src or 'N/A'} Proto={proto} → {ip_dst}"
                escribir_log(LOG_FILE, msg)

                if clave not in COOLDOWN_CORREOS or (ahora - COOLDOWN_CORREOS[clave] > TIEMPO_ESPERA_SEGUNDOS):
                    threading.Thread(target=correo_intruso,
                        args=(ip_src, mac_src, "INTRUSO", proto), daemon=True).start()
                    COOLDOWN_CORREOS[clave] = ahora

            elif mac_src:

                mac_esperada = wl.get(ip_src, "")
                if mac_esperada and mac_esperada != mac_src:
                    msg = f"[SPOOFING] IP {ip_src} usa MAC {mac_src} (esperada: {mac_esperada})"
                    escribir_log(LOG_FILE, msg)
                    clave_s = f"spoof_{ip_src}"
                    if clave_s not in COOLDOWN_CORREOS or (ahora - COOLDOWN_CORREOS[clave_s] > TIEMPO_ESPERA_SEGUNDOS):
                        threading.Thread(target=correo_intruso,
                            args=(ip_src, mac_src, "SPOOFING", proto), daemon=True).start()
                        COOLDOWN_CORREOS[clave_s] = ahora

        # ── ° ────────────────────
        if ip_dst in LISTA_NEGRA_IPS:
            info   = LISTA_NEGRA_IPS[ip_dst]
            clave  = f"amenaza_{ip_src}_{ip_dst}"
            msg    = (f"[AMENAZA] {ip_src} → IP peligrosa {ip_dst} "
                      f"| {info['categoria']} | {info['riesgo']} | {proto}")
            escribir_log(LOG_FILE, msg)

            if clave not in COOLDOWN_CORREOS or (ahora - COOLDOWN_CORREOS[clave] > TIEMPO_ESPERA_SEGUNDOS):
                COOLDOWN_CORREOS[clave] = ahora
                threading.Thread(
                    target=_proceso_forense,
                    args=(ip_src, ip_dst, info, proto),
                    daemon=True
                ).start()

        if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname
            dominio = (qname.decode('utf-8', errors='ignore') if isinstance(qname, bytes)
                       else str(qname)).rstrip('.')
            if dominio and len(dominio) > 4 and '.' in dominio:
                escribir_log(DNS_LOG_FILE, f"[DNS] {ip_src} → {dominio}")

        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt[TCP].dport == 80:
            try:
                payload = bytes(pkt[Raw].load).decode('utf-8', errors='ignore')
                if payload.startswith(('GET ', 'POST ', 'HEAD ')):
                    for linea in payload.split('\r\n'):
                        if linea.lower().startswith('host:'):
                            host = linea.split(':', 1)[1].strip()
                            escribir_log(DNS_LOG_FILE, f"[HTTP] {ip_src} → {host}")
                            break
            except Exception:
                pass

    except Exception as e:
        pass  


def _proceso_forense(ip_origen, ip_destino, info, protocolo):
    whois_data = consultar_whois(ip_destino)
    correo_amenaza(ip_origen, ip_destino, info['categoria'], info['riesgo'], protocolo, whois_data)


# S
def iniciar_sniffer():
    global arp_spoofer

    print(f"[*] Iniciando IDS en interfaz: {INTERFAZ_RED}")
    print(f"[*] IPs propias del host: {HOST_IPS}")


    arp_spoofer = ArpSpoofer(
        interfaz=INTERFAZ_RED,
        log_fn=lambda msg: escribir_log(LOG_FILE, msg)
    )
    ok = arp_spoofer.iniciar()
    if ok:
        print("[*] ARP spoofer activo — interceptando tráfico de toda la red")
    else:
        print("[!] ARP spoofer no pudo iniciarse — solo se verá tráfico local")

    try:
        sniff(
            iface=INTERFAZ_RED,
            prn=analizar_paquete,
            store=False,
            promisc=True,
            filter="ip or arp",
        )
    except PermissionError:
        print("[FATAL] Necesitas ejecutar con: sudo python3 app.py")
        sys.exit(1)
    finally:

        if arp_spoofer:
            arp_spoofer.detener()


# ════════════════════════════════════════════════════════════════════════════════
#  <
# ════════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index(): return render_template('index.html')


@app.route('/api/hosts', methods=['GET'])
def get_hosts():
    hosts = arp_spoofer.get_hosts() if arp_spoofer else []
    return jsonify({'hosts': hosts})

@app.route('/api/whitelist', methods=['GET'])
def get_whitelist(): return jsonify(load_whitelist())

@app.route('/api/whitelist', methods=['POST'])
def add_whitelist():
    data = request.json or {}
    ip  = data.get('ip','').strip()
    mac = data.get('mac','').lower().strip()
    if not ip or not mac:
        return jsonify({'status':'error','message':'IP y MAC requeridas'}), 400
    wl = load_whitelist(); wl[ip] = mac; save_whitelist(wl)
    escribir_log(LOG_FILE, f"[CONFIG] Autorizado: IP={ip} MAC={mac}")
    return jsonify({'status':'ok','message':f'{ip} autorizado'})

@app.route('/api/whitelist/<ip>', methods=['DELETE'])
def delete_whitelist(ip):
    wl = load_whitelist()
    if ip not in wl:
        return jsonify({'status':'error','message':'IP no encontrada'}), 404
    del wl[ip]; save_whitelist(wl)
    escribir_log(LOG_FILE, f"[CONFIG] Eliminado de lista blanca: {ip}")
    return jsonify({'status':'ok','message':f'{ip} eliminada'})

@app.route('/api/report', methods=['GET'])
def get_report():
    lineas = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE,'r') as f: lineas = f.readlines()[-60:]
    return jsonify({'logs': lineas})

@app.route('/api/dns-log', methods=['GET'])
def get_dns_log():
    lineas = []
    if os.path.exists(DNS_LOG_FILE):
        with open(DNS_LOG_FILE,'r') as f: lineas = f.readlines()[-80:]
    return jsonify({'logs': lineas})

@app.route('/api/blacklist', methods=['GET'])
def get_blacklist(): return jsonify(LISTA_NEGRA_IPS)

@app.route('/api/blacklist', methods=['POST'])
def add_blacklist():
    data = request.json or {}
    ip  = data.get('ip','').strip()
    cat = data.get('categoria','Desconocido').strip()
    rv  = data.get('riesgo','MEDIO').strip().upper()
    if not ip: return jsonify({'status':'error','message':'IP requerida'}), 400
    custom = load_json(BLACKLIST_FILE, {})
    custom[ip] = {'categoria': cat, 'riesgo': rv}
    save_json(BLACKLIST_FILE, custom)
    load_blacklist_from_file()
    escribir_log(LOG_FILE, f"[CONFIG] Blacklist: {ip} [{cat}/{rv}]")
    return jsonify({'status':'ok','message':f'{ip} agregada a lista negra'})


# ─────────────────────────────────── = ─────────────────────────────────────────────────


@app.route('/api/config/admin', methods=['GET'])
def get_admin_info():
    email = get_admin_email()
    if email and '@' in email:
        u, d = email.split('@',1)
        preview = u[:2]+'***@'+d
    else:
        preview = 'No configurado'
    return jsonify({'admin_email_preview': preview})

@app.route('/api/config/admin/solicitar', methods=['POST'])
def solicitar_cambio_correo():
    data  = request.json or {}
    nuevo = data.get('nuevo_correo','').strip()
    token = data.get('token','').strip()
    if not nuevo or '@' not in nuevo:
        return jsonify({'fase':'Identificación','message':'Correo inválido'}), 400
    if not ADMIN_TOKEN:
        return jsonify({'fase':'Autenticación','message':'ADMIN_TOKEN no configurado'}), 500
    if token != ADMIN_TOKEN:
        escribir_log(LOG_FILE, f"[SEGURIDAD] Token incorrecto desde {request.remote_addr}")
        return jsonify({'fase':'Autenticación','message':'Token incorrecto'}), 403
    codigo = ''.join(random.choices(string.digits, k=6))
    PENDING_VERIFICATIONS[nuevo] = {'code': codigo, 'expires': time.time()+300,
                                     'remote_ip': request.remote_addr}
    correo_codigo_verificacion(nuevo, codigo)
    return jsonify({'fase':'Autenticación',
                    'message':f'Código enviado a {nuevo[:3]}***. Ingrésalo para confirmar.'})

@app.route('/api/config/admin/confirmar', methods=['POST'])
def confirmar_cambio_correo():
    data   = request.json or {}
    nuevo  = data.get('nuevo_correo','').strip()
    codigo = data.get('codigo','').strip()
    if nuevo not in PENDING_VERIFICATIONS:
        return jsonify({'fase':'Autorización','message':'Sin solicitud pendiente'}), 400
    p = PENDING_VERIFICATIONS[nuevo]
    if time.time() > p['expires']:
        del PENDING_VERIFICATIONS[nuevo]
        return jsonify({'fase':'Autorización','message':'Código expirado'}), 400
    if codigo != p['code']:
        escribir_log(LOG_FILE, f"[SEGURIDAD] Código incorrecto para {nuevo}")
        return jsonify({'fase':'Autorización','message':'Código incorrecto'}), 403
    anterior = get_admin_email()
    cfg = load_config(); cfg['admin_email'] = nuevo; save_config(cfg)
    del PENDING_VERIFICATIONS[nuevo]
    escribir_log(LOG_FILE, f"[CONFIG] Correo admin: {anterior} → {nuevo}")
    return jsonify({'fase':'Autorización','message':f'Correo actualizado a {nuevo}'})


# ════════════════════════════════════════════════════════════════════════════════
#  ~
# ════════════════════════════════════════════════════════════════════════════════


if __name__ == '__main__':
    import signal

    os.makedirs('data', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    HOST_IPS = detectar_ips_propias()
    load_blacklist_from_file()

    def _shutdown(sig, frame):
        print("\n[*] Deteniendo IDS...")
        if arp_spoofer:
            arp_spoofer.detener()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    threading.Thread(target=iniciar_sniffer, daemon=True).start()
    print("[*] IDS → http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
