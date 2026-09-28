#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Escáner de red local | Descubre quién está en tu WiFi.
Solo tu propia red. Fines educativos."""
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from tools import netdiscover, nmapscan, reporter

__version__ = "2.1.5"

if os.name == "nt":
    try:
        os.system("")
    except Exception:
        pass


class C:
    NC = "\033[38;2;0;255;234m"; NP = "\033[38;2;255;0;255m"
    NG = "\033[38;2;57;255;20m"; NY = "\033[38;2;255;255;0m"
    NV = "\033[38;2;176;38;255m"; NO = "\033[38;2;255;110;0m"
    D = "\033[90m"; W = "\033[97m"; BOLD = "\033[1m"; END = "\033[0m"


BANNER = f"""{C.NC}{C.BOLD}
  _____ ___  ____ _   _ _   _ _____ ____
 | ____/ __|/ ___| \\ | | \\ | | ____|  _ \\
 |  _| \\__ \\ |   |  \\| |  \\| |  _| | |_) |
 | |___ ___) | |__| |\\  | |\\  | |___|  _ <
 |_____|____/\\____|_| \\_|_| \\_|_____|_| \\_\\{C.END}
  {C.NP}{C.BOLD}Escáner de red v{__version__}{C.END} {C.NY}(educativo, objetivos autorizados){C.END}
"""


def ask(p):
    return input(f" {C.NC}{C.BOLD}>{C.END} {p}: ").strip()


def confirm_auth() -> bool:
    print(f"\n {C.NY}Solo objetivos propios o con autorización escrita.{C.END}")
    return ask("¿Confirmas autorización? [s/N]").lower() in ("s", "si", "sí", "y", "yes")


def net_audit(devices: list[dict], netinfo: dict, local: bool = True) -> list[str]:
    """Auditoría de RED (no personal). local=False: omite lo que solo vale en LAN."""
    from tools import nmapscan
    hallazgos: list[str] = []
    expuestos: dict[int, list[str]] = {}
    for d in devices:
        for p in d.get("puertos", []):
            expuestos.setdefault(p, []).append(d["ip"])
    if not expuestos:
        hallazgos.append("OK: sin puertos comunes abiertos en los equipos detectados.")
    for p in sorted(expuestos):
        hallazgos.append(f"Puerto {p} abierto en: {', '.join(expuestos[p])}")
    for a in nmapscan.advisories(list(expuestos)):
        hallazgos.append("AVISO: " + a)
    telnet_ftp = [d["ip"] for d in devices
                  if any(x in d.get("puertos", []) for x in (21, 23))]
    if telnet_ftp:
        hallazgos.append("CRÍTICO: FTP/Telnet en claro en: " + ", ".join(telnet_ftp))
    con_ptr = [d["ip"] for d in devices if d.get("nombre", "-") != "-"]
    hallazgos.append(f"Con nombre PTR: {len(con_ptr)}/{len(devices)}")
    if local:
        dns = netdiscover.dns_servers()
        if dns:
            hallazgos.append("DNS de la red: " + ", ".join(dns))
        hallazgos.append("Internet: " + ("OK" if netdiscover.internet_ok() else "sin salida"))
        gw = next((d for d in devices if d["ip"] == netinfo.get("gateway")), None)
        if gw:
            hallazgos.append(f"Gateway {gw['ip']}: {gw.get('vendor', '-')} "
                             f"puertos {','.join(map(str, gw.get('puertos', []))) or '-'}")
    else:
        hallazgos.append("Remoto: MAC/fabricante no aplican fuera de LAN (límite de ARP).")
    return hallazgos


def show(devices):
    print(f"\n {C.BOLD}{'IP':<16}{'MS':<7}{'PUERTOS':<14}{'FABRICANTE':<24}NOMBRE{C.END}")
    for d in devices:
        nuevo = f" {C.NY}[NUEVO]{C.END}" if d.get("nuevo") else ""
        tag = f"{C.NG}[+]{C.END}" if d.get("mac") != "-" else f"{C.D}[-]{C.END}"
        print(f" {tag} {C.W}{d['ip']:<14}{C.END} {str(d.get('latencia', '-')):<6} "
              f"{','.join(map(str, d.get('puertos', []))) or '-':<13} "
              f"{d.get('vendor', '-'):<24} {d.get('nombre', '-')}{nuevo}")


def load_last():
    import json as _j
    p = os.path.join(reporter.ensure_dir(), "last_scan.json")
    try:
        with open(p, encoding="utf-8") as f:
            return set(_j.load(f).get("ips", []))
    except Exception:
        return set()


def save_last(ips):
    import json as _j
    p = os.path.join(reporter.ensure_dir(), "last_scan.json")
    try:
        with open(p, "w", encoding="utf-8") as f:
            _j.dump({"ips": sorted(ips)}, f)
    except Exception:
        pass


def enrich(ips, known=None):
    import ipaddress
    arp = netdiscover.arp_table()
    out = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_multicast or addr.is_reserved:
                continue
        except ValueError:
            continue
        mac = arp.get(ip, "-")
        if mac == "ff:ff:ff:ff:ff:ff":
            continue  # broadcast, no es un equipo
        lat = netdiscover.ping_latency(ip)
        out.append({"ip": ip, "mac": mac,
                    "latencia": lat if lat is not None else "-",
                    "puertos": netdiscover.quick_ports(ip) if mac != "-" else [],
                    "vendor": netdiscover.vendor_of(mac) if mac != "-" else "-",
                    "nombre": netdiscover.reverse_name(ip),
                    "nuevo": bool(known is not None and ip not in known)})
    return out


def main():
    print(BANNER)
    print(f" {C.NY}Solo tu propia red. Fines educativos.{C.END}")
    net = netdiscover.local_network()
    if "error" in net:
        print(f" [!] {net['error']}")
        sys.exit(1)
    last: list[dict] = []
    last_audit: list[str] = []

    def do_scan(red: str, local: bool = True) -> list[dict]:
        """Barrido con nmap si hay, si no Python. Devuelve equipos enriquecidos."""
        if nmapscan.nmap_path():
            print(f" {C.NY}Descubriendo con nmap -sn {red}...{C.END}")
            try:
                vivos = nmapscan.discover(red)
            except Exception as e:
                print(f" [!] nmap falló ({e}), usando sweep Python...")
                vivos = netdiscover.ping_sweep(
                    red, progress=lambda d, t: print(f"   ...{d}/{t}", end="\r"))
                print(" " * 30, end="\r")
        else:
            print(f" {C.NY}Sweep Python en {red} (~30s, instala nmap para ir más rápido)...{C.END}")
            vivos = netdiscover.ping_sweep(
                red, progress=lambda d, t: print(f"   ...{d}/{t}", end="\r"))
            print(" " * 30, end="\r")
        known = load_last()
        devs = enrich(vivos, known or None)
        nuevos = [d for d in devs if d.get("nuevo")]
        if nuevos and known:
            print(f" {C.NY}{C.BOLD}ALERTA: equipo(s) nuevo(s): {', '.join(d['ip'] for d in nuevos)}{C.END}")
        save_last([d["ip"] for d in devs])
        print(f" {C.NG}Encontrados: {len(devs)}{C.END}")
        show(devs)
        print(f"\n {C.NY}{C.BOLD}AUDITORÍA DE RED:{C.END}")
        audit = net_audit(devs, {"gateway": net.get("gateway")}, local=(red == net.get("red")))
        for h in audit:
            col = C.NG if h.startswith("OK") else C.NO if "CRÍTICO" in h else C.NY
            print(f"   {col}·{C.END} {h}")
        nonlocal last_audit
        last_audit = audit
        return devs

    while True:
        print(f"\n {C.NV}{C.BOLD}+-- MENU --+{C.END}")
        print(f"  {C.NC}[1]{C.END} > Escanear red")
        print(f"  {C.NC}[2]{C.END} > Otra red")
        print(f"  {C.NC}[3]{C.END} > Detalle IP")
        print(f"  {C.NC}[4]{C.END} > Vigilar")
        print(f"  {C.NC}[5]{C.END} > Guardar")
        print(f"  {C.NO}[0]{C.END} < Salir")
        c = ask("Elige")
        if c == "0":
            print(" Adiós.")
            return
        elif c == "1":
            last = do_scan(net["red"])
        elif c == "2":
            if not confirm_auth():
                print(" Cancelado: se requiere autorización.")
                continue
            cidr = ask("Red CIDR (ej. 10.0.0.0/24)")
            try:
                import ipaddress as _ip
                red = str(_ip.ip_network(cidr, strict=False))
            except ValueError:
                print(" [!] CIDR no válido.")
                continue
            print(f" {C.D}Nota: MAC/fabricante solo salen en LAN local.{C.END}")
            last = do_scan(red, local=False)
        elif c == "3":
            ip = ask("IP (ej. 192.168.12.1)")
            mac = netdiscover.arp_table().get(ip, "-")
            print(f"   IP: {ip}\n   MAC: {mac}")
            print(f"   Fabricante: {netdiscover.vendor_of(mac) if mac != '-' else '-'}")
            print(f"   Nombre: {netdiscover.reverse_name(ip)}")
            lat = netdiscover.ping_latency(ip)
            print(f"   Latencia: {lat if lat is not None else 'no responde'} ms")
            print(f"   Puertos: {netdiscover.quick_ports(ip) or '-'}")
            if ask("¿Traceroute? [s/N]").lower() in ("s", "si", "sí", "y"):
                print(netdiscover.traceroute(ip))
            if nmapscan.nmap_path():
                if ask("¿Versiones con nmap -sV? [s/N]").lower() in ("s", "si", "sí", "y"):
                    if not confirm_auth():
                        print(" Cancelado.")
                        continue
                    try:
                        servs = nmapscan.versions(ip)
                        for s in servs:
                            print(f"   puerto {s['puerto']}: {s['servicio']} {s['version']}")
                        for a in nmapscan.advisories(
                                [int(s["puerto"]) for s in servs if s["puerto"].isdigit()]):
                            print(f"   {C.NY}! {a}{C.END}")
                    except Exception as e:
                        print(f" [!] {e}")
            else:
                for a in nmapscan.advisories(netdiscover.quick_ports(ip)):
                    print(f"   {C.NY}! {a}{C.END}")
        elif c == "4":
            import time as _t
            mins = ask("Cada cuántos minutos re-escanear [5]") or "5"
            try:
                cada = max(1, int(mins)) * 60
            except ValueError:
                print(" [!] Número no válido.")
                continue
            print(f" {C.NY}Vigilando {net['red']} cada {mins} min. Ctrl+C para parar.{C.END}")
            try:
                while True:
                    devs = do_scan(net["red"])
                    last = devs
                    _t.sleep(cada)
            except KeyboardInterrupt:
                print("\n Vigilancia detenida.")
        elif c == "5":
            if not last:
                print(" [!] Escanea primero (opción 1 o 2).")
                continue
            h, t, c = reporter.save_scan(last, net, last_audit or None)
            print(f" {C.NG}Guardado:{C.END}\n   HTML: {h}\n   TXT : {t}\n   CSV : {c}")
        else:
            print(" Opción no válida")
        input(f"\n {C.D}Enter para continuar...{C.END}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("-v", "--version"):
        print(f"Escáner LAN v{__version__}")
    else:
        main()
