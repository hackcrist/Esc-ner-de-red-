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

from tools import netdiscover, reporter

__version__ = "1.0.0"

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
  {C.NP}{C.BOLD}Escáner de red local v{__version__}{C.END} {C.D}(tu WiFi, educativo){C.END}
"""


def ask(p):
    return input(f" {C.NC}{C.BOLD}>{C.END} {p}: ").strip()


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
    print(f" Tu IP: {C.W}{net['ip']}{C.END} | Red: {C.W}{net['red']}{C.END} "
          f"| Gateway: {C.W}{net['gateway']}{C.END} | Hosts: {net.get('total_hosts')}")
    last: list[dict] = []
    while True:
        print(f"\n {C.NV}{C.BOLD}+-- MENU --+{C.END}")
        print(f"  {C.NC}[1]{C.END} > Escanear mi red")
        print(f"  {C.NC}[2]{C.END} > Ver tabla ARP")
        print(f"  {C.NC}[3]{C.END} > Detalle de una IP")
        print(f"  {C.NC}[4]{C.END} > Guardar reporte (HTML+TXT+CSV)")
        print(f"  {C.NC}[5]{C.END} > Vigilar (alerta intrusos)")
        print(f"  {C.NO}[0]{C.END} < Salir")
        c = ask("Elige")
        if c == "0":
            print(" Adiós.")
            return
        elif c == "1":
            print(f" {C.NY}Escaneando {net['red']} (tarda ~30s)...{C.END}")
            vivos = netdiscover.ping_sweep(
                net["red"],
                progress=lambda d, t: print(f"   ...{d}/{t}", end="\r"))
            print(" " * 30, end="\r")
            known = load_last()
            last = enrich(vivos, known or None)
            nuevos = [d for d in last if d.get("nuevo")]
            if nuevos and known:
                print(f" {C.NY}{C.BOLD}ALERTA: {len(nuevos)} equipo(s) nuevo(s) en tu red:{C.END}")
                for d in nuevos:
                    print(f"   ! {d['ip']} ({d.get('vendor')})")
            save_last([d["ip"] for d in last])
            print(f" {C.NG}Encontrados: {len(last)}{C.END}")
            show(last)
        elif c == "2":
            arp = netdiscover.arp_table()
            last = enrich(sorted(arp))
            print(f" {C.NG}Entradas ARP: {len(last)}{C.END}")
            show(last)
        elif c == "3":
            ip = ask("IP (ej. 192.168.12.1)")
            arp = netdiscover.arp_table()
            mac = arp.get(ip, "-")
            print(f"   IP: {ip}\n   MAC: {mac}")
            print(f"   Fabricante: {netdiscover.vendor_of(mac) if mac != '-' else '-'}")
            print(f"   Nombre: {netdiscover.reverse_name(ip)}")
            print(f"   Ping: {'responde' if netdiscover.ping_one(ip) else 'no responde'}")
        elif c == "4":
            if not last:
                print(" [!] Escanea primero (opción 1 o 2).")
                continue
            h, t, c = reporter.save_scan(last, net)
            print(f" {C.NG}Guardado:{C.END}\n   HTML: {h}\n   TXT : {t}\n   CSV : {c}")
        elif c == "5":
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
                    vivos = netdiscover.ping_sweep(net["red"])
                    known = load_last()
                    devs = enrich(vivos, known or None)
                    nuevos = [d for d in devs if d.get("nuevo")]
                    if nuevos and known:
                        print(f"\n {C.NY}{C.BOLD}INTRUSO: {', '.join(d['ip'] for d in nuevos)}{C.END}")
                    else:
                        print(f" {_t.strftime('%H:%M:%S')} sin novedad ({len(devs)} equipos)")
                    save_last([d["ip"] for d in devs])
                    last = devs
                    _t.sleep(cada)
            except KeyboardInterrupt:
                print("\n Vigilancia detenida.")
        else:
            print(" Opción no válida")
        input(f"\n {C.D}Enter para continuar...{C.END}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("-v", "--version"):
        print(f"Escáner LAN v{__version__}")
    else:
        main()
