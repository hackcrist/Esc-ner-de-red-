"""Descubrimiento LAN: red local, ping sweep, tabla ARP y fabricantes."""
import ipaddress
import os
import platform
import re
import socket
import subprocess


def local_network() -> dict:
    """Detecta IP propia, red y gateway (solo tu red local)."""
    info: dict = {"ip": None, "red": None, "gateway": None}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["ip"] = s.getsockname()[0]
        s.close()
    except Exception as e:
        return {"error": f"No se pudo detectar tu IP: {e}"}
    try:
        if platform.system().lower() == "windows":
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetIPAddress -AddressFamily IPv4 |"
                 " Where-Object {$_.IPAddress -eq '" + info["ip"] + "'} |"
                 " Select-Object -ExpandProperty PrefixLength"],
                capture_output=True, text=True, timeout=15)
            prefix = int((out.stdout or "24").strip().split()[0])
        else:
            prefix = 24
    except Exception:
        prefix = 24
    try:
        net = ipaddress.ip_network(f"{info['ip']}/{prefix}", strict=False)
        info["red"] = str(net)
        info["total_hosts"] = net.num_addresses - 2
    except Exception as e:
        return {"error": f"Red no válida: {e}"}
    info["gateway"] = get_gateway(info["ip"])
    return info


def get_gateway(my_ip: str) -> str:
    try:
        if platform.system().lower() == "windows":
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' |"
                 " Sort-Object RouteMetric | Select-Object -First 1).NextHop"],
                capture_output=True, text=True, timeout=15)
            gw = (out.stdout or "").strip().split()[0]
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", gw):
                return gw
    except Exception:
        pass
    # Respaldo: .1 de tu red
    try:
        base = ".".join(my_ip.split(".")[:3])
        return base + ".1"
    except Exception:
        return "?"


def ping_one(ip: str, timeout_ms: int = 400) -> bool:
    return ping_latency(ip, timeout_ms) is not None


def ping_latency(ip: str, timeout_ms: int = 500) -> float | None:
    """Ping y devuelve latencia en ms (None si no responde)."""
    import time as _t
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        start = _t.time()
        r = subprocess.run(cmd, capture_output=True, timeout=timeout_ms / 1000 + 5)
        if r.returncode != 0:
            return None
        txt = (r.stdout or b"").decode(errors="replace")
        m = re.search(r"[Tt]iempo[=<](\d+)\s*ms|time[=<](\d+\.?\d*)\s*ms", txt)
        if m:
            return float(m.group(1) or m.group(2))
        return round((_t.time() - start) * 1000, 1)
    except Exception:
        return None


def quick_ports(ip: str, ports: tuple = (80, 443, 22, 8080), timeout: float = 0.6) -> list[int]:
    """Puertos comunes abiertos (rápido, solo tu LAN)."""
    import concurrent.futures
    abiertas: list[int] = []

    def check(p):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            ok = s.connect_ex((ip, p)) == 0
            s.close()
            return p if ok else None
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        for r in ex.map(check, ports):
            if r is not None:
                abiertas.append(r)
    return sorted(abiertas)


def ping_sweep(network: str, progress=None) -> list[str]:
    """Hace ping a todos los hosts de la red. Solo tu LAN."""
    import concurrent.futures
    net = ipaddress.ip_network(network, strict=False)
    hosts = [str(h) for h in net.hosts()]
    vivos: list[str] = []
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        fut = {ex.submit(ping_one, h): h for h in hosts}
        for f in concurrent.futures.as_completed(fut):
            done += 1
            if f.result():
                vivos.append(fut[f])
            if progress and done % 25 == 0:
                progress(done, len(hosts))
    return sorted(vivos, key=lambda ip: tuple(int(x) for x in ip.split(".")))


def arp_table() -> dict[str, str]:
    """Lee la tabla ARP del sistema: {ip: mac}."""
    tabla: dict[str, str] = {}
    try:
        if platform.system().lower() == "windows":
            out = subprocess.run(["arp", "-a"], capture_output=True,
                                 text=True, errors="replace", timeout=15)
            for line in (out.stdout or "").splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", line)
                if m:
                    tabla[m.group(1)] = m.group(2).lower().replace("-", ":")
        else:
            out = subprocess.run(["ip", "neigh"], capture_output=True,
                                 text=True, errors="replace", timeout=15)
            for line in (out.stdout or "").splitlines():
                m = re.search(r"^(\S+).*?lladdr\s+([0-9a-fA-F:]{17})", line)
                if m:
                    tabla[m.group(1)] = m.group(2).lower()
    except Exception:
        pass
    return tabla


def vendor_of(mac: str, timeout: int = 6) -> str:
    """Fabricante por OUI: base offline primero, API gratis de respaldo."""
    from tools import oui
    prefix = ":".join(mac.lower().split(":")[:3])
    if prefix in oui.DB:
        return oui.DB[prefix] + " (base local)"
    try:
        import urllib.request
        rq = urllib.request.Request(f"https://api.macvendors.com/{mac}",
                                    headers={"User-Agent": "LAN-Scanner/1.0 (educativo)"})
        with urllib.request.urlopen(rq, timeout=timeout) as r:
            name = r.read().decode().strip()
        if name and "error" not in name.lower():
            return name + " (api.macvendors.com)"
    except Exception:
        pass
    return "Desconocido"


def reverse_name(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "-"


def dns_servers() -> list[str]:
    """DNS configurados en este equipo."""
    out: list[str] = []
    try:
        if platform.system().lower() == "windows":
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-DnsClientServerAddress -AddressFamily IPv4 |"
                 " Where-Object {$_.ServerAddresses}).ServerAddresses"],
                capture_output=True, text=True, timeout=15)
            for token in (r.stdout or "").replace(",", " ").split():
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", token) and token not in out:
                    out.append(token)
        else:
            with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as f:
                for line in f:
                    m = re.match(r"\s*nameserver\s+(\S+)", line)
                    if m and m.group(1) not in out:
                        out.append(m.group(1))
    except Exception:
        pass
    return out


def internet_ok(timeout: float = 3.0) -> bool:
    try:
        s = socket.create_connection(("8.8.8.8", 53), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def traceroute(host: str, max_hops: int = 12, timeout: int = 2) -> str:
    """Traza ruta al objetivo (funciona fuera de tu red)."""
    host = host.strip()
    if not re.match(r"^[A-Za-z0-9.\-:]+$", host):
        return "[!] Host no válido"
    if platform.system().lower() == "windows":
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout * 1000), host]
    else:
        import shutil
        bin_path = shutil.which("traceroute")
        if not bin_path:
            return "[!] Instala traceroute: sudo apt install traceroute"
        cmd = [bin_path, "-n", "-m", str(max_hops), "-w", str(timeout), host]
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=max_hops * (timeout + 1) + 10)
        txt = _decode(out.stdout) or _decode(out.stderr)
        return txt or "[!] Sin salida"
    except Exception as e:
        return f"[!] traceroute falló: {e}"


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if os.name == "nt":
        try:
            out = subprocess.run(["cmd", "/c", "chcp"], capture_output=True, timeout=10)
            nums = re.findall(r"\d+", (out.stdout or b"").decode(errors="replace"))
            return data.decode(f"cp{nums[-1]}" if nums else "cp850", errors="replace")
        except Exception:
            return data.decode("cp850", errors="replace")
    return data.decode(errors="replace")
