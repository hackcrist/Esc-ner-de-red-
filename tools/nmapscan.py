"""Integración opcional con nmap (si está instalado). Solo tu red, con confirmación."""
import re
import shutil
import subprocess


def nmap_path() -> str | None:
    return shutil.which("nmap")


def discover(network: str, timeout: int = 120) -> list[str]:
    """Descubrimiento con nmap -sn (rápido, sin escanear puertos)."""
    nmap = nmap_path()
    if not nmap:
        raise RuntimeError("nmap no instalado (https://nmap.org/download.html)")
    r = subprocess.run([nmap, "-sn", "-oG", "-", network],
                       capture_output=True, text=True, errors="replace", timeout=timeout)
    vivos = []
    for line in (r.stdout or "").splitlines():
        m = re.search(r"Host:\s+(\d+\.\d+\.\d+\.\d+).*Status:\s*Up", line)
        if m:
            vivos.append(m.group(1))
    return sorted(set(vivos), key=lambda ip: tuple(int(x) for x in ip.split(".")))


def versions(host: str, ports: str = "22,80,443,8080,3389,445,139", timeout: int = 120) -> list[dict]:
    """Versiones de servicios con nmap -sV (solo host autorizado)."""
    nmap = nmap_path()
    if not nmap:
        raise RuntimeError("nmap no instalado (https://nmap.org/download.html)")
    r = subprocess.run([nmap, "-sV", "-p", ports, "--open", "-oG", "-", host],
                       capture_output=True, text=True, errors="replace", timeout=timeout)
    out = []
    for line in (r.stdout or "").splitlines():
        if "Ports:" not in line:
            continue
        seg = line.split("Ports:")[1].strip()
        for entry in seg.split(","):
            parts = [p.strip() for p in entry.split("/")]
            # puerto/estado/proto/dueño/servicio/version/...
            if len(parts) >= 5 and parts[1] == "open":
                out.append({"puerto": parts[0], "servicio": parts[4],
                            "version": " ".join(parts[5:]).strip() or "-"})
    return out


SENSIBLES = {21: "FTP: si usa user/pass por defecto, cámbialas ya",
             23: "Telnet: va en claro, desactívalo si puedes",
             445: "SMB expuesto: revisa carpetas compartidas y parches",
             3389: "RDP expuesto: usa contraseña fuerte + NLA",
             5900: "VNC expuesto: pon contraseña fuerte"}


def advisories(open_ports: list[int]) -> list[str]:
    return [SENSIBLES[p] for p in open_ports if p in SENSIBLES]
