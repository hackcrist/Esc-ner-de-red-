"""Reportes del escáner LAN en reportes/ (HTML + TXT + índice)."""
import datetime
import html
import os

BASE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reportes")


def ensure_dir() -> str:
    os.makedirs(BASE_DIR, exist_ok=True)
    return BASE_DIR


def save_scan(devices: list[dict], netinfo: dict, audit: list[str] | None = None) -> tuple[str, str, str]:
    ensure_dir()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fecha = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    red = (netinfo.get("red") or "lan").replace("/", "-")

    txt = os.path.join(BASE_DIR, f"scan_{red}_{ts}.txt")
    with open(txt, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n SCAN RED LOCAL - Solo tu propia red, fines educativos\n" + "=" * 60 + "\n")
        f.write(f"Fecha: {fecha}\nRed: {netinfo.get('red')} | Tu IP: {netinfo.get('ip')} | Gateway: {netinfo.get('gateway')}\n")
        f.write(f"Dispositivos: {len(devices)}\n")
        if audit:
            f.write("AUDITORÍA DE RED:\n")
            for h in audit:
                f.write(f"  · {h}\n")
        f.write("\n")
        f.write(f"{'IP':<16}{'MAC':<20}{'MS':<7}{'PUERTOS':<16}{'FABRICANTE':<24}NOMBRE\n" + "-" * 110 + "\n")
        for d in devices:
            nuevo = " [NUEVO]" if d.get("nuevo") else ""
            f.write(f"{d['ip']:<16}{d.get('mac', '-'):<20}{d.get('latencia', '-'):<7}"
                    f"{','.join(map(str, d.get('puertos', []))) or '-':<16}"
                    f"{d.get('vendor', '-'):<24}{d.get('nombre', '-')}{nuevo}\n")

    import csv
    csvp = os.path.join(BASE_DIR, f"scan_{red}_{ts}.csv")
    with open(csvp, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "mac", "latencia_ms", "puertos", "fabricante", "nombre", "nuevo"])
        for d in devices:
            w.writerow([d["ip"], d.get("mac", "-"), d.get("latencia", "-"),
                        ";".join(map(str, d.get("puertos", []))),
                        d.get("vendor", "-"), d.get("nombre", "-"), bool(d.get("nuevo"))])

    rows = "".join(
        f"<tr><td>{html.escape(d['ip'])}</td><td>{html.escape(d.get('mac', '-'))}</td>"
        f"<td>{html.escape(str(d.get('latencia', '-')))}</td>"
        f"<td>{html.escape(','.join(map(str, d.get('puertos', []))) or '-')}</td>"
        f"<td>{html.escape(d.get('vendor', '-'))}</td><td>{html.escape(d.get('nombre', '-'))}</td>"
        f"<td>{'NUEVO' if d.get('nuevo') else ''}</td></tr>"
        for d in devices)
    page = f"""<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<title>Scan {html.escape(str(netinfo.get('red')))}</title>
<style>body{{font-family:Segoe UI,Arial;background:#0a0a14;color:#eee;margin:0}}
header{{padding:28px;text-align:center;background:linear-gradient(135deg,#00ffea,#ff00ff)}}
h1{{margin:0;color:#000}}table{{width:94%;margin:20px auto;border-collapse:collapse;background:#14142b;font-size:.9em}}
th,td{{padding:8px 10px;border-bottom:1px solid #ffffff18;text-align:left}}th{{color:#00ffea}}</style></head>
<body><header><h1>SCAN RED LOCAL</h1><p>{html.escape(fecha)} · {html.escape(str(netinfo.get('red')))} · {len(devices)} equipos</p></header>
<table><tr><th>IP</th><th>MAC</th><th>ms</th><th>Puertos</th><th>Fabricante</th><th>Nombre</th><th></th></tr>{rows}</table>
<AUDIT/></body></html>"""
    audit_html = ""
    if audit:
        items = "".join(f"<li>{html.escape(h)}</li>" for h in audit)
        audit_html = f'<div style="width:94%;margin:0 auto 30px;background:#14142b;border-radius:12px;padding:16px"><h2 style="color:#ffe600">AUDITORÍA DE RED</h2><ul>{items}</ul></div>'
    page = page.replace("<AUDIT/>", audit_html)
    htm = os.path.join(BASE_DIR, f"scan_{red}_{ts}.html")
    with open(htm, "w", encoding="utf-8") as f:
        f.write(page)
    _index()
    return htm, txt, csvp


def save_audit(devices: list[dict], meta: dict, audit: list[str],
               detalle: list[dict] | None = None) -> tuple[str, str, str]:
    """Reporte profesional: alcance, metodología, hallazgos priorizados y remediación."""
    ensure_dir()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fecha = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    slug = "".join(c if c.isalnum() else "_" for c in meta.get("cliente", "cliente"))[:24].strip("_") or "cliente"

    crit = [h for h in audit if "CRÍTICO" in h]
    avis = [h for h in audit if h.startswith("AVISO")]
    oks = [h for h in audit if h.startswith("OK")]
    resto = [h for h in audit if h not in crit + avis + oks]

    txt = os.path.join(BASE_DIR, f"auditoria_{slug}_{ts}.txt")
    with open(txt, "w", encoding="utf-8") as f:
        f.write("=" * 64 + "\n AUDITORÍA DE RED - REPORTE PROFESIONAL\n" + "=" * 64 + "\n")
        f.write(f"Fecha: {fecha}\nCliente: {meta.get('cliente')}\nAlcance: {meta.get('alcance')}\n")
        f.write(f"Autorización ref: {meta.get('autorizacion')}\nElaborado con: {meta.get('auditor')}\n\n")
        f.write("METODOLOGÍA\n  1. Descubrimiento de hosts (ping/nmap -sn, sin exploit)\n")
        f.write("  2. Enumeración pasiva: MAC/OUI, nombre, latencia, puertos comunes\n")
        f.write("  3. Versiones de servicios (nmap -sV) solo en hosts con puertos abiertos\n")
        f.write("  4. Análisis de exposición y remediación sugerida\n\n")
        f.write(f"RESUMEN: {len(devices)} hosts, {len(crit)} críticos, {len(avis)} avisos\n\n")
        f.write("HALLAZGOS CRÍTICOS\n" + (chr(10).join(f"  ! {h}" for h in crit) or "  (ninguno)") + "\n\n")
        f.write("AVISOS\n" + (chr(10).join(f"  · {h}" for h in avis) or "  (ninguno)") + "\n\n")
        f.write("OTROS\n" + (chr(10).join(f"  · {h}" for h in resto + oks) or "  (ninguno)") + "\n\n")
        f.write("SERVICIOS POR HOST\n")
        for d in devices:
            f.write(f"  {d['ip']}: puertos {','.join(map(str, d.get('puertos', []))) or '-'} "
                    f"| {d.get('vendor', '-')} | {d.get('nombre', '-')}\n")
        if detalle:
            f.write("\nVERSIONES DETECTADAS\n")
            for ent in detalle:
                for s in ent.get("servicios", []):
                    f.write(f"  {ent['ip']}:{s['puerto']} {s['servicio']} {s['version']}\n")
        f.write("\nREMEDIACIÓN SUGERIDA\n"
                "  · Cierra puertos innecesarios en cada equipo.\n"
                "  · Cambia credenciales por defecto (FTP/Telnet/RDP/VNC).\n"
                "  · Desactiva Telnet; prefiere SSH.\n"
                "  · Segmenta la red (invitados/IoT aparte) y repite esta auditoría.\n")

    import csv
    csvp = os.path.join(BASE_DIR, f"auditoria_{slug}_{ts}.csv")
    with open(csvp, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cliente", "alcance", "autorizacion", "fecha"])
        w.writerow([meta.get("cliente"), meta.get("alcance"), meta.get("autorizacion"), fecha])
        w.writerow([])
        w.writerow(["nivel", "hallazgo"])
        for h in crit:
            w.writerow(["CRITICO", h])
        for h in avis:
            w.writerow(["AVISO", h])
        for h in resto + oks:
            w.writerow(["INFO", h])

    def li(items, color):
        return "".join(f'<li style="color:{color}">{html.escape(h)}</li>' for h in items) or "<li>ninguno</li>"

    page = f"""<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<title>Auditoría {html.escape(str(meta.get('cliente')))}</title>
<style>body{{font-family:Segoe UI,Arial;background:#0a0a14;color:#eee;margin:0}}
header{{padding:28px;text-align:center;background:linear-gradient(135deg,#00ffea,#ff00ff)}}
h1{{margin:0;color:#000}}.box{{max-width:900px;margin:16px auto;background:#14142b;border-radius:12px;padding:18px}}
h2{{color:#00ffea}}li{{margin:6px 0}}</style></head>
<body><header><h1>AUDITORÍA DE RED</h1>
<p>{html.escape(str(meta.get('cliente')))} · {html.escape(str(meta.get('alcance')))} · {html.escape(fecha)}</p>
<p>Autorización: {html.escape(str(meta.get('autorizacion')))}</p></header>
<div class="box"><h2>Metodología</h2><p>Descubrimiento → enumeración pasiva → versiones (nmap -sV) → análisis. Sin exploits ni credenciales.</p></div>
<div class="box"><h2>Críticos ({len(crit)})</h2><ul>{li(crit, '#ff5555')}</ul></div>
<div class="box"><h2>Avisos ({len(avis)})</h2><ul>{li(avis, '#ffe600')}</ul></div>
<div class="box"><h2>Otros</h2><ul>{li(resto + oks, '#e8e8f0')}</ul></div>
<div class="box"><h2>Remediación</h2><p>Cierra puertos innecesarios, cambia credenciales por defecto, desactiva Telnet, segmenta la red y repite la auditoría.</p></div>
</body></html>"""
    htm = os.path.join(BASE_DIR, f"auditoria_{slug}_{ts}.html")
    with open(htm, "w", encoding="utf-8") as f:
        f.write(page)
    _index()
    return htm, txt, csvp


def _index():
    ensure_dir()
    files = sorted([a for a in os.listdir(BASE_DIR)
                    if (a.startswith("scan_") or a.startswith("auditoria_")) and a.endswith(".html")],
                   reverse=True)
    items = "".join(f'<li><a href="{html.escape(a)}">{html.escape(a)}</a></li>' for a in files) or "<li>Sin escaneos.</li>"
    page = f"""<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><title>Scans LAN</title>
<style>body{{font-family:Segoe UI,Arial;background:#0a0a14;color:#eee;margin:0}}
header{{padding:26px;text-align:center;background:linear-gradient(135deg,#00ffea,#ff00ff)}}
h1{{margin:0;color:#000}}ul{{max-width:700px;margin:20px auto;list-style:none;padding:0}}
li{{background:#14142b;margin:8px;padding:12px;border-radius:10px}}a{{color:#00ffea}}</style></head>
<body><header><h1>SCANS DE RED LOCAL</h1></header><ul>{items}</ul></body></html>"""
    with open(os.path.join(BASE_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write(page)


def list_reports() -> list[str]:
    ensure_dir()
    return sorted(os.listdir(BASE_DIR), reverse=True)
