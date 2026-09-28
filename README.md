# Escáner de red

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat-square&logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.0-ff00ff?style=flat-square)

Descubre hosts y servicios en redes que te pertenecen o con autorización escrita: ping sweep, ARP, fabricantes por MAC, versiones con nmap y reportes HTML+TXT+CSV. **Python + Go juntos.**

> 📚 **Fines educativos.** Solo objetivos propios o con autorización escrita. El escaneo de versiones pide confirmación explícita.

## ✨ Funciones

| Qué hace | Detalle |
|---|---|
| 🔎 Barrido | nmap `-sn` si está instalado, si no sweep Python (64 hilos) |
| 📡 Por equipo | IP, MAC, latencia ms, puertos comunes, fabricante, nombre |
| 🚨 Intrusos | Compara con el escaneo anterior y marca `[NUEVO]`; modo vigía cada N minutos |
| 🛡️ Auditoría de red | Puertos expuestos, FTP/Telnet en claro, DNS, internet y gateway (nada personal) |
| 🧬 Versiones | nmap `-sV` con confirmación + avisos (FTP/Telnet/SMB/RDP/VNC expuestos) |
| 📁 Reportes | HTML + TXT + CSV con índice auto-generado (carpeta `reportes/`) |
| 🗃️ OUI offline | ~70 prefijos MAC sin internet + api.macvendors.com de respaldo |

## 🚀 Uso rápido

```bash
# Python (requerido) — desde la carpeta del proyecto
python scanner.py            # menú: 1) Escanear  2) Otra red  3) Detalle  4) Vigilar  5) Guardar
python scanner.py --version  # ver versión

# Go (opcional, barrido en ~16s)
cd go
go build -o lanscan-go.exe .
./lanscan-go.exe sweep --net 192.168.1.0/24
./lanscan-go.exe report --net 192.168.1.0/24
./lanscan-go.exe menu
```

Comandos Go: `mynet sweep arp vendor report menu version`.

Opcional: instala [nmap](https://nmap.org/download.html) (+Npcap en Windows) para descubrimiento y versiones más rápidas.

## 📱 Termux (Android)

Instala Termux desde **F-Droid o GitHub** (no Play Store), clona y corre:

```bash
pkg install git python -y
git clone https://github.com/hackcrist/Esc-ner-de-red-.git
cd Esc-ner-de-red-
bash install-termux.sh
python scanner.py
```

Sin dependencias pip: todo es biblioteca estándar. Sin root funciona todo menos algunos modos de nmap.

## 📁 Estructura

```
scanner.py   # menú neón en español
tools/       # netdiscover, nmapscan, oui, reporter
go/          # lanscan-go v1.1: mynet, sweep, arp, vendor, report, menu
reportes/    # se auto-crea al usarlo (no se sube a git)
```

## ⚙️ Cómo funciona

**Idea general:** descubre qué equipos hay en una red y qué ofrecen. `scanner.py` es el menú en Python; `lanscan-go` es el gemelo en Go, más rápido barriendo (goroutines). Ambos escriben los mismos reportes en `reportes/`.

**Flujo:**
1. Detecta tu IP, calcula tu red (`192.168.x.0/24`) y tu gateway solos.
2. **Descubrimiento:** con nmap `-sn` si está instalado, si no ping a los 254 hosts en paralelo (64 hilos). Los que responden son equipos vivos.
3. **Enriquecido:** por cada vivo lee su MAC de la tabla ARP del sistema, busca el fabricante (base OUI offline de ~70 prefijos, si no api.macvendors.com), resuelve su nombre, mide latencia y prueba puertos comunes (80, 443, 22, 8080).
4. **Intrusos:** guarda la lista en `last_scan.json`; en el siguiente escaneo marca `[NUEVO]` lo que no estaba. El modo vigía repite esto cada N minutos.
5. **Versiones (opcional):** con nmap `-sV` y confirmación previa, identifica servicios y avisa si hay FTP/Telnet/SMB/RDP/VNC expuestos (solo avisa, no ataca credenciales).

**Límites honestos:** MAC y fabricante solo salen en LAN local (ARP no cruza routers). Fuera de tu red verás IPs, latencia y puertos, nada más.

## 🖥️ Uso detallado

**Escanear tu red (opción 1):**
1. Elige `1`, espera ~16s (Go/nmap) o ~40s (Python solo).
2. Verás tabla: IP, ms, puertos, fabricante, nombre. `[NUEVO]` si no estaba antes.
3. Opción `5` para guardar el reporte.

**Auditoría profesional (opción 2):**
1. Escribe cliente, alcance CIDR y referencia de autorización (sin referencia no hay auditoría).
2. Corre solo: descubrimiento → enumeración → versiones → reporte `auditoria_<cliente>_*` con metodología, críticos/avisos y remediación.

**Detalle + versiones (opción 3):**
1. Escribe la IP, ej. `192.168.12.1`.
2. Verás MAC, fabricante, latencia y puertos. Si hay nmap, ofrece `-sV` (pide confirmación).

**Vigilar intrusos (opción 4):**
1. Elige cada cuántos minutos, ej. `5`.
2. Deja corriendo; si entra un equipo nuevo grita `INTRUSO: <ip>`. Ctrl+C para parar.

**Comandos Go directos:**
```bash
./lanscan-go.exe mynet                              # tu IP, red y gateway
./lanscan-go.exe sweep --net 192.168.12.0/24        # barrido JSON
./lanscan-go.exe vendor --mac 18:0c:7a:ea:b1:e1     # fabricante
./lanscan-go.exe report --net 192.168.12.0/24       # HTML+TXT+CSV
```

## 👤 Autor

**Crist Code** — https://github.com/hackcrist/Esc-ner-de-red-

---
<p align="center">Hecho con amor por <b>Crist Code</b> ❤️<br>Si te sirve, deja tu ⭐ en GitHub</p>
