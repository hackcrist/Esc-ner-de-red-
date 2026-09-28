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

## 👤 Autor

**Crist Code** — https://github.com/hackcrist/Esc-ner-de-red-

---
<p align="center">Hecho con amor por <b>Crist Code</b> ❤️<br>Si te sirve, deja tu ⭐ en GitHub</p>
