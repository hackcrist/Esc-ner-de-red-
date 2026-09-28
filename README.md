# Escáner de red

Descubre hosts y servicios en redes que te pertenecen o con autorización escrita: ping sweep, ARP, fabricantes, versiones con nmap y reportes HTML+TXT+CSV.

> Fines educativos. Solo objetivos propios o con autorización escrita. El escaneo de puertos/versiones pide confirmación.

## Uso

```bash
python scanner.py            # menú interactivo
python scanner.py --version  # ver versión
```

Menú estable (5 opciones verificadas): `1) Mi red  2) Otra red  3) Detalle+versiones  4) Vigilar  5) Guardar`.

- Cada equipo: IP, MAC, **latencia ms**, **puertos comunes abiertos**, fabricante y nombre.
- **Alerta de intrusos**: compara con el escaneo anterior y marca `[NUEVO]`; el modo vigía re-escanea cada N minutos.
- **Nmap opcional**: descubrimiento `-sn` + versiones `-sV` con confirmación (instálalo de nmap.org + Npcap).
- OUI offline ampliada (~70 prefijos) + api.macvendors.com de respaldo.

Sin dependencias: solo Python 3.10+ (biblioteca estándar).

## Gemelo Go (más rápido)

```bash
cd go
go build -o lanscan-go.exe .
./lanscan-go.exe sweep --net 192.168.12.0/24
./lanscan-go.exe report --net 192.168.12.0/24
./lanscan-go.exe menu
```

Comandos: `mynet sweep arp vendor report menu version`. El sweep en Go tarda ~16s vs ~40s en Python.

## Estructura

```
scanner.py   # menú neón
tools/
  netdiscover.py  # red local, ping sweep, ARP, fabricantes
  oui.py          # base MAC offline + api.macvendors.com de respaldo
  reporter.py     # reportes/ HTML+TXT+índice (se auto-crea)
```
