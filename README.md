# Escáner de red local

Descubre quién está en tu WiFi: ping sweep a tu red, tabla ARP, fabricante por MAC y reportes HTML+TXT.

> Solo tu propia red. Fines educativos.

## Uso

```bash
python scanner.py            # menú interactivo
python scanner.py --version  # ver versión
```

Menú: `1) Escanear  2) ARP  3) Detalle IP  4) Guardar reporte  5) Vigilar`.

- Cada equipo: IP, MAC, **latencia ms**, **puertos comunes abiertos**, fabricante y nombre.
- **Alerta de intrusos**: compara con el escaneo anterior y marca `[NUEVO]`; el modo vigía re-escanea cada N minutos.
- OUI offline ampliada (~70 prefijos) + api.macvendors.com de respaldo.

Sin dependencias: solo Python 3.10+ (biblioteca estándar).

## Estructura

```
scanner.py   # menú neón
tools/
  netdiscover.py  # red local, ping sweep, ARP, fabricantes
  oui.py          # base MAC offline + api.macvendors.com de respaldo
  reporter.py     # reportes/ HTML+TXT+índice (se auto-crea)
```
