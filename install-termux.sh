#!/data/data/com.termux/files/usr/bin/bash
# Escáner de red - Instalador para Termux (Android)
# Uso: bash install-termux.sh
set -e

CYAN='\033[38;2;0;255;234m'; GREEN='\033[38;2;57;255;20m'
YELLOW='\033[38;2;255;255;0m'; BOLD='\033[1m'; END='\033[0m'

echo -e "${CYAN}${BOLD}  Escáner de red - Termux${END}"
echo -e "${CYAN} Instalando...${END}\n"

echo -e "${YELLOW}[1/3] Actualizando paquetes...${END}"
pkg update -y

echo -e "${YELLOW}[2/3] Instalando dependencias...${END}"
pkg install -y python git iputils traceroute procps nmap

echo -e "${YELLOW}[3/3] Permisos...${END}"
chmod +x scanner.py

echo -e "\n${GREEN}${BOLD}Listo. Ejecuta: python scanner.py${END}"
echo -e "${CYAN}Sin dependencias pip: todo es biblioteca estándar.${END}"
echo -e "${CYAN}Nota: nmap -sV puede pedir root; el resto va sin root.${END}"
