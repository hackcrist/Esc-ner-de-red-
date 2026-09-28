#!/usr/bin/env bash
# Escáner de red - actualiza a la última versión de GitHub
# Uso: bash update.sh
set -e
cd "$(dirname "$0")"
git pull --ff-only
echo "Actualizado. Ejecuta: bash run.sh"
