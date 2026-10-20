#!/usr/bin/env bash
# Instala N43 Fixer en Alwaysdata (plan Free, Francia, siempre encendida).
# A diferencia de Render free, aquí NO hay «Application loading...»: el
# proceso está continuamente vivo y responde al instante.
#
# Ejecuta estos comandos DENTRO de tu sesión SSH de Alwaysdata:
#
#     ssh [cuenta]@ssh-[cuenta].alwaysdata.net
#
# Si el repositorio de GitHub es privado, en lugar del "git clone" sube la
# carpeta del proyecto por SFTP (Finder -> Ir -> Conectar al servidor ->
# sftp://[cuenta]@ssh-[cuenta].alwaysdata.net) y deja el código en ~/n43fixer.
set -euo pipefail

REPO_URL="https://github.com/joserrasb1/n43-fixer-saas.git"
REPO_DIR="$HOME/n43fixer"
VENV_DIR="$HOME/venvs/n43fixer"

echo "==> Descargando el repositorio en $REPO_DIR"
if [ -d "$REPO_DIR/.git" ]; then
  (cd "$REPO_DIR" && git pull --ff-only)
else
  git clone "$REPO_URL" "$REPO_DIR"
fi

echo "==> Creando el virtualenv (python -m venv)"
python -m venv "$VENV_DIR"

echo "==> Instalando dependencias (pandas, openpyxl, fastapi...)"
"$VENV_DIR/bin/python" -m pip install -q --upgrade pip
"$VENV_DIR/bin/python" -m pip install -q -r "$REPO_DIR/requirements.txt"

echo
echo "OK. Ahora en el panel admin.alwaysdata.com -> Web > Sites -> Añadir un site:"
echo "  - Tipo:              Python WSGI"
echo "  - Address:           n43fixer.alwaysdata.net"
echo "  - Application path:  $REPO_DIR/wsgi.py"
echo "  - Working directory: $REPO_DIR"
echo "  - Virtualenv:        $VENV_DIR"
echo "Guarda y prueba:"
echo "  curl -s https://n43fixer.alwaysdata.net/health"
echo "  (y abre https://n43fixer.alwaysdata.net/ en el navegador)"
