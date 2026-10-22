#!/bin/bash
# Script de arranque: usa el intérprete Python del entorno virtual (venv)
# donde están instaladas las dependencias (Flask, PyMySQL).
cd "$(dirname "$0")"

if [ -z "${DB_PASSWORD:-}" ]; then
    if [ ! -t 0 ]; then
        echo "Error: define DB_PASSWORD antes de ejecutar run.sh sin una terminal interactiva." >&2
        exit 1
    fi

    read -r -s -p "Contraseña de MySQL: " DB_PASSWORD || {
        echo >&2
        echo "Error: no se pudo leer la contraseña de MySQL." >&2
        exit 1
    }
    echo
    if [ -z "$DB_PASSWORD" ]; then
        echo "Error: la contraseña de MySQL no puede estar vacía." >&2
        exit 1
    fi
fi
export DB_PASSWORD

if [ ! -x "venv/bin/python" ]; then
    echo "El entorno virtual 'venv' no existe. Creándolo..."
    python3 -m venv --without-pip venv
    venv/bin/python -m ensurepip --upgrade 2>/dev/null || \
        curl -sS https://bootstrap.pypa.io/get-pip.py | venv/bin/python
    venv/bin/pip install -r requirements.txt
fi

exec venv/bin/python app.py
