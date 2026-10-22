#!/bin/bash
set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

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

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "Error: no se encontró '$PYTHON_BIN'. Instala Python 3 o define PYTHON_BIN." >&2
    exit 1
fi

if [ ! -x "venv/bin/python" ]; then
    echo "El entorno virtual 'venv' no existe o está incompleto. Creándolo..."
    if ! "$PYTHON_BIN" -m venv venv; then
        echo "Error: no se pudo crear el entorno virtual. Comprueba que Python 3 incluya el módulo venv." >&2
        exit 1
    fi
fi

if ! venv/bin/python -m pip --version >/dev/null 2>&1; then
    if ! venv/bin/python -m ensurepip --upgrade; then
        echo "Error: no se pudo instalar pip en el entorno virtual." >&2
        exit 1
    fi
fi

if ! venv/bin/python -m pip install -r requirements.txt; then
    echo "Error: no se pudieron instalar las dependencias de requirements.txt." >&2
    exit 1
fi

exec venv/bin/python app.py
