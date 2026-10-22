#!/bin/bash
# Script de arranque: usa el intérprete Python del entorno virtual (venv)
# donde están instaladas las dependencias (Flask, PyMySQL).
cd "$(dirname "$0")"

if [ ! -x "venv/bin/python" ]; then
    echo "El entorno virtual 'venv' no existe. Creándolo..."
    python3 -m venv --without-pip venv
    venv/bin/python -m ensurepip --upgrade 2>/dev/null || \
        curl -sS https://bootstrap.pypa.io/get-pip.py | venv/bin/python
    venv/bin/pip install -r requirements.txt
fi

exec venv/bin/python app.py
