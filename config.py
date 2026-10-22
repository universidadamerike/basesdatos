"""
Configuración de conexión a la base de datos.

NOTA DIDÁCTICA: Estas credenciales corresponden a un servidor MySQL de
pruebas usado exclusivamente para la clase de ciberseguridad. En un
entorno real, NUNCA se deben dejar credenciales en texto plano dentro
del código fuente; se deberían usar variables de entorno, un gestor de
secretos (Vault, AWS Secrets Manager, etc.) y una cuenta de base de
datos con privilegios mínimos.
"""

import os

DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_PORT = int(os.environ.get("DB_PORT", "3306"))
DB_USER = os.environ.get("DB_USER", "root")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
DB_NAME = os.environ.get("DB_NAME", "tienda_vulnerable")

# Clave de sesión de Flask (solo para fines de la demo).
SECRET_KEY = os.environ.get("SECRET_KEY", "clave-demo-insegura-no-usar-en-produccion")
