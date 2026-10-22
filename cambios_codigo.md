# cambios_codigo.md — Vulnerabilidades del código y correcciones recomendadas

> ⚠️ **Contexto:** este documento es el complemento técnico de
> [inyection.md](inyection.md). Mientras que `inyection.md` explica
> **cómo explotar** cada vulnerabilidad paso a paso (para la clase),
> este documento está orientado a **qué archivo/línea del código** la
> provoca y **qué cambio concreto** habría que aplicar para eliminarla
> si este sistema fuera a usarse en producción.

## Índice

1. [SQL Injection clásica (login, clientes, productos, ventas)](#1-sql-injection-clásica)
2. [Exposición de errores nativos del motor de base de datos](#2-exposición-de-errores-nativos-del-motor-de-base-de-datos)
3. [Cuenta de conexión a MySQL con privilegios excesivos](#3-cuenta-de-conexión-a-mysql-con-privilegios-excesivos)
4. [Contraseñas almacenadas en texto plano](#4-contraseñas-almacenadas-en-texto-plano)
5. [Stacked Queries (CLIENT_MULTI_STATEMENTS)](#5-stacked-queries-client_multi_statements)
6. [SQL Injection de segundo orden](#6-sql-injection-de-segundo-orden)
7. [IDOR (Insecure Direct Object Reference) en `/perfil`](#7-idor-insecure-direct-object-reference-en-perfil)
8. [Mass Assignment en `/perfil/actualizar`](#8-mass-assignment-en-perfilactualizar)
9. [CSRF (ausencia de token y uso de GET en acciones de escritura)](#9-csrf-ausencia-de-token-y-uso-de-get-en-acciones-de-escritura)
10. [Modo debug y clave de sesión fija](#10-modo-debug-y-clave-de-sesión-fija)
11. [Tabla resumen (prioridad de corrección sugerida)](#11-tabla-resumen)

---

## 1. SQL Injection clásica

**Dónde (archivo: [app.py](app.py)):**
- `login()` — construye el `SELECT` del login concatenando `usuario` y
  `clave` directamente.
- `clientes()` — concatena `termino` dentro de dos cláusulas `LIKE`.
- `productos()` — concatena `filtro_id` en un contexto numérico sin
  comillas.
- `ventas()` — concatena `termino` dentro de un `LIKE` sobre un `JOIN`.

**Código actual (ejemplo, `login()`):**
```python
sql = (
    "SELECT * FROM usuarios WHERE nombre_usuario = '"
    + usuario
    + "' AND password = '"
    + clave
    + "'"
)
```

**Por qué es vulnerable:** cualquier carácter especial de SQL (`'`,
`--`, `UNION`, etc.) que el usuario escriba se interpreta como parte
del comando SQL, no como un dato. Esto permite bypass de
autenticación, extracción de datos vía `UNION SELECT`, y ataques
ciegos (booleanos y de tiempo).

**Corrección recomendada:** usar **siempre** consultas parametrizadas
(placeholders `%s` de PyMySQL), dejando que el driver se encargue del
escape:
```python
cursor.execute(
    "SELECT * FROM usuarios WHERE nombre_usuario = %s AND password = %s",
    (usuario, clave),
)
```
Para `productos()`, además de parametrizar, se debe **validar que
`filtro_id` sea numérico** antes de usarlo:
```python
if filtro_id:
    try:
        filtro_id_int = int(filtro_id)
    except ValueError:
        return render_template("productos.html", productos=[], filtro_id=filtro_id,
                                error_sql=None), 400
    cursor.execute(
        "SELECT p.id, p.nombre, p.descripcion, p.precio, p.stock, "
        "c.nombre AS categoria, p.proveedor "
        "FROM productos p LEFT JOIN categorias c ON p.categoria_id = c.id "
        "WHERE p.id = %s ORDER BY p.id",
        (filtro_id_int,),
    )
```

---

## 2. Exposición de errores nativos del motor de base de datos

**Dónde:** `ejecutar_consulta_vulnerable()` y `ejecutar_consulta_stacked()`
en [app.py](app.py), junto con la macro
[`_error_sql.html`](templates/_error_sql.html) que renderiza el código
de error, el mensaje nativo de MySQL y **la consulta SQL completa**
directamente en el HTML.

**Por qué es vulnerable:** revela al atacante el motor de base de
datos exacto (MySQL 8.x), nombres de columnas y tablas (a través de
mensajes como `Unknown column 'x' in 'where clause'`), y permite
extracción de datos completa vía técnicas error-based como
`EXTRACTVALUE`/`UPDATEXML` (ver Ejercicio 10 de `inyection.md`).

**Corrección recomendada:**
- Nunca mostrar `err.args` ni la consulta SQL al cliente. Registrar el
  detalle en un log del servidor (`logging.exception(...)`) y mostrar
  al usuario un mensaje genérico:
  ```python
  except pymysql.MySQLError as err:
      app.logger.exception("Error de base de datos")
      return None, {"mensaje": "Ocurrió un error. Intenta más tarde."}
  ```
- Verificar que `app.debug = False` en producción (ver punto 10),
  porque el debugger de Werkzeug también expone trazas completas.

---

## 3. Cuenta de conexión a MySQL con privilegios excesivos

**Dónde:** [config.py](config.py) (`DB_USER = "root"`) y
`get_connection()` / `get_connection_multi_statement()` en
[app.py](app.py).

**Por qué es vulnerable:** la aplicación se conecta con una cuenta
`root@localhost` que tiene **todos los privilegios sobre todas las
bases de datos del servidor** (`GRANT ALL ... WITH GRANT OPTION`,
confirmado con `SHOW GRANTS`). Si cualquiera de las SQLi anteriores se
explota, el atacante hereda ese mismo nivel de privilegio: puede leer
y escribir cualquier base de datos del servidor, crear o eliminar
usuarios de MySQL, y (si la configuración del servidor lo permite)
leer o escribir archivos del sistema operativo con `LOAD_FILE()` /
`INTO OUTFILE`.

**Corrección recomendada:** crear una cuenta de MySQL dedicada,
exclusiva para esta aplicación, con el mínimo set de permisos que
realmente necesita:
```sql
CREATE USER 'app_tienda'@'%' IDENTIFIED BY 'una-clave-fuerte-y-unica';
GRANT SELECT, INSERT, UPDATE, DELETE ON tienda_vulnerable.* TO 'app_tienda'@'%';
-- Sin privilegios GLOBALES, sin DROP/CREATE DATABASE, sin FILE,
-- sin acceso a otras bases de datos del servidor.
FLUSH PRIVILEGES;
```
Y actualizar `config.py` para usar esa cuenta en vez de `root`,
idealmente leyendo la contraseña desde una variable de entorno o un
gestor de secretos, nunca desde el código fuente.

---

## 4. Contraseñas almacenadas en texto plano

**Dónde:** tabla `usuarios` en [db/schema.sql](db/schema.sql) (columna
`password VARCHAR(100)`), y la comparación directa en `login()`:
```python
"... AND password = '" + clave + "'"
```

**Por qué es vulnerable:** si un atacante logra leer la tabla
`usuarios` por cualquier vía (SQLi, backup filtrado, acceso físico a
la base de datos), obtiene las contraseñas reales de todos los
usuarios, sin ningún esfuerzo adicional. Además, como las contraseñas
suelen reutilizarse entre sistemas, esto facilita ataques de
"credential stuffing" contra otros servicios de la misma persona.

**Corrección recomendada:**
- Usar un algoritmo de hash con sal diseñado para contraseñas, como
  `bcrypt` (librería `bcrypt` o `werkzeug.security` que ya trae Flask
  como dependencia):
  ```python
  from werkzeug.security import generate_password_hash, check_password_hash

  # Al registrar/crear un usuario:
  password_hash = generate_password_hash(clave)

  # Al autenticar:
  cursor.execute("SELECT * FROM usuarios WHERE nombre_usuario = %s", (usuario,))
  fila = cursor.fetchone()
  if fila and check_password_hash(fila["password"], clave):
      # login correcto
  ```
- Ajustar la columna `password` para almacenar el hash (generalmente
  60-100 caracteres según el algoritmo), no la contraseña original.

---

## 5. Stacked Queries (`CLIENT_MULTI_STATEMENTS`)

**Dónde:** `get_connection_multi_statement()` y la ruta `reportes()`
en [app.py](app.py).

**Código actual:**
```python
def get_connection_multi_statement():
    return pymysql.connect(
        ...,
        client_flag=CLIENT.MULTI_STATEMENTS,
    )
```

**Por qué es vulnerable:** al habilitar `CLIENT_MULTI_STATEMENTS`
sobre una consulta construida por concatenación, un atacante puede
anexar sentencias SQL completamente distintas (`INSERT`, `UPDATE`,
`DROP TABLE`) después de un `;`, que se ejecutarán todas en el mismo
viaje al servidor. Se demostró en el Ejercicio 12 de `inyection.md`
que esto permite crear una cuenta de administrador desde cero.

**Corrección recomendada:**
- Eliminar `client_flag=CLIENT.MULTI_STATEMENTS` por completo; ninguna
  ruta de la aplicación necesita ejecutar varias sentencias en una
  sola llamada.
- Si de verdad se requieren varias operaciones relacionadas (por
  ejemplo, un reporte que combina varias consultas), ejecutarlas como
  llamadas independientes y parametrizadas a `cursor.execute()`,
  idealmente dentro de una transacción explícita si deben ser
  atómicas:
  ```python
  with conexion.cursor() as cursor:
      cursor.execute("SELECT nombre, precio, stock FROM productos WHERE nombre LIKE %s",
                      (f"%{filtro}%",))
      productos = cursor.fetchall()
  ```

---

## 6. SQL Injection de segundo orden

**Dónde:** `clientes_nuevo()` (INSERT parametrizado, seguro) y
`clientes_resumen()` (lectura y reutilización insegura) en
[app.py](app.py).

**Código actual (el problema está en `clientes_resumen`):**
```python
nombre_guardado = cliente["nombre"]
sql = (
    "SELECT v.id, v.total, v.fecha_venta, v.metodo_pago "
    "FROM ventas v JOIN clientes c ON v.cliente_id = c.id "
    "WHERE c.nombre = '" + nombre_guardado + "' ORDER BY v.id DESC"
)
```

**Por qué es vulnerable:** aunque el `INSERT` original en
`clientes_nuevo()` sí está parametrizado (y por tanto es seguro frente
a inyección directa), el valor se vuelve a leer de la base de datos
más adelante y se concatena sin parametrizar en una consulta distinta.
El payload malicioso queda "dormido" en la base de datos hasta que
alguien visita el resumen de ese cliente en particular.

**Corrección recomendada:** parametrizar también esta segunda
consulta, tratando el valor leído de la base de datos con la misma
desconfianza que un dato que viene directamente del usuario (porque,
de hecho, originalmente lo era):
```python
cursor.execute(
    "SELECT v.id, v.total, v.fecha_venta, v.metodo_pago "
    "FROM ventas v JOIN clientes c ON v.cliente_id = c.id "
    "WHERE c.nombre = %s ORDER BY v.id DESC",
    (nombre_guardado,),
)
```
**Principio general para la clase:** *todo* dato que haya sido
ingresado alguna vez por un usuario (sin importar cuántas veces haya
pasado por la base de datos) debe tratarse como no confiable en
**cada** consulta donde se utilice, no solo en la primera.

---

## 7. IDOR (Insecure Direct Object Reference) en `/perfil`

**Dónde:** ruta `perfil()` en [app.py](app.py).

**Código actual:**
```python
usuario_id = request.args.get("usuario_id", str(session["usuario_id"]))
sql = (
    "SELECT id, nombre_usuario, password, nombre_completo, rol, email, "
    "fecha_creacion FROM usuarios WHERE id = " + usuario_id
)
```

**Por qué es vulnerable:** la ruta confía en un parámetro de la URL
(`usuario_id`) controlado por el propio cliente para decidir qué
registro de la tabla `usuarios` mostrar, sin verificar que ese `id`
corresponda al usuario que inició sesión ni que quien lo pida tenga
privilegios de administrador. Además, la columna `password` se
incluye en el `SELECT` y se muestra en pantalla.

**Corrección recomendada:**
```python
@app.route("/perfil")
@login_requerido
def perfil():
    usuario_id = session["usuario_id"]  # nunca se lee de la URL para "mi perfil"

    cursor.execute(
        "SELECT id, nombre_usuario, nombre_completo, rol, email, fecha_creacion "
        "FROM usuarios WHERE id = %s",
        (usuario_id,),
    )
    ...
```
Si se requiere una vista de administración para consultar perfiles de
otros usuarios, debe ser una **ruta separada** (p. ej.
`/admin/usuarios/<int:id>`), protegida con una verificación explícita
de rol en el servidor:
```python
if session.get("rol") != "administrador":
    abort(403)
```
Y en ningún caso debe devolverse la columna `password` en la
respuesta, ni siquiera para el propio usuario autenticado.

---

## 8. Mass Assignment en `/perfil/actualizar`

**Dónde:** ruta `actualizar_perfil()` en [app.py](app.py).

**Código actual:**
```python
datos = request.values
nombre_completo = datos.get("nombre_completo", session.get("nombre_usuario"))
email = datos.get("email", "")
rol = datos.get("rol", session.get("rol"))
...
cursor.execute(
    "UPDATE usuarios SET nombre_completo = %s, email = %s, rol = %s WHERE id = %s",
    (nombre_completo, email, rol, usuario_id),
)
```

**Por qué es vulnerable:** aunque la consulta **sí** está
parametrizada (no hay SQL Injection aquí), la aplicación acepta y
persiste **cualquier** campo que llegue del formulario, incluido
`rol`, que el usuario nunca debería poder modificar sobre sí mismo.
Esto demuestra que parametrizar el SQL no es suficiente: también hay
que controlar la **lógica de negocio**.

**Corrección recomendada:** construir siempre una lista blanca
explícita de los campos editables por el propio usuario, excluyendo
campos sensibles como `rol`:
```python
@app.route("/perfil/actualizar", methods=["POST"])  # solo POST, nunca GET
@login_requerido
def actualizar_perfil():
    nombre_completo = request.form.get("nombre_completo", "")
    email = request.form.get("email", "")
    # "rol" NUNCA se lee del formulario de "mi perfil".

    cursor.execute(
        "UPDATE usuarios SET nombre_completo = %s, email = %s WHERE id = %s",
        (nombre_completo, email, session["usuario_id"]),
    )
```
Si en el futuro se necesita un flujo legítimo para cambiar el rol de
un usuario, debe ser un endpoint de administración aparte, protegido
por verificación de rol, que nunca permita que un usuario se
modifique su propio rol.

---

## 9. CSRF (ausencia de token y uso de GET en acciones de escritura)

**Dónde:** ruta `actualizar_perfil()` (`methods=["GET", "POST"]`) y la
plantilla [perfil.html](templates/perfil.html) (formulario sin token
anti-CSRF) en [app.py](app.py).

**Por qué es vulnerable:**
- La ruta acepta `GET` para una acción que modifica datos
  (`UPDATE usuarios ...`). Los navegadores tratan las peticiones `GET`
  como "seguras" y las incluyen con mucha más facilidad en
  navegaciones automáticas disparadas desde un sitio externo.
- No existe ningún token anti-CSRF que verifique que la petición
  realmente se originó en un formulario legítimo de la propia
  aplicación.
- Se demostró con [csrf_poc/csrf_poc.html](csrf_poc/csrf_poc.html) que
  una página externa puede forzar, sin interacción de la víctima, que
  su navegador envíe esta petición usando sus cookies de sesión.

**Corrección recomendada:**
1. Restringir la ruta exclusivamente a `POST`:
   ```python
   @app.route("/perfil/actualizar", methods=["POST"])
   ```
2. Instalar `Flask-WTF` y usar `CSRFProtect` para generar y validar un
   token único por sesión en cada formulario que modifique datos:
   ```python
   from flask_wtf import CSRFProtect
   csrf = CSRFProtect(app)
   ```
   ```html
   <form method="POST" action="{{ url_for('actualizar_perfil') }}">
       <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
       ...
   </form>
   ```
3. Configurar la cookie de sesión con un atributo `SameSite` explícito
   (como mínimo `"Lax"`, idealmente `"Strict"` para acciones sensibles)
   y `Secure=True` si la aplicación se sirve sobre HTTPS:
   ```python
   app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
   app.config["SESSION_COOKIE_SECURE"] = True
   ```

---

## 10. Modo debug y clave de sesión fija

**Dónde:** [app.py](app.py) (`app.run(..., debug=True)`) y
[config.py](config.py) (`SECRET_KEY` con valor fijo por defecto en el
código fuente).

**Por qué es vulnerable:**
- `debug=True` habilita el debugger interactivo de Werkzeug, que
  permite ejecutar código Python arbitrario en el servidor si un
  atacante logra provocar una excepción no controlada y acceder a la
  consola de depuración (especialmente grave si además está expuesto
  a la red, como ocurre aquí con `host="0.0.0.0"`).
- Una `SECRET_KEY` fija y conocida (presente en el código fuente)
  permite a un atacante **firmar sus propias cookies de sesión**, es
  decir, falsificar una sesión válida de cualquier usuario
  (incluyendo `rol: "administrador"`) sin necesidad de ninguna
  contraseña.

**Corrección recomendada:**
```python
app.run(host="127.0.0.1", port=5000, debug=False)
```
```python
# config.py
import os
SECRET_KEY = os.environ["SECRET_KEY"]  # obligatorio, sin valor por defecto
```
Generar una clave aleatoria fuerte y única por entorno, por ejemplo
con `python -c "import secrets; print(secrets.token_hex(32))"`, y
nunca versionarla en el repositorio.

---

## 11. Tabla resumen

| # | Vulnerabilidad | Archivo(s) | Severidad | Corrección principal |
|---|---|---|---|---|
| 1 | SQL Injection clásica | `app.py` (login, clientes, productos, ventas) | Crítica | Consultas parametrizadas |
| 2 | Exposición de errores nativos | `app.py`, `_error_sql.html` | Alta | No mostrar errores crudos al cliente |
| 3 | Conexión como `root` | `config.py`, `app.py` | Crítica | Usuario de MySQL con privilegios mínimos |
| 4 | Contraseñas en texto plano | `db/schema.sql`, `app.py` | Crítica | Hash con `bcrypt`/`werkzeug.security` |
| 5 | Stacked Queries | `app.py` (`get_connection_multi_statement`, `reportes`) | Crítica | Quitar `CLIENT_MULTI_STATEMENTS` |
| 6 | SQLi de segundo orden | `app.py` (`clientes_resumen`) | Crítica | Parametrizar también la 2ª consulta |
| 7 | IDOR en `/perfil` | `app.py` (`perfil`) | Alta | Usar siempre `session["usuario_id"]`; no exponer `password` |
| 8 | Mass Assignment | `app.py` (`actualizar_perfil`) | Alta | Lista blanca de campos editables |
| 9 | CSRF | `app.py`, `perfil.html`, `csrf_poc/` | Alta | Token CSRF + solo `POST` + `SameSite` |
| 10 | Debug + `SECRET_KEY` fija | `app.py`, `config.py` | Alta | `debug=False`, clave desde variable de entorno |

Todas estas correcciones son **compatibles entre sí** y pueden
aplicarse de forma incremental; de hecho, un ejercicio recomendado
para la clase es: tomar una copia de este proyecto y corregir, una por
una, cada vulnerabilidad de esta tabla, volviendo a ejecutar los
ejercicios de [inyection.md](inyection.md) después de cada corrección
para confirmar que el payload correspondiente deja de funcionar.
