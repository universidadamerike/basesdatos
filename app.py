"""
=================================================================
 Sistema de Tienda Departamental - VERSION VULNERABLE (DEMO)
=================================================================

ADVERTENCIA:
Esta aplicación fue construida INTENCIONALMENTE con vulnerabilidades
de Inyección SQL (SQL Injection) con fines 100% educativos para una
clase de ciberseguridad / seguridad en bases de datos.

NO debe desplegarse en Internet, en una red de producción, ni usarse
como base para un sistema real. Las consultas SQL se arman
concatenando directamente la entrada del usuario (en vez de usar
consultas parametrizadas / prepared statements), que es precisamente
el error que se busca enseñar a identificar y corregir.

Módulos vulnerables incluidos:
  1. /login              -> Bypass de autenticación por inyección SQL.
  2. /clientes            -> Búsqueda vulnerable a UNION-based SQL Injection.
  3. /productos           -> Filtro numérico vulnerable a Error-based / Boolean-based SQLi.
  4. /ventas              -> Búsqueda vulnerable a UNION-based SQL Injection (join).
  5. /reportes            -> Vulnerable a Stacked Queries (inyección de múltiples
                              sentencias SQL) porque la conexión habilita
                              CLIENT_MULTI_STATEMENTS, igual que harían
                              mysqli_multi_query() en PHP o un driver nativo
                              mal configurado.
  6. /clientes/nuevo      -> Alta de clientes mediante consulta PARAMETRIZADA
                              (segura frente a inyección directa), pero el
                              valor queda almacenado para alimentar el
                              Ejercicio de inyección de SEGUNDO ORDEN.
  7. /clientes/<id>/resumen -> VULNERABLE a SQL Injection de segundo orden:
                              toma el nombre ya almacenado en la base de
                              datos y lo concatena sin parametrizar en una
                              segunda consulta.
  8. /perfil              -> VULNERABLE a IDOR (Insecure Direct Object
                              Reference): confía en el parámetro
                              "usuario_id" de la URL en vez de validar que
                              corresponda al usuario en sesión, y además
                              concatena ese valor en la consulta SQL.
  9. /perfil/actualizar   -> VULNERABLE a CSRF (sin token anti-CSRF) y a
                              Mass Assignment (acepta el campo "rol" desde
                              el formulario, permitiendo que un empleado se
                              autoasigne el rol de administrador). Acepta
                              GET y POST, lo cual facilita aún más el CSRF.

En cada módulo, si el motor de MySQL genera un error de sintaxis, el
error crudo (código, mensaje y motor de base de datos) se muestra en
pantalla sin sanitizar, tal como ocurre en aplicaciones reales mal
configuradas (esto facilita la fase de "fingerprinting" del atacante).
"""

from flask import Flask, render_template, request, redirect, url_for, session
import pymysql
import pymysql.cursors
from pymysql.constants import CLIENT

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY


def get_connection():
    """Abre una nueva conexión a MySQL usando PyMySQL."""
    return pymysql.connect(
        host=config.DB_HOST,
        port=config.DB_PORT,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


def get_connection_multi_statement():
    """
    Abre una conexión a MySQL con CLIENT_MULTI_STATEMENTS habilitado.

    VULNERABILIDAD (Stacked Queries / inyección de múltiples sentencias):
    este flag permite ejecutar varias sentencias SQL separadas por ';'
    en una sola llamada a cursor.execute(). Los drivers "normales" de
    PyMySQL/MySQLdb NO lo habilitan por defecto (por eso el resto de la
    app, que usa get_connection(), no es vulnerable a esto), pero es un
    patrón real que existe en otros stacks (p. ej. mysqli_multi_query()
    en PHP, o controladores ODBC/ADO mal configurados). Se aísla en una
    función aparte para que el módulo /reportes sea el único punto donde
    se puedan "apilar" sentencias adicionales (INSERT, UPDATE, DROP...)
    detrás de una consulta SELECT aparentemente inofensiva.
    """
    return pymysql.connect(
        host=config.DB_HOST,
        port=config.DB_PORT,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
        client_flag=CLIENT.MULTI_STATEMENTS,
    )


def ejecutar_consulta_vulnerable(sql):
    """
    Ejecuta una consulta SQL ya construida (potencialmente con datos del
    usuario concatenados por el llamador) y devuelve una tupla:
        (filas, error)

    Si ocurre un error de MySQL, se captura y se arma un diccionario con
    la información cruda del error (a propósito, sin ocultar nada) para
    que se pueda observar en pantalla el "fingerprint" del motor de
    base de datos, tal como pasaría en un sitio vulnerable real.
    """
    conexion = get_connection()
    try:
        with conexion.cursor() as cursor:
            cursor.execute(sql)
            filas = cursor.fetchall()
            return filas, None
    except pymysql.MySQLError as err:
        codigo_error = err.args[0] if len(err.args) > 0 else "N/D"
        mensaje_error = err.args[1] if len(err.args) > 1 else str(err)
        error_info = {
            "motor": "MySQL (detectado mediante el driver PyMySQL / mensaje de error nativo)",
            "codigo": codigo_error,
            "mensaje": mensaje_error,
            "consulta": sql,
        }
        return None, error_info
    finally:
        conexion.close()


def ejecutar_consulta_stacked(sql):
    """
    Ejecuta (potencialmente) VARIAS sentencias SQL separadas por ';' en
    una sola llamada, usando una conexión con CLIENT_MULTI_STATEMENTS.

    VULNERABILIDAD (Stacked Queries): si el texto de "sql" fue construido
    concatenando entrada del usuario (como en la ruta /reportes), un
    atacante puede anexar sentencias adicionales después de un ';', por
    ejemplo un INSERT, UPDATE o DROP TABLE, y estas se ejecutarán todas
    en el servidor aunque la aplicación solo esperaba un SELECT.

    Devuelve una tupla (filas_primer_resultado, error, sentencias_totales).
    """
    conexion = get_connection_multi_statement()
    try:
        with conexion.cursor() as cursor:
            cursor.execute(sql)
            filas = cursor.fetchall()
            sentencias_totales = 1
            # Avanza por todos los result sets restantes para que TODAS
            # las sentencias apiladas (INSERT/UPDATE/DROP, etc.) se
            # terminen de ejecutar en el servidor, no solo la primera.
            while cursor.nextset():
                sentencias_totales += 1
            return filas, None, sentencias_totales
    except pymysql.MySQLError as err:
        codigo_error = err.args[0] if len(err.args) > 0 else "N/D"
        mensaje_error = err.args[1] if len(err.args) > 1 else str(err)
        error_info = {
            "motor": "MySQL (detectado mediante el driver PyMySQL / mensaje de error nativo)",
            "codigo": codigo_error,
            "mensaje": mensaje_error,
            "consulta": sql,
        }
        return None, error_info, 0
    finally:
        conexion.close()


def login_requerido(func):
    """Decorador simple para proteger rutas que requieren sesión iniciada."""
    def wrapper(*args, **kwargs):
        if "usuario_id" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


# -----------------------------------------------------------------
# RUTA: Login  -> VULNERABLE a bypass de autenticación por SQL Injection
# -----------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    if "usuario_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error_sql = None
    error_login = None

    if request.method == "POST":
        usuario = request.form.get("usuario", "")
        clave = request.form.get("clave", "")

        # --------------------------------------------------------------
        # VULNERABILIDAD: la consulta se arma concatenando directamente
        # lo que el usuario escribió en el formulario, sin usar consultas
        # parametrizadas (%s) ni escapar comillas. Esto permite, por
        # ejemplo, iniciar sesión escribiendo en el campo "usuario":
        #
        #       ' OR 1=1 -- -
        #
        # y dejando la contraseña vacía o con cualquier valor.
        # --------------------------------------------------------------
        sql = (
            "SELECT * FROM usuarios WHERE nombre_usuario = '"
            + usuario
            + "' AND password = '"
            + clave
            + "'"
        )

        filas, error = ejecutar_consulta_vulnerable(sql)

        if error:
            error_sql = error
        elif filas:
            usuario_db = filas[0]
            session["usuario_id"] = usuario_db["id"]
            session["nombre_usuario"] = usuario_db["nombre_usuario"]
            session["rol"] = usuario_db["rol"]
            return redirect(url_for("dashboard"))
        else:
            error_login = "Usuario o contraseña incorrectos."

    return render_template("login.html", error_login=error_login, error_sql=error_sql)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# -----------------------------------------------------------------
# RUTA: Dashboard (resumen general de la tienda)
# -----------------------------------------------------------------
@app.route("/dashboard")
@login_requerido
def dashboard():
    conexion = get_connection()
    with conexion.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) AS total FROM clientes")
        total_clientes = cursor.fetchone()["total"]
        cursor.execute("SELECT COUNT(*) AS total FROM productos")
        total_productos = cursor.fetchone()["total"]
        cursor.execute("SELECT COUNT(*) AS total FROM ventas")
        total_ventas = cursor.fetchone()["total"]
        cursor.execute("SELECT COALESCE(SUM(total),0) AS suma FROM ventas")
        monto_total = cursor.fetchone()["suma"]
    conexion.close()

    return render_template(
        "dashboard.html",
        total_clientes=total_clientes,
        total_productos=total_productos,
        total_ventas=total_ventas,
        monto_total=monto_total,
    )


# -----------------------------------------------------------------
# RUTA: Clientes -> VULNERABLE a UNION-based SQL Injection
# -----------------------------------------------------------------
@app.route("/clientes")
@login_requerido
def clientes():
    termino = request.args.get("q", "")

    # --------------------------------------------------------------
    # VULNERABILIDAD: el término de búsqueda se concatena directamente
    # dentro del LIKE, sin parametrizar. La proyección tiene 7 columnas,
    # el mismo número de columnas que la tabla "usuarios", por lo que
    # es posible usar una inyección UNION para extraer usuarios y
    # contraseñas del sistema desde el buscador de clientes. Ejemplo:
    #
    #   ' UNION SELECT id, nombre_usuario, password, nombre_completo,
    #            rol, email, fecha_creacion FROM usuarios -- -
    # --------------------------------------------------------------
    sql = (
        "SELECT id, nombre, apellido, email, telefono, direccion, ciudad "
        "FROM clientes WHERE nombre LIKE '%" + termino + "%' "
        "OR apellido LIKE '%" + termino + "%' ORDER BY id"
    )

    filas, error = ejecutar_consulta_vulnerable(sql)

    return render_template(
        "clientes.html", clientes=filas or [], termino=termino, error_sql=error
    )


# -----------------------------------------------------------------
# RUTA: Alta de clientes -> consulta PARAMETRIZADA (segura frente a
# inyección directa), pero alimenta el Ejercicio de SQLi de 2do orden.
# -----------------------------------------------------------------
@app.route("/clientes/nuevo", methods=["GET", "POST"])
@login_requerido
def clientes_nuevo():
    error_guardado = None
    if request.method == "POST":
        nombre = request.form.get("nombre", "")
        apellido = request.form.get("apellido", "")
        email = request.form.get("email", "")
        telefono = request.form.get("telefono", "")
        direccion = request.form.get("direccion", "")
        ciudad = request.form.get("ciudad", "")

        # --------------------------------------------------------------
        # Esta inserción SÍ usa una consulta parametrizada (placeholders
        # %s), por lo que es segura frente a inyección SQL directa: el
        # valor de "nombre" se guarda tal cual lo escribió el usuario,
        # incluso si contiene comillas o palabras reservadas de SQL.
        #
        # El problema (ver /clientes/<id>/resumen) es que ese valor
        # "seguro" se reutiliza MÁS ADELANTE en otra consulta que sí
        # concatena sin parametrizar: eso es precisamente lo que se
        # conoce como SQL Injection de SEGUNDO ORDEN.
        # --------------------------------------------------------------
        conexion = get_connection()
        try:
            with conexion.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO clientes (nombre, apellido, email, telefono, direccion, ciudad) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (nombre, apellido, email, telefono, direccion, ciudad),
                )
                nuevo_id = cursor.lastrowid
        except pymysql.MySQLError as err:
            error_guardado = str(err)
            nuevo_id = None
        finally:
            conexion.close()

        if nuevo_id:
            return redirect(url_for("clientes_resumen", cliente_id=nuevo_id))

    return render_template("clientes_nuevo.html", error_guardado=error_guardado)


# -----------------------------------------------------------------
# RUTA: Resumen de cliente -> VULNERABLE a SQL Injection de 2do orden
# -----------------------------------------------------------------
@app.route("/clientes/<int:cliente_id>/resumen")
@login_requerido
def clientes_resumen(cliente_id):
    # Paso 1: obtener el cliente de forma segura (cliente_id ya viene
    # forzado a int por Flask gracias al convertidor <int:cliente_id>).
    conexion = get_connection()
    with conexion.cursor() as cursor:
        cursor.execute("SELECT * FROM clientes WHERE id = %s", (cliente_id,))
        cliente = cursor.fetchone()
    conexion.close()

    if not cliente:
        return render_template(
            "clientes_resumen.html", cliente=None, ventas=[], error_sql=None
        )

    # --------------------------------------------------------------
    # VULNERABILIDAD (SQL Injection de 2do orden): el nombre del cliente
    # fue guardado de forma segura (INSERT parametrizado en
    # /clientes/nuevo), pero aquí se vuelve a leer desde la base de
    # datos y se concatena SIN PARAMETRIZAR en una segunda consulta para
    # generar el "resumen de compras". Si al crear el cliente se guardó
    # como nombre, por ejemplo:
    #
    #   x' UNION SELECT id, nombre_usuario, password, 0, NOW(), 'tarjeta
    #
    # la inyección NO se dispara al insertarlo (porque el INSERT es
    # parametrizado), sino más tarde, cada vez que alguien visita el
    # resumen de ESE cliente en particular.
    # --------------------------------------------------------------
    nombre_guardado = cliente["nombre"]
    sql = (
        "SELECT v.id, v.total, v.fecha_venta, v.metodo_pago "
        "FROM ventas v JOIN clientes c ON v.cliente_id = c.id "
        "WHERE c.nombre = '" + nombre_guardado + "' ORDER BY v.id DESC"
    )

    filas, error = ejecutar_consulta_vulnerable(sql)

    return render_template(
        "clientes_resumen.html", cliente=cliente, ventas=filas or [], error_sql=error
    )


# -----------------------------------------------------------------
# RUTA: Productos -> VULNERABLE a Error-based / Boolean-based SQL Injection
# -----------------------------------------------------------------
@app.route("/productos")
@login_requerido
def productos():
    filtro_id = request.args.get("id", "").strip()

    # --------------------------------------------------------------
    # VULNERABILIDAD: el filtro por id se concatena en un contexto
    # NUMÉRICO (sin comillas), por lo que se puede inyectar lógica SQL
    # arbitraria sin necesidad de cerrar comillas. Ejemplos:
    #
    #   id = 0 OR 1=1                -> muestra todos los productos
    #   id = (SELECT 1 FROM usuarios WHERE nombre_usuario='admin')
    #   id = abc                     -> provoca un error de sintaxis
    #                                     de MySQL (fingerprinting)
    # --------------------------------------------------------------
    if filtro_id:
        sql = (
            "SELECT p.id, p.nombre, p.descripcion, p.precio, p.stock, "
            "c.nombre AS categoria, p.proveedor "
            "FROM productos p LEFT JOIN categorias c ON p.categoria_id = c.id "
            "WHERE p.id = " + filtro_id + " ORDER BY p.id"
        )
    else:
        sql = (
            "SELECT p.id, p.nombre, p.descripcion, p.precio, p.stock, "
            "c.nombre AS categoria, p.proveedor "
            "FROM productos p LEFT JOIN categorias c ON p.categoria_id = c.id "
            "ORDER BY p.id"
        )

    filas, error = ejecutar_consulta_vulnerable(sql)

    return render_template(
        "productos.html", productos=filas or [], filtro_id=filtro_id, error_sql=error
    )


# -----------------------------------------------------------------
# RUTA: Ventas -> VULNERABLE a UNION-based SQL Injection (sobre JOIN)
# -----------------------------------------------------------------
@app.route("/ventas")
@login_requerido
def ventas():
    termino = request.args.get("cliente", "")

    # --------------------------------------------------------------
    # VULNERABILIDAD: igual que en /clientes, el término de búsqueda
    # del cliente se concatena sin parametrizar. La proyección tiene 5
    # columnas, por lo que se puede inyectar un UNION SELECT con 5
    # columnas para filtrar datos de la tabla "usuarios" camuflados
    # como si fueran una "venta". Ejemplo de payload para el campo
    # "cliente":
    #
    #   ' UNION SELECT id, CONCAT(nombre_usuario,':',password),
    #            NOW(), 0, rol FROM usuarios -- -
    # --------------------------------------------------------------
    sql = (
        "SELECT v.id, CONCAT(c.nombre,' ',c.apellido) AS cliente, "
        "v.fecha_venta, v.total, v.metodo_pago "
        "FROM ventas v JOIN clientes c ON v.cliente_id = c.id "
        "WHERE c.nombre LIKE '%" + termino + "%' ORDER BY v.id DESC"
    )

    filas, error = ejecutar_consulta_vulnerable(sql)

    return render_template(
        "ventas.html", ventas=filas or [], termino=termino, error_sql=error
    )


# -----------------------------------------------------------------
# RUTA: Reportes -> VULNERABLE a Stacked Queries (múltiples sentencias)
# -----------------------------------------------------------------
@app.route("/reportes")
@login_requerido
def reportes():
    filtro = request.args.get("producto", "")

    # --------------------------------------------------------------
    # VULNERABILIDAD (Stacked Queries): esta consulta se ejecuta sobre
    # una conexión con CLIENT_MULTI_STATEMENTS habilitado (ver
    # get_connection_multi_statement). Eso permite que, si el atacante
    # cierra la cadena e inyecta un ';', pueda "apilar" sentencias SQL
    # adicionales (INSERT, UPDATE, DROP TABLE...) que se ejecutarán
    # todas en el mismo viaje al servidor. Ejemplo de payload para el
    # campo "producto":
    #
    #   x'; INSERT INTO usuarios (nombre_usuario,password,
    #       nombre_completo,rol) VALUES ('hacker','1234','Intruso',
    #       'administrador'); -- -
    #
    # Tras ejecutar ese payload, el atacante puede iniciar sesión en
    # /login con usuario "hacker" y contraseña "1234" con rol
    # "administrador", sin que nadie se lo haya otorgado.
    # --------------------------------------------------------------
    sql = (
        "SELECT nombre, descripcion, precio, stock "
        "FROM productos WHERE nombre LIKE '%" + filtro + "%'"
    )

    filas, error, total_sentencias = ejecutar_consulta_stacked(sql)

    return render_template(
        "reportes.html",
        productos=filas or [],
        filtro=filtro,
        error_sql=error,
        total_sentencias=total_sentencias,
    )


# -----------------------------------------------------------------
# RUTA: Perfil -> VULNERABLE a IDOR (Insecure Direct Object Reference)
# -----------------------------------------------------------------
@app.route("/perfil")
@login_requerido
def perfil():
    # --------------------------------------------------------------
    # VULNERABILIDAD (IDOR): en vez de usar SIEMPRE el id del usuario
    # que inició sesión (session["usuario_id"]), la ruta confía en un
    # parámetro de la URL que el propio usuario puede modificar. Así,
    # cualquier empleado autenticado puede ver el perfil completo
    # (incluida la contraseña en texto plano) de OTRO usuario, por
    # ejemplo del administrador, cambiando solamente el número en la
    # URL:
    #
    #   /perfil?usuario_id=1
    #
    # Además, ese mismo parámetro se concatena sin parametrizar, por lo
    # que también admite SQL Injection clásica, por ejemplo:
    #
    #   /perfil?usuario_id=0 OR 1=1
    # --------------------------------------------------------------
    usuario_id = request.args.get("usuario_id", str(session["usuario_id"]))

    sql = (
        "SELECT id, nombre_usuario, password, nombre_completo, rol, email, "
        "fecha_creacion FROM usuarios WHERE id = " + usuario_id
    )

    filas, error = ejecutar_consulta_vulnerable(sql)
    perfil_consultado = filas[0] if filas else None

    return render_template(
        "perfil.html",
        perfil=perfil_consultado,
        usuario_id=usuario_id,
        error_sql=error,
    )


# -----------------------------------------------------------------
# RUTA: Actualizar perfil -> VULNERABLE a CSRF y a Mass Assignment
# -----------------------------------------------------------------
@app.route("/perfil/actualizar", methods=["GET", "POST"])
@login_requerido
def actualizar_perfil():
    # --------------------------------------------------------------
    # VULNERABILIDAD (CSRF): este formulario no incluye ningún token
    # anti-CSRF, y además acepta tanto GET como POST. Eso permite que
    # un atacante construya una página externa (ver csrf_poc.html) que,
    # al ser abierta por una víctima con sesión activa, haga que su
    # navegador envíe automáticamente esta petición usando las cookies
    # de sesión de la víctima, sin que ella se entere.
    #
    # VULNERABILIDAD (Mass Assignment): la aplicación confía en TODOS
    # los campos que llegan del formulario, incluido "rol". Un usuario
    # con rol "empleado" puede enviar un campo oculto rol=administrador
    # y auto-asignarse privilegios de administrador, aunque la consulta
    # de actualización esté correctamente parametrizada (lo cual
    # demuestra que parametrizar el SQL NO basta para evitar fallas de
    # lógica de negocio / control de acceso).
    # --------------------------------------------------------------
    datos = request.values  # combina argumentos de GET y de POST
    nombre_completo = datos.get("nombre_completo", session.get("nombre_usuario"))
    email = datos.get("email", "")
    rol = datos.get("rol", session.get("rol"))

    usuario_id = session["usuario_id"]

    conexion = get_connection()
    with conexion.cursor() as cursor:
        cursor.execute(
            "UPDATE usuarios SET nombre_completo = %s, email = %s, rol = %s WHERE id = %s",
            (nombre_completo, email, rol, usuario_id),
        )
    conexion.close()

    # La sesión se actualiza de inmediato con el nuevo rol "aprobado"
    # por el propio usuario, reflejando la escalación de privilegios.
    session["rol"] = rol

    return redirect(url_for("perfil"))


if __name__ == "__main__":
    # debug=True también es intencional para la demo (muestra tracebacks
    # de Flask/Werkzeug); en producción SIEMPRE debe estar en False.
    app.run(host="0.0.0.0", port=5000, debug=True)
