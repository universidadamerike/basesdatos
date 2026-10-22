# Riesgos adicionales y ejercicios defensivos

Este documento complementa la práctica de inyección SQL con otros
riesgos que pueden afectar una aplicación conectada a una base de datos.
Los ejercicios están diseñados para revisión, auditoría y validación de
controles en una copia local y aislada del proyecto. No incluyen
payloads de explotación ni requieren acceder a sistemas o datos ajenos.

> **Alcance:** usa exclusivamente cuentas y datos ficticios del
> laboratorio local. No ejecutes cambios destructivos, pruebas de carga,
> intentos de adivinar contraseñas ni acciones que afecten a otros
> usuarios. No registres ni compartas contraseñas que aparezcan en los
> datos de ejemplo.

## Riesgos incluidos en el proyecto

### 1. Privilegios excesivos en la cuenta de base de datos

La aplicación utiliza `root` como usuario predeterminado de MySQL en
`config.py`. Si una aplicación se conecta con una cuenta administrativa,
cualquier falla que permita ejecutar operaciones de base de datos puede
tener un impacto mayor que con una cuenta limitada.

**Mitigación:** crear una cuenta exclusiva para la aplicación, conceder
solo los permisos necesarios sobre su esquema y separar las cuentas de
desarrollo, prueba y producción.

### 2. Contraseñas de usuarios almacenadas en texto plano

La columna `usuarios.password` de `db/schema.sql` está definida para
guardar valores sin hash. Si la base o una respuesta de la aplicación
se expone, las contraseñas podrían quedar legibles y ser reutilizadas
en otros servicios.

**Mitigación:** almacenar hashes adaptativos de contraseña, como Argon2id
o bcrypt, con una biblioteca mantenida; nunca registrar ni mostrar las
contraseñas originales.

### 3. Control de acceso por objeto deficiente (IDOR)

La ruta `/perfil` acepta un identificador de usuario recibido en la
solicitud y no lo restringe al identificador de la sesión. Esto puede
permitir que un usuario autenticado consulte un perfil que no le
corresponde.

**Mitigación:** derivar la identidad de la sesión autenticada y comprobar
la autorización en el servidor para cada objeto solicitado. Ocultar o
adivinar identificadores no sustituye esa comprobación.

### 4. CSRF y asignación masiva

La ruta `/perfil/actualizar` acepta GET y POST, no valida un token
anti-CSRF y toma campos de la solicitud —incluido el rol— para actualizar
el perfil. La parametrización SQL no corrige errores de autorización o
de lógica de negocio.

**Mitigación:** aceptar solo POST para cambios, validar un token CSRF,
usar cookies con atributos apropiados y permitir explícitamente solo
los campos que el usuario puede modificar. El rol debe cambiarse por un
flujo administrativo separado y autorizado.

### 5. Divulgación de errores y detalles internos

Mostrar errores de MySQL, consultas, rutas internas o trazas facilita
que se conozca la estructura y el comportamiento de la aplicación.

**Mitigación:** mostrar al usuario mensajes genéricos y guardar los
detalles técnicos en registros con acceso restringido. Desactivar el
modo de depuración fuera del desarrollo local.

### 6. Disponibilidad y consultas costosas

Consultas sin límites, tiempos de espera o controles de paginación
pueden consumir recursos y afectar la disponibilidad. Las pruebas que
generan esperas deliberadas o grandes volúmenes de solicitudes no son
necesarias para entender este riesgo.

**Mitigación:** aplicar límites de tiempo y de resultados, paginar,
revisar planes de consulta, establecer límites de recursos y monitorizar
la latencia.

### 7. Gestión de secretos y respaldos

Contraseñas de conexión, claves de sesión y respaldos pueden filtrarse
si se guardan en el código, se incluyen en Git o tienen permisos de
archivo demasiado amplios.

**Mitigación:** inyectar secretos desde el entorno o un gestor de
secretos; excluir archivos locales mediante `.gitignore`; limitar el
acceso a respaldos y rotar cualquier secreto que se haya publicado.
Nunca imprimas ni pegues secretos en reportes.

## Ejercicios paso a paso

Realiza los ejercicios en una copia local y desechable. Para cada uno,
entrega una ficha con: **riesgo observado**, **evidencia no sensible**,
**impacto posible** y **control recomendado**.

### Ejercicio 1: revisar los privilegios de la conexión

**Objetivo:** identificar si la aplicación se conecta con más permisos
de los que necesita, sin modificar la base.

1. Abre `config.py` y anota el usuario de base de datos configurado por
   defecto. No copies ni publiques valores de variables de entorno.
2. En el cliente MySQL local, conéctate usando la cuenta administrativa
   que ya tengas configurada.
3. Ejecuta la consulta de solo lectura `SHOW GRANTS FOR CURRENT_USER();`.
4. Compara los permisos observados con las operaciones que la aplicación
   requiere para sus tablas de la tienda.
5. Describe qué permisos podrían eliminarse. No cambies privilegios en
   la base compartida ni uses la cuenta administrativa desde la
   aplicación como solución.

**Resultado esperado:** reconocer que una cuenta de aplicación debería
tener permisos limitados al esquema y a las operaciones estrictamente
necesarias.

### Ejercicio 2: auditar el almacenamiento de contraseñas

**Objetivo:** detectar almacenamiento inseguro sin revelar credenciales.

1. Revisa la definición de la tabla `usuarios` en `db/schema.sql`.
2. Revisa cómo se consulta el campo de contraseña en la ruta de login de
   `app.py`.
3. Registra si el diseño indica contraseña en texto plano o hash. No
   consultes ni transcribas los valores de las filas.
4. Especifica qué cambio harías para almacenar y verificar hashes
   adaptativos con una biblioteca mantenida.
5. Define una prueba para confirmar que el sistema compara un hash y
   nunca devuelve ni registra la contraseña original.

**Resultado esperado:** diferenciar el hash de una contraseña de una
cifrado reversible o del almacenamiento en texto plano.

### Ejercicio 3: revisar autorización a nivel de objeto

**Objetivo:** comprobar que un perfil solo se consulta con autorización
del servidor.

1. Usa únicamente la instancia local y dos cuentas ficticias de prueba.
2. Revisa la ruta `/perfil` en `app.py` y localiza de dónde obtiene el
   identificador consultado.
3. Compara ese identificador con el usuario autenticado en la sesión.
   Anota si el servidor comprueba que ambos corresponden al mismo
   usuario o si existe una regla de autorización explícita.
4. En una copia desechable, define una prueba con dos cuentas ficticias:
   una debe poder consultar su propio perfil y la otra no debe acceder
   al perfil ajeno. No enumeres identificadores ni registres campos
   sensibles.
5. Propón una corrección que tome la identidad desde la sesión o valide
   una autorización explícita antes de consultar el registro.

**Resultado esperado:** la identidad del objeto no basta para conceder
acceso; el servidor debe autorizar cada solicitud.

### Ejercicio 4: validar la actualización segura del perfil

**Objetivo:** separar los campos editables por el usuario de los campos
administrativos y proteger las solicitudes de cambio.

1. Revisa el formulario de perfil y la ruta `/perfil/actualizar`.
2. Anota los métodos HTTP que acepta la ruta y si existe validación
   anti-CSRF.
3. Lista los campos que un usuario debería poder cambiar y separa de
   ellos los campos administrativos, como el rol.
4. En una copia de código para pruebas, define una prueba automatizada:
   una actualización legítima cambia solo los campos permitidos; los
   campos no permitidos permanecen sin cambios.
5. Define otra prueba que compruebe que una solicitud de cambio sin
   token CSRF válido es rechazada. No ejecutes la prueba contra una
   sesión real ni cambies el rol de una cuenta compartida.

**Resultado esperado:** el servidor aplica una lista explícita de campos
permitidos y exige una solicitud protegida para cambios de estado.

### Ejercicio 5: analizar el manejo de errores

**Objetivo:** reducir la información interna que recibe un usuario.

1. Revisa el manejo de excepciones en `app.py` y la plantilla
   `templates/_error_sql.html`.
2. Identifica qué información técnica se muestra en la página y qué
   información debería permanecer solo en los registros internos.
3. Define el mensaje genérico que debería recibir el usuario y los
   metadatos no sensibles que convendría registrar para diagnóstico.
4. Propón una prueba de regresión que compruebe que una excepción de
   base de datos no devuelve consultas, trazas ni datos de conexión.

**Resultado esperado:** diagnóstico disponible para el equipo, sin
exponer detalles internos en la respuesta pública.

### Ejercicio 6: revisar rendimiento sin generar carga

**Objetivo:** entender cómo limitar el costo de las consultas sin
realizar una prueba de denegación de servicio.

1. Selecciona una consulta de lectura normal de la aplicación.
2. En la base local, utiliza `EXPLAIN` sobre una consulta equivalente
   de solo lectura y observa el plan, índices y filas estimadas.
3. Revisa si la ruta limita el número de resultados y si existe un
   tiempo de espera para la consulta.
4. Recomienda paginación, índices o límites de tiempo según el plan.
5. No uses funciones de espera, solicitudes repetidas ni cargas
   concurrentes para este ejercicio.

**Resultado esperado:** identificar medidas de disponibilidad mediante
análisis estático y consultas de diagnóstico, no mediante saturación.

### Ejercicio 7: auditar secretos y archivos locales

**Objetivo:** comprobar que el repositorio no incluya secretos ni claves.

1. Revisa `config.py` y confirma que la contraseña de MySQL se obtiene
   del entorno y no está escrita como valor real en el código.
2. Revisa `.gitignore` para verificar que excluye archivos de entorno,
   entornos virtuales y claves privadas.
3. Revisa la lista de archivos versionados; no abras ni publiques el
   contenido de `.env`, respaldos o claves privadas.
4. Documenta el proceso recomendado para rotar un secreto si alguna vez
   se añadió a un commit.

**Resultado esperado:** separar configuración y secretos del código y
evitar que archivos locales se incorporen al control de versiones.

## Criterios de evaluación

- Se identifica correctamente la causa y el impacto sin recopilar datos
  sensibles.
- Se distingue una vulnerabilidad de SQLi de fallas de autorización,
  CSRF, configuración o disponibilidad.
- La recomendación aborda la causa raíz y puede verificarse con una
  prueba no destructiva.
- Las pruebas se limitan a datos ficticios y a la instancia local
  autorizada.
