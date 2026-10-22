# Inyección SQL: contexto para la práctica en vivo

Material de introducción para presentar antes del laboratorio. Está
pensado para una exposición breve de aproximadamente 10–15 minutos. La
aplicación de este repositorio es intencionalmente vulnerable: úsala
solo en el entorno local autorizado de la clase y no la expongas a
Internet ni a sistemas ajenos.

## Objetivos de aprendizaje

Al terminar la introducción, el grupo podrá:

- Explicar qué es la inyección SQL y por qué ocurre.
- Reconocer contextos de entrada que pueden terminar dentro de una
  consulta dinámica.
- Diferenciar algunas familias comunes de SQLi por su comportamiento.
- Identificar impactos posibles y controles preventivos básicos.
- Realizar la práctica únicamente dentro del laboratorio autorizado.

## Guion sugerido de diapositivas

### 1. ¿Por qué hablar de inyección SQL?

Las aplicaciones suelen recibir datos mediante formularios, parámetros
de URL, cookies, API o integraciones. Si esos datos se incorporan de
forma insegura a una consulta, la base de datos puede interpretarlos
como parte de las instrucciones SQL, en vez de tratarlos como datos.

La debilidad está en la construcción de la consulta, no en que SQL sea
un lenguaje inseguro por sí mismo.

### 2. Breve historia

- **Décadas de 1970–1980:** se consolidan las bases de datos
  relacionales y SQL; se establece la tecnología que posteriormente
  utilizarán las aplicaciones web.
- **Década de 1990:** crecen los sitios web dinámicos conectados a
  bases de datos. Las aplicaciones empiezan a formar consultas a partir
  de datos recibidos de clientes, creando la condición para que una
  entrada pueda alterar la consulta.
- **Finales de 1990:** publicaciones técnicas documentan problemas de
  seguridad en tecnologías web emergentes. Por ejemplo, Phrack 54
  publicó en diciembre de 1998 un análisis de vulnerabilidades en
  tecnologías web de NT. Esto sirve como contexto histórico, no como
  afirmación de que ese artículo fuera el primer registro de SQLi.
- **Décadas de 2000–2010:** la inyección SQL se reconoce ampliamente
  como una clase de vulnerabilidad de aplicaciones. OWASP la incluye
  de forma recurrente entre los riesgos de seguridad de aplicaciones.
- **Actualidad:** las consultas parametrizadas, ORMs y herramientas
  modernas reducen el riesgo, pero SQLi persiste cuando se concatena
  entrada, se usa SQL dinámico inseguro o se omiten controles.

No existe una fecha única aceptada como “origen” de SQLi. Su historia
está ligada a la expansión de aplicaciones web que construyen consultas
dinámicas.

### 3. ¿Qué es SQL injection?

Según CWE-89, ocurre cuando un producto construye todo o parte de una
sentencia SQL con datos influenciados externamente y no separa
correctamente esos datos de la sintaxis SQL.

En términos sencillos:

1. La aplicación recibe un dato que no debe confiarse.
2. Lo concatena o interpola en el texto de una consulta.
3. La base de datos recibe una consulta cuya estructura puede diferir de
   la intención original.

La defensa fundamental es conservar la separación entre **código SQL**
y **valores de datos**.

### 4. Características y condiciones que la favorecen

- Entrada controlada por el usuario llega a una operación de base de
  datos.
- La consulta se construye con concatenación, interpolación o formato
  de cadenas.
- Se usa SQL dinámico sin parametrizar.
- La aplicación revela detalles internos, como consultas o mensajes
  crudos de error.
- La cuenta de base de datos dispone de más privilegios de los
  necesarios.
- La validación se usa como sustituto de la parametrización. Validar
  formato puede ser útil, pero no reemplaza consultas parametrizadas.

Los puntos de entrada no se limitan a campos de texto: también pueden
incluir filtros, identificadores, búsquedas, ordenamientos y datos
persistidos que se reutilizan posteriormente.

### 5. Familias comunes de inyección SQL

Estas categorías describen cómo se observa o procesa una inyección; no
son pasos de explotación:

- **In-band:** la respuesta de la aplicación entrega resultados o
  errores en el mismo canal. Incluye variantes basadas en errores y en
  la composición de resultados.
- **Blind o inferencial:** no se muestran directamente los datos; se
  deducen diferencias a partir de respuestas o tiempos. Puede ser
  booleana o basada en tiempo.
- **Stacked queries:** una configuración del controlador puede permitir
  más de una sentencia en una operación. No todos los drivers permiten
  este comportamiento.
- **Segundo orden:** un dato inicialmente almacenado se reutiliza más
  adelante en una consulta construida de forma insegura. Que el alta
  inicial sea parametrizada no garantiza que todos los usos posteriores
  sean seguros.

El impacto y las posibilidades concretas dependen del motor, el
controlador, la consulta, los permisos de la cuenta y la configuración
del sistema.

### 6. Impactos potenciales

Una SQLi puede afectar distintos objetivos de seguridad:

- **Confidencialidad:** lectura o divulgación no autorizada de datos.
- **Integridad:** cambios o eliminación de registros.
- **Autenticación y autorización:** acceso o acciones que la aplicación
  no debería permitir.
- **Disponibilidad:** degradación o interrupción del servicio.
- **Cumplimiento y confianza:** exposición de datos personales,
  incidentes, costos de respuesta y daño reputacional.

No toda SQLi ofrece todos estos impactos; el alcance depende de los
controles y privilegios disponibles.

### 7. Prevención y defensa en profundidad

1. **Usar consultas parametrizadas** o sentencias preparadas para todos
   los valores de entrada.
2. Para partes que no admiten parámetros —por ejemplo, nombres de
   columna u orden— usar una lista permitida fija y validada; no insertar
   texto arbitrario.
3. Revisar también consultas dinámicas dentro de procedimientos
   almacenados y llamadas de bajo nivel a través de un ORM.
4. Aplicar mínimo privilegio a las cuentas de base de datos y separar
   credenciales por ambiente.
5. Mostrar errores genéricos a usuarios; guardar detalles técnicos en
   registros protegidos.
6. Mantener pruebas de seguridad y revisión de código para rastrear
   entradas hasta su uso en consultas.
7. Proteger secretos fuera del repositorio y evitar que las credenciales
   de desarrollo sean reutilizadas en otros ambientes.

Escapar caracteres o bloquear palabras clave no es una defensa general:
es frágil y depende del contexto y del motor.

### 8. Antes del ejercicio en vivo

Explica al grupo las reglas de alcance:

- La práctica se limita a la aplicación local y a la base de datos de
  laboratorio creadas para la clase.
- No se deben probar técnicas en sitios, redes o bases de datos ajenas.
- Los datos de prueba son ficticios; no se deben introducir datos
  personales o credenciales reales.
- El objetivo es observar cómo una consulta insegura afecta el
  comportamiento y después relacionarlo con su corrección.
- Al final, revisar las medidas defensivas y restaurar el entorno de
  prueba si fue modificado.

### 9. Preguntas para abrir la discusión

- ¿Qué diferencia hay entre validar un dato y parametrizarlo?
- ¿Un ORM garantiza por sí solo que toda consulta sea segura?
- ¿Por qué una cuenta de base de datos con privilegios mínimos reduce
  el impacto?
- ¿Qué debería registrar la aplicación y qué no debería mostrar al
  usuario?
- ¿Cómo puede volver a ser peligroso un valor que se guardó de forma
  segura?

## Fuentes y lecturas

- [OWASP: SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [MITRE CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP: SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Top 10:2021 — A03 Injection](https://owasp.org/Top10/2021/A03_2021-Injection/)
- [Phrack 54, artículo 8: NT Web Technology Vulnerabilities (1998)](https://phrack.org/issues/54/nt-web-technology-vulnerabilities)
