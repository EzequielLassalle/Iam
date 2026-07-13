# Simulador de AWS IAM

Reimplementación en Python del motor de autorización de AWS IAM, sobre una cuenta
simulada, para razonar sobre permisos y auditarlos sin depender de una cuenta real.

Sin dependencias externas: solo la librería estándar.

```
python main.py            # comandos disponibles
python main.py test       # la suite de tests (26)
python main.py escenarios # los casos de IAM, con la traza de decisión
python main.py auditoria  # el reporte de auditoría de la cuenta
```

## Las dos mitades

**Autorización.** `motor_iam.py` responde una sola pregunta: *¿este principal puede hacer
esta acción sobre este recurso?* Reproduce el orden de decisión de AWS:

1. ¿Hay un **Deny explícito** en alguna capa? → Deny. Se termina acá, no hay apelación.
2. ¿Hay un **Allow explícito**? → si no hay, **deny implícito**.
3. ¿Los **techos** (SCP, permission boundary) lo permiten también? → si no, Deny.

Los techos nunca otorgan: solo recortan. El permiso efectivo es la **intersección**.

**Auditoría.** `auditoria.py` responde las preguntas de una revisión de rutina: qué
credenciales están en mal estado (MFA ausente, access keys viejas o abandonadas, usuarios
inactivos, privilegios de más) y qué actividad no debería haber ocurrido (uso del root,
ráfagas de accesos denegados, actividad desde fuera de la red, intentos de apagar el
registro de auditoría).

## Los escenarios

Seis casos donde la evaluación **no coincide con la intuición**. Cada uno declara su
resultado esperado, así que funcionan además como suite de regresión del motor.

| # | Caso | Concepto |
|---|---|---|
| 1 | Un usuario con permiso de lectura intenta borrar | **Deny implícito**: lo que no se permite, se niega |
| 2 | Un administrador con permiso para todo no puede apagar CloudTrail | **Deny explícito**: le gana a todo |
| 3 | La SCP permite y el usuario igual no puede | Las SCP **no otorgan**: recortan |
| 4 | Administrador limitado por un permission boundary | El mismo techo, sobre una identidad |
| 5 | Cross-account sin bucket policy | Hacen falta **las dos puntas** |
| 6 | Cross-account con bucket policy | Y `:root` **delega, no otorga** |

```
python main.py escenarios -q
```

Pide predecir `Allow` o `Deny` antes de mostrar el resultado, la traza de decisión y la
explicación.

## Los módulos

| Archivo | Contenido |
|---|---|
| `motor_iam.py` | El motor de evaluación. La pieza central. |
| `contexto.py` | Qué policies le aplican a cada usuario: directas, heredadas de grupos, boundary y SCP. |
| `escenarios.py` | Los 6 casos. |
| `auditoria.py` | Higiene de credenciales y actividad sospechosa. |
| `tests.py` | 26 tests. Runner propio, sin pytest. |
| `datos/generar_datos.py` | Genera la cuenta y el historial. Reproducible (seed fijo). |

## Los tests de regresión

Cuatro tests cubren bugs reales que el motor tuvo. Tres eran de la única clase que un
motor de autorización no puede permitirse: **otorgar de más**.

- **Fail-open.** Un `Deny` con una condición que el motor no sabía evaluar **se evaporaba**
  y la petición pasaba. Ante lo que no entiende, un motor tiene que cerrar, no abrir. El
  primer arreglo quedó a medias: solo cubría el caso en que la clave de condición viajaba
  en la petición, y el test lo tapaba porque probaba justo ese caso. Con la clave ausente
  —el caso realista— el `Deny` seguía evaporándose.
- **Comodines.** El matching usaba `fnmatch`, que interpreta `[...]` como clase de
  caracteres. IAM solo tiene `*` y `?`, y las claves de S3 admiten corchetes: un patrón
  `bucket/[dev]-*` matcheaba `bucket/d-x`.
- **Delegación.** Un `Principal: ":root"` en una bucket policy se trataba como un Allow
  común, cuando en realidad **delega** en esa cuenta y no otorga por sí solo.
- **Orden.** El motor se quedaba con el primer statement que matcheaba, así que la decisión
  dependía del orden en que estuvieran escritos. En IAM no hay precedencia entre statements.

## La cuenta simulada

Cinco usuarios, cada uno con un hallazgo asociado: `jadmin` es administrador sin MFA,
`svc-reporting` es una cuenta de servicio con una access key de 430 días y otra jamás
usada, `temp-consultor` es un contratista inactivo hace seis meses que conserva sus
permisos — y desde cuya identidad salieron seis intentos de leer la nómina desde una IP
fuera de las redes declaradas.

Los datos viven en `datos/` con el esquema que devuelve la API real (ARNs, policy
documents, eventos de CloudTrail), de modo que apuntar el proyecto a una cuenta real
implica cambiar solo la capa de carga.
