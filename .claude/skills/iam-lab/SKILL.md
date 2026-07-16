---
name: iam-lab
description: Opera el simulador de IAM de BancoXYZ - consultar permisos, evaluar peticiones sueltas, correr los escenarios, mutar la cuenta y restaurarla. Usar cuando se pida trabajar con el motor, la cuenta, las policies, los usuarios o los escenarios del proyecto IAM.
---

# Lab IAM

Consola de operacion del simulador de AWS IAM. El proyecto vive en `C:\Users\Ezela\Desktop\IAM`
y esta version asume el cwd ahi: los comandos son `python main.py <comando>`.

> Copia gemela en `C:\Users\Ezela\.claude\skills\iam-lab\SKILL.md` (skill personal, invocable
> desde cualquier carpeta; usa la ruta absoluta a `main.py`). Si se edita una, sincronizar la
> otra. Esta es la que va al repo.

El motor de decision es `motor_iam.py`. Este skill no razona sobre permisos: los pregunta.
Cuando haya que saber si algo esta permitido, **correr el motor** y leer su traza. Nunca deducir
el resultado de cabeza ni afirmarlo sin haberlo corrido.

## Al entrar

1. Correr `main.py admin estado` y leer la primera linea: dice `[ORIGINAL]` o `[MODIFICADA]`.
2. Mostrar el menu con ese estado en la cabecera.

Si la cuenta figura como MODIFICADA y no fue el usuario quien la muto en esta sesion, avisarlo
antes de cualquier otra cosa y ofrecer `main.py admin restaurar`.

El estado va en la cabecera: `ORIGINAL` o `MODIFICADA`, con el AccountId real que devolvio
`admin estado`.

```
╭──────────────────────────────────────────────────────────────────────────╮
│   \ | /                                                                  │
│  ── * ──   LAB IAM · cuenta 111111111111 (BancoXYZ)                      │
│   / | \    estado: ORIGINAL                                              │
├──────────────────────────────────────────────────────────────────────────┤
│  1) Consultar     permisos efectivos · evaluar una peticion              │
│  2) Escenarios    los 6 · uno solo · modo quiz                           │
│  3) Modificar     usuarios · policies · grupos · boundaries · recursos   │
│  4) Laboratorio   hipotesis, prediccion, mutacion, resultado             │
│  5) Auditoria     credenciales · anomalias de CloudTrail                 │
│  6) Cuenta        diff · restaurar · tests                               │
│                                                                          │
│  0) Salir                                                                │
╰──────────────────────────────────────────────────────────────────────────╯
```

**Copiar el cuadro literal, sin re-dibujarlo.** Todas las lineas miden 76 caracteres; el unico
campo que cambia es `estado:` (`ORIGINAL` o `MODIFICADA`), y hay que reemplazarlo respetando el
ancho para que el borde derecho no se corra. El asterisco va en ASCII (`*`) a proposito: los
glifos tipo `✳` se renderizan con ancho variable segun la fuente del terminal y descuadran el
marco.

Con la cuenta modificada, debajo del cuadro se recuerda `main.py admin restaurar`.

Aceptar tanto el numero como la intencion en lenguaje natural ("mostrame los permisos de jadmin"
entra directo por la 1, sin pasar por el menu).

## Navegacion

**Todo submenu termina con `0) Volver al menu anterior`.** En el menu raiz, `0` es `Salir`.
Despues de ejecutar una accion y presentar el resultado, volver a ofrecer el submenu en el que
estaba el usuario: nunca dejarlo sin salida.

**Los submenus van en cuadro, con el mismo marco y ancho que el menu raiz** (76 caracteres por
linea, marco incluido). Estan dibujados literales mas abajo: copiarlos, no redibujarlos.

**Separar el menu del resultado anterior**: entre la salida del comando y el cuadro va una regla
horizontal (`---`) y una linea en blanco. Un menu pegado al output se lee como parte del output.

## Que devuelve cada opcion

**El usuario NO ve la salida de las tool calls.** Solo ve el texto de la respuesta. Toda salida
de un comando hay que **pegarla en la respuesta**, en un bloque de codigo, textual y completa.
Correr el comando y no transcribir el resultado deja al usuario con la pantalla vacia.

**Datos, no prosa.** Una opcion del menu devuelve la salida del comando (JSON o el reporte del
script) y despues el submenu. Nada mas.

- **No** escribir parrafos interpretando el resultado.
- **No** señalar "lo interesante", ni sacar conclusiones, ni anticipar hallazgos.
- **No** agregar contexto didactico que no se pidio.

**La respuesta se presenta desarmada en secciones, no como un bloque unico.** El comando devuelve
un JSON entero; al mostrarlo, partirlo: cada seccion con su titulo en mayuscula y debajo su
bloque, en ese orden. Nunca pegar el JSON completo de un saque.

    USUARIO
    ```json
    { ... }
    ```

    GRUPOS
    ```json
    [ ... ]
    ```

    IDENTITY
    ```json
    [ ... ]
    ```

    BOUNDARY
    ```json
    []
    ```

    SCP
    ```json
    [ ... ]
    ```

Secciones y orden fijos: `USUARIO`, `GRUPOS`, `IDENTITY`, `BOUNDARY`, `SCP`, y `RESOURCE` cuando
el recurso tiene policy. Una seccion vacia se muestra igual, vacia: un `BOUNDARY` en `[]` es
informacion (ese usuario no tiene techo propio), no un hueco para omitir.

El contenido de cada bloque va **textual**, tal como lo devolvio el comando. No reescribirlo ni
resumirlo.

La explicacion se da **solo si el usuario la pide** ("explicame esto", "por que?"). Es una consola
de operacion: el que lee la salida es el operador, y sabe leerla.

Excepcion unica: la traza de una decision del motor se cita textual, porque es el dato, no una
interpretacion.

## Registro de los menus

Los submenus estan definidos abajo, literales: **mostrarlos tal cual estan escritos** (mas el
`0) Volver al menu anterior`). Es un menu de operacion, no material didactico. No agregarle
ejemplos en lenguaje coloquial, ni glosas sobre que es IAM, ni invitaciones del tipo "tirame la
pregunta y la traduzco". Cada linea se sostiene sola: nada de "lo mismo, pero...".

## 1) Consultar

```
╭──────────────────────────────────────────────────────────────────────────╮
│  1) CONSULTAR                                                            │
├──────────────────────────────────────────────────────────────────────────┤
│  1.1)  Volcado de un usuario: su JSON y el documento de cada policy      │
│  1.2)  Evaluar una peticion: USUARIO / ACCION / RECURSO                  │
│  1.3)  Evaluar forzando el contexto: sin MFA, otra IP, otro tag          │
│  1.4)  Evaluar en cross-account: el recurso vive en otra cuenta          │
│                                                                          │
│  0)   Volver al menu anterior                                            │
╰──────────────────────────────────────────────────────────────────────────╯
```

| Opcion | Comando |
|---|---|
| 1.1 | `main.py permisos <usuario> --json` |
| 1.2 | `main.py evaluar <usuario> <accion> <recurso>` |
| 1.3 | idem + `--mfa` / `--sin-mfa` / `--ip <ip>` / `--ctx clave=valor` |
| 1.4 | idem + `--cuenta-recurso 222222222222` |

**Pedir los campos siempre con el mismo formato en 1.2, 1.3 y 1.4**: una lista con las opciones
posibles de cada campo, un campo por linea. No cambiar de estilo entre una opcion y otra. El
bloque base (1.2) es:

```
usuario:   mlopez · cgomez · svc-reporting · jadmin · temp-consultor
accion:    s3:GetObject · s3:DeleteObject · s3:ListBucket · iam:CreateUser · ec2:StartInstances · ec2:TerminateInstances · cloudtrail:StopLogging
recurso:   arn:aws:s3:::banco-backups/nomina.xlsx · arn:aws:s3:::banco-backups · *
```

Cerrar siempre con la instruccion de pasarlo en una linea, con un ejemplo.

- **1.3 va en dos pasos**, porque el contexto que tiene sentido forzar depende del usuario:
  1. Preguntar primero **de que usuario** (los cinco).
  2. Correr `main.py evaluar <usuario> --forzables` para saber que claves miran sus condiciones,
     y recien entonces mostrar el bloque. La linea `forzar:` incluye `--mfa`/`--sin-mfa` y `--ip`
     siempre, mas el `--ctx` **concreto** que devolvio `--forzables` (con el valor que cumple).
     Si `--forzables` dice que el usuario no tiene condiciones, decirlo: forzar `--ctx` no va a
     cambiar la decision, y solo quedan `--mfa`/`--ip` para probar (que tampoco mira ninguna
     policy de esta cuenta).

  ```
  accion:    (las de arriba)
  recurso:   (los de arriba)
  forzar:    --mfa · --sin-mfa · --ip <ip> (redes: 200.45.10.0/24 · 10.10.0.0/16)
             --ctx aws:ResourceTag/Proyecto=Creditos   (=Creditos cumple para acciones de EC2; otro valor lo deniega)
  ```

  La aclaracion "para acciones de EC2" no es adorno: la condicion solo rige sobre las acciones de
  su statement. Copiar la linea `--ctx` **tal como la devuelve `--forzables`**, con el servicio
  incluido; sin eso, forzar el `--ctx` con una accion de otro servicio no cambia nada y desorienta.

- **1.4** agrega debajo del bloque base:
  ```
  cuenta del recurso:   --cuenta-recurso 222222222222
  ```

En **1.1**, si el usuario no aclara sobre quien, preguntar de cual (o `--json` sin nombre para los
cinco). La salida trae el bloque del usuario tal como esta en `cuenta_iam.json` y, debajo, el
documento completo de cada policy agrupado por capa (`identity`, `boundary`, `scp`) con su
`origen`. Sin `--json` el mismo comando da el reporte en texto. Despues de 1.1 se vuelve al
submenu de Consultar, como siempre.

### Despues de un resultado de 1.2, 1.3 o 1.4

**No** volver al submenu de Consultar. Mostrar este mini menu:

```
╭──────────────────────────────────────────────────────────────────────────╮
│  1)   Explicar este resultado                                            │
│                                                                          │
│  0)   Volver al menu anterior                                            │
╰──────────────────────────────────────────────────────────────────────────╯
```

- `0` -> volver al submenu de Consultar, sin decir nada mas.
- `1` -> explicar el resultado y **despues** volver al submenu de Consultar.

La explicacion (opcion 1) es la unica parte del skill donde se escribe prosa, y tiene su forma:

- Reconstruir **por que** el motor decidio lo que decidio, siguiendo el orden de decision de IAM
  (Deny explicito -> Allow explicito -> techos).
- Ir mostrando los **fragmentos** de JSON que lo explican, no los documentos enteros: el statement
  que matcheo (o el que se esperaba y no esta), la `Condition` que se cumplio o fallo, el
  `Principal` de la resource policy. Cada fragmento con su seccion nombrada (`USUARIO`,
  `IDENTITY`, `SCP`...), igual que en 1.1 pero recortado a lo que decide.
- Si el resultado depende de algo que **no** esta (deny implicito), decirlo y mostrar la policy
  donde el permiso deberia haber estado y no esta.
- Nombrar siempre la policy y el `Sid` concretos. Nada de explicaciones genericas sobre IAM.

**La explicacion termina en la conclusion.** El ultimo parrafo es el que cierra por que dio lo que
dio, y despues va el submenu. Nada de apendices:

- **No** agregar aclaraciones colaterales ("y ojo con esto otro", "esto induce a error").
- **No** plantear hipoteticos que no se pidieron ("si tuviera AdministratorAccess seria Allow").
- **No** conectar con otros escenarios ni con el catalogo.
- **No** comentar partes de la salida que no participaron en la decision.

`evaluar` imprime las capas que participaron (identity, boundary, scp, resource) y la traza de la
decision. **Al reportar el resultado, citar la traza**: la gracia no es el Allow/Deny, es que
policy y que Sid lo produjeron.

Las secciones de la salida de `evaluar` son `PETICION`, `CAPAS EVALUADAS` y `DECISION`.

En `DECISION`, **omitir la traza cuando es redundante**: si es un unico paso que no nombra ninguna
policy ni ningun Sid (el caso del deny implicito, `Sin ningun Allow que matchee -> deny
implicito`), ya lo dice el motivo y repetirlo es ruido. Mostrar solo el veredicto.

Cuando la traza **si** nombra policies o Sids, va entera y textual: ahi esta la atribucion, que es
lo unico que convierte un Allow/Deny en una explicacion. No resumirla nunca en ese caso.

No tocar el texto de la traza en `motor_iam.py`: esto es una regla de presentacion.

La linea `condicion :` de `PETICION` la calcula el propio comando y dice si alguna de las policies
evaluadas tiene `Condition`. Va incluida en el bloque, sin glosa: es el dato que determina si el
contexto pesa en esa peticion o es decorado. **No escribir una nota explicando que son las claves
`aws:*`** salvo que el usuario lo pregunte.

Los ARN completos: el bucket es `arn:aws:s3:::banco-backups`, un objeto es
`arn:aws:s3:::banco-backups/nomina.xlsx`. Para acciones sin recurso (`iam:CreateUser`,
`cloudtrail:StopLogging`) usar `"*"`.

## 2) Escenarios

```
╭──────────────────────────────────────────────────────────────────────────╮
│  2) ESCENARIOS                                                           │
├──────────────────────────────────────────────────────────────────────────┤
│  2.1)  Correr los 6 escenarios                                           │
│  2.2)  Correr uno solo (1-6)                                             │
│                                                                          │
│  0)   Volver al menu anterior                                            │
╰──────────────────────────────────────────────────────────────────────────╯
```

| Opcion | Comando |
|---|---|
| 2.1 | `main.py escenarios` |
| 2.2 | `main.py escenarios <N>` |

El modo quiz (`main.py escenarios -q`) **no esta en el menu**, por decision del usuario. El comando
sigue existiendo: es interactivo, necesita terminal real y no corre desde una tool call. Si lo
pide, decirle que lo corra el mismo prefijando con `!` en el prompt.

Los 6 escenarios, con su resultado: 1) deny implicito -> Deny. 2) Deny explicito de la SCP contra
un admin -> Deny. 3) la SCP permite pero no otorga -> Deny. 4) boundary como techo -> Deny.
5) cross-account sin resource policy -> Deny. 6) cross-account con bucket policy -> Allow.

## 3) Modificar

```
╭──────────────────────────────────────────────────────────────────────────╮
│  3) MODIFICAR                                                            │
├──────────────────────────────────────────────────────────────────────────┤
│  3.1)  Usuarios: crear, borrar, MFA, tags de principal                   │
│  3.2)  Policies: crear, borrar, adjuntar, quitar                         │
│  3.3)  Grupos: crear, altas y bajas de miembros                          │
│  3.4)  Permission boundary: asignar o quitar                             │
│  3.5)  Resource policies: asignar o quitar                               │
│                                                                          │
│  0)   Volver al menu anterior                                            │
╰──────────────────────────────────────────────────────────────────────────╯
```

**Nunca editar `datos/cuenta_iam.json` a mano ni con Edit/Write.** Toda mutacion pasa por
`main.py admin <subcomando>`, que valida antes de escribir. Ver `admin --help`.

```
admin crear-usuario NOMBRE [--grupo G] [--policy P] [--boundary B] [--mfa] [--tag k=v]
admin borrar-usuario NOMBRE
admin crear-policy NOMBRE --archivo doc.json | --json '{...}'
admin borrar-policy NOMBRE          (rechaza si esta en uso)
admin attach POLICY --usuario U | --grupo G
admin detach POLICY --usuario U | --grupo G
admin boundary USUARIO --policy P | --quitar
admin mfa USUARIO --on | --off
admin tag USUARIO CLAVE [VALOR]     (sin VALOR, lo quita)
admin crear-grupo NOMBRE [--policy P]
admin grupo USUARIO GRUPO [--quitar]
admin resource-policy ARN --archivo doc.json | --quitar
```

Protocolo de toda mutacion, sin saltear pasos:

1. **Decir que se va a cambiar y por que**, antes de tocar nada.
2. Aplicar el comando.
3. Mostrar el efecto: `main.py admin diff`.
4. **Re-correr lo que quedo afectado** y ofrecerlo explicitamente: si se toco a un usuario,
   `evaluar` sobre el; si se toco algo de los escenarios 1-3, el escenario que corresponda.
5. Recordar que la cuenta quedo MODIFICADA y que se restaura con `main.py admin restaurar`.

Si hay que escribir un policy document, guardarlo en el scratchpad (no en el repo) y pasarlo con
`--archivo`. Los documentos van con `Version`, `Statement`, y cada statement con `Effect`,
`Action` y `Resource`; las resource policies ademas necesitan `Principal`.

No editar `S3ReadOnlyBackups` para dar permisos nuevos: la comparten el grupo Creditos, el grupo
ServicioLectura y temp-consultor, asi que el cambio pega en tres lados. Crear una policy nueva.

## 4) Laboratorio

```
╭──────────────────────────────────────────────────────────────────────────╮
│  4) LABORATORIO                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│  4.1)  Identity policies: agregar o quitar permisos directos             │
│  4.2)  Techos: SCP y permission boundary                                 │
│  4.3)  Cross-account y resource policies                                 │
│  4.4)  ABAC: tags de principal y condiciones                             │
│                                                                          │
│  0)   Volver al menu anterior                                            │
╰──────────────────────────────────────────────────────────────────────────╯
```

El unico modo con una regla de conduccion propia: **el usuario predice primero.**

1. Plantear la hipotesis concreta dentro de la familia elegida.
2. **Pedir la prediccion: Allow o Deny, y por que. No adelantar nada hasta que arriesgue.**
3. Recien entonces mutar, correr y comparar contra lo que dijo.
4. Restaurar.

Mutaciones que **no** levantan el Deny valen tanto como las que si, y conviene proponerlas:

- Darle `AdministratorAccess` a jadmin no lo deja apagar CloudTrail: el Deny explicito de la SCP
  gana igual (escenario 2).
- Ninguna identity policy arregla el cross-account del escenario 5: falta la otra punta.
- Sacarle el boundary a svc-reporting **si** lo cambia: el techo era lo unico que lo frenaba.

`CreditosABAC` (en mlopez, con condiciones sobre `aws:PrincipalTag/...`) no tiene escenario
propio. Es buen material de laboratorio: cambiarle un tag con `admin tag` y volver a evaluar
muestra ABAC en vivo.

## 5) Auditoria

`main.py auditoria`. Reporta higiene de credenciales (MFA ausente, access keys viejas, usuarios
inactivos) y anomalias de CloudTrail. Es analisis del estado, no del motor.

## 6) Cuenta

```
╭──────────────────────────────────────────────────────────────────────────╮
│  6) CUENTA                                                               │
├──────────────────────────────────────────────────────────────────────────┤
│  6.1)  Diff contra la version commiteada                                 │
│  6.2)  Restaurar la cuenta original                                      │
│  6.3)  Estado completo de la cuenta                                      │
│  6.4)  Correr la suite de tests                                          │
│                                                                          │
│  0)   Volver al menu anterior                                            │
╰──────────────────────────────────────────────────────────────────────────╯
```

| Opcion | Comando |
|---|---|
| 6.1 | `main.py admin diff` |
| 6.2 | `main.py admin restaurar` |
| 6.3 | `main.py admin estado` |
| 6.4 | `main.py test` |

**Restaurar es siempre `admin restaurar` (git checkout por debajo), nunca `main.py datos`.**
Regenerar recalcula las fechas contra el dia de hoy: devuelve una cuenta equivalente pero
distinta, y ensucia el diff.

Antes de commitear una mutacion deliberada, correr `main.py test`: los escenarios son tambien la
suite de regresion del motor.

## Trampas

- **`!! BUG EN EL MOTOR`** solo aparece con la cuenta ORIGINAL, y ahi si es un bug real. Con la
  cuenta modificada, el catalogo avisa que el resultado difiere *por la mutacion* y no acusa al
  motor. Si aparece el cartel de bug con la cuenta original: parar todo, es una regresion.
- El `esperado` de cada escenario describe la **cuenta commiteada**. Mutarla y ver un escenario
  "fallar" es el resultado buscado, no un error.
- Los escenarios 4, 5 y 6 arman sus policies **sinteticamente**, no desde los usuarios del JSON:
  mutar la cuenta no los afecta (salvo la bucket policy, que el 6 si lee del JSON). Para verlos
  cambiar hay que usar `evaluar`, no el catalogo.
