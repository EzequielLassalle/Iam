"""
escenarios.py
=============
Casos donde la evaluacion de IAM no coincide con la intuicion: un administrador que no
puede actuar, una SCP que permite y aun asi deniega, un permiso vigente en la policy pero
inoperante en la practica.

Son seis escenarios sobre cinco conceptos: el cross-account ocupa dos, porque la regla de
"las dos puntas" solo se ve con el contraste entre el caso que falla y el que funciona.
Entre todos cubren el nucleo del motor: el orden de decision y las capas.

Cada escenario declara su resultado esperado, asi que el catalogo funciona ademas como
suite de regresion del motor.

    python escenarios.py          -> todos, con su traza y explicacion
    python escenarios.py --quiz   -> pide predecir el resultado antes de mostrarlo
    python escenarios.py 3        -> solo el escenario 3
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from contexto import (cargar_cuenta, peticion, policies_de_recurso,
                      policies_de_usuario)
from motor_iam import evaluar

CUENTA = cargar_cuenta()
ACCOUNT = CUENTA["AccountId"]          # 111111111111
ACCOUNT_AUDIT = "222222222222"         # la cuenta de auditoria, para el cross-account
POL = CUENTA["ManagedPolicies"]

OBJETO_NOMINA = "arn:aws:s3:::banco-backups/nomina.xlsx"


@dataclass
class Escenario:
    """
    Un caso de IAM listo para evaluar.

    'esperado' es el resultado correcto segun las reglas de AWS y opera como assert.
    'concepto' es la atribucion: por que la evaluacion termina como termina.
    """
    titulo: str
    pregunta: str        # la situacion planteada
    esperado: str        # "Allow" o "Deny"
    concepto: str        # por que da eso
    peticion: dict
    policies: dict


# ---------------------------------------------------------------------------
# Los escenarios
# ---------------------------------------------------------------------------

def _construir():
    """
    Construye el catalogo.

    En una funcion y no a nivel de modulo para que las llamadas a policies_de_usuario() y
    peticion() ocurran en orden, con CUENTA ya cargada.
    """
    esc = []

    # --- 1. Deny implicito: el punto de partida de IAM ----------------------
    esc.append(Escenario(
        titulo="Deny implicito: lo que no se permite, se niega",
        pregunta=(
            "cgomez tiene la policy S3ReadOnlyBackups, que permite s3:GetObject y\n"
            "  s3:ListBucket sobre el bucket de backups. Intenta s3:DeleteObject sobre ese\n"
            "  mismo bucket. Ninguna policy menciona esa accion: ni la permite ni la niega.\n"
            "  Puede borrar?"
        ),
        esperado="Deny",
        concepto=(
            "Deny implicito. En IAM todo esta denegado por defecto: hace falta un Allow\n"
            "  EXPLICITO para que una accion pase. La ausencia de una regla no es permiso.\n"
            "  Es el punto de partida de todo el modelo, y de aca sale el principio de menor\n"
            "  privilegio: uno no saca permisos, uno los agrega de a uno.\n"
            "  Diferencia con el Deny explicito (escenario 2): el implicito se levanta con\n"
            "  agregar un Allow en cualquier policy. El explicito no se levanta con nada."
        ),
        peticion=peticion(CUENTA, "cgomez", "s3:DeleteObject", OBJETO_NOMINA),
        policies=policies_de_usuario(CUENTA, "cgomez"),
    ))

    # --- 2. Deny explicito: le gana a todo ----------------------------------
    esc.append(Escenario(
        titulo="El Deny explicito le gana hasta al AdministratorAccess",
        pregunta=(
            "jadmin tiene AdministratorAccess: Allow '*' sobre '*', o sea permiso para TODO.\n"
            "  Intenta apagar el registro de auditoria (cloudtrail:StopLogging).\n"
            "  La SCP de la organizacion tiene un Deny explicito sobre esa accion.\n"
            "  Puede?"
        ),
        esperado="Deny",
        concepto=(
            "No. El Deny explicito SIEMPRE gana, en cualquier capa, sin apelacion. No importa\n"
            "  que la identity policy diga Allow '*'.\n"
            "  Este es el orden de decision de IAM, y es lo primero que hay que saber:\n"
            "      1. Hay un Deny explicito en alguna capa?  -> Deny. Se termina aca.\n"
            "      2. Hay un Allow explicito?                -> si no hay, deny implicito.\n"
            "      3. Los techos (SCP, boundary) lo permiten? -> si no, Deny.\n"
            "  Y es para lo que existen las SCP: fijar un limite que ni el administrador de la\n"
            "  cuenta puede levantar, porque la SCP no vive en su cuenta sino en la cuenta de\n"
            "  management de la organizacion."
        ),
        peticion=peticion(CUENTA, "jadmin", "cloudtrail:StopLogging", "*"),
        policies=policies_de_usuario(CUENTA, "jadmin"),
    ))

    # --- 3. La SCP no otorga permisos ---------------------------------------
    esc.append(Escenario(
        titulo="La SCP permite, pero el usuario igual no puede",
        pregunta=(
            "La SCP GuardrailBase tiene Allow '*' sobre '*' (lo unico que niega es tocar\n"
            "  CloudTrail). cgomez solo tiene S3ReadOnlyBackups. Intenta apagar un servidor\n"
            "  (ec2:TerminateInstances). La SCP se lo permite. Puede?"
        ),
        esperado="Deny",
        concepto=(
            "No. Las SCP nunca OTORGAN permisos: solo definen el techo de lo que la cuenta\n"
            "  PODRIA llegar a permitir. El permiso efectivo es la INTERSECCION entre lo que\n"
            "  permite la SCP y lo que permite la identity policy del usuario.\n"
            "  Aca la SCP dice que si, pero la identity policy de cgomez no menciona EC2, asi\n"
            "  que la accion cae por deny implicito (escenario 1).\n"
            "  Es la confusion mas comun con las SCP: creer que dan permisos. No dan: recortan."
        ),
        peticion=peticion(CUENTA, "cgomez", "ec2:TerminateInstances",
                          f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0abc"),
        policies=policies_de_usuario(CUENTA, "cgomez"),
    ))

    # --- 4. Permission boundary: el mismo techo, sobre una persona ----------
    esc.append(Escenario(
        titulo="Permission Boundary: administrador en los papeles, limitado en la practica",
        pregunta=(
            "Un usuario tiene AdministratorAccess (Allow '*' sobre '*'), pero ademas tiene un\n"
            "  permission boundary que solo permite s3:*, ec2:Describe*, iam:Get* e iam:List*.\n"
            "  Intenta crear un usuario nuevo (iam:CreateUser). El boundary no menciona esa\n"
            "  accion: ni la permite ni la niega. Puede?"
        ),
        esperado="Deny",
        concepto=(
            "No. El boundary es un TECHO sobre una identidad, igual que la SCP lo es sobre una\n"
            "  cuenta: el permiso efectivo es la interseccion entre la identity policy y el\n"
            "  boundary. iam:CreateUser esta en la identity, pero NO esta dentro del boundary,\n"
            "  asi que cae por deny implicito DEL BOUNDARY.\n"
            "  No es un Deny generico sino un filtro: si este mismo usuario intentara\n"
            "  s3:PutObject, pasaria, porque esa accion si cae en la interseccion (la identity\n"
            "  la permite con '*' y el boundary con 's3:*').\n"
            "  Para que sirve en la practica: dejar que alguien cree roles, pero sin que pueda\n"
            "  crear uno con mas permisos de los que el mismo tiene. Es la defensa contra la\n"
            "  escalada de privilegios."
        ),
        peticion={
            "principal": f"arn:aws:iam::{ACCOUNT}:user/dev-con-boundary",
            "principal_account": ACCOUNT,
            "action": "iam:CreateUser",
            "resource": "*",
            "context": {},
        },
        policies={
            "identity": [("AdministratorAccess", POL["AdministratorAccess"])],
            "boundary": [("BoundaryS3ReadOnly", POL["BoundaryS3ReadOnly"])],
        },
    ))

    # --- 5. Cross-account: hacen falta las dos puntas ------------------------
    # El auditor vive en la cuenta 222. El bucket vive en la 111. Corremos el mismo caso
    # dos veces: primero sin bucket policy y despues con ella, para ver el contraste.
    peticion_auditor = {
        "principal": f"arn:aws:iam::{ACCOUNT_AUDIT}:user/auditor",
        "principal_account": ACCOUNT_AUDIT,
        "action": "s3:GetObject",
        "resource": OBJETO_NOMINA,
        "resource_account": ACCOUNT,      # el recurso es de OTRA cuenta
        "context": {},
    }
    identity_auditor = [("S3ReadOnlyBackups", POL["S3ReadOnlyBackups"])]

    esc.append(Escenario(
        titulo="Cross-account: la identity policy sola no alcanza",
        pregunta=(
            f"Un auditor de la cuenta {ACCOUNT_AUDIT} tiene una identity policy que le permite\n"
            f"  s3:GetObject sobre el bucket banco-backups. Pero ese bucket vive en la cuenta\n"
            f"  {ACCOUNT}, que es otra empresa/cuenta. El bucket no tiene bucket policy.\n"
            "  Su propia cuenta se lo permite. Puede leer?"
        ),
        esperado="Deny",
        concepto=(
            "No. En cross-account hacen falta LAS DOS PUNTAS:\n"
            "      - la cuenta del que llama le tiene que permitir la accion (identity policy), Y\n"
            "      - la cuenta duena del recurso se la tiene que permitir a el (resource policy).\n"
            "  El motivo es evidente cuando se lo piensa al reves: si alcanzara con la identity\n"
            "  policy, cualquiera podria escribirse una policy que diga 'puedo leer el bucket de\n"
            "  ese otro banco' y entrar. Una cuenta no puede auto-otorgarse acceso a los recursos\n"
            "  de otra.\n"
            "  Comparar con same-account, que es distinto: ahi alcanza con UNA de las dos, porque\n"
            "  las dos policies las escribe el mismo dueno.\n"
            "  El escenario que sigue es el mismo caso, pero con la bucket policy puesta."
        ),
        peticion=peticion_auditor,
        policies={"identity": identity_auditor},
    ))

    esc.append(Escenario(
        titulo="Cross-account: con la bucket policy, ahora si",
        pregunta=(
            "El mismo auditor, el mismo bucket. Pero ahora el bucket SI tiene una bucket policy\n"
            f"  con Principal arn:aws:iam::{ACCOUNT_AUDIT}:root y Allow sobre s3:GetObject.\n"
            "  Puede leer?"
        ),
        esperado="Allow",
        concepto=(
            "Si: ahora estan las dos puntas. La cuenta 222 le da el permiso a su usuario, y la\n"
            "  cuenta 111 le da el permiso a la cuenta 222 sobre su bucket.\n"
            "  Atencion al ':root' del Principal, que es lo que mas se confunde: NO significa 'el\n"
            "  usuario root'. Significa 'confio en la cuenta 222 y DELEGO en ella la decision de\n"
            "  cuales de sus principales pueden entrar'. O sea: entra cualquiera de la cuenta 222\n"
            "  a quien SU PROPIA cuenta le haya dado el permiso.\n"
            "  Consecuencia practica: un ':root' no otorga nada por si solo. Si el auditor no\n"
            "  tuviera su identity policy, esto seguiria siendo Deny."
        ),
        peticion=peticion_auditor,
        policies={
            "identity": identity_auditor,
            "resource": policies_de_recurso(CUENTA, OBJETO_NOMINA),
        },
    ))

    return esc


ESCENARIOS = _construir()


# ---------------------------------------------------------------------------
# Ejecucion
# ---------------------------------------------------------------------------

def correr(e: Escenario, numero: int, quiz: bool) -> bool:
    """
    Plantea un escenario, lo evalua y atribuye el resultado.

    Devuelve True si el motor coincidio con lo esperado. Un False indica un bug en el
    motor, no una prediccion fallida en modo quiz.
    """
    print("\n" + "=" * 74)
    print(f"ESCENARIO {numero}: {e.titulo}")
    print("=" * 74)
    print(f"\n  {e.pregunta}\n")

    if quiz:
        try:
            resp = input("  Prediccion [a=Allow / d=Deny]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n  (cortado)")
            return True
        tuya = "Allow" if resp.startswith("a") else "Deny"
        acertaste = tuya == e.esperado
        print(f"\n  Prediccion: {tuya}   |   Correcto: {e.esperado}   "
              f"{'-> OK' if acertaste else '-> incorrecto'}")

    resultado = evaluar(e.peticion, e.policies)

    print(f"\n  Que hizo el motor ({e.peticion['action']}):")
    print(resultado.explicar())

    print(f"\n  POR QUE:\n  {e.concepto}")

    ok = resultado.decision == e.esperado
    if not ok:
        print(f"\n  !! BUG EN EL MOTOR: esperabamos {e.esperado} y dio {resultado.decision}")
    return ok


if __name__ == "__main__":
    args = sys.argv[1:]
    quiz = "--quiz" in args or "-q" in args
    solo = next((int(a) for a in args if a.isdigit()), None)

    if solo is not None and not 1 <= solo <= len(ESCENARIOS):
        print(f"No existe el escenario {solo}. Hay {len(ESCENARIOS)}: 1 a {len(ESCENARIOS)}.")
        sys.exit(1)

    seleccion = [ESCENARIOS[solo - 1]] if solo else ESCENARIOS
    inicio = solo or 1

    if quiz:
        print("MODO QUIZ: predecir Allow o Deny antes de ver el resultado.")

    fallos = 0
    for i, e in enumerate(seleccion, start=inicio):
        fallos += not correr(e, i, quiz)

    print("\n" + "=" * 74)
    print(f"{len(seleccion)} escenario(s) corridos. "
          + ("El motor se comporto como AWS en todos." if not fallos
             else f"{fallos} discrepancia(s) con lo esperado."))
