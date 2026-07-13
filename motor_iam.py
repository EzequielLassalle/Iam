"""
motor_iam.py
============
Motor de evaluacion de policies de AWS IAM.

Reimplementa el orden de decision que AWS aplica en cada llamada a su API:

    1. Deny explicito en cualquier capa aplicable -> denegado, sin apelacion.
    2. Se requiere un Allow explicito             -> si no hay, deny implicito.
    3. Las capas-techo (SCP, permission boundary) deben permitirlo tambien.

SCP y permission boundaries no otorgan permisos: acotan. El permiso efectivo es la
interseccion entre la identity-based policy y esos techos.

Cross-account exige ambas puntas: identity policy en la cuenta del llamante y resource
policy en la cuenta duena del recurso. Same-account, alcanza con una.

Solo libreria estandar.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone


# En Windows la consola a veces usa cp1252 y rompe con tildes. Forzamos UTF-8.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def _como_lista(x):
    """
    Normaliza un campo de policy a lista.

    El JSON de IAM admite string suelto o lista en casi todos los campos ("Action":
    "s3:GetObject" y "Action": [...] son ambos validos).
    """
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


# ---------------------------------------------------------------------------
# Variables de policy:  ${aws:PrincipalTag/Proyecto}, ${aws:username}, ...
# ---------------------------------------------------------------------------

_PATRON_VAR = re.compile(r"\$\{([^}]+)\}")


def interpolar(texto, contexto: dict):
    """
    Resuelve las variables ${...} de una policy contra el contexto de la peticion.
    Es el mecanismo sobre el que se apoya ABAC.

    Una variable sin valor se deja literal a proposito: el statement no matchea con nada
    y el efecto neto es "no aplica", igual que en AWS.
    """
    if not isinstance(texto, str):
        return texto

    def reemplazo(m):
        """Resuelve una ocurrencia ${clave}."""
        valor = contexto.get(m.group(1))
        return str(valor) if valor is not None else m.group(0)

    return _PATRON_VAR.sub(reemplazo, texto)


# ---------------------------------------------------------------------------
# Coincidencia de acciones, recursos y principals (con comodines * y ?)
# ---------------------------------------------------------------------------

def _matchea(patron: str, texto: str) -> bool:
    """
    Compara un texto contra un patron de IAM.

    IAM define exactamente dos comodines: '*' (cualquier secuencia) y '?' (un caracter).
    No usamos fnmatch directo porque ademas interpreta los corchetes como clase de
    caracteres, y eso no es IAM: un patron 'bucket/[dev]-*' matchearia 'bucket/d-x', que
    en AWS no matchea. Como las claves de S3 admiten corchetes, seria un falso Allow.
    Por eso escapamos todo y despues reponemos los dos comodines que si existen.
    """
    regex = re.escape(patron).replace(r"\*", ".*").replace(r"\?", ".")
    return re.fullmatch(regex, texto, flags=re.DOTALL) is not None


def accion_coincide(patron: str, accion: str) -> bool:
    """
    True si una accion concreta cae dentro de un patron ('s3:GetObject' vs 's3:*').

    Las acciones de IAM son case-insensitive: se normalizan ambos lados.
    """
    return _matchea(patron.lower(), accion.lower())


def recurso_coincide(patrones, recurso: str, contexto: dict = None) -> bool:
    """
    True si un ARN cae dentro del campo Resource de un statement.

    A diferencia de las acciones, los recursos son case-sensitive.

    Los patrones se interpolan antes de comparar: un Resource tambien admite variables
    (ej: "arn:aws:s3:::bucket/${aws:username}/*").
    """
    contexto = contexto or {}
    return any(
        _matchea(interpolar(p, contexto), recurso)
        for p in _como_lista(patrones)
    )


def principal_coincide(bloque_principal, peticion: dict):
    """
    Dice si el llamante cae dentro del Principal de un statement, y COMO cae.

    Solo aplica a resource-based y trust policies; una identity-based policy no lleva
    Principal.

    Devuelve None si no matchea, y si matchea devuelve de que forma, porque no son
    equivalentes:

        "directo"   -> el statement nombra al principal (user/mlopez, role/X, "*", un
                       Service). Ese Allow otorga por si solo.
        "delegado"  -> el statement nombra a la CUENTA (arn:aws:iam::111:root). NO otorga:
                       delega en esa cuenta la decision de que principales suyos entran,
                       asi que ademas hace falta que la identity policy del principal lo
                       permita. Es el punto que mas se confunde de ':root'.

    Ambos valores son truthy, asi que los llamadores que solo preguntan "matchea?" siguen
    funcionando.
    """
    if bloque_principal in ("*", ["*"]):
        return "directo"
    if not isinstance(bloque_principal, dict):
        return None

    # Principal de servicio (ej: EC2 asumiendo su instance profile).
    servicio = peticion.get("principal_service")
    if servicio and servicio in _como_lista(bloque_principal.get("Service")):
        return "directo"

    arn = peticion.get("principal", "")
    cuenta = peticion.get("principal_account", "")

    for patron in _como_lista(bloque_principal.get("AWS")):
        patron = str(patron)
        if patron == "*":
            return "directo"

        # La cuenta entera, en sus dos formas validas: el ARN :root o el id pelado.
        m = re.fullmatch(r"arn:aws:iam::(\d+):root|(\d{12})", patron)
        if m and (m.group(1) or m.group(2)) == cuenta:
            return "delegado"

        if _matchea(patron, arn):
            return "directo"

    return None


# ---------------------------------------------------------------------------
# Evaluacion de condiciones (bloque Condition)
# ---------------------------------------------------------------------------
# Comportamiento cuando la clave de condicion no viaja en la peticion. No es un fallo
# uniforme:
#   - operadores positivos (StringEquals, IpAddress...)   -> no matchea
#   - operadores negados  (StringNotEquals, NotIpAddress) -> matchea
#   - sufijo ...IfExists                                  -> matchea
#   - operador Null                                       -> evalua exactamente eso
# Implicancia: un "Deny si MFA es false" con el operador Bool no fuerza MFA, porque en las
# llamadas donde la clave no viaja el Deny no aplica. Para eso esta BoolIfExists.

# Los operadores que _comparar sabe evaluar. Cualquier cosa fuera de esta lista es un
# operador que el motor NO entiende, y eso hay que detectarlo ANTES de mirar si la clave
# viaja en la peticion: si no, un operador desconocido sobre una clave ausente se trata
# como "la condicion no se cumple", el Deny que lo contiene no aplica y la peticion pasa.
# Ese era un fail-open real del motor. Ver evaluar_condiciones.
_OPERADORES_CONOCIDOS = {
    "StringEquals", "StringNotEquals", "StringEqualsIgnoreCase",
    "StringNotEqualsIgnoreCase", "StringLike", "StringNotLike",
    "Bool",
    "IpAddress", "NotIpAddress",
    "NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericLessThanEquals",
    "NumericGreaterThan", "NumericGreaterThanEquals",
    "ArnEquals", "ArnLike", "ArnNotEquals", "ArnNotLike",
    "DateEquals", "DateNotEquals", "DateLessThan", "DateLessThanEquals",
    "DateGreaterThan", "DateGreaterThanEquals",
    "Null",
}

# Los negados son un subconjunto de los conocidos, y matchean cuando la clave esta ausente.
_OPERADORES_NEGADOS = {
    "StringNotEquals", "StringNotEqualsIgnoreCase", "StringNotLike",
    "NotIpAddress", "ArnNotEquals", "ArnNotLike", "NumericNotEquals", "DateNotEquals",
}

assert _OPERADORES_NEGADOS <= _OPERADORES_CONOCIDOS, (
    "hay operadores declarados como negados que _comparar no implementa: "
    f"{_OPERADORES_NEGADOS - _OPERADORES_CONOCIDOS}"
)


def _comparar(operador: str, actual, esperados: list) -> bool:
    """
    Aplica un operador de condicion a un valor.

    'actual' viene de la peticion, 'esperados' de la policy. Cuando la policy lista varios
    valores basta con que matchee uno (OR), salvo en los operadores negados, donde no debe
    matchear ninguno.

    Levanta ValueError si el operador no esta soportado o si el valor no se puede
    interpretar (una IP malformada, un numero que no es numero). El que llama decide que
    hacer con eso: ver evaluar_condiciones.
    """
    if operador == "StringEquals":
        return str(actual) in esperados
    if operador == "StringNotEquals":
        return str(actual) not in esperados
    if operador == "StringEqualsIgnoreCase":
        return str(actual).lower() in [e.lower() for e in esperados]
    if operador == "StringNotEqualsIgnoreCase":
        return str(actual).lower() not in [e.lower() for e in esperados]
    if operador == "StringLike":
        return any(_matchea(e, str(actual)) for e in esperados)
    if operador == "StringNotLike":
        return not any(_matchea(e, str(actual)) for e in esperados)

    if operador == "Bool":
        return any(str(actual).lower() == str(e).lower() for e in esperados)

    if operador in ("IpAddress", "NotIpAddress"):
        ip = ipaddress.ip_address(str(actual))
        dentro = any(ip in ipaddress.ip_network(e, strict=False) for e in esperados)
        return dentro if operador == "IpAddress" else not dentro

    if operador.startswith("Numeric"):
        a = float(actual)
        comparar = {
            "NumericEquals": lambda b: a == b,
            "NumericNotEquals": lambda b: a != b,
            "NumericLessThan": lambda b: a < b,
            "NumericLessThanEquals": lambda b: a <= b,
            "NumericGreaterThan": lambda b: a > b,
            "NumericGreaterThanEquals": lambda b: a >= b,
        }[operador]
        # OR sobre la lista, igual que el resto de los operadores.
        if operador == "NumericNotEquals":
            return all(comparar(float(e)) for e in esperados)
        return any(comparar(float(e)) for e in esperados)

    if operador.startswith("Arn"):
        coincide = any(_matchea(e, str(actual)) for e in esperados)
        return not coincide if operador in ("ArnNotEquals", "ArnNotLike") else coincide

    if operador.startswith("Date"):
        # Se parsean a datetime y no se comparan como strings: AWS acepta ISO-8601 y
        # tambien epoch, y "1783000000" > "2026-01-01T00:00:00Z" da False como string
        # cuando la fecha real es posterior.
        a = _a_fecha(actual)
        comparar = {
            "DateEquals": lambda b: a == b,
            "DateNotEquals": lambda b: a != b,
            "DateLessThan": lambda b: a < b,
            "DateLessThanEquals": lambda b: a <= b,
            "DateGreaterThan": lambda b: a > b,
            "DateGreaterThanEquals": lambda b: a >= b,
        }[operador]
        if operador == "DateNotEquals":
            return all(comparar(_a_fecha(e)) for e in esperados)
        return any(comparar(_a_fecha(e)) for e in esperados)

    raise ValueError(f"Operador de condicion no soportado: {operador}")


def _a_fecha(valor) -> datetime:
    """
    Convierte a datetime un valor de fecha de policy: ISO-8601 o epoch en segundos.

    Levanta ValueError si no es ninguno de los dos, para que el que llama trate la
    condicion como indeterminada en vez de inventar un resultado.
    """
    texto = str(valor).strip()
    if re.fullmatch(r"\d+(\.\d+)?", texto):
        return datetime.fromtimestamp(float(texto), tz=timezone.utc)
    try:
        fecha = datetime.fromisoformat(texto.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"Fecha no reconocida: {valor}")
    return fecha if fecha.tzinfo else fecha.replace(tzinfo=timezone.utc)


def evaluar_condiciones(condiciones: dict, contexto: dict, efecto: str = "Allow") -> bool:
    """
    Evalua el bloque Condition completo contra el contexto de la peticion.

    AND logico entre todas las claves de todos los operadores. Sin Condition, se cumple.

    'efecto' importa cuando la condicion no se puede resolver (un operador que no
    soportamos, un valor malformado). Ahi no se puede responder "se cumple" ni "no se
    cumple": la respuesta honesta es "no se". Y que hacer con un "no se" depende del
    efecto del statement:

        en un Allow -> el statement NO aplica. Ante la duda no otorgamos.
        en un Deny  -> el statement SI aplica. Ante la duda denegamos.

    Las dos ramas son fail-closed. Devolver siempre False seria fail-OPEN en los Deny: el
    Deny se evaporaria y la peticion pasaria, que es justo el error que un motor de
    autorizacion no puede cometer.

    contexto son las claves que AWS adjunta a cada peticion:
        {"aws:SourceIp": "200.45.10.5",
         "aws:MultiFactorAuthPresent": "true",
         "aws:PrincipalTag/Proyecto": "Creditos", ...}
    """
    if not condiciones:
        return True

    indeterminado = (efecto == "Deny")

    for operador, comparaciones in condiciones.items():
        opcional = operador.endswith("IfExists")
        base = operador[:-len("IfExists")] if opcional else operador

        # PRIMERO: el operador, esta dentro de lo que el motor sabe evaluar?
        # Este chequeo va antes que el de la clave ausente a proposito. Al reves, un
        # operador desconocido sobre una clave que no viaja caeria en la rama de "clave
        # ausente" y se resolveria como "no se cumple", con lo cual el Deny que lo
        # contiene no aplicaria y la peticion pasaria. Fail-open.
        if base not in _OPERADORES_CONOCIDOS:
            if not indeterminado:
                return False    # Allow: ante la duda, no otorgamos.
            continue            # Deny: ante la duda, denegamos.

        for clave, esperado in comparaciones.items():
            actual = contexto.get(clave)
            esperados = [interpolar(e, contexto) for e in _como_lista(esperado)]

            if base == "Null":
                # {"Null": {"aws:TokenIssueTime": "true"}} -> la clave no debe existir
                if not esperados:
                    if not indeterminado:
                        return False
                    continue
                debe_faltar = str(esperados[0]).lower() == "true"
                if (actual is None) != debe_faltar:
                    return False
                continue

            if actual is None:
                # Clave ausente: ver la tabla de arriba.
                if opcional or base in _OPERADORES_NEGADOS:
                    continue
                return False

            try:
                if not _comparar(base, actual, esperados):
                    return False
            except (ValueError, KeyError, TypeError, IndexError):
                # El operador existe pero el valor no se pudo interpretar (una IP
                # malformada, un numero que no es numero). Mismo criterio que arriba.
                if not indeterminado:
                    return False

    return True


# ---------------------------------------------------------------------------
# Evaluacion de un statement, de una policy y del conjunto completo
# ---------------------------------------------------------------------------

def _statement_matchea(stmt: dict, peticion: dict, es_resource_policy=False) -> bool:
    """
    True si un statement aplica a esta peticion: principal (solo en resource-based y trust
    policies), accion, recurso y condiciones.

    No mira el Effect: matchear no implica permitir. De eso se encarga _hay_match.
    """
    contexto = peticion.get("context", {})

    # --- Principal / NotPrincipal ---
    if es_resource_policy:
        if "NotPrincipal" in stmt:
            if principal_coincide(stmt["NotPrincipal"], peticion):
                return False
        elif not principal_coincide(stmt.get("Principal", {}), peticion):
            return False

    # --- Action / NotAction ---
    if "NotAction" in stmt:
        if any(accion_coincide(a, peticion["action"]) for a in _como_lista(stmt["NotAction"])):
            return False
    else:
        if not any(accion_coincide(a, peticion["action"])
                   for a in _como_lista(stmt.get("Action"))):
            return False

    # --- Resource / NotResource ---
    # El default cuando el statement no declara Resource NO es el mismo en las dos clases
    # de policy, y no es un capricho: en una resource policy el recurso esta implicito (es
    # aquel al que la policy esta pegada), mientras que en una identity policy el Resource
    # es obligatorio. Un statement de identity sin Resource es una policy invalida, y ante
    # una policy invalida no otorgamos nada.
    if "NotResource" in stmt:
        if recurso_coincide(stmt["NotResource"], peticion["resource"], contexto):
            return False
    elif "Resource" in stmt:
        if not recurso_coincide(stmt["Resource"], peticion["resource"], contexto):
            return False
    elif not es_resource_policy:
        return False

    # --- Condition ---
    # El Effect viaja hasta aca porque decide que hacer con una condicion que no se puede
    # resolver: en un Allow no se otorga, en un Deny se deniega. Las dos son fail-closed.
    return evaluar_condiciones(
        stmt.get("Condition"), contexto, stmt.get("Effect", "Allow")
    )


def _hay_match(policies, peticion, efecto, es_resource_policy=False):
    """
    Busca en una capa de policies un statement del efecto pedido que matchee.

    Devuelve (nombre_policy, Sid, modo) o None. 'modo' solo tiene valor en las resource
    policies, y dice si el Principal nombra al llamante ("directo") o nombra a su cuenta
    ("delegado"): un Allow delegado no otorga por si solo. Ver principal_coincide.

    En IAM no hay precedencia entre statements: el resultado no puede depender del orden en
    que estan escritos. Por eso, cuando hay varios matches en una resource policy, nos
    quedamos con el mas fuerte (un "directo" le gana a un "delegado") y no simplemente con
    el primero: si el mismo bucket tiene un statement que nombra al usuario y otro que
    nombra a su cuenta, el usuario entra, este donde este escrito cada uno.

    Los dos primeros campos permiten atribuir la decision a una policy concreta.
    """
    mejor = None

    for nombre, doc in policies or []:
        for stmt in _como_lista(doc.get("Statement")):
            if stmt.get("Effect") != efecto:
                continue
            if not _statement_matchea(stmt, peticion, es_resource_policy):
                continue

            if not es_resource_policy:
                return (nombre, stmt.get("Sid", "(sin Sid)"), None)

            modo = ("directo" if "NotPrincipal" in stmt
                    else principal_coincide(stmt.get("Principal", {}), peticion))
            hit = (nombre, stmt.get("Sid", "(sin Sid)"), modo)

            if modo == "directo":
                return hit          # el mas fuerte: no hay nada mejor que buscar
            mejor = mejor or hit    # guardamos el delegado por si no aparece un directo

    return mejor


@dataclass
class Resultado:
    """
    Decision del motor sobre una peticion, con la traza de como llego a ella.

    'traza' son los pasos de la evaluacion en orden, para poder atribuir el resultado.
    """
    decision: str                     # "Allow" o "Deny"
    motivo: str                       # explicacion corta legible
    traza: list = field(default_factory=list)

    @property
    def permitido(self) -> bool:
        """La decision, como booleano."""
        return self.decision == "Allow"

    def explicar(self) -> str:
        """Decision y traza formateadas para consola."""
        pasos = "\n".join(f"    {i}. {p}" for i, p in enumerate(self.traza, 1))
        return f"  {self.decision.upper()} -- {self.motivo}\n{pasos}"


def evaluar(peticion: dict, contexto_policies: dict) -> Resultado:
    """
    Evalua una peticion contra todas las capas de policies. Punto de entrada del motor.

    peticion = {
        "principal":         "arn:aws:iam::111111111111:user/mlopez",
        "principal_account": "111111111111",      # opcional (se deduce del ARN)
        "principal_service": "ec2.amazonaws.com", # opcional (para roles de servicio)
        "action":            "s3:GetObject",
        "resource":          "arn:aws:s3:::banco-backups/reporte.xlsx",
        "resource_account":  "111111111111",      # opcional (para cross-account)
        "context":           {"aws:SourceIp": "200.45.10.5", ...}   # opcional
    }

    contexto_policies = {
        "identity":  [(nombre, policyDoc), ...],   # identity-based
        "resource":  [(nombre, policyDoc), ...],   # resource-based (opcional)
        "scp":       [(nombre, policyDoc), ...],   # SCP de Organizations (opcional)
        "boundary":  [(nombre, policyDoc), ...],   # permission boundary (opcional)
    }

    Cuidado con la distincion: [] significa "la capa existe y no permite nada"; None (o
    ausente) significa "la capa no aplica". En una SCP o un boundary, es la diferencia
    entre bloquear todo y no bloquear nada.
    """
    identity = contexto_policies.get("identity", [])
    resource = contexto_policies.get("resource", [])
    scp = contexto_policies.get("scp")            # None si la cuenta no esta en una Org
    boundary = contexto_policies.get("boundary")  # None si el principal no tiene boundary

    # Deducimos la cuenta del principal desde su ARN si no vino explicita.
    if "principal_account" not in peticion:
        m = re.search(r"arn:aws:(?:iam|sts)::(\d+):", peticion.get("principal", ""))
        peticion = {**peticion, "principal_account": m.group(1) if m else None}

    cuenta_principal = peticion.get("principal_account")
    cuenta_recurso = peticion.get("resource_account", cuenta_principal)
    cross_account = (
        cuenta_principal and cuenta_recurso and cuenta_principal != cuenta_recurso
    )

    traza = []
    if cross_account:
        traza.append(
            f"Peticion CROSS-ACCOUNT: principal en {cuenta_principal}, "
            f"recurso en {cuenta_recurso} -> hacen falta AMBAS puntas"
        )

    # --- Paso 1: un Deny explicito en cualquier capa prevalece ------------------
    for etiqueta, capa, es_rp in (
        ("identity", identity, False),
        ("resource", resource, True),
        ("SCP", scp, False),
        ("boundary", boundary, False),
    ):
        hit = _hay_match(capa, peticion, "Deny", es_rp)
        if hit:
            traza.append(f"DENY explicito en {etiqueta}: {hit[0]} / Sid={hit[1]}")
            return Resultado("Deny", f"Deny explicito en {etiqueta} ({hit[0]})", traza)

    # --- Paso 2: hace falta un ALLOW explicito ---------------------------------
    allow_id = _hay_match(identity, peticion, "Allow")
    allow_res = _hay_match(resource, peticion, "Allow", es_resource_policy=True)

    # Un Allow en una resource policy no siempre otorga por si solo: depende de a QUIEN
    # nombre el Principal. Si nombra al llamante, otorga. Si nombra a su CUENTA (:root),
    # solo delega, y ademas hace falta el Allow de la identity policy.
    delegado = bool(allow_res) and allow_res[2] == "delegado"
    allow_res_directo = bool(allow_res) and not delegado

    if allow_id:
        traza.append(f"Allow en identity: {allow_id[0]} / Sid={allow_id[1]}")
    if allow_res:
        traza.append(
            f"Allow en resource: {allow_res[0]} / Sid={allow_res[1]}"
            + (" (Principal = la cuenta, o sea DELEGADO: no otorga por si solo)"
               if delegado else " (Principal nombra al llamante: otorga)")
        )

    if cross_account:
        # Cross-account: la cuenta del llamante lo autoriza Y la cuenta duena del recurso
        # lo autoriza. Una sola punta no alcanza, sea el Principal directo o delegado.
        if not allow_id:
            traza.append("Falta el Allow en la identity policy de la cuenta del llamante")
            return Resultado("Deny", "Cross-account: falta el Allow en identity", traza)
        if not allow_res:
            traza.append("Falta el Allow en la resource policy de la cuenta duena del recurso")
            return Resultado("Deny", "Cross-account: falta el Allow en resource", traza)
    else:
        # Same-account: alcanza con UNA de las dos capas, pero la resource policy solo
        # cuenta si nombra al principal. Un ':root' delega en la cuenta y no otorga nada
        # por si mismo, asi que en ese caso todavia hace falta la identity policy.
        if not (allow_id or allow_res_directo):
            if delegado:
                traza.append(
                    "La resource policy delega en la cuenta (Principal ':root'), pero la "
                    "identity policy del principal no permite la accion"
                )
                return Resultado(
                    "Deny",
                    "La resource policy delega en la cuenta y falta el Allow en identity",
                    traza,
                )
            traza.append("Sin ningun Allow que matchee -> deny implicito")
            return Resultado("Deny", "Deny implicito (ninguna policy lo permite)", traza)

    # --- Paso 3: las capas-techo deben permitirlo tambien -----------------------
    # No otorgan permisos, solo acotan: el permiso efectivo es la interseccion.
    if scp is not None:
        if not _hay_match(scp, peticion, "Allow"):
            traza.append("La SCP no permite esta accion -> bloqueado por SCP")
            return Resultado("Deny", "Bloqueado por SCP (no la permite)", traza)
        traza.append("SCP: permite")

    if boundary is not None:
        if not _hay_match(boundary, peticion, "Allow"):
            traza.append("El permission boundary no incluye esta accion -> bloqueado")
            return Resultado("Deny", "Bloqueado por Permission Boundary", traza)
        traza.append("Permission Boundary: permite")

    traza.append("Resultado final: ALLOW")
    return Resultado("Allow", "Permitido (allow explicito, ningun techo lo bloquea)", traza)


# ---------------------------------------------------------------------------
# Auto-test rapido cuando se corre el modulo directamente
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Auto-test del motor de evaluacion IAM\n" + "-" * 55)

    identity = [("PoliticaLecturaS3", {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PermitirLecturaBackups",
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": ["arn:aws:s3:::banco-backups",
                         "arn:aws:s3:::banco-backups/*"],
        }],
    })]

    abac = [("CreditosABAC", {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "EC2SoloDeMiProyecto",
            "Effect": "Allow",
            "Action": "ec2:*",
            "Resource": "*",
            "Condition": {"StringEquals": {
                "aws:ResourceTag/Proyecto": "${aws:PrincipalTag/Proyecto}"
            }},
        }],
    })]

    casos = [
        ("basico: accion permitida", identity,
         {"action": "s3:GetObject", "resource": "arn:aws:s3:::banco-backups/r.xlsx"}, "Allow"),
        ("basico: accion no listada -> deny implicito", identity,
         {"action": "s3:DeleteObject", "resource": "arn:aws:s3:::banco-backups/r.xlsx"}, "Deny"),
        ("basico: recurso no matchea", identity,
         {"action": "s3:GetObject", "resource": "arn:aws:s3:::otro-bucket/x"}, "Deny"),
        ("ABAC: tags coinciden -> Allow", abac,
         {"action": "ec2:StartInstances", "resource": "arn:aws:ec2:us-east-1:111111111111:instance/i-1",
          "context": {"aws:PrincipalTag/Proyecto": "Creditos",
                      "aws:ResourceTag/Proyecto": "Creditos"}}, "Allow"),
        ("ABAC: tags distintos -> Deny", abac,
         {"action": "ec2:StartInstances", "resource": "arn:aws:ec2:us-east-1:111111111111:instance/i-2",
          "context": {"aws:PrincipalTag/Proyecto": "Creditos",
                      "aws:ResourceTag/Proyecto": "Seguros"}}, "Deny"),
    ]

    fallos = 0
    for titulo, pols, peticion, esperado in casos:
        r = evaluar(peticion, {"identity": pols})
        ok = r.decision == esperado
        fallos += not ok
        print(f"[{'OK' if ok else 'XX'}] {titulo:45} -> {r.decision}")

    print("-" * 55)
    print("Todo OK" if not fallos else f"{fallos} caso(s) fallando")
