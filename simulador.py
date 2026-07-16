"""
simulador.py
============
Evalua una peticion arbitraria contra la cuenta: el equivalente al IAM Policy Simulator.

escenarios.py corre un catalogo fijo. Esto responde la pregunta suelta -- puede este
usuario hacer esta accion sobre este recurso -- contra el estado actual del JSON, que es
lo que hace falta despues de mutar la cuenta.

No implementa reglas de IAM: arma la peticion y las capas con contexto.py y delega la
decision en motor_iam.evaluar(). Toda la logica de autorizacion vive en el motor.

    python main.py evaluar cgomez s3:DeleteObject arn:aws:s3:::banco-backups/nomina.xlsx
    python main.py evaluar svc-reporting iam:CreateUser "*"
    python main.py evaluar jadmin cloudtrail:StopLogging "*" --sin-mfa
    python main.py evaluar mlopez s3:GetObject arn:aws:s3:::banco-backups/x --ip 10.0.0.1
"""

from __future__ import annotations

import argparse
import re
import sys

from contexto import (cargar_cuenta, cuenta_modificada, peticion,
                      policies_de_recurso, policies_de_usuario)
from motor_iam import (_como_lista, accion_coincide, evaluar,
                       evaluar_condiciones, interpolar, recurso_coincide)

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def construir(cuenta: dict, usuario: str, accion: str, recurso: str, *,
              mfa=None, ip=None, cuenta_recurso=None, extra=None):
    """
    Arma (peticion, capas) para el motor.

    La resource policy del recurso se adjunta siempre que exista: AWS la evalua aunque el
    llamante no la mencione. Sin esto, todo recurso con bucket policy se evaluaria mal.
    """
    capas = policies_de_usuario(cuenta, usuario)

    # 'ip' solo se pasa si vino: contexto_peticion() tiene su propio default y un None
    # explicito lo pisaria con un aws:SourceIp vacio.
    ctx_kwargs = {"mfa": mfa}
    if ip is not None:
        ctx_kwargs["ip"] = ip
    ctx_kwargs.update(extra or {})

    pet = peticion(cuenta, usuario, accion, recurso, **ctx_kwargs)

    rp = policies_de_recurso(cuenta, recurso)
    if rp:
        capas["resource"] = rp

    # Fuerza el caso cross-account: mismo principal, recurso en otra cuenta.
    if cuenta_recurso:
        pet["resource_account"] = cuenta_recurso

    return pet, capas


# Operadores de condicion de IAM como simbolo, para la comparacion cruda de PETICION/DECISION.
COMPARADORES = {
    "StringEquals": "==", "StringNotEquals": "!=",
    "StringEqualsIgnoreCase": "== (sin distinguir mayusculas)",
    "StringLike": "coincide con", "StringNotLike": "no coincide con",
    "NumericEquals": "==", "NumericNotEquals": "!=",
    "NumericLessThan": "<", "NumericGreaterThan": ">",
    "DateLessThan": "es anterior a", "DateGreaterThan": "es posterior a",
    "Bool": "==",
    "IpAddress": "esta en", "NotIpAddress": "no esta en",
    "ArnEquals": "==", "ArnLike": "coincide con", "ArnNotLike": "no coincide con",
    "Null": "no existe en la peticion es",
}

# Los mismos operadores en palabras, para la lectura humana de la linea 'condicion' de PETICION.
COMPARADORES_HUMANO = {
    "StringEquals": "es igual a", "StringNotEquals": "es distinto de",
    "StringEqualsIgnoreCase": "es igual a (sin distinguir mayusculas)",
    "StringLike": "coincide con", "StringNotLike": "no coincide con",
    "NumericEquals": "es igual a", "NumericNotEquals": "es distinto de",
    "NumericLessThan": "es menor que", "NumericGreaterThan": "es mayor que",
    "DateLessThan": "es anterior a", "DateGreaterThan": "es posterior a",
    "IpAddress": "esta en", "NotIpAddress": "no esta en",
    "ArnEquals": "es igual a", "ArnLike": "coincide con", "ArnNotLike": "no coincide con",
}


def _servicios_de(stmt: dict) -> str:
    """Las acciones del statement resumidas por servicio: 'acciones de EC2', 'cualquier accion'."""
    salvo = "NotAction" in stmt
    acciones = _como_lista(stmt.get("NotAction") if salvo else stmt.get("Action", []))
    if "*" in acciones:
        base = "cualquier accion"
    else:
        servicios = []
        for a in acciones:
            svc = a.split(":", 1)[0].upper()
            if svc and svc not in servicios:
                servicios.append(svc)
        base = "acciones de " + " y ".join(servicios) if servicios else "acciones"
    return f"cualquier accion salvo {base}" if salvo else base


def _clave_humana(clave: str) -> str:
    """Una clave de condicion aws:* dicha en castellano."""
    if clave.startswith("aws:ResourceTag/"):
        return f'el tag "{clave.split("/", 1)[1]}" del recurso'
    if clave.startswith("aws:PrincipalTag/"):
        return f'el tag "{clave.split("/", 1)[1]}" del usuario'
    return {
        "aws:MultiFactorAuthPresent": "el inicio de sesion con MFA",
        "aws:SourceIp": "la IP de origen",
        "aws:username": "el nombre de usuario",
        "aws:PrincipalAccount": "la cuenta del usuario",
    }.get(clave, clave)


def _valor_humano(valor) -> str:
    """El lado derecho de una comparacion. Una policy variable ${...} se dice, no se muestra cruda."""
    if isinstance(valor, list):
        return " o ".join(_valor_humano(v) for v in valor)
    m = re.fullmatch(r"\$\{(aws:[^}]+)\}", str(valor))
    return _clave_humana(m.group(1)) if m else f'"{valor}"'


def _regla_humana(condicion: dict) -> str:
    """
    La Condition de un statement dicha como una regla en castellano.

    Reconoce los patrones frecuentes (ABAC por tag igual, MFA, IP) y cae en una traduccion
    generica clave-comparador-valor para el resto.
    """
    partes = []
    for operador, bloque in condicion.items():
        opcional = operador.endswith("IfExists")
        base = operador[:-8] if opcional else operador
        for clave, esperado in bloque.items():
            partes.append(_una_regla(base, clave, esperado))
            if opcional:
                partes[-1] += " (y si la peticion no trae ese dato, la condicion se ignora)"
    return ", y ".join(partes)


def _una_regla(operador: str, clave: str, esperado) -> str:
    """Una sola comparacion de una Condition, en castellano."""
    # ABAC clasico: un ResourceTag comparado contra el mismo PrincipalTag.
    if clave.startswith("aws:ResourceTag/") and isinstance(esperado, str):
        tag = clave.split("/", 1)[1]
        if esperado == f"${{aws:PrincipalTag/{tag}}}":
            return f'el recurso y el usuario comparten el mismo tag "{tag}"'

    # MFA: se lee como un si/no, no como "== true".
    if clave == "aws:MultiFactorAuthPresent" and operador == "Bool":
        valor = esperado[0] if isinstance(esperado, list) else esperado
        return ("el usuario inicio sesion con MFA" if str(valor).lower() == "true"
                else "el usuario NO inicio sesion con MFA")

    comparador = COMPARADORES_HUMANO.get(operador, operador)
    return f"{_clave_humana(clave)} {comparador} {_valor_humano(esperado)}"


def _statement_aplica(stmt: dict, peticion: dict) -> bool:
    """
    True si el statement matchea la accion y el recurso de la peticion, IGNORANDO su
    Condition.

    Se usa para no reportar la condicion de un statement que ni siquiera aplica a lo que se
    consulto: una regla sobre ec2:* no tiene por que aparecer al evaluar s3:GetObject, aunque
    viva en una policy del usuario. Reusa el matching de comodines del motor; no mira
    Principal, porque las condiciones que interesan viven en identity policies.
    """
    accion, recurso = peticion["action"], peticion["resource"]
    contexto = peticion.get("context", {})

    if "NotAction" in stmt:
        if any(accion_coincide(a, accion) for a in _como_lista(stmt["NotAction"])):
            return False
    elif not any(accion_coincide(a, accion) for a in _como_lista(stmt.get("Action", []))):
        return False

    if "NotResource" in stmt:
        if recurso_coincide(stmt["NotResource"], recurso, contexto):
            return False
    elif "Resource" in stmt:
        if not recurso_coincide(stmt["Resource"], recurso, contexto):
            return False

    return True


def statements_con_condicion(capas: dict, peticion: dict) -> list:
    """
    Los statements que llevan Condition Y aplican a la accion/recurso de la peticion.

    Devuelve (capa, etiqueta, verbo, condicion_legible) por cada uno. El contexto de la
    peticion (aws:SourceIp, aws:MultiFactorAuthPresent, aws:PrincipalTag/*) solo pesa si
    alguna Condition lo mira: sin condiciones, el contexto es decorado.
    """
    hallados = []
    for capa in ("identity", "boundary", "scp", "resource"):
        for nombre, doc in capas.get(capa) or []:
            for stmt in doc.get("Statement", []):
                cond = stmt.get("Condition")
                if cond and _statement_aplica(stmt, peticion):
                    etiqueta = f"{nombre}/{stmt.get('Sid', '(sin Sid)')}"
                    verbo = "permite" if stmt.get("Effect") == "Allow" else "deniega"
                    hallados.append((etiqueta, verbo, _servicios_de(stmt), _regla_humana(cond)))
    return hallados


def resolver_condiciones(capas: dict, peticion: dict) -> list:
    """
    Cada statement condicionado que aplica a la peticion, resuelto contra su contexto real.

    Devuelve (capa, etiqueta, verbo, se_cumple, comparaciones), donde cada comparacion es
    (clave, valor_en_la_peticion, comparador, valor_esperado_ya_interpolado). Sirve para
    atribuir el resultado: no alcanza con saber que habia una Condition, hay que ver con que
    valores se comparo y si dio. Filtra los statements que no matchean la accion/recurso, para
    no explicar condiciones ajenas a lo que se consulto.
    """
    contexto = peticion.get("context", {})
    resueltas = []
    for capa in ("identity", "boundary", "scp", "resource"):
        for nombre, doc in capas.get(capa) or []:
            for stmt in doc.get("Statement", []):
                cond = stmt.get("Condition")
                if not cond or not _statement_aplica(stmt, peticion):
                    continue

                efecto = stmt.get("Effect", "Allow")
                se_cumple = evaluar_condiciones(cond, contexto, efecto)

                comparaciones = []
                for operador, bloque in cond.items():
                    base = operador[:-8] if operador.endswith("IfExists") else operador
                    comparador = COMPARADORES.get(base, base)
                    for clave, esperado in bloque.items():
                        if isinstance(esperado, list):
                            esperado = " o ".join(str(v) for v in esperado)
                        esperado = str(esperado)
                        resuelto = interpolar(esperado, contexto)
                        # Una policy variable se muestra con su valor al lado: sin eso, el
                        # lado derecho aparece ya resuelto y se pierde de donde salio.
                        if resuelto != esperado:
                            resuelto = f"{esperado} = {resuelto}"
                        comparaciones.append((
                            clave,
                            contexto.get(clave, "(no viene en la peticion)"),
                            comparador,
                            resuelto,
                        ))

                resueltas.append((
                    capa,
                    f"{nombre}/{stmt.get('Sid', '(sin Sid)')}",
                    "permite" if efecto == "Allow" else "deniega",
                    se_cumple,
                    comparaciones,
                ))
    return resueltas


def claves_forzables(cuenta: dict, usuario: str) -> list:
    """
    Las claves de contexto que las condiciones del usuario comparan, con el flag que las fuerza
    y un valor sugerido. Solo tiene sentido forzar una clave que alguna Condition mire: sin
    condicion, cambiar el contexto no cambia la decision.

    Devuelve [(clave, sugerencia_de_flag)].
    """
    from contexto import contexto_peticion

    capas = policies_de_usuario(cuenta, usuario)
    ctx = contexto_peticion(cuenta, usuario)

    vistas = {}
    for capa in ("identity", "boundary", "scp", "resource"):
        for _, doc in capas.get(capa) or []:
            for stmt in doc.get("Statement", []):
                # La condicion solo pesa sobre las acciones de SU statement: forzarla no cambia
                # nada si se consulta una accion que ese statement no cubre.
                servicio = _servicios_de(stmt)
                for _operador, bloque in (stmt.get("Condition") or {}).items():
                    for clave, esperado in bloque.items():
                        if clave not in vistas:
                            vistas[clave] = _sugerencia_forzado(clave, esperado, ctx, servicio)
    return list(vistas.items())


def _sugerencia_forzado(clave: str, esperado, ctx: dict, servicio: str) -> str:
    """
    Como forzar una clave de condicion: el flag, un valor que haga cumplir la comparacion, y
    sobre que acciones aplica. El servicio importa: la condicion solo rige para las acciones de
    su statement, asi que forzarla con otra accion no cambia la decision.
    """
    if clave == "aws:MultiFactorAuthPresent":
        return f"--mfa  /  --sin-mfa  (afecta {servicio})"
    if clave == "aws:SourceIp":
        return f"--ip <ip>  (redes: 200.45.10.0/24 · 10.10.0.0/16; afecta {servicio})"

    # Para el resto, --ctx. Si la comparacion es contra un tag del principal, el valor que la
    # hace cumplir es el que ese tag tiene hoy; cualquier otro la rompe.
    m = re.fullmatch(r"\$\{(aws:[^}]+)\}", str(esperado))
    if m and m.group(1) in ctx:
        cumple = ctx[m.group(1)]
        return f"--ctx {clave}={cumple}  (={cumple} cumple para {servicio}; otro valor lo deniega)"
    if isinstance(esperado, str) and not esperado.startswith("${"):
        return f"--ctx {clave}={esperado}  (={esperado} cumple para {servicio}; otro valor lo deniega)"
    return f"--ctx {clave}=<valor>  (aplica a {servicio})"


def informe(cuenta: dict, pet: dict, capas: dict) -> str:
    """Peticion, capas que participan y decision con su traza."""
    origen = capas.get("_origen", {})
    lineas = []

    lineas.append("Peticion")
    lineas.append(f"  principal : {pet['principal']}")
    lineas.append(f"  action    : {pet['action']}")
    lineas.append(f"  resource  : {pet['resource']}")
    cta_p = pet.get("principal_account")
    cta_r = pet.get("resource_account")
    if cta_p and cta_r and cta_p != cta_r:
        lineas.append(f"  cross-acc : principal en {cta_p}, recurso en {cta_r}"
                      "  <- hacen falta AMBAS puntas")
    ctx = pet.get("context", {})
    relevante = {k: v for k, v in ctx.items()
                 if k in ("aws:MultiFactorAuthPresent", "aws:SourceIp")
                 or k.startswith("aws:PrincipalTag/")}
    lineas.append("  contexto  : "
                  + (", ".join(f"{k}={v}" for k, v in relevante.items()) or "(sin contexto)"))

    condicionadas = statements_con_condicion(capas, pet)
    if not condicionadas:
        lineas.append("  condicion : ninguna policy evaluada tiene Condition")
    else:
        # Por cada statement condicionado que aplica: que permite/deniega y bajo que regla. El
        # efecto solo rige si la regla se cumple contra el contexto de la peticion.
        primero = True
        for etiqueta, verbo, servicio, regla in condicionadas:
            lineas.append(f"{'  condicion : ' if primero else ' ' * 14}{etiqueta}")
            lineas.append(f"{' ' * 14}{verbo} {servicio} solo si {regla}")
            primero = False

    lineas.append("\nCapas evaluadas")
    identity = ", ".join(f"{n} ({origen.get(n, '?')})" for n, _ in capas.get("identity", []))
    lineas.append(f"  identity : {identity or '(ninguna)'}")
    for etiqueta, clave in (("boundary", "boundary"), ("scp", "scp"), ("resource", "resource")):
        capa = capas.get(clave)
        nombres = ", ".join(n for n, _ in capa) if capa else "-"
        lineas.append(f"  {etiqueta:9}: {nombres}")

    resultado = evaluar(pet, capas)
    lineas.append("\nDecision")
    lineas.append(resultado.explicar())

    # Por que la condicion dio lo que dio: los valores concretos que se compararon. Sin esto,
    # una decision atada a una Condition queda sin atribuir.
    for capa, etiqueta, verbo, se_cumple, comparaciones in resolver_condiciones(capas, pet):
        estado = "se cumple" if se_cumple else "NO se cumple"
        lineas.append(f"\n  La condicion de {capa} ({etiqueta}) {estado}, "
                      f"asi que {'' if se_cumple else 'no '}{verbo}:")
        for clave, actual, comparador, esperado in comparaciones:
            lineas.append(f"    {clave} = {actual}   {comparador}   {esperado}")

    return "\n".join(lineas)


def parsear(argv):
    p = argparse.ArgumentParser(
        prog="python main.py evaluar",
        description="Evalua una peticion contra el estado actual de la cuenta.",
    )
    p.add_argument("usuario")
    p.add_argument("accion", nargs="?", help="por ejemplo s3:GetObject")
    p.add_argument("recurso", nargs="?", help="ARN completo, o * ")

    p.add_argument("--forzables", action="store_true",
                   help="lista las claves de contexto que las condiciones del usuario miran, "
                        "y sale (no evalua)")

    mfa = p.add_mutually_exclusive_group()
    mfa.add_argument("--mfa", dest="mfa", action="store_true", default=None,
                     help="fuerza MFA presente (por defecto: lo que diga el usuario)")
    mfa.add_argument("--sin-mfa", dest="mfa", action="store_false",
                     help="fuerza MFA ausente")

    p.add_argument("--ip", help="aws:SourceIp de la peticion")
    p.add_argument("--cuenta-recurso", dest="cuenta_recurso",
                   help="evalua el recurso como si viviera en otra cuenta (cross-account)")
    p.add_argument("--ctx", action="append", default=[], metavar="CLAVE=VALOR",
                   help="clave de condicion extra, repetible "
                        "(por ejemplo --ctx aws:ResourceTag/Proyecto=creditos)")
    return p.parse_args(argv)


def main(argv=None):
    args = parsear(argv if argv is not None else sys.argv[1:])

    cuenta = cargar_cuenta()

    if args.forzables:
        try:
            claves = claves_forzables(cuenta, args.usuario)
        except KeyError as e:
            print(e.args[0])
            return 1
        if not claves:
            print(f"Las policies de {args.usuario} no tienen condiciones: "
                  "no hay contexto que forzar que cambie la decision.")
        else:
            print(f"Contexto que las condiciones de {args.usuario} miran:")
            for clave, sugerencia in claves:
                print(f"  {clave:32} {sugerencia}")
        return 0

    if not args.accion or not args.recurso:
        print("Faltan la accion y/o el recurso. Uso: evaluar <usuario> <accion> <recurso>")
        return 2

    extra = {}
    for par in args.ctx:
        if "=" not in par:
            print(f"--ctx espera CLAVE=VALOR, no '{par}'")
            return 2
        clave, valor = par.split("=", 1)
        extra[clave] = valor

    try:
        pet, capas = construir(
            cuenta, args.usuario, args.accion, args.recurso,
            mfa=args.mfa, ip=args.ip, cuenta_recurso=args.cuenta_recurso, extra=extra,
        )
    except KeyError as e:
        print(e.args[0])
        return 1

    if cuenta_modificada():
        print("[!] La cuenta esta MODIFICADA respecto de la version commiteada.\n")

    print(informe(cuenta, pet, capas))
    return 0


if __name__ == "__main__":
    sys.exit(main())
