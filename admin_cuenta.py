"""
admin_cuenta.py
===============
Mutaciones validadas sobre datos/cuenta_iam.json: el plano de administracion de la cuenta.

El valor del simulador no esta en los seis escenarios sino en poder mover una pieza y
volver a evaluar: un escenario prueba una regla, mutar la cuenta prueba que la regla es la
que manda. Editar el JSON a mano para eso es fragil -- una policy inexistente en un
AttachedPolicies revienta la resolucion en contexto.py, y un nombre repetido produce un
usuario fantasma. Cada operacion de aca valida antes de escribir.

Ninguna funcion decide permisos: eso es motor_iam.py. Esto solo edita el estado.

El ciclo completo -- mutar, evaluar, restaurar -- se apoya en git, que es el unico baseline
byte a byte de la cuenta. Regenerar con generar_datos.py NO restaura: recalcula las fechas
contra el dia de hoy y devuelve una cuenta equivalente pero distinta.

    python main.py admin estado
    python main.py admin crear-policy S3DeleteBackups --archivo /tmp/doc.json
    python main.py admin attach S3DeleteBackups --usuario cgomez
    python main.py admin diff
    python main.py admin restaurar
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone

from contexto import AQUI, RUTA_CUENTA, cargar_cuenta, cuenta_modificada

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


class ErrorAdmin(Exception):
    """Mutacion rechazada por validacion. El estado en disco no se toco."""


# ---------------------------------------------------------------------------
# Persistencia
# ---------------------------------------------------------------------------

def guardar_cuenta(cuenta: dict, ruta=RUTA_CUENTA):
    """Escribe la cuenta con el mismo formato que generar_datos.py, para que el diff de git
    muestre solo el cambio real y no un reformateo entero."""
    ruta.write_text(json.dumps(cuenta, indent=2, ensure_ascii=False), encoding="utf-8")


# ---------------------------------------------------------------------------
# Validaciones
# ---------------------------------------------------------------------------

def _usuario(cuenta: dict, nombre: str) -> dict:
    for u in cuenta["Users"]:
        if u["UserName"] == nombre:
            return u
    disponibles = ", ".join(u["UserName"] for u in cuenta["Users"])
    raise ErrorAdmin(f"No existe el usuario '{nombre}'. Hay: {disponibles}")


def _grupo(cuenta: dict, nombre: str) -> dict:
    for g in cuenta["Groups"]:
        if g["GroupName"] == nombre:
            return g
    disponibles = ", ".join(g["GroupName"] for g in cuenta["Groups"])
    raise ErrorAdmin(f"No existe el grupo '{nombre}'. Hay: {disponibles}")


def _exigir_policy(cuenta: dict, nombre: str):
    """Una policy referenciada pero inexistente rompe la resolucion en contexto.py."""
    if nombre not in cuenta["ManagedPolicies"]:
        disponibles = ", ".join(cuenta["ManagedPolicies"])
        raise ErrorAdmin(f"No existe la policy '{nombre}'. Hay: {disponibles}")


def _validar_documento(doc) -> dict:
    """Estructura minima de un policy document: Version y una lista de Statement."""
    if not isinstance(doc, dict):
        raise ErrorAdmin("El documento debe ser un objeto JSON")
    if "Statement" not in doc or not isinstance(doc["Statement"], list):
        raise ErrorAdmin("El documento necesita una lista 'Statement'")
    for i, stmt in enumerate(doc["Statement"], 1):
        if not isinstance(stmt, dict):
            raise ErrorAdmin(f"El Statement {i} no es un objeto")
        if stmt.get("Effect") not in ("Allow", "Deny"):
            raise ErrorAdmin(f"El Statement {i} necesita Effect 'Allow' o 'Deny'")
        if "Action" not in stmt and "NotAction" not in stmt:
            raise ErrorAdmin(f"El Statement {i} necesita 'Action' o 'NotAction'")
    doc.setdefault("Version", "2012-10-17")
    return doc


def usos_de_policy(cuenta: dict, nombre: str) -> list:
    """Donde esta referenciada una policy: usuarios, grupos y boundaries."""
    usos = []
    for u in cuenta["Users"]:
        if nombre in u.get("AttachedPolicies", []):
            usos.append(f"usuario {u['UserName']} (directa)")
        if u.get("PermissionBoundary") == nombre:
            usos.append(f"usuario {u['UserName']} (boundary)")
    for g in cuenta["Groups"]:
        if nombre in g.get("AttachedPolicies", []):
            usos.append(f"grupo {g['GroupName']}")
    return usos


# ---------------------------------------------------------------------------
# Usuarios
# ---------------------------------------------------------------------------

def crear_usuario(cuenta: dict, nombre: str, *, grupos=None, policies=None,
                  boundary=None, mfa=False, tags=None) -> str:
    if any(u["UserName"] == nombre for u in cuenta["Users"]):
        raise ErrorAdmin(f"El usuario '{nombre}' ya existe")

    for g in grupos or []:
        _grupo(cuenta, g)
    for p in policies or []:
        _exigir_policy(cuenta, p)
    if boundary:
        _exigir_policy(cuenta, boundary)

    cuenta["Users"].append({
        "UserName": nombre,
        "Arn": f"arn:aws:iam::{cuenta['AccountId']}:user/{nombre}",
        "Groups": list(grupos or []),
        "MFAEnabled": bool(mfa),
        "Tags": dict(tags or {}),
        "AttachedPolicies": list(policies or []),
        "PermissionBoundary": boundary,
        "AccessKeys": [],
        "PasswordLastUsed": datetime.now(timezone.utc).isoformat(),
    })
    return (f"Usuario '{nombre}' creado. grupos={grupos or []} "
            f"policies={policies or []} boundary={boundary} mfa={bool(mfa)}")


def borrar_usuario(cuenta: dict, nombre: str) -> str:
    _usuario(cuenta, nombre)
    cuenta["Users"] = [u for u in cuenta["Users"] if u["UserName"] != nombre]
    return f"Usuario '{nombre}' eliminado"


def set_mfa(cuenta: dict, nombre: str, activo: bool) -> str:
    u = _usuario(cuenta, nombre)
    u["MFAEnabled"] = bool(activo)
    return f"MFA de '{nombre}': {'activado' if activo else 'desactivado'}"


def set_tag(cuenta: dict, nombre: str, clave: str, valor) -> str:
    """Un tag de principal: el lado izquierdo de una condicion ABAC."""
    u = _usuario(cuenta, nombre)
    tags = u.setdefault("Tags", {})
    if valor is None:
        tags.pop(clave, None)
        return f"Tag '{clave}' quitado de '{nombre}'"
    tags[clave] = valor
    return f"Tag '{clave}={valor}' puesto en '{nombre}'"


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

def crear_policy(cuenta: dict, nombre: str, documento: dict) -> str:
    if nombre in cuenta["ManagedPolicies"]:
        raise ErrorAdmin(f"La policy '{nombre}' ya existe")
    cuenta["ManagedPolicies"][nombre] = _validar_documento(documento)
    n = len(documento["Statement"])
    return f"Policy '{nombre}' creada ({n} statement/s). Todavia no esta adjunta a nadie."


def borrar_policy(cuenta: dict, nombre: str) -> str:
    _exigir_policy(cuenta, nombre)
    usos = usos_de_policy(cuenta, nombre)
    if usos:
        raise ErrorAdmin(
            f"La policy '{nombre}' esta en uso: {', '.join(usos)}.\n"
            "Hay que hacerle detach primero."
        )
    del cuenta["ManagedPolicies"][nombre]
    return f"Policy '{nombre}' eliminada"


def attach_policy(cuenta: dict, policy: str, *, usuario=None, grupo=None) -> str:
    """Adjunta una managed policy a un usuario (directa) o a un grupo (heredada)."""
    _exigir_policy(cuenta, policy)
    if bool(usuario) == bool(grupo):
        raise ErrorAdmin("Hay que indicar --usuario o --grupo (uno, no los dos)")

    destino = _usuario(cuenta, usuario) if usuario else _grupo(cuenta, grupo)
    adjuntas = destino.setdefault("AttachedPolicies", [])
    etiqueta = f"usuario {usuario}" if usuario else f"grupo {grupo}"

    if policy in adjuntas:
        raise ErrorAdmin(f"'{policy}' ya estaba adjunta al {etiqueta}")
    adjuntas.append(policy)

    if grupo:
        heredan = [u["UserName"] for u in cuenta["Users"] if grupo in u.get("Groups", [])]
        return (f"'{policy}' adjunta al {etiqueta}. "
                f"La heredan: {', '.join(heredan) or '(nadie)'}")
    return f"'{policy}' adjunta al {etiqueta} (directa)"


def detach_policy(cuenta: dict, policy: str, *, usuario=None, grupo=None) -> str:
    if bool(usuario) == bool(grupo):
        raise ErrorAdmin("Hay que indicar --usuario o --grupo (uno, no los dos)")

    destino = _usuario(cuenta, usuario) if usuario else _grupo(cuenta, grupo)
    adjuntas = destino.setdefault("AttachedPolicies", [])
    etiqueta = f"usuario {usuario}" if usuario else f"grupo {grupo}"

    if policy not in adjuntas:
        raise ErrorAdmin(f"'{policy}' no estaba adjunta al {etiqueta}")
    adjuntas.remove(policy)
    return f"'{policy}' quitada del {etiqueta}"


def set_boundary(cuenta: dict, usuario: str, policy=None) -> str:
    """El boundary es un techo sobre la identidad: recorta, nunca otorga."""
    u = _usuario(cuenta, usuario)
    if policy is None:
        anterior = u.get("PermissionBoundary")
        u["PermissionBoundary"] = None
        return (f"Boundary quitado de '{usuario}' (era {anterior})" if anterior
                else f"'{usuario}' no tenia boundary")
    _exigir_policy(cuenta, policy)
    u["PermissionBoundary"] = policy
    return f"Boundary de '{usuario}': {policy}  <- techo, no otorga permisos"


# ---------------------------------------------------------------------------
# Grupos y policies de recurso
# ---------------------------------------------------------------------------

def crear_grupo(cuenta: dict, nombre: str, policies=None) -> str:
    if any(g["GroupName"] == nombre for g in cuenta["Groups"]):
        raise ErrorAdmin(f"El grupo '{nombre}' ya existe")
    for p in policies or []:
        _exigir_policy(cuenta, p)
    cuenta["Groups"].append({"GroupName": nombre,
                             "AttachedPolicies": list(policies or [])})
    return f"Grupo '{nombre}' creado con {policies or []}"


def set_grupo_de_usuario(cuenta: dict, usuario: str, grupo: str, quitar=False) -> str:
    u = _usuario(cuenta, usuario)
    _grupo(cuenta, grupo)
    grupos = u.setdefault("Groups", [])
    if quitar:
        if grupo not in grupos:
            raise ErrorAdmin(f"'{usuario}' no esta en el grupo '{grupo}'")
        grupos.remove(grupo)
        return f"'{usuario}' sacado del grupo '{grupo}'"
    if grupo in grupos:
        raise ErrorAdmin(f"'{usuario}' ya esta en el grupo '{grupo}'")
    grupos.append(grupo)
    return f"'{usuario}' agregado al grupo '{grupo}'"


def set_resource_policy(cuenta: dict, arn: str, documento: dict) -> str:
    """
    Policy pegada al recurso. A diferencia de una identity policy, lleva Principal: dice
    QUIEN puede, no solo QUE se puede.
    """
    doc = _validar_documento(documento)
    for i, stmt in enumerate(doc["Statement"], 1):
        if "Principal" not in stmt and "NotPrincipal" not in stmt:
            raise ErrorAdmin(
                f"El Statement {i} de una resource policy necesita 'Principal'. "
                "Sin Principal no dice a quien le habla."
            )
    nuevo = arn not in cuenta.setdefault("ResourcePolicies", {})
    cuenta["ResourcePolicies"][arn] = doc
    return f"Resource policy {'creada' if nuevo else 'reemplazada'} sobre {arn}"


def quitar_resource_policy(cuenta: dict, arn: str) -> str:
    if arn not in cuenta.get("ResourcePolicies", {}):
        raise ErrorAdmin(f"No hay resource policy sobre '{arn}'")
    del cuenta["ResourcePolicies"][arn]
    return f"Resource policy de {arn} eliminada"


# ---------------------------------------------------------------------------
# Estado del archivo (el baseline es git)
# ---------------------------------------------------------------------------

def _git(*args) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=AQUI, capture_output=True,
                          text=True, encoding="utf-8", errors="replace")


def diff_cuenta() -> str:
    """El diff de la cuenta contra la version commiteada."""
    return _git("diff", "--", str(RUTA_CUENTA)).stdout


def restaurar_cuenta() -> str:
    """
    Devuelve la cuenta a la version commiteada, byte a byte.

    'git checkout --' y no generar_datos.py: la regeneracion recalcula las fechas contra el
    now del dia y produce una cuenta equivalente pero distinta.
    """
    if not cuenta_modificada():
        return "La cuenta ya estaba en su version original. No se toco nada."
    r = _git("checkout", "--", str(RUTA_CUENTA))
    if r.returncode != 0:
        raise ErrorAdmin(f"git no pudo restaurar: {r.stderr.strip()}")
    return "Cuenta restaurada a la version commiteada."


def resumen(cuenta: dict) -> str:
    """Estado de la cuenta: usuarios con sus capas, grupos, policies y techos."""
    lineas = [f"Cuenta {cuenta['AccountId']}   "
              f"[{'MODIFICADA' if cuenta_modificada() else 'ORIGINAL'}]", ""]

    lineas.append("Usuarios")
    for u in cuenta["Users"]:
        directas = ", ".join(u.get("AttachedPolicies", [])) or "-"
        grupos = ", ".join(u.get("Groups", [])) or "-"
        boundary = u.get("PermissionBoundary") or "-"
        lineas.append(f"  {u['UserName']:16} grupos: {grupos:20} directas: {directas:20}")
        lineas.append(f"  {'':16} boundary: {boundary:18} MFA: {'si' if u['MFAEnabled'] else 'NO'}")

    lineas.append("\nGrupos")
    for g in cuenta["Groups"]:
        lineas.append(f"  {g['GroupName']:16} {', '.join(g.get('AttachedPolicies', [])) or '-'}")

    lineas.append("\nManaged policies")
    for nombre in cuenta["ManagedPolicies"]:
        usos = usos_de_policy(cuenta, nombre)
        lineas.append(f"  {nombre:20} {', '.join(usos) if usos else '(sin adjuntar)'}")

    lineas.append("\nTechos y resource policies")
    for nombre in cuenta.get("Organization", {}).get("SCPs", {}):
        lineas.append(f"  SCP {nombre:16} (aplica a toda la cuenta)")
    for arn in cuenta.get("ResourcePolicies", {}):
        lineas.append(f"  ResourcePolicy    {arn}")

    return "\n".join(lineas)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _leer_documento(args) -> dict:
    """El policy document, desde archivo o desde un JSON inline."""
    if args.archivo:
        try:
            crudo = open(args.archivo, encoding="utf-8").read()
        except OSError as e:
            raise ErrorAdmin(f"No pude leer {args.archivo}: {e}")
    elif args.json:
        crudo = args.json
    else:
        raise ErrorAdmin("Hay que pasar --archivo o --json con el documento")
    try:
        return json.loads(crudo)
    except json.JSONDecodeError as e:
        raise ErrorAdmin(f"El documento no es JSON valido: {e}")


def construir_parser():
    p = argparse.ArgumentParser(
        prog="python main.py admin",
        description="Modifica la cuenta. Toda mutacion valida antes de escribir.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("estado", help="usuarios, grupos, policies y techos")
    sub.add_parser("diff", help="diff de la cuenta contra la version commiteada")
    sub.add_parser("restaurar", help="vuelve la cuenta a la version commiteada")

    c = sub.add_parser("crear-usuario", help="crea un usuario")
    c.add_argument("nombre")
    c.add_argument("--grupo", action="append", default=[], dest="grupos")
    c.add_argument("--policy", action="append", default=[], dest="policies")
    c.add_argument("--boundary")
    c.add_argument("--mfa", action="store_true")
    c.add_argument("--tag", action="append", default=[], metavar="CLAVE=VALOR")

    b = sub.add_parser("borrar-usuario", help="elimina un usuario")
    b.add_argument("nombre")

    m = sub.add_parser("mfa", help="activa o desactiva el MFA de un usuario")
    m.add_argument("usuario")
    g = m.add_mutually_exclusive_group(required=True)
    g.add_argument("--on", dest="on", action="store_true")
    g.add_argument("--off", dest="on", action="store_false")

    t = sub.add_parser("tag", help="pone o quita un tag de principal (ABAC)")
    t.add_argument("usuario")
    t.add_argument("clave")
    t.add_argument("valor", nargs="?", help="omitir para quitar el tag")

    cp = sub.add_parser("crear-policy", help="crea una managed policy")
    cp.add_argument("nombre")
    cp.add_argument("--archivo")
    cp.add_argument("--json")

    bp = sub.add_parser("borrar-policy", help="elimina una managed policy sin uso")
    bp.add_argument("nombre")

    for nombre_cmd, ayuda in (("attach", "adjunta una policy"),
                              ("detach", "quita una policy adjunta")):
        a = sub.add_parser(nombre_cmd, help=ayuda)
        a.add_argument("policy")
        a.add_argument("--usuario")
        a.add_argument("--grupo")

    bd = sub.add_parser("boundary", help="pone o quita el permission boundary de un usuario")
    bd.add_argument("usuario")
    bd.add_argument("--policy")
    bd.add_argument("--quitar", action="store_true")

    cg = sub.add_parser("crear-grupo", help="crea un grupo")
    cg.add_argument("nombre")
    cg.add_argument("--policy", action="append", default=[], dest="policies")

    gr = sub.add_parser("grupo", help="agrega o saca a un usuario de un grupo")
    gr.add_argument("usuario")
    gr.add_argument("grupo")
    gr.add_argument("--quitar", action="store_true")

    rp = sub.add_parser("resource-policy", help="pone o quita la policy de un recurso")
    rp.add_argument("arn")
    rp.add_argument("--archivo")
    rp.add_argument("--json")
    rp.add_argument("--quitar", action="store_true")

    return p


def despachar(args, cuenta: dict):
    """Ejecuta el subcomando. Devuelve (mensaje, escribir)."""
    c = args.cmd

    if c == "estado":
        return resumen(cuenta), False
    if c == "diff":
        d = diff_cuenta()
        return (d or "Sin cambios respecto de la version commiteada."), False
    if c == "restaurar":
        return restaurar_cuenta(), False

    if c == "crear-usuario":
        tags = {}
        for par in args.tag:
            if "=" not in par:
                raise ErrorAdmin(f"--tag espera CLAVE=VALOR, no '{par}'")
            k, v = par.split("=", 1)
            tags[k] = v
        return crear_usuario(cuenta, args.nombre, grupos=args.grupos,
                             policies=args.policies, boundary=args.boundary,
                             mfa=args.mfa, tags=tags), True

    if c == "borrar-usuario":
        return borrar_usuario(cuenta, args.nombre), True
    if c == "mfa":
        return set_mfa(cuenta, args.usuario, args.on), True
    if c == "tag":
        return set_tag(cuenta, args.usuario, args.clave, args.valor), True
    if c == "crear-policy":
        return crear_policy(cuenta, args.nombre, _leer_documento(args)), True
    if c == "borrar-policy":
        return borrar_policy(cuenta, args.nombre), True
    if c == "attach":
        return attach_policy(cuenta, args.policy, usuario=args.usuario,
                             grupo=args.grupo), True
    if c == "detach":
        return detach_policy(cuenta, args.policy, usuario=args.usuario,
                             grupo=args.grupo), True
    if c == "boundary":
        if args.quitar:
            return set_boundary(cuenta, args.usuario, None), True
        if not args.policy:
            raise ErrorAdmin("Hay que pasar --policy o --quitar")
        return set_boundary(cuenta, args.usuario, args.policy), True
    if c == "crear-grupo":
        return crear_grupo(cuenta, args.nombre, args.policies), True
    if c == "grupo":
        return set_grupo_de_usuario(cuenta, args.usuario, args.grupo,
                                    quitar=args.quitar), True
    if c == "resource-policy":
        if args.quitar:
            return quitar_resource_policy(cuenta, args.arn), True
        return set_resource_policy(cuenta, args.arn, _leer_documento(args)), True

    raise ErrorAdmin(f"Subcomando no implementado: {c}")


def main(argv=None):
    args = construir_parser().parse_args(argv if argv is not None else sys.argv[1:])
    cuenta = cargar_cuenta()

    try:
        mensaje, escribir = despachar(args, cuenta)
    except ErrorAdmin as e:
        print(f"[rechazado] {e}")
        return 1

    if escribir:
        guardar_cuenta(cuenta)
        print(f"[ok] {mensaje}")
        print("\nLa cuenta quedo MODIFICADA. Para volver al original:"
              "\n  python main.py admin restaurar")
    else:
        print(mensaje)
    return 0


if __name__ == "__main__":
    sys.exit(main())
