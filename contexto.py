"""
contexto.py
===========
Resuelve que policies aplican a cada principal: el paso que AWS hace antes de evaluar.

Los permisos efectivos de un usuario son:

    1. Sus policies adjuntas directamente          (AttachedPolicies)
    2. Las heredadas de cada grupo al que pertenece
    3. Su permission boundary, si tiene            (capa-techo)
    4. Las SCP de la organizacion                  (capa-techo)

1 y 2 suman (union); 3 y 4 solo acotan (interseccion). Esa asimetria es la que define
cuanto puede hacer realmente un principal.

Arma tambien el contexto de la peticion: las claves aws:* (aws:username, aws:SourceIp,
aws:MultiFactorAuthPresent, aws:PrincipalTag/...) que AWS adjunta a cada llamada y contra
las que se evaluan las condiciones de las policies.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

AQUI = Path(__file__).resolve().parent
RUTA_CUENTA = AQUI / "datos" / "cuenta_iam.json"


# ---------------------------------------------------------------------------
# Carga
# ---------------------------------------------------------------------------

def cargar_cuenta(ruta: Path = RUTA_CUENTA) -> dict:
    """Carga el estado de la cuenta. Equivale a un dump de iam:List* / iam:Get*."""
    if not ruta.exists():
        raise FileNotFoundError(
            f"No existe {ruta}.\nCorre primero:  python datos/generar_datos.py"
        )
    return json.loads(ruta.read_text(encoding="utf-8"))


def cuenta_modificada(ruta: Path = RUTA_CUENTA) -> bool:
    """
    True si la cuenta en disco difiere de la version commiteada.

    Distingue una mutacion deliberada (admin_cuenta.py) de un bug: si la cuenta cambio, un
    resultado distinto del esperado por el catalogo es la consecuencia, no una falla.

    False si no hay repo git o si git no esta disponible: sin baseline no se puede afirmar
    que haya cambios.
    """
    try:
        r = subprocess.run(
            ["git", "diff", "--quiet", "--", str(ruta)],
            cwd=AQUI, capture_output=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 1     # 0 = sin cambios, 1 = difiere, otro = error de git


def buscar_usuario(cuenta: dict, nombre: str) -> dict:
    """Usuario por UserName. KeyError con los disponibles si no existe."""
    for u in cuenta["Users"]:
        if u["UserName"] == nombre:
            return u
    disponibles = ", ".join(u["UserName"] for u in cuenta["Users"])
    raise KeyError(f"No existe el usuario '{nombre}'. Hay: {disponibles}")


# ---------------------------------------------------------------------------
# Resolucion de policies
# ---------------------------------------------------------------------------

def _resolver(cuenta: dict, nombres) -> list:
    """
    Resuelve nombres de policy contra el catalogo: ['S3ReadOnlyBackups'] ->
    [('S3ReadOnlyBackups', {documento})], que es el formato de capa que espera el motor.

    Falla fuerte ante un nombre inexistente: silenciarlo produciria permisos fantasma.
    """
    catalogo = cuenta["ManagedPolicies"]
    resueltas = []
    for n in nombres:
        if n not in catalogo:
            raise KeyError(f"La policy '{n}' no existe en ManagedPolicies")
        resueltas.append((n, catalogo[n]))
    return resueltas


def policies_de_usuario(cuenta: dict, nombre: str) -> dict:
    """
    Arma el contexto_policies de un usuario, listo para motor_iam.evaluar().

    Union de policies directas y heredadas de grupos, mas las capas-techo (boundary del
    usuario y SCP de la organizacion).

    Incluye '_origen': {policy: procedencia}, para poder atribuir cada permiso.
    """
    usuario = buscar_usuario(cuenta, nombre)

    # 1 + 2: union de directas y heredadas. Lista + dict de origen en vez de set, para
    # preservar el orden y poder rastrear la procedencia.
    nombres, origen = [], {}

    for p in usuario.get("AttachedPolicies", []):
        if p not in origen:
            nombres.append(p)
            origen[p] = "directa"

    grupos_por_nombre = {g["GroupName"]: g for g in cuenta["Groups"]}
    for nombre_grupo in usuario.get("Groups", []):
        grupo = grupos_por_nombre.get(nombre_grupo)
        if not grupo:
            continue
        for p in grupo.get("AttachedPolicies", []):
            if p not in origen:
                nombres.append(p)
                origen[p] = f"grupo {nombre_grupo}"

    ctx = {"identity": _resolver(cuenta, nombres), "_origen": origen}

    # 3: permission boundary (capa-techo, solo si el usuario tiene uno).
    boundary = usuario.get("PermissionBoundary")
    if boundary:
        ctx["boundary"] = _resolver(cuenta, [boundary])

    # 4: SCP de la organizacion (capa-techo, aplican a TODA la cuenta).
    scps = cuenta.get("Organization", {}).get("SCPs", {})
    if scps:
        ctx["scp"] = list(scps.items())

    return ctx


def policies_de_recurso(cuenta: dict, arn_recurso: str) -> list:
    """
    Resource-based policy asociada al recurso, buscada por ARN y no por principal.

    Un objeto hereda la policy de su bucket: 'arn:aws:s3:::banco-backups/nomina.xlsx'
    resuelve contra la policy de 'arn:aws:s3:::banco-backups'. Devuelve [] si no hay.
    """
    encontradas = []
    for arn_dueno, doc in cuenta.get("ResourcePolicies", {}).items():
        if arn_recurso == arn_dueno or arn_recurso.startswith(arn_dueno + "/"):
            encontradas.append((f"ResourcePolicy[{arn_dueno}]", doc))
    return encontradas


# ---------------------------------------------------------------------------
# Contexto de la peticion (las claves aws:* que ve el motor de autorizacion)
# ---------------------------------------------------------------------------

def contexto_peticion(cuenta: dict, nombre_usuario: str, *, mfa=None,
                      ip="200.45.10.5", **extra) -> dict:
    """
    Arma las claves de condicion que AWS adjunta a cada peticion.

    Las aws:PrincipalTag/* salen de los tags del usuario: son el lado izquierdo de la
    comparacion en ABAC.

    mfa e ip se pueden pisar para simular escenarios. El resto de claves
    (aws:ResourceTag/*, sts:ExternalId...) entran por **extra.
    """
    usuario = buscar_usuario(cuenta, nombre_usuario)

    ctx = {
        "aws:username": usuario["UserName"],
        "aws:PrincipalAccount": cuenta["AccountId"],
        "aws:SourceIp": ip,
        "aws:MultiFactorAuthPresent": str(
            usuario["MFAEnabled"] if mfa is None else mfa
        ).lower(),
    }
    for clave, valor in usuario.get("Tags", {}).items():
        ctx[f"aws:PrincipalTag/{clave}"] = valor

    ctx.update(extra)   # por ejemplo aws:ResourceTag/Proyecto, sts:ExternalId
    return ctx


def peticion(cuenta: dict, usuario: str, action: str, resource: str, **ctx_extra) -> dict:
    """Arma la peticion completa (principal + accion + recurso + contexto)."""
    u = buscar_usuario(cuenta, usuario)
    return {
        "principal": u["Arn"],
        "principal_account": cuenta["AccountId"],
        "action": action,
        "resource": resource,
        "context": contexto_peticion(cuenta, usuario, **ctx_extra),
    }


# ---------------------------------------------------------------------------
# Volcado: el usuario y los documentos de las policies que le aplican
# ---------------------------------------------------------------------------

def volcar(cuenta: dict, nombre: str) -> dict:
    """
    El usuario tal como esta en la cuenta, sus grupos, y el documento completo de cada policy
    que le aplica, agrupado por capa y con la procedencia de cada una.

    Los grupos van explicitos y no solo como 'origen' de una policy: sin ellos hay que
    inferir la cadena usuario -> grupo -> policy en vez de leerla.

    Es la vista cruda: lo que hay que leer para explicar una decision del motor.
    """
    usuario = buscar_usuario(cuenta, nombre)
    ctx = policies_de_usuario(cuenta, nombre)
    origen = ctx["_origen"]

    def capa(clave):
        return [{"nombre": n, "origen": origen.get(n, clave), "documento": doc}
                for n, doc in ctx.get(clave, [])]

    grupos = [g for g in cuenta["Groups"] if g["GroupName"] in usuario.get("Groups", [])]

    salida = {
        "usuario": usuario,
        "grupos": grupos,
        "identity": capa("identity"),
    }
    salida["boundary"] = capa("boundary") if "boundary" in ctx else []
    salida["scp"] = capa("scp") if "scp" in ctx else []
    return salida


# ---------------------------------------------------------------------------
# Demo: que permisos efectivos tiene cada usuario y de donde salen
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    from motor_iam import evaluar

    cuenta = cargar_cuenta()

    args = [a for a in sys.argv[1:] if a != "--json"]
    como_json = "--json" in sys.argv[1:]

    if como_json:
        objetivo = args[0] if args else None
        if objetivo:
            datos = volcar(cuenta, objetivo)
        else:
            datos = [volcar(cuenta, u["UserName"]) for u in cuenta["Users"]]
        print(json.dumps(datos, indent=2, ensure_ascii=False))
        sys.exit(0)

    print(f"Cuenta {cuenta['AccountId']} -- permisos efectivos por usuario")
    print("=" * 70)

    seleccion = [buscar_usuario(cuenta, args[0])] if args else cuenta["Users"]

    for u in seleccion:
        nombre = u["UserName"]
        ctx = policies_de_usuario(cuenta, nombre)
        origen = ctx["_origen"]

        print(f"\n{nombre}  ({u['Arn']})")
        print(f"  MFA: {'si' if u['MFAEnabled'] else 'NO'}"
              f"   Tags: {u.get('Tags', {})}")
        print("  Identity policies:")
        for n, _ in ctx["identity"]:
            print(f"    - {n:22} (origen: {origen[n]})")
        if "boundary" in ctx:
            print(f"  Permission boundary: {ctx['boundary'][0][0]}  <- capa-techo")
        if "scp" in ctx:
            print(f"  SCP de la org:       {', '.join(n for n, _ in ctx['scp'])}  <- capa-techo")

        # Lectura al bucket de backups, para ver el efecto real.
        pet = peticion(cuenta, nombre, "s3:GetObject",
                       "arn:aws:s3:::banco-backups/nomina.xlsx")
        r = evaluar(pet, ctx)
        print(f"  -> s3:GetObject sobre banco-backups/nomina.xlsx: {r.decision}"
              f" ({r.motivo})")
