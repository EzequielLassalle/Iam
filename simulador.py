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
import sys

from contexto import (cargar_cuenta, cuenta_modificada, peticion,
                      policies_de_recurso, policies_de_usuario)
from motor_iam import evaluar

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


def informe(cuenta: dict, pet: dict, capas: dict) -> str:
    """Peticion, capas que participan y decision con su traza."""
    origen = capas.get("_origen", {})
    lineas = []

    lineas.append("Peticion")
    lineas.append(f"  principal : {pet['principal']}")
    lineas.append(f"  action    : {pet['action']}")
    lineas.append(f"  resource  : {pet['resource']}")
    if pet.get("resource_account"):
        lineas.append(f"  recurso en: cuenta {pet['resource_account']}  <- CROSS-ACCOUNT")
    ctx = pet.get("context", {})
    relevante = {k: v for k, v in ctx.items()
                 if k in ("aws:MultiFactorAuthPresent", "aws:SourceIp")
                 or k.startswith("aws:PrincipalTag/")}
    lineas.append("  contexto  : " + ", ".join(f"{k}={v}" for k, v in relevante.items()))

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

    return "\n".join(lineas)


def parsear(argv):
    p = argparse.ArgumentParser(
        prog="python main.py evaluar",
        description="Evalua una peticion contra el estado actual de la cuenta.",
    )
    p.add_argument("usuario")
    p.add_argument("accion", help="p.ej. s3:GetObject")
    p.add_argument("recurso", help="ARN completo, o * ")

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
                        "(p.ej. --ctx aws:ResourceTag/Proyecto=creditos)")
    return p.parse_args(argv)


def main(argv=None):
    args = parsear(argv if argv is not None else sys.argv[1:])

    extra = {}
    for par in args.ctx:
        if "=" not in par:
            print(f"--ctx espera CLAVE=VALOR, no '{par}'")
            return 2
        clave, valor = par.split("=", 1)
        extra[clave] = valor

    cuenta = cargar_cuenta()

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
