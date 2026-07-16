"""
recursos.py
===========
Analisis de acceso efectivo: sobre que recursos del inventario un usuario puede una accion.

Las opciones de 'evaluar' responden por un recurso puntual. Esta barre el inventario entero
(datos/recursos.json) y evalua la misma accion contra cada recurso del servicio, que es como se
audita el acceso en la practica: no "puede tocar este bucket", sino "de todo lo que hay, a que
llega". Con el ABAC por tags, el resultado se parte solo: un usuario alcanza los recursos de su
proyecto y no los de otros.

Toma los tags del recurso real, sin inyectarlos por contexto. Nada de logica de decision: cada
recurso se evalua con el motor, via simulador.construir.

    python main.py recursos mlopez ec2:StartInstances
    python main.py recursos cgomez s3:GetObject
"""

from __future__ import annotations

import argparse
import sys

from contexto import cargar_cuenta, cargar_recursos
from motor_iam import evaluar
from simulador import construir

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def accesibles(cuenta: dict, recursos: dict, usuario: str, accion: str) -> list:
    """
    Por cada recurso del servicio de la accion: (decision, arn, tags, motivo).

    Filtra por servicio (el prefijo de la accion): evaluar s3:GetObject contra una instancia
    EC2 no dice nada, solo ensucia. El servicio sale de 'ec2:StartInstances' -> 'ec2'.
    """
    servicio = accion.split(":", 1)[0]
    prefijo = f"arn:aws:{servicio}:"
    filas = []
    for arn, meta in recursos.items():
        if not arn.startswith(prefijo):
            continue
        pet, capas = construir(cuenta, usuario, accion, arn)
        r = evaluar(pet, capas)
        filas.append((r.decision, arn, meta.get("Tags", {}), r.motivo))
    return filas


def informe(usuario: str, accion: str, filas: list) -> str:
    lineas = [f"{usuario} / {accion}  -- recursos del inventario:"]
    if not filas:
        lineas.append("  (no hay recursos del servicio de esa accion en el inventario)")
        return "\n".join(lineas)

    ancho = max(len(arn) for _, arn, _, _ in filas)
    for decision, arn, tags, motivo in filas:
        marca = "ALLOW" if decision == "Allow" else "DENY "
        tags_txt = ", ".join(f"{k}={v}" for k, v in tags.items())
        lineas.append(f"  {marca}  {arn:{ancho}}  ({tags_txt})")

    permitidos = sum(1 for d, _, _, _ in filas if d == "Allow")
    lineas.append(f"\n  {permitidos} de {len(filas)} accesibles.")
    return "\n".join(lineas)


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="python main.py recursos",
        description="Sobre que recursos del inventario un usuario puede una accion.",
    )
    p.add_argument("usuario")
    p.add_argument("accion", help="por ejemplo ec2:StartInstances o s3:GetObject")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    cuenta = cargar_cuenta()
    recursos = cargar_recursos()
    if not recursos:
        print("No hay inventario de recursos (datos/recursos.json).")
        return 1

    try:
        filas = accesibles(cuenta, recursos, args.usuario, args.accion)
    except KeyError as e:
        print(e.args[0])
        return 1

    print(informe(args.usuario, args.accion, filas))
    return 0


if __name__ == "__main__":
    sys.exit(main())
