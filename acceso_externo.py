"""
acceso_externo.py
=================
Cross-account entrante: puede un principal de OTRA cuenta acceder a un recurso de esta.

El comando 'evaluar' mira la cuenta desde adentro (un usuario nuestro pidiendo algo). Esto mira
el otro sentido, el que importa administrar: alguien de afuera tocando un recurso nuestro. Ahi no
se elige un usuario propio -- el principal es externo. Se elige la accion, el recurso propio y la
cuenta desde la que se accede.

Se ASUME que la cuenta externa ya le concedio el permiso a su usuario (una de las dos puntas del
cross-account). La decision depende entonces de la unica punta que controla esta cuenta: la
resource policy del recurso. La pregunta concreta es "mi bucket policy, deja entrar a esa cuenta?".

    python main.py acceso-externo s3:GetObject arn:aws:s3:::banco-backups/nomina.xlsx 222222222222
"""

from __future__ import annotations

import argparse
import sys

from contexto import cargar_cuenta, cuenta_modificada, policies_de_recurso
from simulador import informe

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def construir_entrante(cuenta: dict, accion: str, recurso: str, cuenta_externa: str):
    """
    Arma (peticion, capas) para un acceso entrante.

    La identity del principal externo se da por concedida: es la punta que vive en la otra
    cuenta y que esta cuenta no controla. Se modela como un Allow sintetico de la accion sobre
    el recurso, para que la decision recaiga en la resource policy propia.
    """
    nombre_id = "IdentityAsumida"
    identity = [(nombre_id, {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PermisoConcedidoPorLaCuentaExterna",
            "Effect": "Allow",
            "Action": accion,
            "Resource": recurso,
        }],
    })]

    pet = {
        "principal": f"arn:aws:iam::{cuenta_externa}:user/externo",
        "principal_account": cuenta_externa,
        "action": accion,
        "resource": recurso,
        "resource_account": cuenta["AccountId"],
        "context": {},
    }

    capas = {"identity": identity,
             "_origen": {nombre_id: f"asumida en la cuenta {cuenta_externa}"}}
    rp = policies_de_recurso(cuenta, recurso)
    if rp:
        capas["resource"] = rp

    return pet, capas


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="python main.py acceso-externo",
        description="Cross-account entrante: puede otra cuenta acceder a un recurso nuestro.",
    )
    p.add_argument("accion", help="la accion que intenta el externo, por ejemplo s3:GetObject")
    p.add_argument("recurso", help="el recurso propio, por ARN")
    p.add_argument("cuenta_externa", help="la cuenta desde la que se accede, por ejemplo 222222222222")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    cuenta = cargar_cuenta()

    if args.cuenta_externa == cuenta["AccountId"]:
        print(f"{args.cuenta_externa} es la propia cuenta: no es cross-account. Usá 'evaluar'.")
        return 2

    pet, capas = construir_entrante(cuenta, args.accion, args.recurso, args.cuenta_externa)

    if cuenta_modificada():
        print("[!] La cuenta esta MODIFICADA respecto de la version commiteada.\n")

    print("Acceso ENTRANTE (se asume que la cuenta externa concedio la identity)\n")
    print(informe(cuenta, pet, capas))
    return 0


if __name__ == "__main__":
    sys.exit(main())
