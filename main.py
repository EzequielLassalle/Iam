"""
main.py
=======
Puerta de entrada unica al proyecto.

Cada modulo corre por separado (python motor_iam.py, python auditoria.py...); esto los
centraliza.

    python main.py                 -> muestra los comandos
    python main.py motor           -> auto-test del motor de evaluacion
    python main.py permisos        -> permisos efectivos de cada usuario y de donde salen
    python main.py evaluar U A R   -> evalua una peticion suelta contra la cuenta actual
    python main.py recursos U A    -> sobre que recursos del inventario puede U la accion A
    python main.py acceso-externo A R C -> cross-account entrante: cuenta C accede al recurso R
    python main.py escenarios      -> los 6 casos de IAM
    python main.py escenarios -q   -> los mismos, prediciendo el resultado antes de verlo
    python main.py escenarios 3    -> solo el escenario 3
    python main.py admin ...       -> modifica la cuenta (subcomandos: admin --help)
    python main.py auditoria       -> el reporte de auditoria de la cuenta
    python main.py datos           -> regenera los JSON de datos
    python main.py test            -> corre la suite de tests
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

AQUI = Path(__file__).resolve().parent

COMANDOS = {
    "motor":      ("motor_iam.py",           "Auto-test del motor de evaluacion"),
    "permisos":   ("contexto.py",            "Permisos efectivos de cada usuario y de donde salen"),
    "evaluar":    ("simulador.py",           "Evalua una peticion: <usuario> <accion> <recurso>"),
    "recursos":   ("recursos.py",            "Sobre que recursos del inventario puede: <usuario> <accion>"),
    "acceso-externo": ("acceso_externo.py",  "Cross-account entrante: <accion> <recurso> <cuenta-externa>"),
    "escenarios": ("escenarios.py",          "Los casos de IAM (-q para predecir antes de ver)"),
    "admin":      ("admin_cuenta.py",        "Modifica la cuenta: usuarios, policies, grupos, techos"),
    "auditoria":  ("auditoria.py",           "Auditoria de la cuenta: credenciales y actividad"),
    "datos":      ("datos/generar_datos.py", "Regenera los JSON de la cuenta y de CloudTrail"),
    "test":       ("tests.py",               "Corre la suite de tests"),
}


def correr(script: str, args: list) -> int:
    """
    Ejecuta un script del proyecto como si se lo hubiera invocado directo.

    Subproceso y no import, para que cada modulo corra con su propio __main__ y con sus
    argumentos, que es como estan escritos.
    """
    return subprocess.call([sys.executable, str(AQUI / script), *args])


def ayuda():
    """Imprime el menu de comandos disponibles."""
    print("Simulador de AWS IAM -- BancoXYZ\n")
    print("Comandos:")
    for nombre, (_, desc) in COMANDOS.items():
        print(f"  python main.py {nombre:12} {desc}")


if __name__ == "__main__":
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help", "help"):
        ayuda()
        sys.exit(0)

    comando, resto = args[0], args[1:]

    if comando not in COMANDOS:
        print(f"No conozco el comando '{comando}'.\n")
        ayuda()
        sys.exit(1)

    script, _ = COMANDOS[comando]
    sys.exit(correr(script, resto))
