"""
auditoria.py
============
Revision de la cuenta: que credenciales estan en mal estado y que actividad no deberia
haber ocurrido.

Mientras el motor responde "esta peticion se permite?", este modulo responde las dos
preguntas de una auditoria de rutina:

    A. Higiene de credenciales   -> sale del estado de la cuenta (cuenta_iam.json).
                                    Es lo que en AWS se saca del IAM Credential Report:
                                    MFA, antiguedad y uso de las access keys, usuarios
                                    inactivos, quien tiene privilegios de mas.

    B. Actividad sospechosa      -> sale del historial (eventos_cloudtrail.json).
                                    Reglas sobre cosas que en una cuenta sana no pasan:
                                    uso del root, rafagas de accesos denegados, actividad
                                    desde fuera de la red, intentos de apagar el registro
                                    de auditoria.

No hay deteccion estadistica: son umbrales y reglas explicitas. Es como se hace esto en
la practica, y es lo que permite explicar y defender cada hallazgo.

    python auditoria.py              -> el reporte completo
    python auditoria.py --bloque A   -> solo credenciales
    python auditoria.py --bloque B   -> solo actividad
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path

from contexto import cargar_cuenta, policies_de_usuario

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

AQUI = Path(__file__).resolve().parent
RUTA_EVENTOS = AQUI / "datos" / "eventos_cloudtrail.json"

# --- Umbrales de la politica de seguridad -----------------------------------
# Parametros de negocio, no de implementacion: se ajustan sin tocar la logica.
DIAS_KEY_VIEJA = 90        # antiguedad maxima de una access key antes de rotarla
DIAS_INACTIVIDAD = 90      # sin actividad por mas tiempo, la identidad se considera muerta
RAFAGA_DENEGADOS = 5       # AccessDenied del mismo principal que dejan de ser ruido

# Secuencia de escalada: crear identidad, otorgarle permisos y emitirle credenciales.
# Cada accion es rutinaria por separado; encadenadas por un mismo actor, no.
ACCIONES_DE_ESCALADA = ["CreateUser", "AttachUserPolicy", "CreateAccessKey"]

# Manipulacion del rastro de auditoria.
ACCIONES_ANTI_FORENSES = {"StopLogging", "DeleteTrail", "PutEventSelectors"}

ORDEN_SEVERIDAD = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAJO": 3}


@dataclass
class Hallazgo:
    """Un hallazgo, con lo minimo necesario para poder accionarlo."""
    severidad: str      # CRITICO / ALTO / MEDIO / BAJO
    categoria: str      # de que tipo de problema se trata
    sujeto: str         # a quien o a que afecta
    detalle: str        # que se encontro
    recomendacion: str  # que hacer

    def __str__(self):
        """Una linea por hallazgo, alineada para lectura en diagonal."""
        return (f"  [{self.severidad:8}] {self.categoria:24} {self.sujeto:16} {self.detalle}\n"
                f"  {'':11}-> {self.recomendacion}")


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def cargar_eventos(ruta: Path = RUTA_EVENTOS) -> list:
    """
    Carga el historial de CloudTrail. Equivale a cloudtrail:LookupEvents.

    En produccion serian eventos leidos desde S3; el esquema es el mismo, asi que el
    resto del modulo no cambiaria.
    """
    if not ruta.exists():
        raise FileNotFoundError(
            f"No existe {ruta}.\nCorre primero:  python datos/generar_datos.py"
        )
    return json.loads(ruta.read_text(encoding="utf-8"))["Events"]


def dias_desde(texto: str | None) -> int | None:
    """
    Dias transcurridos desde un timestamp. None si el timestamp es None.

    Ese None hay que propagarlo: en IAM significa "nunca". Una key con LastUsedDate=None
    no es una key vieja, es una key jamas usada, y son hallazgos distintos.
    """
    if not texto:
        return None
    fecha = datetime.fromisoformat(str(texto).replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - fecha).days


def ip_es_corporativa(ip: str, redes: list) -> bool:
    """True si la IP cae dentro de alguno de los rangos declarados."""
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    return any(addr in ip_network(red, strict=False) for red in redes)


def recurso_de_evento(ev: dict) -> str:
    """Nombre del recurso que tocaba un evento, o '*' si el evento no declara ninguno."""
    for r in ev.get("Resources", []):
        return r.get("ResourceName", "*")
    return "*"


def es_admin(cuenta: dict, nombre_usuario: str) -> bool:
    """True si al usuario le aplica AdministratorAccess, sea directa o heredada de un grupo."""
    policies = policies_de_usuario(cuenta, nombre_usuario)["identity"]
    return any(nombre == "AdministratorAccess" for nombre, _ in policies)


# ---------------------------------------------------------------------------
# BLOQUE A -- Higiene de credenciales
# ---------------------------------------------------------------------------

def revisar_credenciales(cuenta: dict) -> list:
    """
    Contrasta las credenciales de cada usuario contra los umbrales de la politica.

    Es el equivalente al IAM Credential Report: MFA, antiguedad y uso de las access keys,
    inactividad y privilegios excesivos.
    """
    hallazgos = []

    for usuario in cuenta["Users"]:
        nombre = usuario["UserName"]
        es_servicio = usuario.get("Tags", {}).get("Tipo") == "servicio"
        admin = es_admin(cuenta, nombre)

        # --- Privilegio maximo ---
        if admin:
            hallazgos.append(Hallazgo(
                "ALTO", "privilegio-maximo", nombre,
                "tiene AdministratorAccess (Allow '*' sobre '*')",
                "Acotar a los permisos que realmente usa. Como minimo, asignarle un "
                "permission boundary y exigir MFA.",
            ))

        # --- MFA ---
        if not usuario.get("MFAEnabled"):
            if admin:
                hallazgos.append(Hallazgo(
                    "CRITICO", "mfa-ausente", nombre,
                    "es administrador y NO tiene MFA habilitado",
                    "Habilitar MFA de inmediato: es el unico factor entre una password "
                    "comprometida y el control total de la cuenta.",
                ))
            elif es_servicio:
                hallazgos.append(Hallazgo(
                    "MEDIO", "mfa-ausente", nombre,
                    "cuenta de servicio sin MFA (esperable: no hay quien apriete el token)",
                    "No aplica MFA. Migrar a un rol con credenciales temporales para "
                    "eliminar la dependencia de access keys de larga duracion.",
                ))
            else:
                hallazgos.append(Hallazgo(
                    "ALTO", "mfa-ausente", nombre,
                    "usuario humano sin MFA habilitado",
                    "Habilitar MFA y forzarlo con un Deny condicional "
                    "(BoolIfExists sobre aws:MultiFactorAuthPresent).",
                ))

        # --- Access keys ---
        for key in usuario.get("AccessKeys", []):
            if key["Status"] != "Active":
                continue
            kid = key["AccessKeyId"]
            edad = dias_desde(key["CreateDate"])
            ultimo_uso = dias_desde(key.get("LastUsedDate"))

            if ultimo_uso is None:
                hallazgos.append(Hallazgo(
                    "ALTO", "key-nunca-usada", nombre,
                    f"{kid} esta activa desde hace {edad} dias y NUNCA se uso",
                    "Eliminarla: superficie de ataque sin contrapartida operativa.",
                ))
            elif ultimo_uso > DIAS_INACTIVIDAD:
                hallazgos.append(Hallazgo(
                    "ALTO", "key-abandonada", nombre,
                    f"{kid} sigue activa pero no se usa hace {ultimo_uso} dias",
                    "Desactivarla y eliminarla tras un periodo de gracia sin incidencias.",
                ))

            if edad is not None and edad > DIAS_KEY_VIEJA:
                hallazgos.append(Hallazgo(
                    "MEDIO", "key-sin-rotar", nombre,
                    f"{kid} tiene {edad} dias de antiguedad (limite: {DIAS_KEY_VIEJA})",
                    "Rotarla: la exposicion acumulada crece con la antiguedad.",
                ))

        # --- Actividad del usuario ---
        inactivo = dias_desde(usuario.get("PasswordLastUsed"))
        if inactivo is not None and inactivo > DIAS_INACTIVIDAD:
            hallazgos.append(Hallazgo(
                "ALTO", "usuario-inactivo", nombre,
                f"no se loguea hace {inactivo} dias, pero conserva sus permisos",
                "Validar con RRHH la vigencia de la persona. Si causo baja, ejecutar el "
                "leaver: deshabilitar credenciales y remover permisos.",
            ))

        # --- Permisos directos en vez de por grupo ---
        if usuario.get("AttachedPolicies") and not usuario.get("Groups"):
            hallazgos.append(Hallazgo(
                "BAJO", "permisos-directos", nombre,
                "tiene policies pegadas al usuario y no pertenece a ningun grupo",
                "Asignar permisos via grupo: los adjuntos directos escapan a la revision "
                "periodica y sobreviven a los cambios de puesto.",
            ))

    return hallazgos


# ---------------------------------------------------------------------------
# BLOQUE B -- Actividad sospechosa en el historial
# ---------------------------------------------------------------------------

def detectar_anomalias(cuenta: dict, eventos: list) -> list:
    """
    Reglas sobre el historial: patrones que en una cuenta sana no aparecen.

    En produccion cada una de estas reglas seria una alarma conectada a EventBridge.
    """
    hallazgos = []
    redes = cuenta.get("RedesCorporativas", [])

    # --- 1. Uso del usuario root ---------------------------------------------
    root = [e for e in eventos if e["UserIdentity"].get("type") == "Root"]
    if root:
        cuando = ", ".join(sorted({e["EventTime"][:16] for e in root}))
        ips = ", ".join(sorted({e["SourceIPAddress"] for e in root}))
        hallazgos.append(Hallazgo(
            "CRITICO", "uso-de-root", "root",
            f"{len(root)} evento(s) del usuario root ({cuando}) desde {ips}",
            "El root no debe usarse para operar: ignora las identity policies y los "
            "permission boundaries. Custodiar sus credenciales con MFA fisico y trabajar "
            "siempre con usuarios o roles.",
        ))

    # --- 2. Rafagas de AccessDenied ------------------------------------------
    # Un AccessDenied aislado es ruido; una serie contra el mismo recurso es enumeracion.
    denegados = defaultdict(list)
    for e in eventos:
        if e.get("ErrorCode") == "AccessDenied":
            denegados[e["UserIdentity"].get("userName")].append(e)

    for usuario, evs in denegados.items():
        if len(evs) >= RAFAGA_DENEGADOS:
            ips = ", ".join(sorted({e["SourceIPAddress"] for e in evs}))
            recursos = ", ".join(sorted({recurso_de_evento(e) for e in evs}))
            hallazgos.append(Hallazgo(
                "CRITICO", "rafaga-denegados", usuario,
                f"{len(evs)} AccessDenied seguidos desde {ips} contra {recursos}",
                "Tratar la credencial como comprometida: desactivar las access keys, "
                "inventariar que llamadas SI tuvieron exito, y despues investigar.",
            ))

    # --- 3. Intentos de manipular el rastro de auditoria ----------------------
    for e in [ev for ev in eventos if ev["EventName"] in ACCIONES_ANTI_FORENSES]:
        usuario = e["UserIdentity"].get("userName")
        resultado = e.get("ErrorCode", "EXITOSO")
        hallazgos.append(Hallazgo(
            "CRITICO", "anti-forense", usuario,
            f"intento de {e['EventName']} sobre CloudTrail desde {e['SourceIPAddress']} "
            f"({resultado})",
            "Manipular el rastro de auditoria precede a la actividad que se quiere ocultar. "
            "Que la llamada haya sido denegada no cierra el caso: hay que establecer por que "
            "ese principal la intento.",
        ))

    # --- 4. Secuencia de escalada de privilegios -----------------------------
    por_usuario = defaultdict(set)
    for e in eventos:
        por_usuario[e["UserIdentity"].get("userName")].add(e["EventName"])

    for usuario, nombres in por_usuario.items():
        hechas = [a for a in ACCIONES_DE_ESCALADA if a in nombres]
        if len(hechas) == len(ACCIONES_DE_ESCALADA):
            hallazgos.append(Hallazgo(
                "ALTO", "escalada-privilegios", usuario,
                f"encadeno {' + '.join(hechas)} en la misma ventana",
                "Verificar que exista un cambio aprobado que lo respalde. Sin respaldo, "
                "tratar la identidad creada como puerta trasera: eliminarla y rotar las "
                "credenciales del principal que la creo.",
            ))

    # --- 5. Actividad desde fuera de la red corporativa ----------------------
    fuera = defaultdict(set)
    for e in eventos:
        ip = e["SourceIPAddress"]
        if redes and not ip_es_corporativa(ip, redes):
            fuera[ip].add(e["UserIdentity"].get("userName"))

    for ip, usuarios in sorted(fuera.items()):
        hallazgos.append(Hallazgo(
            "ALTO", "ip-no-corporativa", ip,
            f"actividad desde fuera de la red declarada, afectando a: "
            f"{', '.join(sorted(usuarios))}",
            f"Redes declaradas: {', '.join(redes)}. Bloquear el origen y auditar toda la "
            "actividad registrada desde el.",
        ))

    return hallazgos


# ---------------------------------------------------------------------------
# Reporte
# ---------------------------------------------------------------------------

def imprimir_hallazgos(titulo: str, hallazgos: list):
    """Imprime los hallazgos ordenados por severidad descendente."""
    print("\n" + "=" * 78)
    print(titulo)
    print("=" * 78)

    if not hallazgos:
        print("  Sin hallazgos.")
        return

    for h in sorted(hallazgos, key=lambda x: (ORDEN_SEVERIDAD[x.severidad], x.sujeto)):
        print(h)
        print()


def resumen(todos: list):
    """Conteo por severidad y lista de los criticos."""
    conteo = defaultdict(int)
    for h in todos:
        conteo[h.severidad] += 1

    print("\n" + "=" * 78)
    print("RESUMEN")
    print("=" * 78)
    for sev in ("CRITICO", "ALTO", "MEDIO", "BAJO"):
        if conteo[sev]:
            print(f"  {sev:8} : {conteo[sev]}")
    print(f"  {'TOTAL':8} : {len(todos)} hallazgo(s)")

    criticos = [h for h in todos if h.severidad == "CRITICO"]
    if criticos:
        print("\n  Remediacion inmediata:")
        for h in criticos:
            print(f"    - {h.sujeto}: {h.detalle}")


if __name__ == "__main__":
    args = sys.argv[1:]
    solo = None
    if "--bloque" in args:
        i = args.index("--bloque") + 1
        solo = args[i].upper() if i < len(args) else None
        if solo not in ("A", "B", None):
            print(f"Bloque desconocido: '{solo}'. Los bloques son A y B.")
            sys.exit(1)

    cuenta = cargar_cuenta()
    eventos = cargar_eventos()

    print("=" * 78)
    print(f"AUDITORIA DE LA CUENTA {cuenta['AccountId']}")
    print(f"{len(cuenta['Users'])} usuarios, {len(eventos)} eventos de CloudTrail analizados")
    print("=" * 78)

    todos = []

    if solo in (None, "A"):
        h = revisar_credenciales(cuenta)
        imprimir_hallazgos("BLOQUE A -- Higiene de credenciales", h)
        todos += h

    if solo in (None, "B"):
        h = detectar_anomalias(cuenta, eventos)
        imprimir_hallazgos("BLOQUE B -- Actividad sospechosa en el historial", h)
        todos += h

    if solo is None:
        resumen(todos)
