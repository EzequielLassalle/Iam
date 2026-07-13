"""
generar_datos.py
================
Genera la data SIMULADA del proyecto (los JSON que consumen los demas scripts).

Reproduce el esquema que devuelve la API real (ARNs, policy documents, eventos de
CloudTrail), de modo que enchufar el proyecto a una cuenta de verdad implique cambiar
solo la capa de carga.

Escenario: un banco ficticio (BancoXYZ). Reproducible con seed fijo, para que los
reportes sean comparables entre corridas.

Genera:
    datos/cuenta_iam.json         -> usuarios, grupos, roles, policies, SCP, bucket policy
    datos/eventos_cloudtrail.json -> ~30 eventos, con anomalias sembradas para auditoria.py
"""

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(2026)
AHORA = datetime.now(timezone.utc)
AQUI = Path(__file__).resolve().parent
ACCOUNT = "111111111111"          # cuenta principal de BancoXYZ
ACCOUNT_AUDIT = "222222222222"    # cuenta de auditoria (cross-account)


def iso(dt: datetime) -> str:
    """Formatea un datetime como ISO-8601 sin microsegundos, igual que lo hace AWS."""
    return dt.replace(microsecond=0).isoformat()


def hace(dias=0, horas=0) -> datetime:
    """
    Momento relativo a AHORA.

    Las fechas del dataset son relativas y no absolutas para que siga siendo valido sin
    importar cuando se regenere: una key creada hace 430 dias sigue estando vencida.
    """
    return AHORA - timedelta(days=dias, hours=horas)


# ---------------------------------------------------------------------------
# Policy documents reutilizables (JSON real de IAM)
# ---------------------------------------------------------------------------

POL_ADMIN = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}

POL_S3_READONLY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "LecturaBackups",
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:ListBucket"],
        "Resource": ["arn:aws:s3:::banco-backups", "arn:aws:s3:::banco-backups/*"],
    }],
}

POL_CREDITOS_ABAC = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "EC2SoloDeMiProyecto",
        "Effect": "Allow",
        "Action": ["ec2:StartInstances", "ec2:StopInstances", "ec2:DescribeInstances"],
        "Resource": "*",
        "Condition": {
            "StringEquals": {
                "aws:ResourceTag/Proyecto": "${aws:PrincipalTag/Proyecto}"
            }
        },
    }],
}

POL_DENY_SIN_MFA = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "NegarTodoSinMFA",
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}},
    }],
}

# SCP de guardrail a nivel Organization: prohibe apagar CloudTrail y salir de region
SCP_GUARDRAIL = {
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "PermitirTodoLoDemas", "Effect": "Allow", "Action": "*", "Resource": "*"},
        {"Sid": "ProhibirTocarCloudTrail", "Effect": "Deny",
         "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail"],
         "Resource": "*"},
    ],
}

# Rangos de red declarados: oficinas y VPN. Todo lo de afuera es anomalo por definicion.
REDES_CORPORATIVAS = ["200.45.10.0/24", "10.10.0.0/16"]

# Bucket policy de banco-backups: una resource-based policy, pegada al recurso y no al
# principal. Habilita a una cuenta AJENA (la de auditoria) a leer el bucket. Sin esto no
# hay cross-account posible, por mas permisos que la otra cuenta se otorgue a si misma.
#
# El Principal es ":root", que NO es el usuario root: delega en la cuenta 222 la decision
# de cuales de sus principales entran. Delega, no otorga: el principal de la 222 igual
# necesita que su propia identity policy se lo permita.
BUCKET_POLICY_BACKUPS = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PermitirALaCuentaDeAuditoria",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_AUDIT}:root"},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::banco-backups/*",
        },
    ],
}

# Permission boundary: techo que solo permite S3 y lectura, nada mas
BOUNDARY_S3 = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "TechoS3YReadOnly", "Effect": "Allow",
        "Action": ["s3:*", "ec2:Describe*", "iam:Get*", "iam:List*"],
        "Resource": "*",
    }],
}


# ---------------------------------------------------------------------------
# Usuarios (con access keys, MFA, tags) -- data cruda para el reporte de auditoria
# ---------------------------------------------------------------------------

def access_key(creada_hace_dias, ultimo_uso_hace_dias=None, activa=True):
    """
    Access key con el esquema de iam:ListAccessKeys.

    ultimo_uso_hace_dias=None modela una key creada y jamas usada.
    """
    key = {
        "AccessKeyId": "AKIA" + "".join(random.choice("ABCDEFGHJKLMNPQRSTUVWXYZ234567")
                                         for _ in range(16)),
        "Status": "Active" if activa else "Inactive",
        "CreateDate": iso(hace(creada_hace_dias)),
        "LastUsedDate": None if ultimo_uso_hace_dias is None
                        else iso(hace(ultimo_uso_hace_dias)),
    }
    return key


usuarios = [
    {
        "UserName": "mlopez", "Arn": f"arn:aws:iam::{ACCOUNT}:user/mlopez",
        "Groups": ["Creditos"], "MFAEnabled": True,
        "Tags": {"Proyecto": "Creditos", "Sucursal": "Rosario"},
        # Solo CreditosABAC directa: S3ReadOnlyBackups la HEREDA del grupo Creditos.
        "AttachedPolicies": ["CreditosABAC"],
        "PermissionBoundary": None,
        "AccessKeys": [access_key(120, ultimo_uso_hace_dias=2)],
        "PasswordLastUsed": iso(hace(1)),
    },
    {
        "UserName": "cgomez", "Arn": f"arn:aws:iam::{ACCOUNT}:user/cgomez",
        "Groups": ["Creditos"], "MFAEnabled": True,
        "Tags": {"Proyecto": "Creditos", "Sucursal": "Cordoba"},
        # Sin policies directas: todo lo que puede hacer lo hereda del grupo Creditos.
        "AttachedPolicies": [],
        "PermissionBoundary": None,
        "AccessKeys": [access_key(30, ultimo_uso_hace_dias=5)],
        "PasswordLastUsed": iso(hace(3)),
    },
    {
        # Cuenta de servicio con access key MUY vieja y sin MFA: hallazgo tipico
        "UserName": "svc-reporting", "Arn": f"arn:aws:iam::{ACCOUNT}:user/svc-reporting",
        "Groups": ["ServicioLectura"], "MFAEnabled": False,
        "Tags": {"Proyecto": "Plataforma", "Tipo": "servicio"},
        "AttachedPolicies": [],   # hereda S3ReadOnlyBackups del grupo ServicioLectura
        "PermissionBoundary": "BoundaryS3ReadOnly",
        "AccessKeys": [access_key(430, ultimo_uso_hace_dias=1),
                       access_key(430, ultimo_uso_hace_dias=None)],  # 2da key nunca usada
        "PasswordLastUsed": None,  # cuenta de servicio: sin consola
    },
    {
        # Usuario con AdministratorAccess: privilegio maximo, hay que auditarlo
        "UserName": "jadmin", "Arn": f"arn:aws:iam::{ACCOUNT}:user/jadmin",
        "Groups": ["Administradores"], "MFAEnabled": False,   # admin SIN MFA: rojo
        "Tags": {"Proyecto": "IT"},
        "AttachedPolicies": [],   # es admin por pertenecer al grupo Administradores
        "PermissionBoundary": None,
        "AccessKeys": [access_key(200, ultimo_uso_hace_dias=90)],
        "PasswordLastUsed": iso(hace(75)),  # admin sin actividad hace 75 dias
    },
    {
        # Contratista que dejo el banco: key activa, sin uso hace mucho
        "UserName": "temp-consultor", "Arn": f"arn:aws:iam::{ACCOUNT}:user/temp-consultor",
        "Groups": [], "MFAEnabled": False,
        "Tags": {"Proyecto": "Seguros", "Tipo": "contratista"},
        "AttachedPolicies": ["S3ReadOnlyBackups"],
        "PermissionBoundary": None,
        "AccessKeys": [access_key(250, ultimo_uso_hace_dias=180)],
        "PasswordLastUsed": iso(hace(180)),
    },
]

grupos = [
    {"GroupName": "Creditos", "AttachedPolicies": ["S3ReadOnlyBackups"]},
    {"GroupName": "Administradores", "AttachedPolicies": ["AdministratorAccess"]},
    {"GroupName": "ServicioLectura", "AttachedPolicies": ["S3ReadOnlyBackups"]},
]

managed_policies = {
    "AdministratorAccess": POL_ADMIN,
    "S3ReadOnlyBackups": POL_S3_READONLY,
    "CreditosABAC": POL_CREDITOS_ABAC,
    "NegarSinMFA": POL_DENY_SIN_MFA,
    "BoundaryS3ReadOnly": BOUNDARY_S3,
}

# Indexadas por ARN del recurso: una resource policy se resuelve por el recurso que se
# toca, no por el principal que llama.
resource_policies = {
    "arn:aws:s3:::banco-backups": BUCKET_POLICY_BACKUPS,
}

cuenta = {
    "AccountId": ACCOUNT,
    "GeneradoEl": iso(AHORA),
    "RedesCorporativas": REDES_CORPORATIVAS,
    "Organization": {"SCPs": {"GuardrailBase": SCP_GUARDRAIL}},
    "Users": usuarios,
    "Groups": grupos,
    "ManagedPolicies": managed_policies,
    "ResourcePolicies": resource_policies,
}


# ---------------------------------------------------------------------------
# Eventos de CloudTrail (con anomalias plantadas para el analizador)
# ---------------------------------------------------------------------------

def evento(nombre, usuario, tipo="IAMUser", cuando=None, ip="200.45.10.5",
           error=None, recurso=None, region="us-east-1"):
    """
    Evento con el esquema de cloudtrail:LookupEvents.

    ErrorCode solo se emite cuando la llamada fallo: en CloudTrail el campo no existe si
    la llamada tuvo exito, y esa ausencia es lo que distingue un intento de un exito.
    """
    ev = {
        "EventName": nombre,
        "EventTime": iso(cuando or hace(0, random.randint(1, 200))),
        "EventSource": nombre_a_source(nombre),
        "AwsRegion": region,
        "SourceIPAddress": ip,
        "UserIdentity": {"type": tipo, "userName": usuario,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/{usuario}"},
    }
    if error:
        ev["ErrorCode"] = error
    if recurso:
        ev["Resources"] = [recurso]
    return ev


# Eventos cuyo servicio no se deduce del prefijo. Se consultan primero: por prefijo,
# "DeleteTrail" caeria en "Delete" -> s3, que es el servicio equivocado.
SERVICIO_EXACTO = {
    "AssumeRole": "sts",
    "ConsoleLogin": "signin",
    "CreateUser": "iam",
    "AttachUserPolicy": "iam",
    "CreateAccessKey": "iam",
    "StopLogging": "cloudtrail",
    "DeleteTrail": "cloudtrail",
    "DescribeInstances": "ec2",
    "StartInstances": "ec2",
    "StopInstances": "ec2",
}

# El resto se deduce por prefijo (las operaciones de objeto de S3).
SERVICIO_POR_PREFIJO = {"Get": "s3", "Put": "s3", "List": "s3", "Delete": "s3"}


def nombre_a_source(nombre):
    """
    EventSource a partir del EventName: 'GetObject' -> 's3.amazonaws.com'.

    Coincidencia exacta primero y prefijo despues: hay nombres con el mismo prefijo en
    servicios distintos (DeleteObject en S3, DeleteTrail en CloudTrail).
    """
    if nombre in SERVICIO_EXACTO:
        return f"{SERVICIO_EXACTO[nombre]}.amazonaws.com"
    for prefijo, servicio in SERVICIO_POR_PREFIJO.items():
        if nombre.startswith(prefijo):
            return f"{servicio}.amazonaws.com"
    return "unknown.amazonaws.com"


eventos = []

# Actividad normal de mlopez y cgomez
for _ in range(12):
    u = random.choice(["mlopez", "cgomez"])
    eventos.append(evento(random.choice(["GetObject", "ListBucket", "DescribeInstances"]),
                          u, ip="200.45.10." + str(random.randint(2, 60))))

# ANOMALIA 1: login de root (nunca deberia usarse para el dia a dia)
eventos.append(evento("ConsoleLogin", "root", tipo="Root",
                      cuando=hace(0, 3), ip="45.133.1.90"))

# ANOMALIA 2: rafaga de AccessDenied de temp-consultor (posible cuenta comprometida)
for i in range(6):
    eventos.append(evento("GetObject", "temp-consultor", cuando=hace(0, i),
                          ip="45.133.1.90", error="AccessDenied",
                          recurso={"ResourceType": "AWS::S3::Object",
                                   "ResourceName": "banco-backups/nomina.xlsx"}))

# ANOMALIA 3: alguien intento apagar CloudTrail (lo bloquea la SCP, pero queda el intento)
eventos.append(evento("StopLogging", "jadmin", cuando=hace(0, 5), ip="45.133.1.90",
                      error="AccessDenied"))
eventos.append(evento("DeleteTrail", "jadmin", cuando=hace(0, 5), ip="45.133.1.90",
                      error="AccessDenied"))

# ANOMALIA 4: escalada de privilegios -> crear usuario + darle admin + crear key
eventos.append(evento("CreateUser", "jadmin", cuando=hace(0, 6)))
eventos.append(evento("AttachUserPolicy", "jadmin", cuando=hace(0, 6)))
eventos.append(evento("CreateAccessKey", "jadmin", cuando=hace(0, 6)))

# Actividad legitima de AssumeRole (cuenta de auditoria)
for _ in range(4):
    eventos.append(evento("AssumeRole", "svc-reporting", cuando=hace(random.randint(1, 3)),
                          ip="10.10.1.20"))

eventos.sort(key=lambda e: e["EventTime"], reverse=True)


# ---------------------------------------------------------------------------
# Escritura
# ---------------------------------------------------------------------------

def escribir(nombre, obj):
    """Serializa un dict a JSON indentado en datos/."""
    ruta = AQUI / nombre
    ruta.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  generado  {ruta.relative_to(AQUI.parent)}  ({ruta.stat().st_size:,} bytes)")


if __name__ == "__main__":
    print("Generando datos simulados de BancoXYZ...")
    escribir("cuenta_iam.json", cuenta)
    escribir("eventos_cloudtrail.json", {"Events": eventos})
    print(f"\nListo. {len(usuarios)} usuarios, {len(grupos)} grupos, "
          f"{len(eventos)} eventos de CloudTrail.")
